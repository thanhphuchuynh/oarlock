package sshsrv

// The `log` profile from an operator's `ssh`.
//
//	ssh -s log:messages treadmill-4821@gateway
//	ssh -s log:agent treadmill-4821@gateway | grep -i refused
//
// # Why the source rides in the subsystem string
//
// `ssh -s` takes one string and no arguments, so that string is the only place an operator
// can say *which* log. The alternative was `ssh device log messages`, and that argv is
// already the `exec` profile — overloading it would make "run the command `log`" and
// "stream the log source `log`" the same request, decided by a lookup somewhere.
//
// The shape it buys is worth having: a log session is stdout and nothing else, so it pipes.
// `| grep`, `| tail`, `> file` all work with no client to install.
//
// # Why this is not `file:read` with a nicer name
//
// The gateway names a *source*, not a path, and the device holds the mapping. So the
// authorisation question is "may this operator read the agent log on this device", which
// somebody can write a policy for across a mixed fleet — rather than a path that differs
// per platform. See frame.LogSource.
//
// It also means this profile cannot be turned into an arbitrary file read by a compromised
// gateway, which `file` deliberately can be within its root.
//
// # Recorded, and dropping rather than blocking
//
// A log tail is recorded like a shell: it is terminal-shaped output an operator read, and
// "what were they looking at" is the same question. But its backpressure policy is Drop —
// internal/pump/policy.go — because a reader who falls behind on a log wants current lines
// and a THROTTLE saying how much it missed, not a stall. A shell is the opposite, and the
// difference is the profile string.

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	gssh "github.com/gliderlabs/ssh"

	"github.com/oarlock/oarlock/internal/invite"
	"github.com/oarlock/oarlock/internal/sessionrun"
	"github.com/oarlock/oarlock/internal/sessions"
	"github.com/oarlock/oarlock/pkg/condition"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
	"github.com/oarlock/oarlock/pkg/transport"
)

// LogSubsystem is the `ssh -s` prefix. The source name follows a colon.
const LogSubsystem = "log"

// ProfileLog is the session profile and the string written to the ledger. It is the one
// internal/pump gives Drop backpressure to, along with `exec`.
const ProfileLog = "log"

// MaxLogSourceName bounds the name an operator may ask for.
//
// The name is looked up in a map on the device, so a long one costs nothing there — but it
// is written to the ledger, printed in a banner and passed to an authorizer, and a
// kilobyte of it in each of those is a kilobyte somebody has to store per session.
const MaxLogSourceName = 128

// handleLog streams one device log source to the operator's stdout.
func (s *Server) handleLog(sess gssh.Session, dev *plugin.Device, p *plugin.Principal,
	source string, log *slog.Logger) {

	ctx := sess.Context()

	if source == "" {
		fmt.Fprintln(sess.Stderr(), "oarlock: name a log source, e.g. -s log:messages")
		_ = sess.Exit(1)
		return
	}
	if len(source) > MaxLogSourceName {
		fmt.Fprintln(sess.Stderr(), "oarlock: that log source name is too long")
		_ = sess.Exit(1)
		return
	}
	if !dev.Supports(ProfileLog) {
		// The device said which profiles it serves. Refusing here beats waking it for a
		// session it will refuse itself after a round trip.
		log.Warn("log refused: device does not offer log")
		fmt.Fprintln(sess.Stderr(), "oarlock: this device does not offer log streaming")
		_ = sess.Exit(1)
		return
	}

	// Authorisation, per device and per source. `log` is its own action: a grant to open
	// a shell is not a grant to read every log the device publishes, and one of those
	// logs is usually the one recording what everybody else did.
	target := plugin.Target{Log: source}
	if verdict := s.o.Authz.AtOpen(ctx, p, dev, plugin.ActionLog, target); !verdict.Allow() {
		c, _ := condition.Lookup(verdict.Code)
		text := c.Text()
		if verdict.Reason != "" {
			text = verdict.Reason
		}
		log.Warn("log refused by authorization", "source", source,
			"outcome", verdict.Outcome, "code", verdict.Code, "error", verdict.Err)
		s.audit(ctx, plugin.AuditEvent{
			Kind: plugin.AuditSessionRejected, DeviceID: dev.ID, Principal: p.ID,
			Surface: "ssh", Code: verdict.Code, Reason: verdict.Reason,
			Action: string(plugin.ActionLog),
		})
		fmt.Fprintf(sess.Stderr(), "oarlock: %s\r\n", safeText(text))
		_ = sess.Exit(1)
		return
	}

	// record_input is resolved because a log session *is* recorded, and a policy conflict
	// has to refuse rather than pick — even though there is no operator input to capture,
	// the recording still exists and the policy still governs it.
	recordInput, err := s.o.RecordInput.Resolve(p, dev)
	if err != nil {
		log.Warn("log refused by record_input policy", "error", err)
		fmt.Fprintf(sess.Stderr(), "oarlock: record_input policy conflict: %s\r\n",
			safeText(err.Error()))
		_ = sess.Exit(1)
		return
	}

	sessionID := s.o.NewSessionID()
	row := &sessions.Session{
		ID: sessionID, DeviceID: dev.ID, Profile: ProfileLog,
		Mode: string(dev.ResolvedMode()), Principal: p.ID,
		RecordInput: recordInput,
		State:       sessions.StateWaking, RecordingState: sessions.NotRecorded,
	}
	if err := s.o.Sessions.Create(ctx, row); err != nil {
		if errors.Is(err, sessions.ErrLimit) {
			fmt.Fprintln(sess.Stderr(), "oarlock: too many sessions are open on this device")
		} else {
			log.Error("could not create a session row", "error", err)
			fmt.Fprintln(sess.Stderr(), "oarlock: could not open a session")
		}
		_ = sess.Exit(1)
		return
	}

	// Follow is always on from this surface: an operator who wanted a snapshot would
	// redirect to a file and press Ctrl-C, and an `ssh -s log:` that exited after the
	// history would be a `tail` with no `-f` and no way to ask for one.
	pending, err := s.o.Inviter.Invite(ctx, dev, invite.Request{
		SessionID:   sessionID,
		Profile:     ProfileLog,
		Principal:   p.ID,
		RecordInput: recordInput,
		Log:         &frame.LogSource{Name: source, Follow: true},
	})
	if err != nil {
		var f *invite.Failure
		if errors.As(err, &f) {
			log.Warn("could not invite the device", "code", f.Code, "error", err)
			fmt.Fprintf(sess.Stderr(), "oarlock: %s\r\n", safeText(operatorText(f)))
		} else {
			log.Error("invite failed", "error", err)
			fmt.Fprintln(sess.Stderr(), "oarlock: could not open a session")
		}
		s.reject(ctx, sessionID, closeReason(err, "device_offline"))
		_ = sess.Exit(1)
		return
	}

	att, err := pending.Wait(ctx)
	if err != nil {
		s.o.Inviter.Cancel(ctx, sessionID, "operator_gave_up")
		var f *invite.Failure
		if errors.As(err, &f) {
			fmt.Fprintf(sess.Stderr(), "oarlock: %s\r\n", safeText(operatorText(f)))
		} else {
			fmt.Fprintln(sess.Stderr(), "oarlock: session setup failed")
		}
		s.reject(ctx, sessionID, closeReason(err, "device_offline"))
		_ = sess.Exit(1)
		return
	}
	defer att.Done()

	_ = s.o.Sessions.Update(ctx, sessionID, func(row *sessions.Session) error {
		row.State = sessions.StateAttached
		row.AttachedAt = time.Now()
		return nil
	})

	runner := &sessionrun.Runner{
		Sessions: s.o.Sessions, Live: s.o.Live, Recorder: s.o.Recorder,
		Limits: s.o.Limits, Deadlines: s.o.Deadlines, Log: s.log,
		Authz: s.o.AuthzSupervisor,
	}
	opConn := newForwardConn(sess, sess.RemoteAddr().String(), s.log.With("session", sessionID))
	defer opConn.Close(transport.CloseNormal, "log over")

	params := sessionrun.Params{
		SessionID: sessionID, DeviceID: dev.ID, Profile: ProfileLog,
		Principal: p.ID, Action: plugin.ActionLog, Target: target,
		Surface: "ssh", Grantee: p, RecordInput: recordInput,
		Device: att.Conn,
		// No PTY: a log stream is bytes, and giving it a terminal would invite a client
		// to send window changes to something with no window.
		Operator: opConn,
	}

	rw, recording, startedAt, err := runner.Prepare(ctx, params)
	if err != nil {
		// Fail closed, same as a shell: a session that looks recorded and is not is worse
		// than one that never opened, and this one is recorded by design.
		log.Error("could not start recording", "session", sessionID, "error", err)
		runner.Reject(ctx, sessionID, "recorder_failed")
		fmt.Fprintln(sess.Stderr(), "oarlock: could not start recording; refusing the session")
		_ = sess.Exit(1)
		return
	}

	// The disclosure goes on stderr, so a pipeline gets only log lines on stdout. A
	// banner mixed into `| grep` output would be a line somebody's alerting matches on.
	fmt.Fprint(sess.Stderr(), logBanner(dev, source, sessionID, recording))
	log.Info("log open", "session", sessionID, "source", source, "recording", recording)

	out := runner.Run(ctx, params, rw, startedAt)
	log.Info("log closed", "session", sessionID, "reason", out.Result.Reason,
		"bytes_out", out.Result.Stats.BytesOut, "dropped", out.Result.Stats.BytesDropped)

	// Said again at the end, for the same reason a shell's is: nobody should learn
	// whether a session was recorded from the absence of a recording weeks later. It also
	// carries the dropped count, which is the one number a log reader needs and cannot
	// get any other way — a gap in a tail is invisible by construction.
	fmt.Fprint(sess.Stderr(), logClosing(sessionID, out.Result.Reason,
		out.Result.Stats.BytesDropped, recording))
	_ = sess.Exit(0)
}

func logBanner(dev *plugin.Device, source, sessionID string, recording bool) string {
	return fmt.Sprintf("oarlock: %s log on %s · session %s · this session is %s\r\n",
		safeText(source), safeText(dev.ID), safeText(sessionID), recordingWord(recording))
}

func logClosing(sessionID, reason string, dropped int64, recording bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\r\noarlock: log session %s ended (%s) · was %s",
		safeText(sessionID), safeText(reason), recordingWord(recording))
	if dropped > 0 {
		// Not a footnote. A log tail that fell behind has a hole in it, and the reader
		// cannot see the hole — only this number says it is there.
		fmt.Fprintf(&b, " · %d bytes were dropped and are NOT in what you saw", dropped)
	}
	b.WriteString("\r\n")
	return b.String()
}
