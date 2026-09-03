package sshsrv

// Mode A: passthrough, as an SSH subsystem.
//
// The gateway becomes a blind relay. The operator's `ssh` terminates at an `sshd` the
// device runs on its own loopback, and every byte crossing this gateway is ciphertext it
// cannot read. `scp`, `sftp`, `rsync`, agent forwarding and everything else the protocol
// offers arrive free, and session recording becomes impossible rather than merely absent.
//
// # Why this is a subsystem and not a second front door
//
// ARCHITECTURE § 4.3 already settled the shape: "mode A is run `sshd` on loopback,
// forward 22, on an architecture that already exists". The `tcp` profile does that
// forwarding, so this file adds no relay of its own — it adds the *decision*. What was
// missing was never the plumbing.
//
// A subsystem is the trigger because it gives an operator a stdio pipe, which is exactly
// what `ProxyCommand` wants:
//
//	ssh -o ProxyCommand="ssh -s passthrough treadmill-4821@gateway" root@treadmill-4821
//
// The outer `ssh` authenticates to Oarlock and is authorised for `passthrough` on that
// device; the inner one authenticates to the device's own `sshd` with the device's own
// keys. Two authentications, deliberately: in mode A the gateway is not trusted with the
// session, so it does not get to be the only thing deciding who may have it.
//
// # The guard rails, and why there are four
//
// An unrecorded session must never be an accident, so nothing here is on by default and
// no single setting is enough.
//
//  1. `devices[].allow_passthrough` — the fleet operator's key.
//  2. `policy.allow_unrecorded` — the deployment's key. Two people, two decisions.
//  3. The `passthrough` action, authorised per device like every other action.
//  4. A disclosure the operator sees before the session and again as it closes.
//
// The two keys are the important pair. Either alone would let one person turn recording
// off for a device without anybody else having agreed the deployment permits it at all.
//
// # Why the disclosure is said twice
//
// Nobody should discover which mode they were in from the absence of a recording six
// weeks later. A disclosure carried only by an early message is also one deleted packet
// away from never having been said: Terrapin (CVE-2023-48795) lets an attacker who can
// modify traffic delete a bounded prefix right after the channel opens. Strict key
// exchange removes that primitive; saying it again at the end removes the dependency on
// strict key exchange having worked.

import (
	"errors"
	"fmt"
	"log/slog"
	"strconv"
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

// PassthroughSubsystem is what an operator asks for with `ssh -s`.
//
// `sshpass` rather than `passthrough`, because that is what ARCHITECTURE § 6 and
// sessionrun.Recorded already call this profile — and a fourth name for one thing is
// worse than a name that also belongs to an unrelated Linux tool. The *action* stays
// `passthrough`: the profile is what the device is asked to do, the action is what the
// operator is authorised for, and here they genuinely are different words.
const PassthroughSubsystem = "sshpass"

// ProfilePassthrough is the session profile and the string written to the ledger. It is
// the one sessionrun.Recorded already refuses to record.
const ProfilePassthrough = "sshpass"

// handlePassthrough relays one opaque SSH connection to the device's own sshd.
//
// It returns true when it has handled the session — including every refusal, since a
// refusal here is still this handler's business to explain.
func (s *Server) handlePassthrough(sess gssh.Session, dev *plugin.Device,
	p *plugin.Principal, log *slog.Logger) bool {

	ctx := sess.Context()
	port := s.o.PassthroughPort
	if port == 0 {
		port = 22
	}

	// ── guard rail 1: the deployment ──
	//
	// Checked before the device flag so that a deployment which has not opted in gives
	// the same answer for every device, and cannot be used to probe which devices carry
	// the flag.
	if !s.o.AllowUnrecorded {
		log.Warn("passthrough refused: the deployment does not permit unrecorded sessions")
		fmt.Fprintln(sess.Stderr(), "oarlock: this gateway does not permit unrecorded "+
			"sessions (policy.allow_unrecorded is off)")
		_ = sess.Exit(1)
		return true
	}
	// ── guard rail 2: the device ──
	if !dev.AllowPassthrough {
		log.Warn("passthrough refused: the device does not allow it")
		fmt.Fprintln(sess.Stderr(), "oarlock: this device does not allow passthrough")
		_ = sess.Exit(1)
		return true
	}

	// ── guard rail 3: authorisation, per device, as its own action ──
	//
	// The target names the port, so a grant can be written for the device's sshd and
	// nothing else — the same shape `tcp` uses, and it means "may open an unrecorded
	// session" is a distinct grant from "may open a shell".
	target := plugin.Target{Port: port}
	if verdict := s.o.Authz.AtOpen(ctx, p, dev, plugin.ActionPassthrough, target); !verdict.Allow() {
		c, _ := condition.Lookup(verdict.Code)
		text := c.Text()
		if verdict.Reason != "" {
			text = verdict.Reason
		}
		log.Warn("passthrough refused by authorization",
			"outcome", verdict.Outcome, "code", verdict.Code, "error", verdict.Err)
		s.audit(ctx, plugin.AuditEvent{
			Kind: plugin.AuditSessionRejected, DeviceID: dev.ID, Principal: p.ID,
			Surface: "ssh", Code: verdict.Code, Reason: verdict.Reason,
			Action: string(plugin.ActionPassthrough),
		})
		fmt.Fprintf(sess.Stderr(), "oarlock: %s\r\n", safeText(text))
		_ = sess.Exit(1)
		return true
	}

	sessionID := s.o.NewSessionID()

	// `recording_state: not_recorded` on a row that exists, rather than no row at all.
	// An unrecorded session has to be a queryable fact — "which sessions could nobody
	// read" is the question this whole mode creates, and it must be answerable in SQL
	// rather than by noticing a missing file.
	row := &sessions.Session{
		ID: sessionID, DeviceID: dev.ID, Profile: ProfilePassthrough,
		Mode: "passthrough", Principal: p.ID,
		State: sessions.StateWaking, RecordingState: sessions.NotRecorded,
	}
	if err := s.o.Sessions.Create(ctx, row); err != nil {
		if errors.Is(err, sessions.ErrLimit) {
			fmt.Fprintln(sess.Stderr(), "oarlock: too many sessions are open on this device")
		} else {
			log.Error("could not create a session row", "error", err)
			fmt.Fprintln(sess.Stderr(), "oarlock: could not open a session")
		}
		_ = sess.Exit(1)
		return true
	}

	// The device is asked for a `tcp` connection to its own sshd. Bytes are bytes: the
	// device side of passthrough is the forwarding it already implements, and the
	// difference between the two modes lives entirely on this side of the wire.
	pending, err := s.o.Inviter.Invite(ctx, dev, invite.Request{
		SessionID: sessionID,
		Profile:   ProfilePassthrough,
		Principal: p.ID,
		TCP:       &frame.TCPTarget{Port: port},
	})
	if err != nil {
		var f *invite.Failure
		if errors.As(err, &f) {
			log.Warn("could not invite the device", "code", f.Code, "error", err)
			fmt.Fprintf(sess.Stderr(), "oarlock: %s\r\n", operatorText(f))
		} else {
			log.Error("invite failed", "error", err)
			fmt.Fprintln(sess.Stderr(), "oarlock: could not open a session")
		}
		s.reject(ctx, sessionID, closeReason(err, "device_offline"))
		_ = sess.Exit(1)
		return true
	}

	att, err := pending.Wait(ctx)
	if err != nil {
		s.o.Inviter.Cancel(ctx, sessionID, "operator_gave_up")
		var f *invite.Failure
		if errors.As(err, &f) {
			fmt.Fprintf(sess.Stderr(), "oarlock: %s\r\n", operatorText(f))
		} else {
			fmt.Fprintln(sess.Stderr(), "oarlock: session setup failed")
		}
		s.reject(ctx, sessionID, closeReason(err, "device_offline"))
		_ = sess.Exit(1)
		return true
	}
	defer att.Done()

	_ = s.o.Sessions.Update(ctx, sessionID, func(row *sessions.Session) error {
		row.State = sessions.StateAttached
		row.AttachedAt = time.Now()
		return nil
	})

	// ── guard rail 4, first half ──
	//
	// On stderr, always. stdout is the tunnel: the operator's inner ssh is reading the
	// device's SSH banner from it, and one byte of ours in that stream is a protocol
	// error rather than a disclosure.
	fmt.Fprint(sess.Stderr(), passthroughBanner(dev, sessionID, port))

	log.Info("passthrough open", "session", sessionID, "port", port,
		"origin", sess.RemoteAddr().String())

	runner := &sessionrun.Runner{
		Sessions: s.o.Sessions, Live: s.o.Live, Recorder: s.o.Recorder,
		Limits: s.o.Limits, Deadlines: s.o.Deadlines, Log: s.log,
		Authz: s.o.AuthzSupervisor,
	}
	// gliderlabs' Session embeds an SSH channel, so the adapter the `tcp` forward uses
	// fits here unchanged.
	opConn := newForwardConn(sess, sess.RemoteAddr().String(), s.log.With("session", sessionID))
	defer opConn.Close(transport.CloseNormal, "passthrough over")

	params := sessionrun.Params{
		SessionID: sessionID, DeviceID: dev.ID, Profile: ProfilePassthrough,
		Principal: p.ID, Action: plugin.ActionPassthrough, Target: target,
		Surface: "ssh", Grantee: p,
		Device: att.Conn,
		// No PTY and no reattach: the terminal, if there is one, belongs to the inner
		// ssh and this gateway never sees it.
		Operator: opConn,
	}

	// Prepare skips the recorder — Recorded("passthrough") is false, and it is false
	// because a recording of ciphertext is a file that looks like evidence and is not.
	// It is still called, because it emits the session-opened audit event: an unrecorded
	// session missing from the audit trail as well is the one combination nobody could
	// reconstruct anything from.
	rw, recording, startedAt, err := runner.Prepare(ctx, params)
	if err != nil {
		log.Error("could not prepare the passthrough", "session", sessionID, "error", err)
		runner.Reject(ctx, sessionID, "internal")
		_ = sess.Exit(1)
		return true
	}
	if recording {
		// Unreachable unless Recorded() changes underneath this, and a passthrough that
		// believes it is recording is a claim about ciphertext. Refuse rather than run.
		log.Error("passthrough was prepared as a recorded session", "session", sessionID)
		runner.Reject(ctx, sessionID, "internal")
		fmt.Fprintln(sess.Stderr(), "oarlock: internal error: refusing to record a "+
			"session the gateway cannot read")
		_ = sess.Exit(1)
		return true
	}

	out := runner.Run(ctx, params, rw, startedAt)
	log.Info("passthrough closed", "session", sessionID, "reason", out.Result.Reason,
		"bytes_in", out.Result.Stats.BytesIn, "bytes_out", out.Result.Stats.BytesOut)

	// ── guard rail 4, second half ──
	//
	// At a point no prefix-truncation attack can reach. See the file comment: this is
	// what removes the dependency on strict key exchange having worked.
	fmt.Fprint(sess.Stderr(), passthroughClosing(sessionID, out.Result.Reason))
	_ = sess.Exit(0)
	return true
}

// passthroughBanner is the opening disclosure.
//
// It names the session id, because "which session was that" is the first question anybody
// asks afterwards and there is no recording to look it up in.
func passthroughBanner(dev *plugin.Device, sessionID string, port int) string {
	return fmt.Sprintf(
		"oarlock: passthrough to %s:%s — this session is NOT recorded and this gateway "+
			"cannot read it. Session %s.\r\n",
		safeText(dev.ID), strconv.Itoa(port), safeText(sessionID))
}

func passthroughClosing(sessionID, reason string) string {
	return fmt.Sprintf(
		"oarlock: passthrough session %s closed (%s) — it was NOT recorded.\r\n",
		safeText(sessionID), safeText(reason))
}

// handleSubsystem is the entry point for `ssh -s`.
//
// It exists because gliderlabs dispatches subsystem requests through their own table and
// never through Handler — so the branch that used to sit in handleSession was unreachable,
// and so was the sentence it printed for sftp. Registering `default` here is what makes
// that refusal an actual message rather than a bare protocol-level failure.
func (s *Server) handleSubsystem(sess gssh.Session) {
	ctx := sess.Context()
	deviceID := sess.User()
	sub := sess.Subsystem()

	p, _ := ctx.Value(principalKey{}).(*plugin.Principal)
	if p == nil {
		// Cannot happen with PublicKeyHandler set, and an unattributed session is worse
		// than no session.
		fmt.Fprintln(sess.Stderr(), "oarlock: no authenticated principal")
		_ = sess.Exit(1)
		return
	}
	log := s.log.With("principal", p.ID, "device", deviceID, "subsystem", sub)

	if sub != PassthroughSubsystem {
		// sftp is E5.S4. Refusing clearly beats half-running something.
		fmt.Fprintf(sess.Stderr(), "oarlock: the %s subsystem is not supported\r\n",
			safeText(sub))
		_ = sess.Exit(1)
		return
	}

	dev, err := s.o.Registry.Get(ctx, deviceID)
	if err != nil || dev.Disabled {
		// The same sentence as everywhere else: a valid key must not be able to
		// enumerate the fleet by trying usernames.
		log.Warn("device lookup failed", "error", err)
		fmt.Fprintln(sess.Stderr(), "oarlock: no such device, or you don't have access")
		_ = sess.Exit(1)
		return
	}
	s.handlePassthrough(sess, dev, p, log.With("profile", ProfilePassthrough))
}
