// Package sessionrun runs one paired session, whichever operator surface it came
// from.
//
// # Why this is shared rather than copied
//
// There are two operator surfaces — the SSH front door and the browser's `/ws/attach`
// — and everything after "both ends are present" is identical: open the recording,
// mark the row attached, register the session so it can be killed from outside, pump
// bytes, finalise the recording, close the row with one true reason.
//
// Copied into both, that sequence drifts. The interesting drift is not cosmetic: it
// is a recorder that gets finalised on one path and not the other, or a kill reason
// that survives on one surface and is overwritten by the transport on the other. So
// there is one copy, and the surfaces differ only in how they obtained the two
// connections.
package sessionrun

import (
	"context"
	"log/slog"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/oarlock/oarlock/internal/authz"
	"github.com/oarlock/oarlock/internal/pump"
	"github.com/oarlock/oarlock/internal/ring"
	"github.com/oarlock/oarlock/internal/sessions"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
	"github.com/oarlock/oarlock/pkg/transport"
)

// Runner holds the shared dependencies.
type Runner struct {
	Sessions  sessions.Store
	Live      *sessions.Registry
	Recorder  plugin.Recorder
	Limits    pump.Limits
	Deadlines pump.Deadlines
	Log       *slog.Logger

	// Scrollback is the ring size for surfaces that can reattach. Zero means the
	// documented default; a negative value disables the ring.
	Scrollback int

	// Authz re-checks live sessions and closes the ones that lose their grant. Nil
	// means no supervision, which is what a deployment with no authorizer gets.
	Authz *authz.Supervisor
	// Audit receives lifecycle events. Nil disables audit emission.
	Audit plugin.AuditSink
}

// Params is one session's particulars.
type Params struct {
	SessionID  string
	DeviceID   string
	Profile    string
	Principal  string
	OpenedBy   string
	Unattended bool

	// Grantee is the full principal, for re-checks.
	//
	// The id alone is not enough: a backend that authorises on group membership reads
	// Principal.Attrs, and a re-check handed an empty Attrs would deny — turning
	// supervision into a spurious revocation, which is worse than not supervising. Nil
	// falls back to an id-only principal, which is correct for a backend that matches
	// on id and wrong for one that does not.
	//
	// The browser path can only supply an id today: the attach ticket carries
	// `principal` as a string, and the attributes known at `POST /sessions` are gone by
	// the time the socket arrives. Carrying them in the ticket makes a short-lived
	// credential bigger and staler, so the fix belongs with the authorisation epic
	// rather than here — and until then an attribute-based backend should be pointed at
	// the SSH surface, or re-resolve the principal itself.
	Grantee *plugin.Principal
	// Surface names where the operator came from — "ssh" or "browser" — for logs
	// and for the audit trail. Two surfaces reaching one device is worth being able
	// to tell apart afterwards.
	Surface string

	Device   transport.Conn
	Operator transport.Conn
	PTY      *frame.PTY

	// Reattachable says whether a dropped operator should be waited for rather than
	// ending the session.
	//
	// True for the browser, false for SSH — and that is not a limitation of the SSH
	// surface, it is what SSH means: a second `ssh` invocation is a new session, so
	// there is nothing to reattach to. A detached SSH session would be a shell nobody
	// can reach, holding the device's only slot until the idle timer fired, which is
	// worse than closing it.
	Reattachable bool

	// RecordInput is resolved before a session is invited, when the full principal
	// and device attributes are still available.
	RecordInput bool
}

// NoExitStatus is reported when a session ended without the device sending one. It
// matches ssh's own convention for a session that failed rather than a command that ran.
const NoExitStatus = 255

// Outcome is what happened, including whether it was recorded — which the caller
// needs in order to tell the operator the truth.
type Outcome struct {
	Result    pump.Result
	Recording bool
	ExitCode  int
}

// Prepare starts the recording and marks the row attached, before any bytes move.
//
// Separate from Run because the caller has to know whether the session is being
// recorded *before* it prints a disclosure — and because a recorder that cannot start
// must fail the session rather than produce one that looks recorded and is not.
func (r *Runner) Prepare(ctx context.Context, p Params) (plugin.RecordingWriter, bool, time.Time, error) {
	startedAt := time.Now()
	var rw plugin.RecordingWriter
	recording := false

	if r.Recorder != nil {
		var err error
		rw, err = r.Recorder.Open(ctx, &plugin.SessionMeta{
			SessionID: p.SessionID, DeviceID: p.DeviceID, Profile: p.Profile,
			Mode: "gateway", Principal: p.Principal,
			OpenedBy: p.OpenedBy, Unattended: p.Unattended,
			Term: term(p.PTY), Cols: cols(p.PTY), Rows: rows(p.PTY),
			StartedAt:   startedAt,
			RecordInput: p.RecordInput,
		})
		if err != nil {
			return nil, false, startedAt, err
		}
		recording = true
		_ = r.Sessions.Update(ctx, p.SessionID, func(row *sessions.Session) error {
			row.RecordingState = sessions.Recorded
			return nil
		})
	}
	r.audit(ctx, plugin.AuditEvent{
		Kind: plugin.AuditSessionOpened, SessionID: p.SessionID, DeviceID: p.DeviceID,
		Principal: p.Principal, OpenedBy: p.OpenedBy, Surface: p.Surface,
		Action: p.Profile,
	})

	_ = r.Sessions.Update(ctx, p.SessionID, func(row *sessions.Session) error {
		row.State = sessions.StateAttached
		row.AttachedAt = startedAt
		return nil
	})
	return rw, recording, startedAt, nil
}

// Run pumps until the session ends, then finalises everything.
//
// It always finalises: the recorder is closed and the row is finished even when the
// session died badly, because a recording of a session that ended abruptly is exactly
// the one somebody will want to read.
func (r *Runner) Run(ctx context.Context, p Params, rw plugin.RecordingWriter,
	startedAt time.Time) Outcome {
	log := r.log().With("session", p.SessionID, "device", p.DeviceID,
		"principal", p.Principal, "surface", p.Surface)

	// Registered while it runs, so the API's admin kill, an authorisation withdrawal
	// or a drain can end it. The reason travels with the kill: a session ended by an
	// administrator and one ended by a revoked grant must not both be recorded as
	// "the transport went away".
	runCtx, kill := context.WithCancel(ctx)
	defer kill()
	var killReason atomic.Value
	handle := &sessions.Handle{
		ID: p.SessionID, DeviceID: p.DeviceID, Principal: p.Principal, Profile: p.Profile,
	}

	ps := &pump.Session{
		Device:    p.Device,
		Operator:  p.Operator,
		SessionID: p.SessionID,
		Profile:   p.Profile,
		Limits:    r.Limits,
		Deadlines: r.Deadlines,
		Recorder:  rw,
		StartedAt: startedAt,
		Log:       r.log(),
	}

	// Read-only watchers (FR13). Offered wherever reattach is, which is the browser:
	// there is no ssh surface for watching, because there is no ssh surface for being
	// told you are watched — and observation nobody is told about is surveillance.
	if p.Reattachable {
		observe := make(chan pump.Observation)
		ps.Observe = observe
		ps.OnObservers = func(list []frame.Observer) {
			names := make([]string, 0, len(list))
			for _, o := range list {
				names = append(names, o.Principal)
			}
			log.Info("watchers changed", "watchers", names)
		}
		handle.SetObserve(func(ctx context.Context, principal string, conn transport.Conn,
			greet func([]frame.Observer) (frame.Frame, error)) (sessions.Watcher, error) {
			done := make(chan pump.ObserveResult, 1)
			select {
			case observe <- pump.Observation{
				Principal: principal, Conn: conn, Greet: greet, Done: done,
			}:
			case <-runCtx.Done():
				return nil, sessions.ErrNotLive
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			select {
			case res := <-done:
				if res.Err != nil {
					return nil, res.Err
				}
				return res.Handle, nil
			case <-runCtx.Done():
				return nil, sessions.ErrNotLive
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		})
	}

	if p.Reattachable && r.Scrollback >= 0 {
		reattach := make(chan pump.Reattachment)
		ps.Ring = ring.New(r.Scrollback)
		ps.Reattach = reattach
		ps.OnDetach = func() {
			// The row stays `attached`: the session still holds the device, which is
			// what the state means. Recording the operator's absence in the row would
			// invite somebody to treat a reconnecting operator as a closed session.
			log.Info("operator detached; waiting for a reattach")
		}
		handle.SetReattach(func(ctx context.Context, conn transport.Conn,
			greet func(ring.Snapshot) (frame.Frame, error)) error {
			done := make(chan error, 1)
			select {
			case reattach <- pump.Reattachment{Conn: conn, Greet: greet, Done: done}:
			case <-runCtx.Done():
				return sessions.ErrNotLive
			case <-ctx.Done():
				return ctx.Err()
			}
			select {
			case err := <-done:
				return err
			case <-runCtx.Done():
				return sessions.ErrNotLive
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}

	// Registered only once it can actually be reattached to: a handle published before
	// SetReattach would answer "this session cannot take a replacement operator" for
	// the first few microseconds of its life, which is the kind of window that shows up
	// once a month in production and never in a test.
	r.live().Add(handle, func(reason string) {
		killReason.Store(reason)
		kill()
	})
	defer r.live().Remove(p.SessionID)

	// Supervision starts once the session is killable, and stops with it. Without this
	// the grant is checked at open and never again — so an operator whose access is
	// withdrawn keeps their shell until they close it, which is the one thing FR16
	// exists to prevent.
	if r.Authz != nil && p.Principal != "" {
		grantee := p.Grantee
		if grantee == nil {
			grantee = &plugin.Principal{ID: p.Principal}
		}
		go r.Authz.Guard(runCtx, p.SessionID, grantee,
			&plugin.Device{ID: p.DeviceID}, plugin.ActionShell)
	}

	res, err := ps.Run(runCtx)
	if reason, ok := killReason.Load().(string); ok && reason != "" {
		// An external kill is the true reason; whatever the transport noticed
		// afterwards is a consequence of it.
		res.Reason = reason
	}
	if err != nil {
		log.Warn("session ended with an error", "error", err)
	}

	// A session that ended without an EXIT frame did not run a command to completion —
	// the device reported an error, the recorder failed, an administrator killed it, the
	// gateway drained. Reporting 0 for that says "your command succeeded" to anything
	// that checks a status, which for the exec profile is the whole audience.
	//
	// 255 because that is what `ssh` itself returns when the session fails rather than
	// the command running, so automation already knows the number. A command's own
	// status, when there is one, passes through untouched.
	code := NoExitStatus
	if res.ExitCode != nil {
		code = *res.ExitCode
	}

	// Finalisation runs on a context that outlives the session's.
	//
	// Sessions usually end *because* a context was cancelled — a drain, an admin kill, an
	// operator closing their terminal — and using that context here means the recording
	// is not finalised and the row never gets its close reason. Found by draining a
	// running gateway: the log said `gateway_shutdown` and the ledger said nothing,
	// which is exactly the row somebody reads afterwards to find out what a deploy did.
	//
	// Bounded, because a stuck store must not hold a shutdown open indefinitely.
	final, cancelFinal := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancelFinal()

	if rw != nil {
		if cerr := rw.Close(final, plugin.RecordingResult{
			CloseReason:  res.Reason,
			ExitCode:     res.ExitCode,
			BytesDropped: res.Stats.BytesDropped,
			ClosedAt:     time.Now(),
		}); cerr != nil {
			log.Error("could not finalise the recording", "error", cerr)
		}
	}
	if cerr := r.Sessions.Finish(final, p.SessionID, sessions.Result{
		CloseReason:  res.Reason,
		ExitCode:     res.ExitCode,
		BytesIn:      res.Stats.BytesIn,
		BytesOut:     res.Stats.BytesOut,
		BytesDropped: res.Stats.BytesDropped,
	}); cerr != nil {
		log.Error("could not close the session row", "error", cerr)
	}

	log.Info("session closed", "reason", res.Reason, "exit", code,
		"bytes_out", res.Stats.BytesOut, "dropped", res.Stats.BytesDropped,
		"stalls", res.Stats.Stalls)
	r.audit(final, plugin.AuditEvent{
		Kind: plugin.AuditSessionClosed, SessionID: p.SessionID, DeviceID: p.DeviceID,
		Principal: p.Principal, OpenedBy: p.OpenedBy, Surface: p.Surface,
		Action: p.Profile, Reason: res.Reason,
		Attrs: map[string]string{
			"bytes_in":      strconv.FormatInt(res.Stats.BytesIn, 10),
			"bytes_out":     strconv.FormatInt(res.Stats.BytesOut, 10),
			"bytes_dropped": strconv.FormatInt(res.Stats.BytesDropped, 10),
		},
	})
	return Outcome{Result: res, Recording: rw != nil, ExitCode: code}
}

// Reject marks a session that never opened, so "why did nobody get a shell on that
// treadmill" has an answer that does not depend on the logs still existing.
func (r *Runner) Reject(ctx context.Context, sessionID, reason string) {
	var deviceID, principal string
	_ = r.Sessions.Update(ctx, sessionID, func(row *sessions.Session) error {
		deviceID, principal = row.DeviceID, row.Principal
		row.State = sessions.StateRejected
		row.CloseReason = reason
		row.ClosedAt = time.Now()
		return nil
	})
	r.audit(ctx, plugin.AuditEvent{
		Kind: plugin.AuditSessionRejected, SessionID: sessionID, DeviceID: deviceID,
		Principal: principal, Reason: reason,
	})
}

func (r *Runner) audit(ctx context.Context, e plugin.AuditEvent) {
	if r.Audit != nil {
		r.Audit.Emit(ctx, e)
	}
}

func (r *Runner) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.Default()
}

func (r *Runner) live() *sessions.Registry {
	if r.Live == nil {
		r.Live = sessions.NewRegistry()
	}
	return r.Live
}

func term(p *frame.PTY) string {
	if p == nil {
		return ""
	}
	return p.Term
}
func cols(p *frame.PTY) int {
	if p == nil {
		return 0
	}
	return p.Cols
}
func rows(p *frame.PTY) int {
	if p == nil {
		return 0
	}
	return p.Rows
}
