package apisrv

// `POST /api/v1/devices/{id}/exec`: run one allow-listed command and return its output.
//
// The other endpoints hand back a ticket and let the caller attach. This one does not:
// there is no terminal to attach to and nothing to interact with, so the gateway runs the
// session itself and answers with stdout, stderr and an exit code. That is the point of
// the profile — a backend that wants one command should not have to speak the session
// protocol to get it.
//
// It is still a real session: its own row, its own recording, the same authorisation and
// the same audit trail. `exec` being convenient must not make it invisible.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/oarlock/oarlock/internal/invite"
	"github.com/oarlock/oarlock/internal/sessionrun"
	"github.com/oarlock/oarlock/internal/sessions"
	"github.com/oarlock/oarlock/pkg/condition"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
	"github.com/oarlock/oarlock/pkg/transport"
)

const (
	// DefaultExecTimeout bounds one API exec call end to end, including waking the
	// device. A caller is holding an HTTP request open for the whole thing.
	DefaultExecTimeout = 60 * time.Second
	// MaxExecOutput caps each of stdout and stderr in the response.
	//
	// The output is buffered to be returned as JSON, so it is this process's memory. A
	// command that produces more than this is a command that wanted a shell — and the
	// truncation is reported rather than silent, because a caller parsing a truncated
	// log must be able to tell.
	MaxExecOutput = 1 << 20
)

type execRequest struct {
	// Argv is the command, already split. Never a shell string: there is no shell
	// anywhere on this path, so a string here could only be mis-split by whoever
	// eventually decided to split it.
	Argv   []string `json:"argv"`
	Reason string   `json:"reason,omitempty"`
	// TimeoutMS bounds this call. Clamped to MaxExecTimeout.
	TimeoutMS int `json:"timeout_ms,omitempty"`
}

type execResponse struct {
	SessionID string `json:"session_id"`
	DeviceID  string `json:"device_id"`
	ExitCode  int    `json:"exit_code"`
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
	// Truncated says one of the streams hit MaxExecOutput. A caller that parses output
	// has to know it is looking at part of it.
	Truncated bool `json:"truncated,omitempty"`
	Recorded  bool `json:"recorded"`
	// CloseReason is the session's own reason, from the closed condition set, so a
	// caller can tell "the command ran and exited" from "the device went away".
	CloseReason string `json:"close_reason,omitempty"`
}

// execOnDevice runs one command and answers with its output.
func (s *Server) execOnDevice(w http.ResponseWriter, r *http.Request, p *plugin.Principal) {
	var req execRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.problem(w, r, http.StatusBadRequest, "invalid_argument",
			"The exec request is invalid", err.Error(), false)
		return
	}
	if len(req.Argv) == 0 {
		s.problem(w, r, http.StatusBadRequest, "invalid_argument",
			"No command to run", "argv must have at least one element", false)
		return
	}
	for i, a := range req.Argv {
		if a == "" && i == 0 {
			s.problem(w, r, http.StatusBadRequest, "invalid_argument",
				"No command to run", "argv[0] is empty", false)
			return
		}
	}

	dev, err := s.o.Registry.Get(r.Context(), r.PathValue("id"))
	if err != nil || dev.Disabled {
		// The same answer whether the device is unknown or the caller may not see it:
		// an authenticated caller must not be able to enumerate the fleet by trying ids.
		c, _ := condition.Lookup("device_unknown")
		s.problem(w, r, statusFor("device_unknown"), "device_unknown",
			c.Headline, c.NextAction, false)
		return
	}

	// `exec` is its own action. It does not imply `shell` and `shell` does not imply it:
	// the point of the profile is that most support work can be granted without granting
	// a shell, and that only works if they are authorised separately.
	if v := s.o.Authz.AtOpen(r.Context(), p, dev, plugin.ActionExec); !v.Allow() {
		s.refuseByAuthz(w, r, v)
		return
	}
	recordInput, err := s.o.RecordInput.Resolve(p, dev)
	if err != nil {
		s.problem(w, r, statusFor("policy_conflict"), "policy_conflict",
			"record_input policy conflict", err.Error(), false)
		return
	}

	timeout := DefaultExecTimeout
	if req.TimeoutMS > 0 {
		if d := time.Duration(req.TimeoutMS) * time.Millisecond; d < timeout {
			timeout = d
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	sessionID := newSessionID()
	row := &sessions.Session{
		ID: sessionID, DeviceID: dev.ID, Profile: "exec",
		Mode: string(dev.ResolvedMode()), Principal: p.ID, OpenedBy: p.OpenedBy,
		Unattended: p.Unattended, RecordInput: recordInput, Reason: req.Reason,
		State: sessions.StateWaking, RecordingState: sessions.NotRecorded,
	}
	if err := s.o.Sessions.Create(ctx, row); err != nil {
		if errors.Is(err, sessions.ErrLimit) {
			s.problem(w, r, http.StatusConflict, "session_limit",
				"That device already has a session open",
				"wait for it to end, or end it", true)
			return
		}
		s.problem(w, r, http.StatusInternalServerError, "internal",
			"Could not create the session", err.Error(), true)
		return
	}

	pending, err := s.o.Inviter.Invite(ctx, dev, invite.Request{
		SessionID: sessionID, Profile: "exec", Principal: p.ID,
		OpenedBy: p.OpenedBy, Unattended: p.Unattended,
		RecordInput: recordInput,
		// No attach ticket: nobody is going to attach. Minting one would be a
		// short-lived credential issued for a session that has no second party.
		Exec: req.Argv,
	})
	if err != nil {
		var f *invite.Failure
		if errors.As(err, &f) {
			s.reject(ctx, sessionID, f.Code)
			s.problem(w, r, statusFor(f.Code), f.Code, f.Operator, err.Error(), f.Retryable)
			return
		}
		s.reject(ctx, sessionID, "internal")
		s.problem(w, r, http.StatusInternalServerError, "internal",
			"Could not open the session", err.Error(), true)
		return
	}

	att, err := pending.Wait(ctx)
	if err != nil {
		s.o.Inviter.Cancel(ctx, sessionID, "operator_gave_up")
		var f *invite.Failure
		if errors.As(err, &f) {
			s.reject(ctx, sessionID, f.Code)
			s.problem(w, r, statusFor(f.Code), f.Code, f.Operator, err.Error(), f.Retryable)
			return
		}
		s.reject(ctx, sessionID, "device_offline")
		s.problem(w, r, statusFor("device_offline"), "device_offline",
			"The device did not answer", err.Error(), true)
		return
	}
	defer att.Done()

	_ = s.o.Sessions.Update(ctx, sessionID, func(row *sessions.Session) error {
		row.State = sessions.StateAttached
		row.AttachedAt = s.nowFn()
		return nil
	})

	runner := &sessionrun.Runner{
		Sessions: s.o.Sessions, Live: s.o.Live, Recorder: s.o.Recorder,
		Limits: s.o.Limits, Deadlines: s.o.Deadlines, Log: s.log,
		Authz: s.o.AuthzSupervisor,
	}
	params := sessionrun.Params{
		SessionID: sessionID, DeviceID: dev.ID, Profile: "exec", Principal: p.ID,
		Action:   plugin.ActionExec,
		OpenedBy: p.OpenedBy, Unattended: p.Unattended,
		Surface: "api", Grantee: p, Device: att.Conn, RecordInput: recordInput,
	}

	// Recorded before anything runs, on the same rule as a shell: a session that looks
	// recorded and is not is worse than one that never happened.
	rw, recording, startedAt, err := runner.Prepare(ctx, params)
	if err != nil {
		runner.Reject(ctx, sessionID, "recorder_failed")
		s.problem(w, r, statusFor("recorder_failed"), "recorder_failed",
			"Could not start recording", err.Error(), true)
		return
	}

	sink := newExecSink()
	params.Operator = sink
	out := runner.Run(ctx, params, rw, startedAt)

	s.log.Info("command run via the API", "session", sessionID, "device", dev.ID,
		"principal", p.ID, "argv", req.Argv, "exit", out.ExitCode,
		"request", requestID(r))
	s.writeJSON(w, http.StatusOK, execResponse{
		SessionID: sessionID, DeviceID: dev.ID,
		ExitCode: out.ExitCode,
		Stdout:   sink.stdout(), Stderr: sink.stderr(),
		Truncated: sink.wasTruncated(), Recorded: recording,
		CloseReason: out.Result.Reason,
	})
}

// execSink is the operator side of an exec session: a transport.Conn that collects.
//
// The pump does not know or care that nobody is attached — it writes DATA and DATA_ERR to
// an operator connection either way — so implementing the interface is how the gateway
// becomes its own operator. The alternative would be a second pump path for
// nobody-is-watching, and two pumps is how the recording and the response come to
// disagree about what happened.
type execSink struct {
	mu        sync.Mutex
	out, err  []byte
	truncated bool
	closed    chan struct{}
	closeOnce sync.Once
}

var _ transport.Conn = (*execSink)(nil)

func newExecSink() *execSink {
	return &execSink{closed: make(chan struct{})}
}

// Recv blocks until the session ends.
//
// An exec session has no operator input — there is no stdin — so this never yields a
// frame. It has to block rather than return an error, because an error here is how the
// pump learns the operator hung up, and it would tear the session down before the command
// had run.
func (e *execSink) Recv(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-e.closed:
		return nil, transport.ErrClosed
	}
}

func (e *execSink) Send(_ context.Context, b []byte) error {
	f, err := frame.Codec{}.Decode(b)
	if err != nil {
		// Not fatal: a frame this side cannot parse is a bug worth a session failure,
		// but silently swallowing it would make the response look complete.
		return fmt.Errorf("apisrv: undecodable frame on an exec session: %w", err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	switch f.Type {
	case frame.TypeData:
		e.out = e.appendCapped(e.out, f.Payload)
	case frame.TypeDataErr:
		e.err = e.appendCapped(e.err, f.Payload)
	}
	// Everything else — READY, THROTTLE, EXIT, CLOSE, ERROR — is the pump's business and
	// reaches the response through the Outcome rather than through here.
	return nil
}

// appendCapped stops at MaxExecOutput and records that it did.
func (e *execSink) appendCapped(dst, src []byte) []byte {
	room := MaxExecOutput - len(dst)
	if room <= 0 {
		e.truncated = true
		return dst
	}
	if len(src) > room {
		e.truncated = true
		src = src[:room]
	}
	return append(dst, src...)
}

func (e *execSink) Close(transport.CloseCode, string) error {
	e.closeOnce.Do(func() { close(e.closed) })
	return nil
}

func (e *execSink) RemoteAddr() string { return "" }

func (e *execSink) stdout() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return string(e.out)
}

func (e *execSink) stderr() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return string(e.err)
}

func (e *execSink) wasTruncated() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.truncated
}
