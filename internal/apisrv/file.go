package apisrv

// `GET` and `PUT /api/v1/devices/{id}/file?path=…`: read and write one file on a device.
//
// Like exec, the gateway runs the session itself rather than handing back a ticket: there
// is nothing to attach to. Unlike exec, the bytes are not buffered — a log is streamed
// straight to the response, because holding 64 MiB per concurrent request is a memory
// profile nobody asked for.
//
// Streaming has one consequence worth being deliberate about: the status line goes out
// before the outcome is known. A transfer that fails halfway therefore cannot be reported
// as a 500 — so it is reported by aborting the connection, which makes a client see a
// truncated transfer as an error rather than as a complete file. Silently short files are
// the failure this profile exists to avoid.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"

	"github.com/oarlock/oarlock/internal/invite"
	"github.com/oarlock/oarlock/internal/sessionrun"
	"github.com/oarlock/oarlock/internal/sessions"
	"github.com/oarlock/oarlock/pkg/condition"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
	"github.com/oarlock/oarlock/pkg/transport"
)

// MaxFileBytes bounds one transfer through the API. The device has its own ceiling; this
// one stops a request being accepted that the device would only refuse later.
const MaxFileBytes int64 = 64 << 20

// readFileOnDevice streams one file out of a device.
func (s *Server) readFileOnDevice(w http.ResponseWriter, r *http.Request, p *plugin.Principal) {
	dev, rel, ok := s.fileTarget(w, r, p, plugin.ActionFileRead)
	if !ok {
		return
	}
	sink := &fileSink{w: w, started: new(bool)}
	out, sessionID, ok := s.runFileSession(w, r, p, dev, frame.FileOp{
		Op: "read", Path: rel,
	}, sink)
	if !ok {
		return
	}

	// The device reported a failure and nothing has been written yet: a clean problem
	// document is still possible, which is much better than an aborted connection.
	if out.ExitCode != 0 && !*sink.started {
		s.problem(w, r, http.StatusBadGateway, "internal",
			"The device could not read that file", out.Result.Reason, false)
		return
	}
	if out.ExitCode != 0 {
		// Bytes are already on the wire. Abort rather than finish cleanly, so the client
		// sees an unexpected EOF instead of a file it thinks is complete.
		s.log.Warn("a file read failed after the response had started",
			"session", sessionID, "device", dev.ID, "reason", out.Result.Reason)
		panic(http.ErrAbortHandler)
	}
	s.log.Info("file read via the API", "session", sessionID, "device", dev.ID,
		"principal", p.ID, "path", rel, "bytes", sink.written, "request", requestID(r))
}

// writeFileOnDevice sends one file to a device.
func (s *Server) writeFileOnDevice(w http.ResponseWriter, r *http.Request, p *plugin.Principal) {
	dev, rel, ok := s.fileTarget(w, r, p, plugin.ActionFileWrite)
	if !ok {
		return
	}
	// Content-Length is required, and that is not laziness: the device is told the exact
	// size up front so a short transfer is detectable rather than committed as a
	// truncated file. Learning the size by buffering would mean holding the whole thing
	// in memory to avoid a mistake the length header already prevents.
	if r.ContentLength < 0 {
		s.problem(w, r, http.StatusLengthRequired, "invalid_argument",
			"A file write needs a Content-Length",
			"the device is told the exact size so a short transfer cannot be committed "+
				"as a whole file; send a length rather than a chunked body", false)
		return
	}
	if r.ContentLength > MaxFileBytes {
		s.problem(w, r, http.StatusRequestEntityTooLarge, "invalid_argument",
			"That file is too large", fmt.Sprintf("the limit is %d bytes", MaxFileBytes), false)
		return
	}

	mode := uint32(0)
	if raw := r.URL.Query().Get("mode"); raw != "" {
		parsed, err := strconv.ParseUint(raw, 8, 32)
		if err != nil {
			s.problem(w, r, http.StatusBadRequest, "invalid_argument",
				"mode must be octal", err.Error(), false)
			return
		}
		mode = uint32(parsed)
	}

	body := http.MaxBytesReader(w, r.Body, MaxFileBytes)
	out, sessionID, ok := s.runFileSession(w, r, p, dev, frame.FileOp{
		Op: "write", Path: rel, Size: r.ContentLength, Mode: mode,
	}, &fileSource{r: body, size: r.ContentLength})
	if !ok {
		return
	}
	if out.ExitCode != 0 {
		s.problem(w, r, http.StatusBadGateway, "internal",
			"The device could not write that file", out.Result.Reason, false)
		return
	}
	s.log.Info("file written via the API", "session", sessionID, "device", dev.ID,
		"principal", p.ID, "path", rel, "bytes", r.ContentLength, "request", requestID(r))
	s.writeJSON(w, http.StatusOK, map[string]any{
		"session_id": sessionID, "device_id": dev.ID, "path": rel,
		"bytes": r.ContentLength,
	})
}

// fileTarget resolves and authorises the device and path.
func (s *Server) fileTarget(w http.ResponseWriter, r *http.Request, p *plugin.Principal,
	action plugin.Action) (*plugin.Device, string, bool) {

	rel := r.URL.Query().Get("path")
	if strings.TrimSpace(rel) == "" {
		s.problem(w, r, http.StatusBadRequest, "invalid_argument",
			"No path", "pass ?path= relative to the device's file root", false)
		return nil, "", false
	}
	// Refused here as well as on the device, and the device's check is the one that
	// counts: this one exists so an obvious mistake gets a 400 with a sentence instead of
	// a session that opens and immediately fails.
	if path.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, "../") ||
		strings.Contains(rel, "\x00") {
		s.problem(w, r, http.StatusBadRequest, "invalid_argument",
			"That path is not allowed",
			"paths are relative to the device's file root and cannot climb out of it", false)
		return nil, "", false
	}

	dev, err := s.o.Registry.Get(r.Context(), r.PathValue("id"))
	if err != nil || dev.Disabled {
		c, _ := condition.Lookup("device_unknown")
		s.problem(w, r, statusFor("device_unknown"), "device_unknown",
			c.Headline, c.NextAction, false)
		return nil, "", false
	}
	// `file:read` and `file:write` are separate actions, so a grant to pull logs is not a
	// grant to replace a configuration file.
	// The path as the caller wrote it, so a grant can be narrowed to part of the
	// device's file root. The agent's own os.Root confinement still applies.
	if v := s.o.Authz.AtOpen(r.Context(), p, dev, action, plugin.Target{Path: rel}); !v.Allow() {
		s.refuseByAuthz(w, r, v)
		return nil, "", false
	}
	return dev, rel, true
}

// runFileSession opens a session, runs it against op, and returns the outcome.
func (s *Server) runFileSession(w http.ResponseWriter, r *http.Request, p *plugin.Principal,
	dev *plugin.Device, op frame.FileOp, operator transport.Conn) (sessionrun.Outcome, string, bool) {

	var zero sessionrun.Outcome
	ctx := r.Context()

	sessionID := newSessionID()
	row := &sessions.Session{
		ID: sessionID, DeviceID: dev.ID, Profile: "file",
		Mode: string(dev.ResolvedMode()), Principal: p.ID, OpenedBy: p.OpenedBy,
		Unattended: p.Unattended, Reason: r.URL.Query().Get("reason"),
		State: sessions.StateWaking, RecordingState: sessions.NotRecorded,
	}
	if err := s.o.Sessions.Create(ctx, row); err != nil {
		if errors.Is(err, sessions.ErrLimit) {
			s.problem(w, r, http.StatusConflict, "session_limit",
				"That device already has a session open",
				"wait for it to end, or end it", true)
			return zero, "", false
		}
		s.problem(w, r, http.StatusInternalServerError, "internal",
			"Could not create the session", err.Error(), true)
		return zero, "", false
	}

	pending, err := s.o.Inviter.Invite(ctx, dev, invite.Request{
		SessionID: sessionID, Profile: "file", Principal: p.ID,
		OpenedBy: p.OpenedBy, Unattended: p.Unattended, File: &op,
	})
	if err != nil {
		var f *invite.Failure
		if errors.As(err, &f) {
			s.reject(ctx, sessionID, f.Code)
			s.problem(w, r, statusFor(f.Code), f.Code, f.Operator, err.Error(), f.Retryable)
			return zero, "", false
		}
		s.reject(ctx, sessionID, "internal")
		s.problem(w, r, http.StatusInternalServerError, "internal",
			"Could not open the session", err.Error(), true)
		return zero, "", false
	}

	att, err := pending.Wait(ctx)
	if err != nil {
		s.o.Inviter.Cancel(ctx, sessionID, "operator_gave_up")
		var f *invite.Failure
		if errors.As(err, &f) {
			s.reject(ctx, sessionID, f.Code)
			s.problem(w, r, statusFor(f.Code), f.Code, f.Operator, err.Error(), f.Retryable)
			return zero, "", false
		}
		s.reject(ctx, sessionID, "device_offline")
		s.problem(w, r, statusFor("device_offline"), "device_offline",
			"The device did not answer", err.Error(), true)
		return zero, "", false
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
		SessionID: sessionID, DeviceID: dev.ID, Profile: "file", Principal: p.ID,
		// Read and write are separate grants, so supervision has to be told which
		// one this session is holding — ActionFor cannot derive it.
		Action:   fileAction(op.Op),
		Target:   plugin.Target{Path: op.Path},
		OpenedBy: p.OpenedBy, Unattended: p.Unattended,
		Surface: "api", Grantee: p, Device: att.Conn,
	}
	// Not recorded — sessionrun skips the recorder for this profile, because an asciicast
	// of a binary transfer is unwatchable and a second copy of the bytes in the recording
	// store is not what anybody asked for. The row still says so.
	rw, _, startedAt, err := runner.Prepare(ctx, params)
	if err != nil {
		runner.Reject(ctx, sessionID, "internal")
		s.problem(w, r, http.StatusInternalServerError, "internal",
			"Could not start the session", err.Error(), true)
		return zero, "", false
	}
	params.Operator = operator
	return runner.Run(ctx, params, rw, startedAt), sessionID, true
}

// fileSink streams DATA frames straight to an HTTP response.
type fileSink struct {
	w http.ResponseWriter

	mu      sync.Mutex
	written int64
	// started records whether any body byte has gone out, because that is the moment a
	// clean error response stops being possible.
	started *bool
	closed  chan struct{}
	once    sync.Once
}

var _ transport.Conn = (*fileSink)(nil)

func (f *fileSink) Recv(ctx context.Context) ([]byte, error) {
	f.once.Do(func() { f.closed = make(chan struct{}) })
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-f.closed:
		return nil, transport.ErrClosed
	}
}

func (f *fileSink) Send(_ context.Context, b []byte) error {
	fr, err := frame.Codec{}.Decode(b)
	if err != nil {
		return fmt.Errorf("apisrv: undecodable frame on a file session: %w", err)
	}
	if fr.Type != frame.TypeData {
		// READY, EXIT, CLOSE, ERROR are the pump's business and reach the handler
		// through the Outcome.
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !*f.started {
		*f.started = true
		// Octet-stream, and no filename: the gateway does not know what the caller
		// wants to call it, and guessing produces a Content-Disposition that is wrong
		// often enough to be worse than absent.
		f.w.Header().Set("Content-Type", "application/octet-stream")
		f.w.Header().Set("X-Content-Type-Options", "nosniff")
		f.w.WriteHeader(http.StatusOK)
	}
	n, err := f.w.Write(fr.Payload)
	f.written += int64(n)
	if err != nil {
		return err
	}
	if flusher, ok := f.w.(http.Flusher); ok {
		// Flushed as it arrives: a caller tailing a large log should not wait for the
		// whole thing to buffer in the server.
		flusher.Flush()
	}
	return nil
}

func (f *fileSink) Close(transport.CloseCode, string) error {
	f.once.Do(func() { f.closed = make(chan struct{}) })
	select {
	case <-f.closed:
	default:
		close(f.closed)
	}
	return nil
}

func (f *fileSink) RemoteAddr() string { return "" }

// fileSource turns a request body into DATA frames for the device.
type fileSource struct {
	r    interface{ Read([]byte) (int, error) }
	size int64

	sent   int64
	closed chan struct{}
	once   sync.Once
	buf    []byte
}

var _ transport.Conn = (*fileSource)(nil)

// Recv hands the next chunk of the body to the pump, as an encoded DATA frame.
//
// The operator direction is a *source* here rather than a sink, which is the one place the
// file profile inverts the usual shape: for every other profile the operator sends
// keystrokes and the device sends output.
func (f *fileSource) Recv(ctx context.Context) ([]byte, error) {
	f.once.Do(func() { f.closed = make(chan struct{}) })
	if f.sent >= f.size {
		// Everything promised has been sent. Block rather than return an error: the
		// device is still going to write, sync, rename and answer, and an error here
		// would tear the session down before it could.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-f.closed:
			return nil, transport.ErrClosed
		}
	}
	if f.buf == nil {
		f.buf = make([]byte, 32<<10)
	}
	n, err := f.r.Read(f.buf)
	if n > 0 {
		f.sent += int64(n)
		return frame.Codec{}.Encode(nil, frame.Data(f.buf[:n]))
	}
	if err != nil {
		return nil, err
	}
	return nil, transport.ErrClosed
}

func (f *fileSource) Send(context.Context, []byte) error { return nil }

func (f *fileSource) Close(transport.CloseCode, string) error {
	f.once.Do(func() { f.closed = make(chan struct{}) })
	select {
	case <-f.closed:
	default:
		close(f.closed)
	}
	return nil
}

func (f *fileSource) RemoteAddr() string { return "" }

// fileAction is which grant a file session has to keep holding while it runs.
func fileAction(op string) plugin.Action {
	if op == "write" {
		return plugin.ActionFileWrite
	}
	return plugin.ActionFileRead
}
