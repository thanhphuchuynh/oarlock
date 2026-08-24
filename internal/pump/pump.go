package pump

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oarlock/oarlock/internal/ring"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
	"github.com/oarlock/oarlock/pkg/transport"
)

// Session moves bytes between one device connection and one operator connection.
//
// Both are session connections: each carries exactly one session (ADR-024), so
// there is no routing to do here and no stream id to consult. Applying
// backpressure means not reading one socket, and that slows exactly the session
// that is not keeping up.
type Session struct {
	// Device is the agent's connection. Operator is the browser's or the SSH
	// front door's.
	Device   transport.Conn
	Operator transport.Conn

	SessionID string
	Profile   string
	Limits    Limits
	Deadlines Deadlines

	// Recorder receives the session's events. Nil records nothing.
	//
	// It sees every device→operator byte, **including bytes the live view drops**:
	// the recording should say what the device produced, not what a slow operator
	// happened to see. A THROTTLE marker tells the operator their view had a gap;
	// the recording has none, so an auditor asking what a command printed gets the
	// real answer.
	Recorder plugin.RecordingWriter

	// Ring is the scrollback a reattaching operator gets replayed.
	//
	// Its presence is what turns a dropped operator socket into a detach rather than a
	// close: with a ring, output keeps draining into it and the session waits; without
	// one, there is nothing to replay and the session ends as it always did. That
	// makes the SSH surface's behaviour (no ring, no reattach — there is nothing to
	// reattach *to* over ssh) a configuration rather than a special case.
	Ring *ring.Ring

	// Reattach delivers replacement operator connections. Nil means no reattach.
	//
	// A request rather than a bare connection, because the caller needs to know
	// whether the attach succeeded — a second operator is refused — and needs its
	// greeting sent inside the port's write lock.
	Reattach <-chan Reattachment

	// OnDetach and OnAttach report the operator coming and going, for the ledger and
	// the logs. OnAttach's error is non-nil when the reattach itself failed.
	OnDetach func()
	OnAttach func(snap ring.Snapshot, err error)

	// Observe delivers read-only watchers. Nil means observation is not offered.
	Observe <-chan Observation

	// OnObservers reports the watcher list changing, for the logs and the audit trail.
	OnObservers func(list []frame.Observer)

	// StartedAt anchors recorded timestamps. Zero means now.
	StartedAt time.Time

	// WriteTimeout bounds writes to the *operator*. Device writes are bounded by
	// Output's rate limiter and by backpressure; an operator that stops reading is
	// what this catches.
	WriteTimeout time.Duration

	Log *slog.Logger
}

// Deadlines are the session's time limits. Zero disables one.
//
// # Why there are two idle timers
//
// Counting only operator *input* kills the sessions that matter most: an operator who
// starts a twenty-minute firmware flash and watches it scroll has typed nothing for
// nineteen of those minutes, and killing that session mid-flash is a defect with a
// plausible path to bricking hardware.
//
// Counting only *any* traffic has the opposite failure: a `tail -f` that nobody is
// reading keeps a session — and the device's only slot — alive indefinitely.
//
// So both. Idle is "nothing at all is happening", short. IdleInput is "the operator
// has stopped participating while output still flows", long.
type Deadlines struct {
	// Idle closes when no bytes have moved in *either* direction.
	Idle time.Duration
	// IdleInput closes when the operator has sent nothing, even if output flows.
	IdleInput time.Duration
	// Max is the total session ceiling. Nothing legitimate needs longer, and it
	// bounds a session somebody forgot.
	Max time.Duration
}

// DefaultDeadlines matches ARCHITECTURE § 9.3.
//
// Idle is short because an abandoned root shell on a device in a gym is the thing to
// worry about. IdleInput is long because an operator watching a firmware flash is
// working, not idling. Max bounds a session somebody forgot.
func DefaultDeadlines() Deadlines {
	return Deadlines{
		Idle:      5 * time.Minute,
		IdleInput: 60 * time.Minute,
		Max:       4 * time.Hour,
	}
}

// Observation is a request to attach a read-only watcher (FR13).
type Observation struct {
	Principal string
	Conn      transport.Conn
	// Greet builds the watcher's own READY, from the list they are joining. Optional.
	Greet func(list []frame.Observer) (frame.Frame, error)
	// Done receives the handle, or an error. Buffered by the caller.
	Done chan ObserveResult
}

// ObserveResult is what an observation request produced.
type ObserveResult struct {
	Handle ObserverHandle
	Err    error
}

// Reattachment is a request to install a replacement operator.
type Reattachment struct {
	Conn transport.Conn
	// Greet builds the frame to send before the scrollback, from the snapshot that is
	// about to be replayed. Optional.
	Greet func(ring.Snapshot) (frame.Frame, error)
	// Done receives the outcome, if the caller is waiting for one. It must be buffered:
	// the pump does not block on a caller who stopped listening.
	Done chan error
}

// Result is why a session ended, and what moved.
type Result struct {
	// Reason is a close_reason from ARCHITECTURE § 6.
	Reason   string
	ExitCode *int
	Stats    Stats
}

// DefaultWriteTimeout bounds a write to the operator.
const DefaultWriteTimeout = 10 * time.Second

// Run pumps until either end closes, and reports why.
//
// It does not enforce idle or duration limits: those belong to the session ledger
// (E2.S3), which owns the timers and the close reasons that go with them.
func (s *Session) Run(ctx context.Context) (Result, error) {
	if s.Device == nil || s.Operator == nil {
		return Result{}, errors.New("pump: both connections are required")
	}
	log := s.Log
	if log == nil {
		log = slog.Default()
	}
	log = log.With("session", s.SessionID, "profile", s.Profile)

	wt := s.WriteTimeout
	if wt <= 0 {
		wt = DefaultWriteTimeout
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	started := s.StartedAt
	if started.IsZero() {
		started = time.Now()
	}
	rec := &recorderTee{w: s.Recorder, started: started, log: log}

	opSink := newOperatorPort(s.Operator, wt, s.Ring)
	// Watchers go when the session does, so the handlers holding their sockets return
	// instead of waiting for a browser to notice.
	defer opSink.releaseObservers()
	out := NewOutput(Options{
		Sink:    opSink,
		Policy:  PolicyFor(s.Profile),
		Limits:  s.Limits,
		Profile: s.Profile,
		Tee:     teeTo(rec.output, s.Ring),
	})

	// A recording failure ends the session *when it happens*, not when the session
	// happens to end. The spool has already absorbed everything it agreed to absorb
	// by this point, so continuing would mean running unrecorded — which is the one
	// state the whole mechanism exists to prevent.
	rec.onFail = cancel

	act := &activity{start: started}
	act.mark(started, true)

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		reason   string
		exitCode *int
		firstErr error
	)
	finish := func(r string, err error) {
		mu.Lock()
		defer mu.Unlock()
		if reason == "" {
			reason = r
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	// The coalescer runs on a context that outlives the session's own.
	//
	// Close() means "stop accepting writes and send what is buffered" — and the event
	// that triggers it, the device ending the session, is the same event that cancels
	// ctx. Draining on the cancelled context therefore raced the cancellation and lost
	// the final batch: for a shell that is the last line before the prompt comes back,
	// and for `exec` it is the answer. It showed up as a one-in-many flake on a loaded
	// machine, which is what a lost race looks like from the outside.
	//
	// Bounded rather than unbounded, so an operator socket that never drains cannot hold
	// the session open. One coalescing window would do; five seconds is generous and
	// still finite.
	drainCtx, stopDrain := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer stopDrain()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := out.Run(drainCtx); err != nil && !errors.Is(err, context.Canceled) &&
			!errors.Is(err, context.DeadlineExceeded) {
			finish("transport_error", err)
			cancel()
		}
	}()

	// Read-only watchers. Their connections are never read by the pump, which is what
	// makes read-only structural rather than enforced: there is no code path from a
	// watcher's socket to the device.
	if s.Observe != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case req, ok := <-s.Observe:
					if !ok {
						return
					}
					o, err := opSink.addObserver(ctx, req.Principal, req.Conn, req.Greet)
					if err != nil {
						log.Warn("could not add an observer",
							"principal", req.Principal, "error", err)
					} else {
						log.Info("session is being watched",
							"observer", req.Principal, "watchers", len(opSink.observerList()))
						if s.OnObservers != nil {
							s.OnObservers(opSink.observerList())
						}
					}
					if req.Done != nil {
						var h ObserverHandle
						if o != nil {
							h = o
						}
						req.Done <- ObserveResult{Handle: h, Err: err}
					}
				}
			}
		}()
	}

	// Reattaching operators. A separate goroutine because an attach has to be able to
	// happen while the reader is blocked waiting for one.
	if s.Reattach != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case req, ok := <-s.Reattach:
					if !ok {
						return
					}
					snap, err := opSink.attach(ctx, req.Conn, req.Greet)
					if err != nil {
						log.Warn("a reattach failed", "error", err)
					} else {
						log.Info("operator reattached",
							"replayed", len(snap.Replay),
							"skipped_for_safety", snap.SkippedForSafety,
							"dropped", snap.Dropped)
					}
					if req.Done != nil {
						req.Done <- err
					}
					if s.OnAttach != nil {
						s.OnAttach(snap, err)
					}
				}
			}
		}()
	}

	// The deadline supervisor. It sends CLOSE to both ends before cancelling, so the
	// operator sees a reason rather than a dropped connection, and the agent tears
	// down its PTY rather than waiting for a socket to notice.
	if d := s.Deadlines; d.Idle > 0 || d.IdleInput > 0 || d.Max > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r := s.supervise(ctx, act, opSink, log); r != "" {
				finish(r, nil)
				s.announce(ctx, r, opSink, log)
				cancel()
			}
		}()
	}

	// device → operator
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		code, r, err := s.readDevice(ctx, out, opSink, rec, act, log)
		if code != nil {
			mu.Lock()
			exitCode = code
			mu.Unlock()
		}
		out.Close()
		finish(r, err)
	}()

	// operator → device
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		r, err := s.readOperator(ctx, opSink, rec, act, log)
		finish(r, err)
	}()

	wg.Wait()
	out.Wait()

	// A recorder that failed is a session that must not be reported as recorded.
	// Until the spool lands (E2.S2) any failure is terminal, which is the safe
	// direction: an unrecorded session that looks recorded is worse than a session
	// that ended.
	if rerr := rec.err(); rerr != nil {
		finish("recorder_failed", rerr)
	}

	mu.Lock()
	res := Result{Reason: reason, ExitCode: exitCode, Stats: out.Stats()}
	err := firstErr
	mu.Unlock()

	if res.Reason == "" {
		res.Reason = "transport_error"
	}
	log.Info("session ended", "reason", res.Reason,
		"bytes_out", res.Stats.BytesOut, "dropped", res.Stats.BytesDropped,
		"stalls", res.Stats.Stalls)
	return res, err
}

// readDevice consumes the device's frames. Output.Write is called inline, so when
// it blocks under backpressure this loop stops reading — which is the mechanism.
func (s *Session) readDevice(ctx context.Context, out *Output, opSink *operatorPort,
	rec *recorderTee, act *activity, log *slog.Logger) (*int, string, error) {
	c := frame.Codec{}
	for {
		msg, err := s.Device.Recv(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil, "", nil
			}
			return nil, "device_close", err
		}
		f, err := c.Decode(msg)
		if err != nil {
			return nil, "transport_error", err
		}
		if err := frame.Expect(frame.ScopeSession, f); err != nil {
			return nil, "transport_error", err
		}
		if f.Type.Disposition() == frame.Ignore {
			log.Debug("ignoring an unknown frame from the device", "type", f.Type)
			continue
		}

		switch f.Type {
		case frame.TypeData:
			// Output counts as activity but not as input: that distinction is the
			// whole reason there are two idle timers.
			act.mark(time.Now(), false)
			if _, err := out.Write(f.Payload); err != nil {
				return nil, "transport_error", err
			}
		case frame.TypeDataErr:
			// exec only, and low volume. Forwarded immediately rather than through
			// the coalescer: interleaving stdout and stderr is inherently racy, and
			// batching one but not the other would make it look deterministic when
			// it is not.
			if err := opSink.broadcast(ctx, frame.DataErr(f.Payload)); err != nil {
				return nil, "transport_error", err
			}
		case frame.TypeExit:
			var e frame.Exit
			if err := frame.Unmarshal(f, &e); err != nil {
				return nil, "transport_error", err
			}
			code := e.Code
			rec.exit(code)
			// Drain what is buffered before reporting the exit, or the last line of
			// output races the exit code to the operator.
			return &code, "device_close", nil
		case frame.TypeClose:
			var cl frame.Close
			_ = frame.Unmarshal(f, &cl)
			r := cl.Reason
			if r == "" {
				r = "device_close"
			}
			return nil, r, nil
		case frame.TypeError:
			var e frame.Error
			_ = frame.Unmarshal(f, &e)
			log.Warn("device reported an error", "code", e.Code, "message", e.Message)
			if err := opSink.broadcast(ctx, f.Clone()); err != nil {
				return nil, "transport_error", err
			}
			return nil, "device_close", nil
		case frame.TypePing:
			stamp, err := frame.ReadStamp(f)
			if err != nil {
				return nil, "transport_error", err
			}
			pong, _ := frame.Stamp(frame.TypePong, stamp)
			if err := s.sendTo(ctx, s.Device, pong); err != nil {
				return nil, "transport_error", err
			}
		case frame.TypePong:
			// Liveness is the ledger's business; nothing to do here.
		case frame.TypeThrottle:
			// THROTTLE is gateway→operator only. A device claiming to have dropped
			// bytes on our behalf is a confused agent.
			return nil, "transport_error",
				fmt.Errorf("pump: THROTTLE from the device")
		default:
			return nil, "transport_error",
				fmt.Errorf("pump: %s is not valid from a device", f.Type)
		}
	}
}

// readOperator forwards operator input. Never batched: a human is waiting on the
// echo, and 25 ms on every keystroke is felt.
func (s *Session) readOperator(ctx context.Context, port *operatorPort,
	rec *recorderTee, act *activity, log *slog.Logger) (string, error) {
	c := frame.Codec{}
	for {
		conn, gen := port.current()
		if conn == nil {
			// Detached. Wait for somebody to come back rather than ending the session:
			// operators lose wifi constantly, and a shell that dies with it is a shell
			// nobody trusts with a long command. What bounds the wait is `limits.idle`
			// — a detached session receives no operator input, so the idle supervisor
			// closes it in its own time, which is exactly the behaviour an abandoned
			// session should get.
			if err := port.waitPresent(ctx); err != nil {
				return "", nil
			}
			continue
		}

		msg, err := conn.Recv(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return "", nil
			}
			// With a ring, a dropped operator connection is a detach. Without one
			// there is nothing to reattach to — over SSH a second `ssh` invocation is
			// a new session — and a detached SSH session would be a shell nobody can
			// reach, holding the device's only slot until the idle timer fired. That
			// is worse than closing it.
			if s.Ring == nil || s.Reattach == nil {
				return "operator_close", err
			}
			if port.detach(gen) {
				log.Info("operator detached; the session stays attached", "error", err)
				if s.OnDetach != nil {
					s.OnDetach()
				}
			}
			continue
		}

		f, err := c.Decode(msg)
		if err != nil {
			return "transport_error", err
		}
		if err := frame.Expect(frame.ScopeSession, f); err != nil {
			return "transport_error", err
		}
		if f.Type.Disposition() == frame.Ignore {
			continue
		}

		switch f.Type {
		case frame.TypeResize:
			// A resize with a non-positive dimension is not a resize. It arrives from
			// clients that do not know their own terminal size — `ssh -tt` with piped
			// stdin asks for a PTY while stdin is not a terminal — and it used to end
			// the session, because the recorder refuses a zero-sized resize and a
			// recording failure cancels. Dropped rather than forwarded: neither the
			// device nor the recording has any use for it.
			var rs frame.Resize
			if err := frame.Unmarshal(f, &rs); err != nil {
				return "transport_error", err
			}
			if rs.Cols <= 0 || rs.Rows <= 0 {
				log.Debug("dropped a resize with no size",
					"cols", rs.Cols, "rows", rs.Rows)
				continue
			}
			// A resize is not input: dragging a window edge is not the operator
			// participating, and treating it as such would keep an abandoned session
			// alive on browser reflow alone.
			act.mark(time.Now(), false)
			rec.fromOperator(f)
			if err := s.sendTo(ctx, s.Device, f); err != nil {
				return "transport_error", err
			}

		case frame.TypeData, frame.TypeSignal:
			// A keystroke is input.
			act.mark(time.Now(), f.Type == frame.TypeData)
			// Recorded before forwarding, so a resize that reaches the device is in
			// the recording even if the session dies immediately after.
			rec.fromOperator(f)
			if err := s.sendTo(ctx, s.Device, f); err != nil {
				return "transport_error", err
			}
		case frame.TypeClose:
			var cl frame.Close
			_ = frame.Unmarshal(f, &cl)
			r := cl.Reason
			if r == "" {
				r = "operator_close"
			}
			return r, nil
		case frame.TypePing:
			stamp, err := frame.ReadStamp(f)
			if err != nil {
				return "transport_error", err
			}
			pong, _ := frame.Stamp(frame.TypePong, stamp)
			// Through the port, not the connection: a pong written straight to a
			// socket that has since been replaced would go to the wrong operator.
			if err := port.sendFrame(ctx, pong); err != nil {
				return "transport_error", err
			}
		case frame.TypePong:
		default:
			// READY, OPEN, EXIT, THROTTLE, DATA_ERR from an operator.
			return "transport_error",
				fmt.Errorf("pump: %s is not valid from an operator", f.Type)
		}
	}
}

func (s *Session) sendTo(ctx context.Context, conn transport.Conn, f frame.Frame) error {
	wt := s.WriteTimeout
	if wt <= 0 {
		wt = DefaultWriteTimeout
	}
	wire, err := frame.Codec{}.Encode(nil, f)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, wt)
	defer cancel()
	return conn.Send(ctx, wire)
}

// teeTo fans the accepted-byte tap out to the recorder and the scrollback ring.
//
// Both see what the *device* produced rather than what a slow operator happened to
// receive: an auditor asking "what did that command print" gets the real answer, and a
// reattaching operator gets the screen as it actually is rather than as their dropped
// connection last managed to render it.
func teeTo(rec func([]byte), r *ring.Ring) func([]byte) {
	if r == nil {
		return rec
	}
	return func(b []byte) {
		rec(b)
		_, _ = r.Write(b) // the ring never fails and never blocks
	}
}

// recorderTee adapts the pump's events to a RecordingWriter.
//
// It converts wall-clock into elapsed time — the recording format wants intervals
// from the session's start, not absolute stamps — and it collects the first error
// rather than each caller having to. Recording is not on the hot path's critical
// path: a failure is noticed at the end of the session, not mid-keystroke.
type recorderTee struct {
	log     *slog.Logger
	w       plugin.RecordingWriter
	started time.Time
	// onFail is called once, on the first recording error, to end the session.
	onFail func()

	mu    sync.Mutex
	first error
}

func (r *recorderTee) at() time.Duration { return time.Since(r.started) }

func (r *recorderTee) fail(err error) {
	if err == nil {
		return
	}
	r.mu.Lock()
	first := r.first == nil
	if first {
		r.first = err
	}
	onFail := r.onFail
	r.mu.Unlock()

	if !first {
		return
	}
	// Logged here, at the moment it happens, because this cancels the session: without
	// it an operator gets `transport_error` and the logs say nothing about why. That is
	// how a recorder refusing a zero-sized resize came to look like a network fault for
	// an afternoon.
	if r.log != nil {
		r.log.Error("recording failed; ending the session", "error", err)
	}
	if onFail != nil {
		onFail()
	}
}

func (r *recorderTee) err() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.first
}

// output records device→operator bytes. Called from the shaper's Tee, so it sees
// everything accepted into the pump including what the live view drops.
func (r *recorderTee) output(b []byte) {
	if r.w == nil {
		return
	}
	r.fail(r.w.Output(r.at(), b))
}

// fromOperator records input and resizes. The writer decides whether input is
// captured at all, from the per-session policy — this side does not second-guess it.
func (r *recorderTee) fromOperator(f frame.Frame) {
	if r.w == nil {
		return
	}
	switch f.Type {
	case frame.TypeData:
		r.fail(r.w.Input(r.at(), f.Payload))
	case frame.TypeResize:
		var rs frame.Resize
		if err := frame.Unmarshal(f, &rs); err == nil {
			r.fail(r.w.Resize(r.at(), rs.Cols, rs.Rows))
		}
	}
}

func (r *recorderTee) exit(code int) {
	if r.w == nil {
		return
	}
	r.fail(r.w.Exit(r.at(), code))
}

// activity tracks when anything last happened, and when the operator last did.
type activity struct {
	start time.Time
	// Unix nanoseconds, so the supervisor can read them without a lock.
	last      atomic.Int64
	lastInput atomic.Int64
}

func (a *activity) mark(at time.Time, input bool) {
	a.last.Store(at.UnixNano())
	if input {
		a.lastInput.Store(at.UnixNano())
	}
}

func (a *activity) idleFor(now time.Time) time.Duration {
	return now.Sub(time.Unix(0, a.last.Load()))
}

func (a *activity) inputIdleFor(now time.Time) time.Duration {
	return now.Sub(time.Unix(0, a.lastInput.Load()))
}

// supervise watches the deadlines and returns the close reason that fired, or "" if
// the session ended for another reason first.
func (s *Session) supervise(ctx context.Context, act *activity, sink *operatorPort,
	log *slog.Logger) string {
	d := s.Deadlines
	// Check often enough to be accurate to a fraction of the shortest deadline, and
	// rarely enough that ten thousand idle sessions are not a busy loop.
	tick := shortest(d.Idle, d.IdleInput, d.Max) / 8
	if tick < 10*time.Millisecond {
		tick = 10 * time.Millisecond
	}
	if tick > 5*time.Second {
		tick = 5 * time.Second
	}
	t := time.NewTicker(tick)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return ""
		case now := <-t.C:
			switch {
			case d.Max > 0 && now.Sub(act.start) >= d.Max:
				log.Info("session hit its duration ceiling", "after", d.Max)
				return "max_duration"
			case d.Idle > 0 && act.idleFor(now) >= d.Idle:
				log.Info("session idle in both directions", "for", d.Idle)
				return "idle_timeout"
			case d.IdleInput > 0 && act.inputIdleFor(now) >= d.IdleInput:
				// Output may still be flowing — a tail -f nobody is reading. The
				// device's only slot is worth more than an unwatched log stream.
				log.Info("operator stopped participating", "for", d.IdleInput)
				return "idle_timeout"
			}
		}
	}
}

// announce tells both ends why the session is ending, so the operator sees a reason
// rather than a dropped connection.
func (s *Session) announce(ctx context.Context, reason string, sink *operatorPort,
	log *slog.Logger) {
	f, err := frame.Marshal(frame.TypeClose, frame.Close{Reason: reason})
	if err != nil {
		return
	}
	// Best effort, and bounded: if either side has already gone, saying so is not
	// worth holding the teardown open.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := sink.broadcast(ctx, f); err != nil {
		log.Debug("could not tell the operator why", "reason", reason, "error", err)
	}
	if err := s.sendTo(ctx, s.Device, f); err != nil {
		log.Debug("could not tell the device why", "reason", reason, "error", err)
	}
}

func shortest(ds ...time.Duration) time.Duration {
	var out time.Duration
	for _, d := range ds {
		if d > 0 && (out == 0 || d < out) {
			out = d
		}
	}
	if out == 0 {
		out = time.Second
	}
	return out
}
