package pump_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/pump"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
	"github.com/oarlock/oarlock/pkg/transport"
	"github.com/oarlock/oarlock/pkg/transport/memory"
)

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// wiring gives a test the two far ends: what the device sees and what the operator
// sees, with a real pump.Session in between.
type wiring struct {
	device   transport.Conn // the agent's end
	operator transport.Conn // the browser's end
	result   chan pump.Result
	errs     chan error
}

func wire(t *testing.T, profile string, limits pump.Limits) *wiring {
	t.Helper()
	devGW, devAgent := memory.Pair(0)
	opGW, opBrowser := memory.Pair(0)

	s := &pump.Session{
		Device: devGW, Operator: opGW,
		SessionID: "sess_1", Profile: profile, Limits: limits,
		WriteTimeout: 2 * time.Second, Log: quiet(),
	}
	w := &wiring{device: devAgent, operator: opBrowser,
		result: make(chan pump.Result, 1), errs: make(chan error, 1)}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		res, err := s.Run(ctx)
		w.errs <- err
		w.result <- res
	}()
	t.Cleanup(func() {
		_ = devAgent.Close(transport.CloseNormal, "test over")
		_ = opBrowser.Close(transport.CloseNormal, "test over")
	})
	return w
}

func send(t *testing.T, c transport.Conn, f frame.Frame) {
	t.Helper()
	wire, err := frame.Codec{}.Encode(nil, f)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Send(context.Background(), wire); err != nil {
		t.Fatalf("send %s: %v", f.Type, err)
	}
}

func recv(t *testing.T, c transport.Conn) frame.Frame {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	msg, err := c.Recv(ctx)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	f, err := frame.Codec{}.Decode(msg)
	if err != nil {
		t.Fatal(err)
	}
	return f.Clone()
}

func fastLimits() pump.Limits {
	return pump.Limits{Batch: 4096, Window: 5 * time.Millisecond,
		HighWater: 1 << 16, LowWater: 1 << 12}
}

// ── both directions ─────────────────────────────────────────────────────────────

func TestOutputReachesTheOperator(t *testing.T) {
	w := wire(t, "shell", fastLimits())
	send(t, w.device, frame.Data([]byte("total 0\r\n")))
	f := recv(t, w.operator)
	if f.Type != frame.TypeData || string(f.Payload) != "total 0\r\n" {
		t.Fatalf("operator received %v %q", f.Type, f.Payload)
	}
}

// TestInputIsNeverBatched: a human is waiting on the echo, and 25 ms added to every
// keystroke is felt.
func TestInputIsNeverBatched(t *testing.T) {
	w := wire(t, "shell", pump.Limits{Batch: 4096, Window: time.Second,
		HighWater: 1 << 16, LowWater: 1 << 12})

	for _, key := range []string{"l", "s", "\r"} {
		start := time.Now()
		send(t, w.operator, frame.Data([]byte(key)))
		f := recv(t, w.device)
		if string(f.Payload) != key {
			t.Fatalf("device received %q, want %q", f.Payload, key)
		}
		// The coalescing window is a second; input must not wait for it.
		if elapsed := time.Since(start); elapsed > 300*time.Millisecond {
			t.Errorf("keystroke %q took %v — input is being batched", key, elapsed)
		}
	}
}

func TestResizeAndSignalReachTheDevice(t *testing.T) {
	w := wire(t, "shell", fastLimits())

	rf, err := frame.Marshal(frame.TypeResize, frame.Resize{Cols: 132, Rows: 38})
	if err != nil {
		t.Fatal(err)
	}
	send(t, w.operator, rf)
	got := recv(t, w.device)
	if got.Type != frame.TypeResize {
		t.Fatalf("device received %v", got.Type)
	}
	var r frame.Resize
	if err := frame.Unmarshal(got, &r); err != nil {
		t.Fatal(err)
	}
	if r.Cols != 132 || r.Rows != 38 {
		t.Errorf("resize arrived as %+v", r)
	}

	sf, _ := frame.Marshal(frame.TypeSignal, frame.Signal{Signal: "INT"})
	send(t, w.operator, sf)
	if got := recv(t, w.device); got.Type != frame.TypeSignal {
		t.Fatalf("device received %v, want SIGNAL", got.Type)
	}
}

func TestDataErrIsForwardedImmediately(t *testing.T) {
	// exec only, low volume, and not coalesced: interleaving stdout and stderr is
	// inherently racy, and batching one but not the other would make it look
	// deterministic when it is not.
	w := wire(t, "exec", pump.Limits{Batch: 4096, Window: time.Second,
		HighWater: 1 << 16, LowWater: 1 << 12})
	send(t, w.device, frame.DataErr([]byte("permission denied\n")))
	f := recv(t, w.operator)
	if f.Type != frame.TypeDataErr || string(f.Payload) != "permission denied\n" {
		t.Fatalf("operator received %v %q", f.Type, f.Payload)
	}
}

// ── ending ──────────────────────────────────────────────────────────────────────

func TestExitCodeIsReported(t *testing.T) {
	w := wire(t, "exec", fastLimits())
	ef, _ := frame.Marshal(frame.TypeExit, frame.Exit{Code: 130})
	send(t, w.device, ef)

	select {
	case res := <-w.result:
		if res.ExitCode == nil || *res.ExitCode != 130 {
			t.Fatalf("exit code %v", res.ExitCode)
		}
		if res.Reason != "device_close" {
			t.Errorf("reason %q", res.Reason)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the pump did not finish after EXIT")
	}
}

func TestCloseReasonsAreCarried(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		fromDevice   bool
	}{
		{"operator closes", "operator_close", false},
		{"device closes", "device_close", true},
		{"idle timeout from the ledger", "idle_timeout", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := wire(t, "shell", fastLimits())
			cf, _ := frame.Marshal(frame.TypeClose, frame.Close{Reason: tc.reason})
			if tc.fromDevice {
				send(t, w.device, cf)
			} else {
				send(t, w.operator, cf)
			}
			select {
			case res := <-w.result:
				if res.Reason != tc.reason {
					t.Errorf("reason %q, want %q", res.Reason, tc.reason)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("the pump did not finish")
			}
		})
	}
}

// ── protocol discipline ─────────────────────────────────────────────────────────

func TestFramesFromTheWrongSideAreRejected(t *testing.T) {
	throttle, _ := frame.Marshal(frame.TypeThrottle, frame.Throttle{DroppedBytes: 1})
	ready, _ := frame.Marshal(frame.TypeReady, frame.Ready{SessionID: "x"})
	exit, _ := frame.Marshal(frame.TypeExit, frame.Exit{Code: 0})

	tests := []struct {
		name       string
		f          frame.Frame
		fromDevice bool
	}{
		// A device claiming to have dropped bytes on the gateway's behalf is a
		// confused agent: THROTTLE is gateway→operator only.
		{"THROTTLE from the device", throttle, true},
		{"READY from the operator", ready, false},
		{"EXIT from the operator", exit, false},
		// A control-channel frame down a session connection: the peer is confused
		// about which connection it is holding.
		{"DIAL from the device", mustDial(t), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := wire(t, "shell", fastLimits())
			if tc.fromDevice {
				send(t, w.device, tc.f)
			} else {
				send(t, w.operator, tc.f)
			}
			select {
			case res := <-w.result:
				if res.Reason != "transport_error" {
					t.Errorf("reason %q, want transport_error", res.Reason)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("the pump accepted a frame from the wrong side")
			}
		})
	}
}

func mustDial(t *testing.T) frame.Frame {
	t.Helper()
	f, err := frame.Marshal(frame.TypeDial, frame.Invitation{SessionID: "x"})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// TestPingWorksOnASessionConnection: PING and PONG are valid on both connection
// kinds, because a session where nobody is typing still has to be known to exist.
// Scoping them to the control channel — which is where 0x1x lives — made the pump
// reject them, which is how this was found.
func TestPingWorksOnASessionConnection(t *testing.T) {
	w := wire(t, "shell", fastLimits())
	for _, side := range []struct {
		name string
		conn transport.Conn
	}{
		{"operator", w.operator},
		{"device", w.device},
	} {
		t.Run(side.name, func(t *testing.T) {
			ping, err := frame.Stamp(frame.TypePing, 12345)
			if err != nil {
				t.Fatal(err)
			}
			send(t, side.conn, ping)
			got := recv(t, side.conn)
			if got.Type != frame.TypePong {
				t.Fatalf("got %v, want PONG", got.Type)
			}
			if stamp, err := frame.ReadStamp(got); err != nil || stamp != 12345 {
				t.Errorf("stamp %d, %v — it must be echoed verbatim", stamp, err)
			}
		})
	}
}

// ── the shell property, end to end through the pump ─────────────────────────────

// TestShellFloodIsLossless drives a megabyte through a deliberately small buffer and
// asserts the operator receives it byte-exact. This is the vi-does-not-corrupt
// property at the pump level; the real vi-under-flood test needs a PTY and lands
// with E1.S6.
func TestShellFloodIsLossless(t *testing.T) {
	w := wire(t, "shell", pump.Limits{Batch: 2048, Window: time.Millisecond,
		HighWater: 8192, LowWater: 1024})

	const chunks = 512
	chunk := bytes.Repeat([]byte("\x1b[1;32m0123456789\x1b[0m"), 32)
	want := bytes.Repeat(chunk, chunks)

	go func() {
		for range chunks {
			wire, _ := frame.Codec{}.Encode(nil, frame.Data(chunk))
			if err := w.device.Send(context.Background(), wire); err != nil {
				return
			}
		}
	}()

	var got []byte
	deadline := time.Now().Add(20 * time.Second)
	for len(got) < len(want) && time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		msg, err := w.operator.Recv(ctx)
		cancel()
		if err != nil {
			t.Fatalf("after %d of %d bytes: %v", len(got), len(want), err)
		}
		f, err := frame.Codec{}.Decode(msg)
		if err != nil {
			t.Fatal(err)
		}
		switch f.Type {
		case frame.TypeData:
			got = append(got, f.Payload...)
		case frame.TypeThrottle:
			t.Fatal("THROTTLE on a shell stream: it must backpressure, never drop")
		default:
			t.Fatalf("unexpected %v", f.Type)
		}
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("flood was not lossless: sent %d, received %d", len(want), len(got))
	}
}

func TestBothConnectionsRequired(t *testing.T) {
	s := &pump.Session{SessionID: "x", Profile: "shell", Log: quiet()}
	if _, err := s.Run(context.Background()); err == nil {
		t.Error("a session with no connections ran")
	}
}

// failingRecorder fails after n successful writes, standing in for a spool that has
// spent its tolerance band.
type failingRecorder struct {
	afterN int
	n      int
	mu     sync.Mutex
	closed bool
}

func (r *failingRecorder) Output(_ time.Duration, _ []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.n++
	if r.n > r.afterN {
		return errors.New("record: spool exhausted")
	}
	return nil
}
func (r *failingRecorder) Input(time.Duration, []byte) error    { return nil }
func (r *failingRecorder) Resize(time.Duration, int, int) error { return nil }
func (r *failingRecorder) Exit(time.Duration, int) error        { return nil }
func (r *failingRecorder) Close(context.Context, plugin.RecordingResult) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}

// TestRecordingFailureEndsTheSession: past the tolerance band, continuing would mean
// running unrecorded — which is the one state the spool exists to prevent. So the
// session ends, and it ends with the true reason.
func TestRecordingFailureEndsTheSession(t *testing.T) {
	devGW, devAgent := memory.Pair(0)
	opGW, opBrowser := memory.Pair(0)

	rec := &failingRecorder{afterN: 2}
	s := &pump.Session{
		Device: devGW, Operator: opGW, SessionID: "sess_rec", Profile: "shell",
		Limits: fastLimits(), Recorder: rec, WriteTimeout: 2 * time.Second, Log: quiet(),
	}
	result := make(chan pump.Result, 1)
	go func() {
		res, _ := s.Run(context.Background())
		result <- res
	}()

	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	// Drain the operator side, or an undrained sink stalls the pump and masks the
	// recording failure behind a transport one.
	go func() {
		for {
			if _, err := opBrowser.Recv(ctx); err != nil {
				return
			}
		}
	}()
	// Send from a goroutine with a per-send deadline: once the pump gives up nobody
	// reads the device side, and an unbounded Send would block forever — which is
	// correct backpressure, and a trap for a test that sends inline.
	go func() {
		for i := range 50 {
			wire, err := frame.Codec{}.Encode(nil, frame.Data([]byte(fmt.Sprintf("row %d\r\n", i))))
			if err != nil {
				return
			}
			sendCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
			err = devAgent.Send(sendCtx, wire)
			cancel()
			if err != nil {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	select {
	case res := <-result:
		if res.Reason != "recorder_failed" {
			t.Fatalf("reason %q, want recorder_failed", res.Reason)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the session continued after the recording failed")
	}
}

// ── deadlines ───────────────────────────────────────────────────────────────────

// deadlineFixture drives a session with deadlines and lets a test feed either side.
type deadlineFixture struct {
	device   transport.Conn
	operator transport.Conn
	result   chan pump.Result
}

func withDeadlines(t *testing.T, d pump.Deadlines) *deadlineFixture {
	t.Helper()
	devGW, devAgent := memory.Pair(0)
	opGW, opBrowser := memory.Pair(0)

	s := &pump.Session{
		Device: devGW, Operator: opGW, SessionID: "sess_dl", Profile: "shell",
		Limits: fastLimits(), Deadlines: d, WriteTimeout: 2 * time.Second, Log: quiet(),
	}
	f := &deadlineFixture{device: devAgent, operator: opBrowser,
		result: make(chan pump.Result, 1)}

	go func() {
		res, _ := s.Run(context.Background())
		f.result <- res
	}()
	ctx, stop := context.WithCancel(context.Background())
	t.Cleanup(stop)
	// Drain **both** sides. An undrained sink stalls the pump, and then every
	// deadline test measures buffer pressure instead of the deadline it names —
	// which is how a passing test proves the wrong thing.
	for _, c := range []transport.Conn{opBrowser, devAgent} {
		conn := c
		go func() {
			for {
				if _, err := conn.Recv(ctx); err != nil {
					return
				}
			}
		}()
	}
	t.Cleanup(func() {
		_ = devAgent.Close(transport.CloseNormal, "test over")
		_ = opBrowser.Close(transport.CloseNormal, "test over")
	})
	return f
}

func (f *deadlineFixture) sendOutput(ctx context.Context, s string) error {
	wire, err := frame.Codec{}.Encode(nil, frame.Data([]byte(s)))
	if err != nil {
		return err
	}
	sendCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	return f.device.Send(sendCtx, wire)
}

func (f *deadlineFixture) sendInput(ctx context.Context, s string) error {
	wire, err := frame.Codec{}.Encode(nil, frame.Data([]byte(s)))
	if err != nil {
		return err
	}
	sendCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	return f.operator.Send(sendCtx, wire)
}

func (f *deadlineFixture) await(t *testing.T, d time.Duration) (pump.Result, bool) {
	t.Helper()
	select {
	case res := <-f.result:
		return res, true
	case <-time.After(d):
		return pump.Result{}, false
	}
}

// TestOutputAloneKeepsASessionAlive is the firmware-flash case, scaled down. An
// operator who starts a twenty-minute flash and watches it scroll has typed nothing
// for nineteen of those minutes, and killing that session mid-flash is a defect with
// a plausible path to bricking hardware.
func TestOutputAloneKeepsASessionAlive(t *testing.T) {
	f := withDeadlines(t, pump.Deadlines{
		Idle:      120 * time.Millisecond, // short: any traffic must reset it
		IdleInput: 10 * time.Second,       // long: the operator is allowed to watch
	})
	ctx := context.Background()

	// Output only, for several multiples of the both-directions deadline.
	deadline := time.Now().Add(700 * time.Millisecond)
	for time.Now().Before(deadline) {
		if err := f.sendOutput(ctx, "flashing... 42%\r\n"); err != nil {
			t.Fatalf("the session died mid-flash: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if res, ended := f.await(t, 50*time.Millisecond); ended {
		t.Fatalf("the session was closed while output was flowing: %q", res.Reason)
	}
}

// TestUnwatchedOutputIsEventuallyClosed is the other half: a tail -f nobody is
// reading must not hold the device's only slot forever.
func TestUnwatchedOutputIsEventuallyClosed(t *testing.T) {
	f := withDeadlines(t, pump.Deadlines{
		Idle:      10 * time.Second,       // long: traffic is flowing, so this never fires
		IdleInput: 150 * time.Millisecond, // short: the operator has stopped participating
	})
	ctx := context.Background()

	go func() {
		for {
			if err := f.sendOutput(ctx, "I/Display frame ok\r\n"); err != nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	res, ended := f.await(t, 5*time.Second)
	if !ended {
		t.Fatal("an unwatched stream held the session open indefinitely")
	}
	if res.Reason != "idle_timeout" {
		t.Errorf("reason %q, want idle_timeout", res.Reason)
	}
}

// TestKeystrokesKeepTheInputTimerAlive: an operator who is participating must not be
// timed out by the input deadline.
func TestKeystrokesKeepTheInputTimerAlive(t *testing.T) {
	f := withDeadlines(t, pump.Deadlines{IdleInput: 200 * time.Millisecond})
	ctx := context.Background()

	deadline := time.Now().Add(700 * time.Millisecond)
	for time.Now().Before(deadline) {
		if err := f.sendInput(ctx, "x"); err != nil {
			t.Fatalf("the session died while the operator was typing: %v", err)
		}
		time.Sleep(40 * time.Millisecond)
	}
	if res, ended := f.await(t, 50*time.Millisecond); ended {
		t.Fatalf("a participating operator was timed out: %q", res.Reason)
	}
}

// TestResizeIsNotParticipation: dragging a browser window edge is not the operator
// working, and treating it as input would keep an abandoned session alive on reflow
// alone.
func TestResizeIsNotParticipation(t *testing.T) {
	f := withDeadlines(t, pump.Deadlines{IdleInput: 200 * time.Millisecond})
	ctx := context.Background()

	go func() {
		for i := 0; ; i++ {
			rf, err := frame.Marshal(frame.TypeResize, frame.Resize{Cols: 80 + i%20, Rows: 24})
			if err != nil {
				return
			}
			wire, err := frame.Codec{}.Encode(nil, rf)
			if err != nil {
				return
			}
			sendCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
			err = f.operator.Send(sendCtx, wire)
			cancel()
			if err != nil {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	res, ended := f.await(t, 5*time.Second)
	if !ended {
		t.Fatal("window resizes kept an abandoned session alive")
	}
	if res.Reason != "idle_timeout" {
		t.Errorf("reason %q, want idle_timeout", res.Reason)
	}
}

func TestSilentSessionHitsTheIdleTimeout(t *testing.T) {
	f := withDeadlines(t, pump.Deadlines{Idle: 100 * time.Millisecond})
	res, ended := f.await(t, 5*time.Second)
	if !ended {
		t.Fatal("a silent session stayed open")
	}
	if res.Reason != "idle_timeout" {
		t.Errorf("reason %q, want idle_timeout", res.Reason)
	}
}

// TestMaxDurationCeiling: nothing legitimate needs longer, and it bounds a session
// somebody forgot about.
func TestMaxDurationCeiling(t *testing.T) {
	f := withDeadlines(t, pump.Deadlines{Max: 200 * time.Millisecond, IdleInput: time.Hour})
	ctx := context.Background()

	go func() {
		for {
			if err := f.sendInput(ctx, "still here"); err != nil {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	res, ended := f.await(t, 5*time.Second)
	if !ended {
		t.Fatal("an active session ignored the duration ceiling")
	}
	if res.Reason != "max_duration" {
		t.Errorf("reason %q, want max_duration", res.Reason)
	}
}

// TestDeadlineTellsBothEnds: the operator should see a reason, not a dropped
// connection, and the device should tear down its PTY rather than wait for a socket
// to notice.
func TestDeadlineTellsBothEnds(t *testing.T) {
	devGW, devAgent := memory.Pair(0)
	opGW, opBrowser := memory.Pair(0)
	s := &pump.Session{
		Device: devGW, Operator: opGW, SessionID: "sess_tell", Profile: "shell",
		Limits: fastLimits(), WriteTimeout: 2 * time.Second, Log: quiet(),
		Deadlines: pump.Deadlines{Idle: 80 * time.Millisecond},
	}
	go func() { _, _ = s.Run(context.Background()) }()

	for name, conn := range map[string]transport.Conn{"operator": opBrowser, "device": devAgent} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		msg, err := conn.Recv(ctx)
		cancel()
		if err != nil {
			t.Fatalf("%s was never told why: %v", name, err)
		}
		f, err := frame.Codec{}.Decode(msg)
		if err != nil {
			t.Fatal(err)
		}
		if f.Type != frame.TypeClose {
			t.Fatalf("%s received %v, want CLOSE", name, f.Type)
		}
		var cl frame.Close
		if err := frame.Unmarshal(f, &cl); err != nil {
			t.Fatal(err)
		}
		if cl.Reason != "idle_timeout" {
			t.Errorf("%s was told %q", name, cl.Reason)
		}
	}
}

func TestNoDeadlinesMeansNoSupervisor(t *testing.T) {
	// The zero Deadlines must not close anything: a caller that has not configured
	// timers should get a session that lasts as long as its ends do.
	f := withDeadlines(t, pump.Deadlines{})
	ctx := context.Background()
	if err := f.sendOutput(ctx, "hello"); err != nil {
		t.Fatal(err)
	}
	if res, ended := f.await(t, 400*time.Millisecond); ended {
		t.Fatalf("a session with no deadlines was closed: %q", res.Reason)
	}
}

// TestBufferedOutputSurvivesTheSessionEnding.
//
// Output.Close() promises to "stop accepting writes and let Run drain what is buffered".
// The event that triggers it — the device ending the session — is the same event that
// cancels the pump's context, so draining on that context raced the cancellation and
// dropped the final batch. For a shell that is the last line before the prompt returns;
// for `exec`, where the whole point is collecting an answer, it is the answer.
//
// A long coalescing window makes the race deterministic in the failing direction: the
// bytes are certainly still buffered when the session ends.
func TestBufferedOutputSurvivesTheSessionEnding(t *testing.T) {
	w := wire(t, "exec", pump.Limits{
		Batch: 1 << 20, Window: 2 * time.Second,
		HighWater: 1 << 16, LowWater: 1 << 12,
	})

	// Far below Batch, so nothing is flushed by size, and the window has not elapsed.
	send(t, w.device, frame.Data([]byte("the answer")))
	exit, _ := frame.Marshal(frame.TypeExit, frame.Exit{Code: 0})
	send(t, w.device, exit)
	closeFrame, _ := frame.Marshal(frame.TypeClose, frame.Close{Reason: "device_close"})
	send(t, w.device, closeFrame)

	// The buffered stdout has to arrive even though the session is over.
	deadline := time.After(10 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("the buffered output never arrived: the final batch was dropped when " +
				"the session ended")
		default:
		}
		f := recv(t, w.operator)
		if f.Type == frame.TypeData {
			if string(f.Payload) != "the answer" {
				t.Fatalf("payload = %q", f.Payload)
			}
			return
		}
		if f.Type == frame.TypeClose {
			t.Fatal("the session closed before the buffered output was sent")
		}
	}
}

// TestOutputKeepsFlowingOnALongSession.
//
// The regression for a fix that was worse than the bug. Draining on a context that the
// session's end cannot cancel is right; giving that context a *deadline* is not, because
// `context.WithTimeout` starts counting when the pump starts rather than when the drain
// does. A five second bound therefore stopped output halfway through every session that
// lasted longer than five seconds — which no short test noticed and the e2e suite did.
//
// Six seconds of real time, deliberately: a shorter one cannot distinguish the two.
func TestOutputKeepsFlowingOnALongSession(t *testing.T) {
	if testing.Short() {
		t.Skip("this one has to spend real time to mean anything")
	}
	w := wire(t, "shell", pump.Limits{
		Batch: 4096, Window: 10 * time.Millisecond,
		HighWater: 1 << 16, LowWater: 1 << 12,
	})

	// Output at the start, and again after any plausible fixed drain budget has passed.
	send(t, w.device, frame.Data([]byte("early")))
	if got := readData(t, w.operator, 5*time.Second); got != "early" {
		t.Fatalf("early output = %q", got)
	}

	time.Sleep(6 * time.Second)

	send(t, w.device, frame.Data([]byte("late")))
	if got := readData(t, w.operator, 5*time.Second); got != "late" {
		t.Fatalf("late output = %q — the coalescer stopped delivering mid-session", got)
	}
}

// readData waits for the next DATA frame, skipping the housekeeping ones.
func readData(t *testing.T, c transport.Conn, within time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		f := recv(t, c)
		if f.Type == frame.TypeData {
			return string(f.Payload)
		}
		if f.Type == frame.TypeClose {
			t.Fatalf("the session closed while waiting for output")
		}
	}
	t.Fatal("no DATA frame arrived")
	return ""
}
