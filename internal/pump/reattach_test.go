package pump_test

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/pump"
	"github.com/oarlock/oarlock/internal/ring"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/transport"
	"github.com/oarlock/oarlock/pkg/transport/memory"
)

// reattachable is a pump with a ring, which is what turns a dropped operator socket
// into a detach rather than a close.
type reattachable struct {
	device   transport.Conn
	operator transport.Conn
	reattach chan pump.Reattachment
	result   chan pump.Result
	errs     chan error
	detaches atomic.Int32
	attaches chan ring.Snapshot
}

func wireReattachable(t *testing.T, scrollback int, d pump.Deadlines) *reattachable {
	t.Helper()
	devGW, devAgent := memory.Pair(0)
	opGW, opBrowser := memory.Pair(0)

	w := &reattachable{
		device: devAgent, operator: opBrowser,
		reattach: make(chan pump.Reattachment, 1),
		result:   make(chan pump.Result, 1),
		errs:     make(chan error, 1),
		attaches: make(chan ring.Snapshot, 4),
	}

	s := &pump.Session{
		Device: devGW, Operator: opGW,
		SessionID: "sess_1", Profile: "shell",
		Limits:       pump.Limits{Batch: 64 << 10, Window: 5 * time.Millisecond},
		Deadlines:    d,
		WriteTimeout: 2 * time.Second,
		Log:          quiet(),
		Ring:         ring.New(scrollback),
		Reattach:     w.reattach,
		OnDetach:     func() { w.detaches.Add(1) },
		OnAttach: func(snap ring.Snapshot, err error) {
			if err == nil {
				w.attaches <- snap
			}
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		res, err := s.Run(ctx)
		w.errs <- err
		w.result <- res
	}()
	t.Cleanup(func() { _ = devAgent.Close(transport.CloseNormal, "test over") })
	return w
}

// reattach drops the current operator and hands the pump a fresh connection, the way
// /ws/attach does. It returns the new far end.
func (w *reattachable) reattachNow(t *testing.T) transport.Conn {
	t.Helper()
	opGW, opBrowser := memory.Pair(0)
	w.reattach <- pump.Reattachment{Conn: opGW}
	t.Cleanup(func() { _ = opBrowser.Close(transport.CloseNormal, "test over") })
	return opBrowser
}

// TestADroppedOperatorIsNotAClose is the core of FR8 and of ARCHITECTURE § 6: operators
// lose wifi constantly, and a shell that dies with it is a shell nobody trusts with a
// long command.
func TestADroppedOperatorIsNotAClose(t *testing.T) {
	w := wireReattachable(t, 64<<10, pump.Deadlines{})

	send(t, w.operator, frame.Data([]byte("before")))
	if got := recv(t, w.device); string(got.Payload) != "before" {
		t.Fatalf("device got %q", got.Payload)
	}

	// The operator's connection dies mid-session.
	_ = w.operator.Close(transport.CloseGoingAway, "wifi")

	// The device keeps working, and the session does not end.
	send(t, w.device, frame.Data([]byte("output while nobody was watching\r\n")))
	waitFor(t, func() bool { return w.detaches.Load() == 1 }, "the pump to notice the detach")

	select {
	case res := <-w.result:
		t.Fatalf("the session ended when the operator dropped: %+v", res)
	case <-time.After(200 * time.Millisecond):
	}

	// A new operator arrives and is caught up.
	next := w.reattachNow(t)
	snap := <-w.attaches
	if !strings.Contains(string(snap.Replay), "output while nobody was watching") {
		t.Errorf("the scrollback does not contain what the device said: %q", snap.Replay)
	}
	if got := readAll(t, next, "output while nobody was watching"); !strings.Contains(got, "output while nobody was watching") {
		t.Errorf("the replay never reached the new operator: %q", got)
	}

	// And the session is live again, in both directions.
	send(t, next, frame.Data([]byte("still here")))
	if got := recv(t, w.device); string(got.Payload) != "still here" {
		t.Errorf("device got %q after the reattach", got.Payload)
	}
	send(t, w.device, frame.Data([]byte("welcome back")))
	if got := readAll(t, next, "welcome back"); !strings.Contains(got, "welcome back") {
		t.Errorf("live output after the reattach: %q", got)
	}
}

// TestTheDeviceIsNotBlockedByAnAbsentOperator: the alternative to draining into the ring
// is backpressure all the way to a PTY, where a background job stalls because somebody's
// wifi dropped.
func TestTheDeviceIsNotBlockedByAnAbsentOperator(t *testing.T) {
	w := wireReattachable(t, 8<<10, pump.Deadlines{})
	_ = w.operator.Close(transport.CloseGoingAway, "wifi")
	waitFor(t, func() bool { return w.detaches.Load() == 1 }, "the detach")

	// Far more than the ring holds, which is the case that would deadlock if the pump
	// were waiting for somebody to read it.
	line := strings.Repeat("x", 1024)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 64 {
			send(t, w.device, frame.Data([]byte(line)))
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the device blocked writing to a detached session")
	}

	next := w.reattachNow(t)
	snap := <-w.attaches
	// Bounded: the operator gets the tail, not 64 KiB of history.
	if len(snap.Replay) > 8<<10 {
		t.Errorf("replayed %d bytes from an 8 KiB ring", len(snap.Replay))
	}
	if snap.Dropped == 0 {
		t.Error("nothing was reported dropped after overflowing the ring")
	}
	_ = next
}

// TestReplayPrecedesLiveOutput: a DATA frame produced a microsecond after the reattach
// must not overtake the scrollback, or the screen is assembled in the wrong order.
func TestReplayPrecedesLiveOutput(t *testing.T) {
	w := wireReattachable(t, 64<<10, pump.Deadlines{})
	send(t, w.device, frame.Data([]byte("FIRST-")))
	// Let it reach the ring before the operator goes away.
	waitFor(t, func() bool {
		return strings.Contains(readSome(t, w.operator), "FIRST-")
	}, "the first output")

	_ = w.operator.Close(transport.CloseGoingAway, "wifi")
	waitFor(t, func() bool { return w.detaches.Load() == 1 }, "the detach")

	next := w.reattachNow(t)
	<-w.attaches
	send(t, w.device, frame.Data([]byte("SECOND")))

	got := readAll(t, next, "SECOND")
	first := strings.Index(got, "FIRST-")
	second := strings.Index(got, "SECOND")
	if first < 0 || second < 0 {
		t.Fatalf("both should be present: %q", got)
	}
	if first > second {
		t.Errorf("live output overtook the replay: %q", got)
	}
}

// TestASecondOperatorIsRefused: two pumps writing into one shell would interleave their
// keystrokes. A read-only observer is a different feature (FR13).
func TestASecondOperatorIsRefused(t *testing.T) {
	w := wireReattachable(t, 64<<10, pump.Deadlines{})
	// The first operator is still attached.
	next := w.reattachNow(t)

	select {
	case snap := <-w.attaches:
		t.Fatalf("a second operator was attached: %+v", snap)
	case <-time.After(300 * time.Millisecond):
	}

	// The original is untouched.
	send(t, w.device, frame.Data([]byte("mine")))
	if got := readAll(t, w.operator, "mine"); !strings.Contains(got, "mine") {
		t.Errorf("the original operator stopped receiving: %q", got)
	}
	_ = next
}

// TestAnAbandonedSessionIsClosedByTheIdleTimer: a detached session receives no operator
// input, so `limits.idle` is what bounds it. That is deliberate — it means an abandoned
// session is closed by the same rule as an idle one, rather than by a second timer with
// its own edge cases.
func TestAnAbandonedSessionIsClosedByTheIdleTimer(t *testing.T) {
	w := wireReattachable(t, 64<<10, pump.Deadlines{Idle: 250 * time.Millisecond})
	_ = w.operator.Close(transport.CloseGoingAway, "wifi")
	waitFor(t, func() bool { return w.detaches.Load() == 1 }, "the detach")

	select {
	case res := <-w.result:
		if res.Reason != "idle_timeout" {
			t.Errorf("reason %q, want idle_timeout", res.Reason)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an abandoned session was never closed")
	}
}

// TestWithoutARingADroppedOperatorEndsTheSession is the SSH surface's behaviour: there
// is nothing to reattach to, because a second `ssh` invocation is a new session. A
// detached SSH session would be a shell nobody can reach, holding the device's only slot
// until the idle timer fired.
func TestWithoutARingADroppedOperatorEndsTheSession(t *testing.T) {
	w := wire(t, "shell", pump.Limits{Batch: 64 << 10, Window: 5 * time.Millisecond})
	_ = w.operator.Close(transport.CloseGoingAway, "gone")

	select {
	case res := <-w.result:
		if res.Reason != "operator_close" {
			t.Errorf("reason %q, want operator_close", res.Reason)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the session outlived its only operator with no way to reattach")
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────────

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// readAll accumulates DATA payloads until the wanted text appears, or it times out.
func readAll(t *testing.T, c transport.Conn, want string) string {
	t.Helper()
	var sb strings.Builder
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		msg, err := c.Recv(ctx)
		cancel()
		if err != nil {
			continue
		}
		f, err := frame.Codec{}.Decode(msg)
		if err != nil {
			continue
		}
		if f.Type == frame.TypeData {
			sb.Write(f.Payload)
		}
		if strings.Contains(sb.String(), want) {
			return sb.String()
		}
	}
	return sb.String()
}

// readSome drains whatever is waiting without failing if nothing is.
func readSome(t *testing.T, c transport.Conn) string {
	t.Helper()
	var sb strings.Builder
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		msg, err := c.Recv(ctx)
		cancel()
		if err != nil {
			return sb.String()
		}
		f, derr := frame.Codec{}.Decode(msg)
		if derr == nil && f.Type == frame.TypeData {
			sb.Write(f.Payload)
		}
	}
}
