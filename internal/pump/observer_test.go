package pump_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/pump"
	"github.com/oarlock/oarlock/internal/ring"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/transport"
	"github.com/oarlock/oarlock/pkg/transport/memory"
)

type watchable struct {
	device   transport.Conn
	operator transport.Conn
	observe  chan pump.Observation
	result   chan pump.Result
	lists    chan []frame.Observer
}

func wireWatchable(t *testing.T) *watchable {
	t.Helper()
	devGW, devAgent := memory.Pair(0)
	opGW, opBrowser := memory.Pair(0)

	w := &watchable{
		device: devAgent, operator: opBrowser,
		observe: make(chan pump.Observation),
		result:  make(chan pump.Result, 1),
		lists:   make(chan []frame.Observer, 16),
	}
	s := &pump.Session{
		Device: devGW, Operator: opGW,
		SessionID: "sess_1", Profile: "shell",
		Limits:       pump.Limits{Batch: 64 << 10, Window: 5 * time.Millisecond},
		WriteTimeout: 2 * time.Second,
		Log:          quiet(),
		Ring:         ring.New(64 << 10),
		Observe:      w.observe,
		OnObservers:  func(l []frame.Observer) { w.lists <- l },
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		res, _ := s.Run(ctx)
		w.result <- res
	}()
	t.Cleanup(func() { _ = devAgent.Close(transport.CloseNormal, "test over") })
	return w
}

// readyOf waits for a tap's READY frame and returns it.
func (w *watchable) readyOf(t *testing.T, tp *tap) frame.Ready {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, ty := range tp.frameTypes() {
			if ty == frame.TypeReady {
				return tp.ready(t)
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no READY arrived")
	return frame.Ready{}
}

// watch attaches a read-only observer and returns their far end.
func (w *watchable) watch(t *testing.T, principal string) (transport.Conn, pump.ObserverHandle) {
	t.Helper()
	obGW, obClient := memory.Pair(0)
	done := make(chan pump.ObserveResult, 1)
	w.observe <- pump.Observation{
		Principal: principal,
		Conn:      obGW,
		Greet: func(list []frame.Observer) (frame.Frame, error) {
			return frame.Marshal(frame.TypeReady, frame.Ready{
				SessionID: "sess_1", ReadOnly: true, Watching: "phuc@example.com",
				Observers: list,
			})
		},
		Done: done,
	}
	res := <-done
	if res.Err != nil {
		t.Fatalf("could not observe: %v", res.Err)
	}
	t.Cleanup(func() { _ = obClient.Close(transport.CloseNormal, "test over") })
	return obClient, res.Handle
}

// TestAnObserverSeesTheOutput is the point of FR13.
func TestAnObserverSeesTheOutput(t *testing.T) {
	w := wireWatchable(t)
	opTap := newTap(t, w.operator)
	ob, _ := w.watch(t, "sam@example.com")
	obTap := newTap(t, ob)

	// The watcher's own READY says what they are: read-only, and who they are watching.
	ready := w.readyOf(t, obTap)
	if !ready.ReadOnly {
		t.Error("READY does not tell the observer they are read-only")
	}
	if ready.Watching != "phuc@example.com" {
		t.Errorf("watching %q", ready.Watching)
	}
	if len(ready.Observers) != 1 || ready.Observers[0].Principal != "sam@example.com" {
		t.Errorf("the observer is not in their own list: %+v", ready.Observers)
	}

	send(t, w.device, frame.Data([]byte("visible to both\r\n")))
	obTap.waitText(t, "visible to both")
	opTap.waitText(t, "visible to both")
}

// TestTheOperatorIsToldWhoIsWatching is FR13's other half, and the one that matters: you
// behave differently when observed, and you are entitled to know.
func TestTheOperatorIsToldWhoIsWatching(t *testing.T) {
	w := wireWatchable(t)
	opTap := newTap(t, w.operator)
	_, handle := w.watch(t, "sam@example.com")

	list := opTap.waitObservers(t, 0)
	if len(list) != 1 {
		t.Fatalf("the operator was told %d watchers, want 1", len(list))
	}
	// Named, always. A UI that could only say "1 watcher" would be a UI that had thrown
	// the answer away.
	if list[0].Principal != "sam@example.com" {
		t.Errorf("watcher %q", list[0].Principal)
	}
	if list[0].Since == "" {
		t.Error("no since — 'watched since before I ran that' has to be answerable")
	}

	// And told again when they leave, with an explicitly empty list: the indicator has
	// to be able to go away, and a session sitting at a prompt produces no output to
	// carry the news.
	handle.Leave()
	if empty := opTap.waitObservers(t, 1); len(empty) != 0 {
		t.Errorf("after leaving, the operator still sees %+v", empty)
	}
}

// TestAnObserverCannotType is the security property, and it is structural: the pump never
// reads an observer's connection, so there is no path from their socket to the device.
func TestAnObserverCannotType(t *testing.T) {
	w := wireWatchable(t)
	opTap := newTap(t, w.operator)
	devTap := newTap(t, w.device)
	ob, _ := w.watch(t, "sam@example.com")
	obTap := newTap(t, ob)
	w.readyOf(t, obTap)

	// Everything an observer could try. Sent with trySend, because at the pump level
	// nothing reads an observer's socket at all — the first message fills the transport
	// and the rest cannot even be delivered. That is the structural guarantee in its
	// rawest form, and the reason the assertion below is about the *device* rather than
	// about the gateway declining to forward.
	trySend(t, ob, frame.Data([]byte("rm -rf /\n")))
	trySend(t, ob, mustFrame(t, frame.TypeResize, frame.Resize{Cols: 1, Rows: 1}))
	trySend(t, ob, mustFrame(t, frame.TypeSignal, frame.Signal{Signal: "KILL"}))
	trySend(t, ob, mustFrame(t, frame.TypeClose, frame.Close{Reason: "operator_close"}))

	// The operator types something, and *that* arrives — which proves the device is
	// still being read from the right connection, so the assertion below is not merely
	// a race the test won.
	send(t, w.operator, frame.Data([]byte("mine\n")))
	devTap.waitText(t, "mine\n")

	if got := devTap.String(); strings.Contains(got, "rm -rf") {
		t.Fatalf("an observer's keystrokes reached the device: %q", got)
	}
	for _, ty := range devTap.frameTypes() {
		if ty == frame.TypeResize || ty == frame.TypeSignal {
			t.Errorf("the device received %v from an observer", ty)
		}
	}

	// And the observer's CLOSE did not end the session.
	select {
	case res := <-w.result:
		t.Fatalf("an observer closed the session: %+v", res)
	case <-time.After(200 * time.Millisecond):
	}
	send(t, w.device, frame.Data([]byte("still mine\r\n")))
	opTap.waitText(t, "still mine")
}

// TestAnObserverLeavingDoesNotDisturbTheSession: a watcher whose socket dies must not be
// able to interrupt the session they were watching.
func TestAnObserverLeavingDoesNotDisturbTheSession(t *testing.T) {
	w := wireWatchable(t)
	opTap := newTap(t, w.operator)
	ob, handle := w.watch(t, "sam@example.com")
	obTap := newTap(t, ob)
	w.readyOf(t, obTap)

	_ = ob.Close(transport.CloseGoingAway, "gone")
	// The port notices on its next write, so produce one.
	send(t, w.device, frame.Data([]byte("poke\r\n")))
	select {
	case <-handle.Gone():
	case <-time.After(5 * time.Second):
		t.Fatal("the observer was never released")
	}

	send(t, w.device, frame.Data([]byte("still working\r\n")))
	opTap.waitText(t, "still working")
}

func TestTheWatcherCeilingIsEnforced(t *testing.T) {
	w := wireWatchable(t)
	newTap(t, w.operator)
	for range pump.MaxObservers {
		conn, _ := w.watch(t, "watcher@example.com")
		newTap(t, conn)
	}
	// One more. Every observer is a socket the output path writes to, and a slow one
	// holds a write timeout's worth of the pump's attention.
	obGW, _ := memory.Pair(0)
	done := make(chan pump.ObserveResult, 1)
	w.observe <- pump.Observation{Principal: "one@too.many", Conn: obGW, Done: done}
	if res := <-done; res.Err == nil {
		t.Error("the ceiling was not enforced")
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────────

// trySend attempts a send and does not care whether it lands.
//
// For an observer's connection it usually will not: nothing reads it, so the transport
// fills. A test asserting on what the *device* received does not need the send to
// succeed — and demanding that it did would be demanding that somebody was reading.
func trySend(t *testing.T, c transport.Conn, f frame.Frame) {
	t.Helper()
	wire, err := frame.Codec{}.Encode(nil, f)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = c.Send(ctx, wire)
}

func mustFrame(t *testing.T, ty frame.Type, v any) frame.Frame {
	t.Helper()
	f, err := frame.Marshal(ty, v)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// tap drains a connection continuously, accumulating what arrived.
//
// Necessary rather than convenient: the memory transport holds exactly one message, so
// any connection a test is not actively reading stalls the pump's write to it. For the
// operator that now means a *detach* — a stalled write is treated as a dropped socket —
// so a test that read one end at a time would silently be measuring a reattach instead of
// a fan-out. That is what made the first version of these tests fail.
type tap struct {
	mu   sync.Mutex
	text strings.Builder
	// last is the most recent OBSERVERS list, and seen counts them, so a test can wait
	// for the *next* one rather than racing the one already delivered.
	last       []frame.Observer
	seen       int
	types      []frame.Type
	readyFrame frame.Ready
}

func newTap(t *testing.T, c transport.Conn) *tap {
	t.Helper()
	tp := &tap{}
	done := make(chan struct{})
	t.Cleanup(func() { <-done })
	go func() {
		defer close(done)
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			msg, err := c.Recv(ctx)
			cancel()
			if err != nil {
				return
			}
			f, derr := frame.Codec{}.Decode(msg)
			if derr != nil {
				continue
			}
			tp.mu.Lock()
			tp.types = append(tp.types, f.Type)
			switch f.Type {
			case frame.TypeData, frame.TypeDataErr:
				tp.text.Write(f.Payload)
			case frame.TypeReady:
				_ = frame.Unmarshal(f, &tp.readyFrame)
			case frame.TypeObservers:
				var list frame.Observers
				if frame.Unmarshal(f, &list) == nil {
					tp.last = list.Observers
					tp.seen++
				}
			}
			tp.mu.Unlock()
		}
	}()
	return tp
}

func (tp *tap) String() string {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	return tp.text.String()
}

func (tp *tap) observerCount() int {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	return tp.seen
}

func (tp *tap) observers() []frame.Observer {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	return tp.last
}

func (tp *tap) ready(t *testing.T) frame.Ready {
	t.Helper()
	tp.mu.Lock()
	defer tp.mu.Unlock()
	return tp.readyFrame
}

func (tp *tap) frameTypes() []frame.Type {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	return append([]frame.Type(nil), tp.types...)
}

// waitText blocks until the tap has seen the text, or fails.
func (tp *tap) waitText(t *testing.T, want string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := tp.String(); strings.Contains(got, want) {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Errorf("never saw %q; got %q", want, tp.String())
	return tp.String()
}

// waitObservers blocks until an OBSERVERS frame beyond `after` has arrived.
func (tp *tap) waitObservers(t *testing.T, after int) []frame.Observer {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if tp.observerCount() > after {
			return tp.observers()
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no OBSERVERS frame after %d arrived", after)
	return nil
}
