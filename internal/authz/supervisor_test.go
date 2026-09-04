package authz_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/authz"
	"github.com/oarlock/oarlock/internal/backoff"
	"github.com/oarlock/oarlock/pkg/plugin"
)

// killer records what the supervisor closed.
type killer struct {
	mu      sync.Mutex
	killed  []string
	reasons map[string]string
	matched []string
}

func newKiller() *killer {
	return &killer{reasons: map[string]string{}}
}

func (k *killer) Kill(_ context.Context, id, reason string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.killed = append(k.killed, id)
	k.reasons[id] = reason
	return nil
}

func (k *killer) KillMatching(principal, device, reason string) int {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.matched = append(k.matched, principal+"/"+device+"/"+reason)
	return 1
}

func (k *killer) count() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.killed)
}

func (k *killer) reason(id string) string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.reasons[id]
}

func (k *killer) matches() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]string(nil), k.matched...)
}

// watchable is a backend whose stream a test can drop.
type watchable struct {
	backend
	mu        sync.Mutex
	streams   int
	current   chan plugin.RevocationEvent
	watchErr  error
	subscribe chan struct{} // signalled on each successful Watch
}

func newWatchable(allow bool) *watchable {
	w := &watchable{subscribe: make(chan struct{}, 16)}
	w.allow = allow
	return w
}

func (w *watchable) Watch(ctx context.Context) (<-chan plugin.RevocationEvent, error) {
	w.mu.Lock()
	if w.watchErr != nil {
		err := w.watchErr
		w.mu.Unlock()
		return nil, err
	}
	ch := make(chan plugin.RevocationEvent, 4)
	w.current = ch
	w.streams++
	w.mu.Unlock()

	select {
	case w.subscribe <- struct{}{}:
	default:
	}
	return ch, nil
}

func (w *watchable) send(ev plugin.RevocationEvent) {
	w.mu.Lock()
	ch := w.current
	w.mu.Unlock()
	if ch != nil {
		ch <- ev
	}
}

// dropStream closes the current stream, the way a proxy timing out an SSE connection
// does: no error, no event, just gone.
func (w *watchable) dropStream() {
	w.mu.Lock()
	ch := w.current
	w.current = nil
	w.mu.Unlock()
	if ch != nil {
		close(ch)
	}
}

func (w *watchable) streamCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.streams
}

// ── the re-check loop ───────────────────────────────────────────────────────────

// TestARevocationClosesTheSessionWithoutWatch is R-003's central case.
//
// The stream is killed *first*, and only then is the grant withdrawn. A test that goes
// through Watch instead would pass on a build where the interval loop is broken — which is
// exactly the build where revocation quietly stops working, and nobody finds out until
// somebody's access is withdrawn and their shell keeps going.
func TestARevocationClosesTheSessionWithoutWatch(t *testing.T) {
	b := newWatchable(true)
	b.mu.Lock()
	b.watchErr = errors.New("the stream is down") // no Watch at all
	b.mu.Unlock()

	k := newKiller()
	sup := &authz.Supervisor{
		Checker:  &authz.Checker{Backend: b, Log: quiet()},
		Live:     k,
		Interval: 20 * time.Millisecond,
		Log:      quiet(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		sup.Guard(ctx, "sess_1", phuc, tread, plugin.ActionShell, plugin.Target{})
	}()

	// The grant is withdrawn while the stream is dead.
	b.set(false, "left the on-call rota", nil)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the session was never closed — the re-check interval is the guarantee, " +
			"and it did not fire")
	}
	if k.count() != 1 {
		t.Fatalf("%d sessions closed, want 1", k.count())
	}
	// The reason has to be true: a human withdrew access.
	if got := k.reason("sess_1"); got != "revoked" {
		t.Errorf("close reason %q, want revoked", got)
	}
}

// TestAnOutagePastTheGraceWindowClosesAsUnavailable: the other outcome, through the loop.
func TestAnOutagePastTheGraceWindowClosesAsUnavailable(t *testing.T) {
	b := newWatchable(true)
	k := newKiller()
	sup := &authz.Supervisor{
		Checker: &authz.Checker{
			Backend: b, Grace: authz.GraceOf(2), Log: quiet(),
		},
		Live:     k,
		Interval: 10 * time.Millisecond,
		Log:      quiet(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		sup.Guard(ctx, "sess_1", phuc, tread, plugin.ActionShell, plugin.Target{})
	}()

	b.set(false, "", errors.New("the permissions API is down"))
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the session was never closed")
	}
	// Recording `revoked` for an outage poisons every audit query built on the close
	// reason, and tells an operator their access was withdrawn when it was not.
	if got := k.reason("sess_1"); got != "authz_unavailable" {
		t.Errorf("close reason %q, want authz_unavailable", got)
	}
}

func TestAHealthySessionIsNeverClosed(t *testing.T) {
	b := newWatchable(true)
	k := newKiller()
	sup := &authz.Supervisor{
		Checker:  &authz.Checker{Backend: b, Log: quiet()},
		Live:     k,
		Interval: 5 * time.Millisecond,
		Log:      quiet(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	sup.Guard(ctx, "sess_1", phuc, tread, plugin.ActionShell, plugin.Target{})

	if k.count() != 0 {
		t.Errorf("%d sessions closed while the grant held", k.count())
	}
	if b.calls.Load() < 5 {
		t.Errorf("only %d re-checks in 300ms at a 5ms interval — the loop is not running",
			b.calls.Load())
	}
}

// TestAGrantMayAskToBeRecheckedSoonerButNotLater.
func TestAGrantMayAskToBeRecheckedSoonerButNotLater(t *testing.T) {
	count := func(ttl time.Duration, interval time.Duration) int32 {
		b := &ttlBackend{ttl: ttl}
		sup := &authz.Supervisor{
			Checker:  &authz.Checker{Backend: b, Log: quiet()},
			Live:     newKiller(),
			Interval: interval,
			Log:      quiet(),
		}
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		sup.Guard(ctx, "sess_1", phuc, tread, plugin.ActionShell, plugin.Target{})
		return b.calls.Load()
	}

	// A short TTL shortens the interval.
	sooner := count(5*time.Millisecond, 50*time.Millisecond)
	baseline := count(0, 50*time.Millisecond)
	if sooner <= baseline {
		t.Errorf("a 5ms TTL produced %d re-checks against a baseline of %d at a 50ms "+
			"interval — the grant's request was ignored", sooner, baseline)
	}

	// A long TTL does not lengthen it: a backend that wanted a longer leash would be
	// choosing how stale its own revocations may be.
	later := count(10*time.Second, 20*time.Millisecond)
	if later < 3 {
		t.Errorf("a 10s TTL cut the re-checks to %d at a 20ms interval — a grant must "+
			"not be able to ask for less supervision", later)
	}
}

type ttlBackend struct {
	ttl   time.Duration
	calls atomic.Int32
}

func (b *ttlBackend) Authorize(context.Context, *plugin.Principal, *plugin.Device,
	plugin.Action, plugin.Target) (plugin.Decision, error) {
	b.calls.Add(1)
	return plugin.Decision{Allow: true, TTL: b.ttl}, nil
}

func (b *ttlBackend) Watch(context.Context) (<-chan plugin.RevocationEvent, error) {
	return nil, plugin.ErrUnsupported
}

func TestGuardStopsWhenTheSessionEnds(t *testing.T) {
	b := newWatchable(true)
	sup := &authz.Supervisor{
		Checker:  &authz.Checker{Backend: b, Log: quiet()},
		Live:     newKiller(),
		Interval: 5 * time.Millisecond,
		Log:      quiet(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		sup.Guard(ctx, "sess_1", phuc, tread, plugin.ActionShell, plugin.Target{})
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Guard outlived its session — one leaked goroutine per session")
	}
}

func TestGuardWithNoBackendReturnsImmediately(t *testing.T) {
	sup := &authz.Supervisor{Checker: &authz.Checker{Log: quiet()}, Live: newKiller()}
	done := make(chan struct{})
	go func() {
		defer close(done)
		sup.Guard(context.Background(), "sess_1", phuc, tread, plugin.ActionShell, plugin.Target{})
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Guard with no authorizer did not return")
	}
}

// ── Watch ───────────────────────────────────────────────────────────────────────

func TestWatchClosesMatchingSessions(t *testing.T) {
	b := newWatchable(true)
	k := newKiller()
	sup := &authz.Supervisor{
		Checker: &authz.Checker{Backend: b, Log: quiet()},
		Live:    k, Log: quiet(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sup.WatchRevocations(ctx)
	<-b.subscribe

	b.send(plugin.RevocationEvent{PrincipalID: "admin@mail.com", Reason: "left"})
	waitUntil(t, func() bool { return len(k.matches()) == 1 }, "the revocation to be applied")

	if got := k.matches()[0]; got != "admin@mail.com//revoked" {
		t.Errorf("matched %q", got)
	}
	if sup.WatchStatus() != authz.WatchConnected {
		t.Errorf("status %v", sup.WatchStatus())
	}
	if sup.Events() != 1 {
		t.Errorf("events %d", sup.Events())
	}
}

// TestAnEventWithNoNamesMeansEverything: what a backend sends when it has lost track of
// its own state and wants the gateway to stop trusting anything it said.
func TestAnEventWithNoNamesMeansEverything(t *testing.T) {
	b := newWatchable(true)
	k := newKiller()
	sup := &authz.Supervisor{
		Checker: &authz.Checker{Backend: b, Log: quiet()},
		Live:    k, Log: quiet(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sup.WatchRevocations(ctx)
	<-b.subscribe

	b.send(plugin.RevocationEvent{Reason: "resynchronising"})
	waitUntil(t, func() bool { return len(k.matches()) == 1 }, "the revocation")
	if got := k.matches()[0]; got != "//revoked" {
		t.Errorf("matched %q, want everything", got)
	}
}

// TestADroppedStreamIsNotARevocation is the failure that would turn a network blip into a
// fleet-wide kill — the three-outcome contract's failure arriving by a different door.
func TestADroppedStreamIsNotARevocation(t *testing.T) {
	b := newWatchable(true)
	k := newKiller()
	sup := &authz.Supervisor{
		Checker: &authz.Checker{Backend: b, Log: quiet()},
		Live:    k,
		Backoff: backoff.Policy{Base: time.Millisecond, Cap: 5 * time.Millisecond},
		Log:     quiet(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sup.WatchRevocations(ctx)
	<-b.subscribe

	b.dropStream()

	// It reconnects, and closes nothing on the way.
	waitUntil(t, func() bool { return b.streamCount() >= 2 }, "a reconnect")
	if n := len(k.matches()); n != 0 {
		t.Errorf("a dropped stream closed %d sessions: %v", n, k.matches())
	}
	if sup.WatchDrops() < 1 {
		t.Error("the drop was not counted — a stream that dies quietly is R-003")
	}
	waitUntil(t, func() bool { return sup.WatchStatus() == authz.WatchConnected },
		"the status to return to connected")

	// And the reconnected stream works.
	b.send(plugin.RevocationEvent{PrincipalID: "admin@mail.com"})
	waitUntil(t, func() bool { return len(k.matches()) == 1 }, "an event after reconnecting")
}

func TestAnUnsupportedWatchIsNotADegradedState(t *testing.T) {
	// Most backends. Saying so once beats a reconnect loop against a method that will
	// never work.
	b := &backend{allow: true}
	sup := &authz.Supervisor{
		Checker: &authz.Checker{Backend: b, Log: quiet()},
		Live:    newKiller(), Log: quiet(),
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		sup.WatchRevocations(context.Background())
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("WatchRevocations kept retrying a backend that does not support it")
	}
	if sup.WatchStatus() != authz.WatchUnsupported {
		t.Errorf("status %v, want unsupported", sup.WatchStatus())
	}
	if sup.WatchDrops() != 0 {
		t.Errorf("an unsupported Watch counted %d drops", sup.WatchDrops())
	}
}

func TestWatchRetriesASubscriptionThatFails(t *testing.T) {
	b := newWatchable(true)
	b.mu.Lock()
	b.watchErr = errors.New("503")
	b.mu.Unlock()

	sup := &authz.Supervisor{
		Checker: &authz.Checker{Backend: b, Log: quiet()},
		Live:    newKiller(),
		Backoff: backoff.Policy{Base: time.Millisecond, Cap: 3 * time.Millisecond},
		Log:     quiet(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sup.WatchRevocations(ctx)

	waitUntil(t, func() bool { return sup.WatchStatus() == authz.WatchDisconnected },
		"the status to show disconnected")

	// The service comes back.
	b.mu.Lock()
	b.watchErr = nil
	b.mu.Unlock()
	waitUntil(t, func() bool { return sup.WatchStatus() == authz.WatchConnected },
		"it to reconnect once the backend recovered")
}

func TestWatchStopsWithItsContext(t *testing.T) {
	b := newWatchable(true)
	sup := &authz.Supervisor{
		Checker: &authz.Checker{Backend: b, Log: quiet()},
		Live:    newKiller(), Log: quiet(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		sup.WatchRevocations(ctx)
	}()
	<-b.subscribe
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("WatchRevocations outlived its context")
	}
}

// ── both together ───────────────────────────────────────────────────────────────

// TestTheIntervalStillWorksWhileWatchIsBroken states the priority directly: Watch is the
// optimisation, the interval is the guarantee, and a build where that is reversed passes
// every happy-path test.
func TestTheIntervalStillWorksWhileWatchIsBroken(t *testing.T) {
	b := newWatchable(true)
	k := newKiller()
	sup := &authz.Supervisor{
		Checker:  &authz.Checker{Backend: b, Log: quiet()},
		Live:     k,
		Interval: 15 * time.Millisecond,
		Backoff:  backoff.Policy{Base: time.Millisecond, Cap: 2 * time.Millisecond},
		Log:      quiet(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sup.WatchRevocations(ctx)
	<-b.subscribe

	guard := make(chan struct{})
	go func() {
		defer close(guard)
		sup.Guard(ctx, "sess_1", phuc, tread, plugin.ActionShell, plugin.Target{})
	}()

	// The stream dies, and *stays* dead for the rest of the test.
	b.mu.Lock()
	b.watchErr = errors.New("down for the duration")
	b.mu.Unlock()
	b.dropStream()

	// Then the grant is withdrawn. Nothing will deliver an event; only the loop can
	// notice.
	b.set(false, "withdrawn", nil)

	select {
	case <-guard:
	case <-time.After(3 * time.Second):
		t.Fatal("with Watch down, the re-check interval did not close a revoked session")
	}
	if got := k.reason("sess_1"); got != "revoked" {
		t.Errorf("close reason %q", got)
	}
}

func waitUntil(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
