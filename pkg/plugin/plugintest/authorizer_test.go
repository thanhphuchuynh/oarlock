package plugintest

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oarlock/oarlock/pkg/plugin"
)

// The suite is the mitigation for this epic's top risk, which makes a suite that passes a
// wrong backend worthless. So these tests run it against backends that are wrong in each
// specific way, and assert that it says so.

var (
	alice = &plugin.Principal{ID: "alice@example.com"}
	bob   = &plugin.Principal{ID: "bob@example.com"}
	tread = &plugin.Device{ID: "treadmill-4821"}
)

// correct is a backend that honours the contract.
type correct struct {
	mu     sync.Mutex
	broken bool
	watch  bool
	events chan plugin.RevocationEvent
}

func (c *correct) Authorize(ctx context.Context, p *plugin.Principal, _ *plugin.Device,
	_ plugin.Action, tgt plugin.Target) (plugin.Decision, error) {
	if err := ctx.Err(); err != nil {
		return plugin.Decision{}, err
	}
	c.mu.Lock()
	broken := c.broken
	c.mu.Unlock()
	if broken {
		// The whole point: cannot decide is an error, not a denial.
		return plugin.Decision{}, errors.New("authz: backend unavailable")
	}
	if p.ID == alice.ID {
		return plugin.Decision{Allow: true}, nil
	}
	return plugin.Decision{Allow: false, Reason: "not in the on-call group"}, nil
}

func (c *correct) Watch(ctx context.Context) (<-chan plugin.RevocationEvent, error) {
	if !c.watch {
		return nil, plugin.ErrUnsupported
	}
	c.mu.Lock()
	if c.events == nil {
		c.events = make(chan plugin.RevocationEvent, 4)
	}
	ch := c.events
	c.mu.Unlock()

	out := make(chan plugin.RevocationEvent)
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-ch:
				select {
				case out <- ev:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out, nil
}

func (c *correct) breakIt() func() {
	c.mu.Lock()
	c.broken = true
	c.mu.Unlock()
	return func() {
		c.mu.Lock()
		c.broken = false
		c.mu.Unlock()
	}
}

func (c *correct) revoke(id string) {
	c.mu.Lock()
	if c.events == nil {
		c.events = make(chan plugin.RevocationEvent, 4)
	}
	ch := c.events
	c.mu.Unlock()
	ch <- plugin.RevocationEvent{PrincipalID: id, Reason: "left the group"}
}

func harnessFor(a plugin.Authorizer, breakIt func(*testing.T) func()) AuthorizerHarness {
	h := AuthorizerHarness{
		New: func(*testing.T) plugin.Authorizer { return a },
		Allowed: func() (*plugin.Principal, *plugin.Device, plugin.Action) {
			return alice, tread, plugin.ActionShell
		},
		Denied: func() (*plugin.Principal, *plugin.Device, plugin.Action) {
			return bob, tread, plugin.ActionShell
		},
	}
	if breakIt != nil {
		h.BreakDependency = breakIt
	}
	return h
}

// run executes the suite against a harness and returns what it reported.
func run(h AuthorizerHarness) *recorded {
	r := &recorded{name: "suite"}
	func() {
		defer func() {
			if p := recover(); p != nil {
				if _, ok := p.(fatalSentinel); !ok {
					panic(p)
				}
			}
		}()
		runAuthorizer(r, h)
	}()
	return r
}

func TestACorrectBackendPasses(t *testing.T) {
	c := &correct{}
	got := run(harnessFor(c, func(*testing.T) func() { return c.breakIt() }))
	if got.failed() {
		t.Errorf("a conforming backend failed the suite:\n%s", got.messages())
	}
}

func TestACorrectBackendWithWatchPasses(t *testing.T) {
	c := &correct{watch: true}
	h := harnessFor(c, func(*testing.T) func() { return c.breakIt() })
	h.SupportsWatch = true
	h.Revoke = func(_ *testing.T, p *plugin.Principal, _ *plugin.Device) { c.revoke(p.ID) }
	got := run(h)
	if got.failed() {
		t.Errorf("a conforming backend with Watch failed the suite:\n%s", got.messages())
	}
}

// ── the backends the suite has to reject ────────────────────────────────────────

// deniesOnError is R-001 itself: it answers "no" when it cannot reach its dependency.
type deniesOnError struct{ correct }

func (d *deniesOnError) Authorize(ctx context.Context, p *plugin.Principal,
	dev *plugin.Device, a plugin.Action, tgt plugin.Target) (plugin.Decision, error) {
	d.mu.Lock()
	broken := d.broken
	d.mu.Unlock()
	if broken {
		return plugin.Decision{Allow: false, Reason: "denied"}, nil
	}
	return d.correct.Authorize(ctx, p, dev, a, tgt)
}

func TestABackendThatDeniesOnErrorFails(t *testing.T) {
	d := &deniesOnError{}
	got := run(harnessFor(d, func(*testing.T) func() { return d.breakIt() }))
	if !got.failed() {
		t.Fatal("the suite passed a backend that reports an outage as a denial — " +
			"which is the one thing it exists to catch")
	}
	// And it says which case failed, and why, in terms the author can act on.
	msg := got.messages()
	if !strings.Contains(msg, "Allow:false") {
		t.Errorf("the failure does not name what the backend did:\n%s", msg)
	}
	if !strings.Contains(msg, "revoked") {
		t.Errorf("the failure does not say what it costs:\n%s", msg)
	}
	if !contains(got.failedCases(), "a broken dependency is an error, not a denial") {
		t.Errorf("the wrong case failed: %v", got.failedCases())
	}
}

// allowsOnError fails open, which is worse in the other direction.
type allowsOnError struct{ correct }

func (d *allowsOnError) Authorize(ctx context.Context, p *plugin.Principal,
	dev *plugin.Device, a plugin.Action, tgt plugin.Target) (plugin.Decision, error) {
	d.mu.Lock()
	broken := d.broken
	d.mu.Unlock()
	if broken {
		return plugin.Decision{Allow: true}, nil
	}
	return d.correct.Authorize(ctx, p, dev, a, tgt)
}

func TestABackendThatAllowsOnErrorFails(t *testing.T) {
	d := &allowsOnError{}
	got := run(harnessFor(d, func(*testing.T) func() { return d.breakIt() }))
	if !got.failed() {
		t.Fatal("the suite passed a backend that vouches for people while its own " +
			"source of truth is unreachable")
	}
	if !strings.Contains(got.messages(), "Allow:true") {
		t.Errorf("the failure does not name what it did:\n%s", got.messages())
	}
}

// erroringDenial returns an error alongside a real denial, so the gateway waits out a
// grace window instead of refusing.
type erroringDenial struct{ correct }

func (d *erroringDenial) Authorize(ctx context.Context, p *plugin.Principal,
	dev *plugin.Device, a plugin.Action, tgt plugin.Target) (plugin.Decision, error) {
	if p.ID != alice.ID {
		return plugin.Decision{}, errors.New("not allowed")
	}
	return d.correct.Authorize(ctx, p, dev, a, tgt)
}

func TestABackendThatErrorsInsteadOfDenyingFails(t *testing.T) {
	d := &erroringDenial{}
	got := run(harnessFor(d, func(*testing.T) func() { return d.breakIt() }))
	if !got.failed() {
		t.Fatal("the suite passed a backend that reports denials as errors")
	}
	if !contains(got.failedCases(), "denies what it should, without an error") {
		t.Errorf("the wrong case failed: %v", got.failedCases())
	}
}

// silentDenial denies with no reason, so the operator is told nothing actionable.
type silentDenial struct{ correct }

func (d *silentDenial) Authorize(_ context.Context, p *plugin.Principal, _ *plugin.Device,
	_ plugin.Action, tgt plugin.Target) (plugin.Decision, error) {
	if p.ID == alice.ID {
		return plugin.Decision{Allow: true}, nil
	}
	return plugin.Decision{Allow: false}, nil
}

func TestABackendThatDeniesWithoutAReasonFails(t *testing.T) {
	d := &silentDenial{}
	got := run(harnessFor(d, nil))
	if !got.failed() {
		t.Fatal("the suite passed a backend whose denials say nothing")
	}
}

// ignoresCancellation keeps working and returns a grant on a dead context.
type ignoresCancellation struct{ correct }

func (d *ignoresCancellation) Authorize(_ context.Context, _ *plugin.Principal,
	_ *plugin.Device, _ plugin.Action, tgt plugin.Target) (plugin.Decision, error) {
	return plugin.Decision{Allow: true}, nil
}

func TestABackendThatIgnoresCancellationFails(t *testing.T) {
	d := &ignoresCancellation{}
	h := harnessFor(d, nil)
	h.NoDependencyToBreak = true
	got := run(h)
	if !got.failed() {
		t.Fatal("the suite passed a backend that grants on a cancelled context")
	}
	if !contains(got.failedCases(), "cancellation is honoured") {
		t.Errorf("the wrong case failed: %v", got.failedCases())
	}
}

// inconsistent gives different answers to the same question under load.
//
// Deliberately *not* an unguarded field. A genuine data race is the race detector's
// business, and putting one in a fixture makes this package fail its own -race run rather
// than demonstrate anything. What the suite can catch on its own is the observable
// symptom: the same request answered two ways, which is what a shared cache with a broken
// lock looks like from outside.
//
// The two together are the point — the suite catches wrong answers, and running it under
// -race catches the reason.
type inconsistent struct {
	correct
	counter atomic.Int32
}

func (d *inconsistent) Authorize(ctx context.Context, p *plugin.Principal,
	dev *plugin.Device, a plugin.Action, tgt plugin.Target) (plugin.Decision, error) {
	if d.counter.Add(1)%3 == 0 {
		return plugin.Decision{Allow: p.ID != alice.ID, Reason: "cache says so"}, nil
	}
	return d.correct.Authorize(ctx, p, dev, a, tgt)
}

func TestABackendThatIsNotConcurrencySafeFails(t *testing.T) {
	d := &inconsistent{}
	h := harnessFor(d, nil)
	h.NoDependencyToBreak = true
	got := run(h)
	if !got.failed() {
		t.Fatal("the suite passed a backend whose answers change under concurrency")
	}
}

// nilWatch returns a nil channel and no error, which would hang the gateway's watcher.
type nilWatch struct{ correct }

func (d *nilWatch) Watch(context.Context) (<-chan plugin.RevocationEvent, error) {
	return nil, nil
}

func TestABackendWithAHangingWatchFails(t *testing.T) {
	d := &nilWatch{}
	h := harnessFor(d, nil)
	h.NoDependencyToBreak = true
	got := run(h)
	if !got.failed() {
		t.Fatal("the suite passed a Watch that returns a nil channel and no error — " +
			"the gateway would block on it forever, waiting for revocations that are " +
			"never coming")
	}
	if !contains(got.failedCases(), "Watch says what it is") {
		t.Errorf("the wrong case failed: %v", got.failedCases())
	}
}

// leakyWatch never closes its channel when the context is cancelled.
type leakyWatch struct{ correct }

func (d *leakyWatch) Watch(context.Context) (<-chan plugin.RevocationEvent, error) {
	return make(chan plugin.RevocationEvent), nil
}

func TestABackendWhoseWatchLeaksFails(t *testing.T) {
	d := &leakyWatch{}
	h := harnessFor(d, nil)
	h.NoDependencyToBreak = true
	h.SupportsWatch = true
	got := run(h)
	if !got.failed() {
		t.Fatal("the suite passed a Watch that ignores cancellation; the gateway leaks " +
			"a goroutine per reconnect")
	}
}

// ── the harness itself has to be complete ───────────────────────────────────────

func TestAnIncompleteHarnessFails(t *testing.T) {
	// The failure mode this guards: a suite whose most important case is omitted by
	// leaving a field nil, reporting success for a backend it never tested.
	c := &correct{}
	got := run(harnessFor(c, nil))
	if !got.failed() {
		t.Fatal("the suite passed with no BreakDependency, so its central case never ran")
	}
	if !strings.Contains(got.messages(), "NoDependencyToBreak") {
		t.Errorf("the failure does not say how to proceed:\n%s", got.messages())
	}
}

func TestTheOptOutStillChecksSomething(t *testing.T) {
	// NoDependencyToBreak is a claim, and the suite checks the part of it that is
	// checkable: a backend with no dependency should at least answer consistently.
	c := &correct{}
	h := harnessFor(c, nil)
	h.NoDependencyToBreak = true
	if got := run(h); got.failed() {
		t.Errorf("a genuinely dependency-free backend failed:\n%s", got.messages())
	}
}

func TestAMissingNewIsFatal(t *testing.T) {
	got := run(AuthorizerHarness{})
	if !got.failed() {
		t.Fatal("an empty harness passed")
	}
}

func TestAHarnessWithOnlyOneAnswerFails(t *testing.T) {
	// A suite that only ever sees "allowed" cannot tell an allow from a deny, and would
	// pass a backend that says yes to everything.
	got := run(AuthorizerHarness{
		New: func(*testing.T) plugin.Authorizer { return &correct{} },
		Allowed: func() (*plugin.Principal, *plugin.Device, plugin.Action) {
			return alice, tread, plugin.ActionShell
		},
	})
	if !got.failed() {
		t.Fatal("a harness with no Denied case passed")
	}
}

// ── a slow backend must not be mistaken for a broken one ────────────────────────

type slow struct {
	correct
	delay time.Duration
}

func (d *slow) Authorize(ctx context.Context, p *plugin.Principal, dev *plugin.Device,
	a plugin.Action, tgt plugin.Target) (plugin.Decision, error) {
	select {
	case <-time.After(d.delay):
	case <-ctx.Done():
		return plugin.Decision{}, ctx.Err()
	}
	return d.correct.Authorize(ctx, p, dev, a, tgt)
}

func TestASlowButCorrectBackendPasses(t *testing.T) {
	// The suite must not have a hidden latency budget: a backend that takes 20ms per
	// call is slow, not wrong, and failing it would push authors towards caching
	// decisions they should not cache.
	d := &slow{delay: 20 * time.Millisecond}
	h := harnessFor(d, func(*testing.T) func() { return d.breakIt() })
	if got := run(h); got.failed() {
		t.Errorf("a slow but correct backend failed:\n%s", got.messages())
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
