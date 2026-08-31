package authz_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/oarlock/oarlock/internal/authz"
	"github.com/oarlock/oarlock/pkg/plugin"
)

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// backend is a controllable Authorizer.
type backend struct {
	mu     sync.Mutex
	allow  bool
	reason string
	err    error
	calls  atomic.Int32
}

func (b *backend) Authorize(context.Context, *plugin.Principal, *plugin.Device,
	plugin.Action, plugin.Target) (plugin.Decision, error) {
	b.calls.Add(1)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return plugin.Decision{}, b.err
	}
	return plugin.Decision{Allow: b.allow, Reason: b.reason}, nil
}

func (b *backend) Watch(context.Context) (<-chan plugin.RevocationEvent, error) {
	return nil, plugin.ErrUnsupported
}

func (b *backend) set(allow bool, reason string, err error) {
	b.mu.Lock()
	b.allow, b.reason, b.err = allow, reason, err
	b.mu.Unlock()
}

var (
	phuc  = &plugin.Principal{ID: "phuc@example.com"}
	tread = &plugin.Device{ID: "treadmill-4821"}
)

func checker(b plugin.Authorizer, grace int) *authz.Checker {
	return &authz.Checker{Backend: b, Grace: authz.GraceOf(grace), Log: quiet()}
}

// defaultChecker leaves Grace unset, which is the only way to ask for the default —
// zero means strict fail-closed.
func defaultChecker(b plugin.Authorizer) *authz.Checker {
	return &authz.Checker{Backend: b, Log: quiet()}
}

// ── at open ─────────────────────────────────────────────────────────────────────

func TestAtOpenHasThreeOutcomes(t *testing.T) {
	b := &backend{allow: true}
	c := checker(b, 3)
	ctx := context.Background()

	got := c.AtOpen(ctx, phuc, tread, plugin.ActionShell, plugin.Target{})
	if !got.Allow() {
		t.Errorf("an allowed open was refused: %+v", got)
	}

	b.set(false, "not in the on-call group", nil)
	got = c.AtOpen(ctx, phuc, tread, plugin.ActionShell, plugin.Target{})
	if got.Outcome != authz.Denied {
		t.Errorf("outcome %v, want denied", got.Outcome)
	}
	if got.Code != "not_authorized" {
		t.Errorf("code %q, want not_authorized", got.Code)
	}
	if got.Reason != "not in the on-call group" {
		t.Errorf("the operator-facing reason was lost: %q", got.Reason)
	}

	b.set(false, "", errors.New("dial tcp: connection refused"))
	got = c.AtOpen(ctx, phuc, tread, plugin.ActionShell, plugin.Target{})
	if got.Outcome != authz.Unavailable {
		t.Errorf("outcome %v, want unavailable", got.Outcome)
	}
	// The distinction the whole package exists for: an outage is not a denial, and the
	// two are different screens that send somebody to different places.
	if got.Code != "authz_unavailable" {
		t.Errorf("code %q, want authz_unavailable", got.Code)
	}
	if got.Reason != "" {
		t.Errorf("an outage produced an operator-facing reason: %q — %q is not something "+
			"an operator can act on", got.Reason, got.Reason)
	}
}

// TestAnOutageRefusesNewSessionsFromTheFirstFailure.
//
// New sessions get no grace, deliberately: opening a session on a stale decision is a
// different risk from letting an operator finish a command on one.
func TestAnOutageRefusesNewSessionsFromTheFirstFailure(t *testing.T) {
	b := &backend{err: errors.New("down")}
	c := checker(b, 100) // a huge grace window, which must not apply here
	for i := range 3 {
		if got := c.AtOpen(context.Background(), phuc, tread, plugin.ActionShell, plugin.Target{}); got.Allow() {
			t.Fatalf("attempt %d: a new session was opened while authorization was down", i)
		}
	}
}

func TestNoBackendAllows(t *testing.T) {
	// A deployment with no Authorizer configured. Authentication still applies and
	// internal/safety refuses to boot production without one; a gateway that refused
	// every session until somebody wrote a rules file would be one nobody could evaluate.
	var c *authz.Checker
	if !c.AtOpen(context.Background(), phuc, tread, plugin.ActionShell, plugin.Target{}).Allow() {
		t.Error("a nil checker refused a session")
	}
	if !checker(nil, 3).AtOpen(context.Background(), phuc, tread, plugin.ActionShell, plugin.Target{}).Allow() {
		t.Error("a checker with no backend refused a session")
	}
}

// ── live sessions ───────────────────────────────────────────────────────────────

// TestADenialClosesAsRevoked: a human decided to withdraw access, and the close reason
// has to say so.
func TestADenialClosesAsRevoked(t *testing.T) {
	b := &backend{allow: true}
	s := checker(b, 3).Track(phuc, tread, plugin.ActionShell, plugin.Target{})
	if got := s.Recheck(context.Background()); !got.Allow() {
		t.Fatal("the first re-check refused")
	}

	b.set(false, "left the on-call rota", nil)
	got := s.Recheck(context.Background())
	if got.Outcome != authz.Denied {
		t.Fatalf("outcome %v, want denied", got.Outcome)
	}
	if got.Code != "revoked" {
		t.Errorf("code %q, want revoked", got.Code)
	}
	if got.Reason != "left the on-call rota" {
		t.Errorf("reason %q", got.Reason)
	}
}

// TestAnOutageIsSurvivedForExactlyTheGraceWindow is SC5 and NFR13: a dependency's bad
// minute must not be an outage.
func TestAnOutageIsSurvivedForExactlyTheGraceWindow(t *testing.T) {
	for _, grace := range []int{1, 3, 5} {
		b := &backend{allow: true}
		s := checker(b, grace).Track(phuc, tread, plugin.ActionShell, plugin.Target{})
		s.Recheck(context.Background()) // one good answer to be stale about

		b.set(false, "", errors.New("down"))
		for i := 1; i <= grace; i++ {
			got := s.Recheck(context.Background())
			if !got.Allow() {
				t.Fatalf("grace %d: closed on failure %d, inside the window", grace, i)
			}
			if got.Err == nil {
				t.Errorf("grace %d: failure %d reported no error for the logs", grace, i)
			}
		}
		// One past the window.
		got := s.Recheck(context.Background())
		if got.Allow() {
			t.Errorf("grace %d: survived %d failures", grace, grace+1)
		}
		if got.Code != "authz_unavailable" {
			t.Errorf("grace %d: code %q, want authz_unavailable — recording `revoked` for "+
				"an outage poisons every audit query built on top of it", grace, got.Code)
		}
	}
}

// TestRecoveryResetsTheWindow: a blip, then another blip a minute later, must not add up
// to a closure.
func TestRecoveryResetsTheWindow(t *testing.T) {
	b := &backend{allow: true}
	s := checker(b, 2).Track(phuc, tread, plugin.ActionShell, plugin.Target{})

	for range 3 {
		b.set(false, "", errors.New("down"))
		for range 2 {
			if got := s.Recheck(context.Background()); !got.Allow() {
				t.Fatal("closed inside the window")
			}
		}
		b.set(true, "", nil)
		if got := s.Recheck(context.Background()); !got.Allow() {
			t.Fatal("a recovered backend refused")
		}
		if s.Failures() != 0 {
			t.Errorf("after recovery the failure count is %d", s.Failures())
		}
	}
}

// TestADenialEndsTheOutage: a backend that can say no is a backend that is reachable, so a
// denial arriving mid-window closes as `revoked` rather than being counted as a failure.
func TestADenialEndsTheOutage(t *testing.T) {
	b := &backend{allow: true}
	s := checker(b, 3).Track(phuc, tread, plugin.ActionShell, plugin.Target{})
	s.Recheck(context.Background())

	b.set(false, "", errors.New("down"))
	s.Recheck(context.Background())
	if s.Failures() != 1 {
		t.Fatalf("failures %d", s.Failures())
	}

	b.set(false, "access withdrawn", nil)
	got := s.Recheck(context.Background())
	if got.Code != "revoked" {
		t.Errorf("code %q, want revoked", got.Code)
	}
	if s.Failures() != 0 {
		t.Errorf("a denial left the failure count at %d", s.Failures())
	}
}

// TestStrictFailClosed: the right setting where a session is more dangerous than an
// outage, and it has to actually be reachable.
// TestStrictFailClosed: `authz.grace: 0` restores strict fail-closed, which is what both
// ARCHITECTURE § 7.1 and the boot gate say it means.
//
// This was wrong when first written: the Checker treated 0 as "unset, use the default 3",
// so an operator who explicitly disabled the grace window got one anyway — silently, and
// in the direction that keeps sessions alive. Grace is a pointer now, so unset and zero
// are different things.
func TestStrictFailClosed(t *testing.T) {
	b := &backend{allow: true}
	s := checker(b, 0).Track(phuc, tread, plugin.ActionShell, plugin.Target{})
	s.Recheck(context.Background())

	b.set(false, "", errors.New("down"))
	got := s.Recheck(context.Background())
	if got.Allow() {
		t.Error("with grace disabled, the first failure did not close the session")
	}
	if got.Code != "authz_unavailable" {
		t.Errorf("code %q — even fail-closed, the reason must be true", got.Code)
	}
}

func TestGraceDefaultsToThree(t *testing.T) {
	b := &backend{allow: true}
	s := defaultChecker(b).Track(phuc, tread, plugin.ActionShell, plugin.Target{})
	s.Recheck(context.Background())
	b.set(false, "", errors.New("down"))
	for i := 1; i <= authz.DefaultGrace; i++ {
		if got := s.Recheck(context.Background()); !got.Allow() {
			t.Fatalf("closed on failure %d with the default grace", i)
		}
	}
	if s.Recheck(context.Background()).Allow() {
		t.Errorf("survived more than the default grace of %d", authz.DefaultGrace)
	}
}

// TestZeroSessionsClosedInASixtySecondOutage is E4.S4's acceptance criterion, run as fault
// injection over the number of re-checks a 60 s outage produces at the default interval.
func TestZeroSessionsClosedInASixtySecondOutage(t *testing.T) {
	// 60 s at the default 30 s interval is two re-checks. The default grace of three
	// survives it — which is the whole claim, and it is worth asserting as arithmetic
	// rather than trusting that the numbers happen to line up.
	const rechecksIn60s = 2
	if authz.DefaultGrace < rechecksIn60s {
		t.Fatalf("the default grace of %d does not survive a 60s outage (%d re-checks); "+
			"SC5 says a dependency's bad minute is not an outage",
			authz.DefaultGrace, rechecksIn60s)
	}

	b := &backend{allow: true}
	var live []*authz.Session
	c := defaultChecker(b)
	for range 50 {
		s := c.Track(phuc, tread, plugin.ActionShell, plugin.Target{})
		s.Recheck(context.Background())
		live = append(live, s)
	}

	b.set(false, "", errors.New("the permissions API is down"))
	closed := 0
	for range rechecksIn60s {
		for _, s := range live {
			if !s.Recheck(context.Background()).Allow() {
				closed++
			}
		}
	}
	if closed != 0 {
		t.Errorf("%d of %d sessions closed during a 60s outage", closed, len(live))
	}

	// And when it recovers, every one of them is still live and back to normal.
	b.set(true, "", nil)
	for i, s := range live {
		if got := s.Recheck(context.Background()); !got.Allow() {
			t.Fatalf("session %d did not recover: %+v", i, got)
		}
		if s.Failures() != 0 {
			t.Errorf("session %d still counts %d failures", i, s.Failures())
		}
	}
}

func TestConcurrentRechecksAreSafe(t *testing.T) {
	b := &backend{allow: true}
	c := checker(b, 3)
	var wg sync.WaitGroup
	for range 32 {
		s := c.Track(phuc, tread, plugin.ActionShell, plugin.Target{})
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10 {
				s.Recheck(context.Background())
			}
		}()
	}
	wg.Wait()
}

// TestZeroAndUnsetAreDifferent pins the distinction directly, because it is exactly the
// kind that gets flattened back into an int by somebody tidying up.
func TestZeroAndUnsetAreDifferent(t *testing.T) {
	fail := func(c *authz.Checker) bool {
		b := &backend{allow: true}
		c.Backend = b
		s := c.Track(phuc, tread, plugin.ActionShell, plugin.Target{})
		s.Recheck(context.Background())
		b.set(false, "", errors.New("down"))
		return !s.Recheck(context.Background()).Allow()
	}

	// Unset: the default window, so the first failure is survived.
	if fail(&authz.Checker{Log: quiet()}) {
		t.Error("with Grace unset, the first failure closed the session — unset must " +
			"mean the default window")
	}
	// Zero: strict fail-closed, so the first failure closes it.
	if !fail(&authz.Checker{Grace: authz.GraceOf(0), Log: quiet()}) {
		t.Error("with Grace explicitly 0, the first failure did not close the session — " +
			"an operator who disabled the window got one anyway")
	}
}
