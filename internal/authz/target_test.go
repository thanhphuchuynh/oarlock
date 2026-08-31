package authz_test

import (
	"context"
	"sync"
	"testing"

	"github.com/oarlock/oarlock/internal/authz"
	"github.com/oarlock/oarlock/pkg/plugin"
)

// recorder remembers every target it was asked about.
type recorder struct {
	mu      sync.Mutex
	targets []plugin.Target
	allow   bool
}

func (r *recorder) Authorize(_ context.Context, _ *plugin.Principal, _ *plugin.Device,
	_ plugin.Action, tgt plugin.Target) (plugin.Decision, error) {
	r.mu.Lock()
	r.targets = append(r.targets, tgt)
	r.mu.Unlock()
	return plugin.Decision{Allow: r.allow}, nil
}

func (r *recorder) Watch(context.Context) (<-chan plugin.RevocationEvent, error) {
	return nil, plugin.ErrUnsupported
}

func (r *recorder) seen() []plugin.Target {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]plugin.Target(nil), r.targets...)
}

// TestAtOpenPassesTheTargetThrough is the floor: a target handed to AtOpen must reach the
// backend. Without it every narrowing below is decoration.
func TestAtOpenPassesTheTargetThrough(t *testing.T) {
	r := &recorder{allow: true}
	c := checker(r, 3)

	want := plugin.Target{Port: 3000}
	if got := c.AtOpen(context.Background(), phuc, tread, plugin.ActionTCP, want); !got.Allow() {
		t.Fatalf("AtOpen refused: %+v", got)
	}
	seen := r.seen()
	if len(seen) != 1 || !seen[0].Equal(want) {
		t.Fatalf("backend saw %+v, want exactly one %+v", seen, want)
	}
}

// TestRecheckAsksAboutTheSameTarget is the property the whole feature rests on.
//
// A grant narrowed to port 3000 that is re-checked as "any port" is a grant that can never
// be revoked by narrowing it: the withdrawal would apply to a question nobody asks again.
// Worse, a backend answering the wider question may well allow, so the session would
// survive its own revocation — the exact failure supervision exists to prevent, reappearing
// through the new parameter.
func TestRecheckAsksAboutTheSameTarget(t *testing.T) {
	r := &recorder{allow: true}
	c := checker(r, 3)

	want := plugin.Target{Port: 3000}
	if got := c.AtOpen(context.Background(), phuc, tread, plugin.ActionTCP, want); !got.Allow() {
		t.Fatalf("AtOpen refused: %+v", got)
	}
	s := c.Track(phuc, tread, plugin.ActionTCP, want)
	for range 3 {
		if got := s.Recheck(context.Background()); !got.Allow() {
			t.Fatalf("Recheck refused: %+v", got)
		}
	}

	seen := r.seen()
	if len(seen) != 4 {
		t.Fatalf("backend was asked %d times, want 4 (one open, three re-checks)", len(seen))
	}
	for i, got := range seen {
		if !got.Equal(want) {
			t.Errorf("call %d asked about %+v, want %+v", i, got, want)
		}
	}
}

// TestZeroTargetSurvivesTheRoundTrip pins that an action naming no target arrives as one
// that names no target — not as a nil-ish value a backend has to guess about, and not
// silently replaced by a previous session's.
func TestZeroTargetSurvivesTheRoundTrip(t *testing.T) {
	r := &recorder{allow: true}
	c := checker(r, 3)

	if got := c.AtOpen(context.Background(), phuc, tread, plugin.ActionShell, plugin.Target{}); !got.Allow() {
		t.Fatalf("AtOpen refused: %+v", got)
	}
	seen := r.seen()
	if len(seen) != 1 {
		t.Fatalf("backend asked %d times, want 1", len(seen))
	}
	if !seen[0].IsZero() {
		t.Fatalf("shell arrived with target %+v, want a zero target", seen[0])
	}
}

// TestAdministratorShortCircuitStillReachesNoBackend guards the break-glass path: a
// config-declared administrator is allowed without asking, and adding a parameter must not
// have turned that into a backend call.
func TestAdministratorShortCircuitStillReachesNoBackend(t *testing.T) {
	r := &recorder{allow: false}
	c := &authz.Checker{Backend: r, Admins: []string{phuc.ID}, Log: quiet()}

	got := c.AtOpen(context.Background(), phuc, tread, plugin.ActionAdminPermissions, plugin.Target{})
	if !got.Allow() {
		t.Fatalf("the declared administrator was refused: %+v", got)
	}
	if n := len(r.seen()); n != 0 {
		t.Fatalf("the backend was asked %d times, want 0", n)
	}
}
