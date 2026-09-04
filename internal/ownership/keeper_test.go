package ownership_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/ownership"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// spy wraps a registry to count calls and announce renewals, so the loop is tested by
// waiting for an event rather than by asserting a rate against the wall clock.
type spy struct {
	ownership.Registry

	mu       sync.Mutex
	renews   int
	releases int
	claimErr error

	renewed chan struct{}
}

func newSpy(inner ownership.Registry) *spy {
	return &spy{Registry: inner, renewed: make(chan struct{}, 64)}
}

func (s *spy) Claim(ctx context.Context, deviceID, node string, ttl time.Duration) (ownership.Lease, error) {
	s.mu.Lock()
	err := s.claimErr
	s.mu.Unlock()
	if err != nil {
		return ownership.Lease{}, err
	}
	return s.Registry.Claim(ctx, deviceID, node, ttl)
}

func (s *spy) Renew(ctx context.Context, deviceID, node string, ttl time.Duration) (ownership.Lease, error) {
	l, err := s.Registry.Renew(ctx, deviceID, node, ttl)
	s.mu.Lock()
	s.renews++
	s.mu.Unlock()
	select {
	case s.renewed <- struct{}{}:
	default:
	}
	return l, err
}

func (s *spy) Release(ctx context.Context, deviceID, node string) error {
	s.mu.Lock()
	s.releases++
	s.mu.Unlock()
	return s.Registry.Release(ctx, deviceID, node)
}

func (s *spy) counts() (renews, releases int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.renews, s.releases
}

func keeper(r ownership.Registry, node string) *ownership.Keeper {
	return &ownership.Keeper{
		Registry: r, Node: node,
		// Short enough that the loop runs during a test, and every assertion waits for
		// an event rather than for this to elapse a fixed number of times.
		RenewInterval: 2 * time.Millisecond,
		TTL:           time.Minute,
		Log:           quiet(),
	}
}

func TestHoldRecordsTheNodeAndReleaseGivesItBack(t *testing.T) {
	t.Parallel()
	r := ownership.NewMemory(nil)
	k := keeper(r, nodeA)
	ctx := context.Background()

	release, err := k.Hold(ctx, dev)
	if err != nil {
		t.Fatalf("Hold: %v", err)
	}
	l, err := r.Lookup(ctx, dev)
	if err != nil {
		t.Fatalf("the device is not recorded while held: %v", err)
	}
	if l.Node != nodeA {
		t.Fatalf("recorded as held by %q, want %q", l.Node, nodeA)
	}

	release()
	if _, err := r.Lookup(ctx, dev); !errors.Is(err, ownership.ErrNotHeld) {
		t.Fatalf("the lease survived release: %v", err)
	}
}

func TestReleaseIsIdempotent(t *testing.T) {
	t.Parallel()
	s := newSpy(ownership.NewMemory(nil))
	k := keeper(s, nodeA)

	release, err := k.Hold(context.Background(), dev)
	if err != nil {
		t.Fatalf("Hold: %v", err)
	}
	release()
	release()
	release()

	if _, releases := s.counts(); releases != 1 {
		t.Fatalf("three calls to release reached the registry %d times, want 1", releases)
	}
}

// The lease has to outlive the renew interval, or a long-lived control channel goes
// unroutable while the device is sitting right there.
func TestTheLeaseIsRenewedWhileTheChannelIsUp(t *testing.T) {
	t.Parallel()
	s := newSpy(ownership.NewMemory(nil))
	k := keeper(s, nodeA)

	release, err := k.Hold(context.Background(), dev)
	if err != nil {
		t.Fatalf("Hold: %v", err)
	}
	defer release()

	for i := 0; i < 3; i++ {
		select {
		case <-s.renewed:
		case <-time.After(5 * time.Second):
			renews, _ := s.counts()
			t.Fatalf("waiting for renew %d: only %d happened", i+1, renews)
		}
	}
}

// The keeper's half of the half-open case: A is still serving a dead socket when B
// takes the device. A's release must leave B's lease alone.
func TestReleaseAfterATakeoverLeavesTheNewOwnerAlone(t *testing.T) {
	t.Parallel()
	r := ownership.NewMemory(nil)
	ctx := context.Background()

	a := keeper(r, nodeA)
	releaseA, err := a.Hold(ctx, dev)
	if err != nil {
		t.Fatalf("A's Hold: %v", err)
	}

	b := keeper(r, nodeB)
	releaseB, err := b.Hold(ctx, dev)
	if err != nil {
		t.Fatalf("B's Hold: %v", err)
	}
	defer releaseB()

	releaseA()

	l, err := r.Lookup(ctx, dev)
	if err != nil {
		t.Fatalf("B's lease is gone after A's channel ended: %v", err)
	}
	if l.Node != nodeB {
		t.Fatalf("held by %q after A released, want %q", l.Node, nodeB)
	}
}

// A registry that cannot record must not cost the device its channel: Hold reports the
// failure and still returns a release the caller can defer unconditionally.
func TestAFailedClaimStillReturnsAUsableRelease(t *testing.T) {
	t.Parallel()
	s := newSpy(ownership.NewMemory(nil))
	s.claimErr = errors.New("registry is down")

	release, err := keeper(s, nodeA).Hold(context.Background(), dev)
	if err == nil {
		t.Fatal("Hold hid a claim failure")
	}
	if release == nil {
		t.Fatal("Hold returned a nil release, which a deferred call would panic on")
	}
	release()
}

// A gateway with no registry configured is the single-node deployment, and it must not
// need a branch at the call site.
func TestANilKeeperIsAWorkingSingleNodeGateway(t *testing.T) {
	t.Parallel()
	var k *ownership.Keeper
	release, err := k.Hold(context.Background(), dev)
	if err != nil {
		t.Fatalf("a nil keeper refused: %v", err)
	}
	release()
	if got := k.Elsewhere(context.Background(), dev); got != "" {
		t.Fatalf("a nil keeper named %q as another node", got)
	}
	if k.Enabled() {
		t.Fatal("a nil keeper reports itself enabled")
	}
}

func TestElsewhereNamesAnotherNodeAndNeverThisOne(t *testing.T) {
	t.Parallel()
	r := ownership.NewMemory(nil)
	ctx := context.Background()

	a := keeper(r, nodeA)
	release, err := a.Hold(ctx, dev)
	if err != nil {
		t.Fatalf("Hold: %v", err)
	}

	// Held here: there is no elsewhere, and saying so would send an operator to a node
	// that is already the one they are talking to.
	if got := a.Elsewhere(ctx, dev); got != "" {
		t.Fatalf("Elsewhere named %q for a device this node holds", got)
	}

	// Held by B: A can now say where it went instead of claiming it is not connected.
	release()
	b := keeper(r, nodeB)
	releaseB, err := b.Hold(ctx, dev)
	if err != nil {
		t.Fatalf("B's Hold: %v", err)
	}
	defer releaseB()

	if got := a.Elsewhere(ctx, dev); got != nodeB {
		t.Fatalf("Elsewhere answered %q, want %q", got, nodeB)
	}
}

// A registry that is down must not turn into a different answer for the operator: an
// unanswerable lookup and an unheld device both mean "not somewhere else that I know
// of", and the caller's next move is identical.
func TestAFailedLookupIsNotAnAnswer(t *testing.T) {
	t.Parallel()
	k := keeper(&brokenLookup{ownership.NewMemory(nil)}, nodeA)
	if got := k.Elsewhere(context.Background(), dev); got != "" {
		t.Fatalf("a broken registry named %q as another node", got)
	}
}

type brokenLookup struct{ ownership.Registry }

func (b *brokenLookup) Lookup(context.Context, string) (ownership.Lease, error) {
	return ownership.Lease{}, errors.New("registry is down")
}
