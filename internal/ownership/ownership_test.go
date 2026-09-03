package ownership_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/ownership"
)

// clock is a hand-wound clock, so lease expiry is tested by arithmetic rather than by
// sleeping. A test that waits for a real TTL is a test that is slow when it passes and
// flaky when the machine is loaded.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

const (
	nodeA = "wss://gw-a.example.org"
	nodeB = "wss://gw-b.example.org"
	dev   = "treadmill-4821"
)

func TestLookupAnswersTheClaimingNode(t *testing.T) {
	t.Parallel()
	r := ownership.NewMemory(newClock().now)
	ctx := context.Background()

	if _, err := r.Lookup(ctx, dev); !errors.Is(err, ownership.ErrNotHeld) {
		t.Fatalf("an unheld device answered %v, want ErrNotHeld", err)
	}
	if _, err := r.Claim(ctx, dev, nodeA, time.Minute); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	l, err := r.Lookup(ctx, dev)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if l.Node != nodeA || l.DeviceID != dev {
		t.Fatalf("Lookup returned %+v, want %s held by %s", l, dev, nodeA)
	}
}

// A device that reconnects to another replica moves. The registry must follow the
// device rather than the record: the new node is the one holding a live channel, and a
// registry that refused the claim would make the device unreachable for a whole lease
// in exchange for nothing.
func TestClaimTakesOverFromAnotherNode(t *testing.T) {
	t.Parallel()
	r := ownership.NewMemory(newClock().now)
	ctx := context.Background()

	mustClaim(t, r, dev, nodeA)
	mustClaim(t, r, dev, nodeB)

	if l, _ := r.Lookup(ctx, dev); l.Node != nodeB {
		t.Fatalf("after B claimed, the device is held by %q, want %q", l.Node, nodeB)
	}
}

// The case owner-checking exists for, and it is ordinary rather than exotic: a device
// loses its radio, reconnects to B, and A's half-open socket only notices seconds
// later. A's release must not delete B's lease.
func TestADepartingNodeCannotReleaseItsSuccessorsLease(t *testing.T) {
	t.Parallel()
	r := ownership.NewMemory(newClock().now)
	ctx := context.Background()

	mustClaim(t, r, dev, nodeA)
	mustClaim(t, r, dev, nodeB)

	if err := r.Release(ctx, dev, nodeA); !errors.Is(err, ownership.ErrHeldByAnother) {
		t.Fatalf("A's release answered %v, want ErrHeldByAnother", err)
	}
	l, err := r.Lookup(ctx, dev)
	if err != nil {
		t.Fatalf("B's lease is gone after A released: %v", err)
	}
	if l.Node != nodeB {
		t.Fatalf("the device is held by %q, want %q", l.Node, nodeB)
	}
}

func TestRenewOnlyExtendsYourOwnLease(t *testing.T) {
	t.Parallel()
	c := newClock()
	r := ownership.NewMemory(c.now)
	ctx := context.Background()

	mustClaim(t, r, dev, nodeA)
	if _, err := r.Renew(ctx, dev, nodeB, time.Minute); !errors.Is(err, ownership.ErrHeldByAnother) {
		t.Fatalf("B renewed A's lease: %v", err)
	}

	// A's own renew moves the deadline, which is what keeps the device from lapsing.
	c.advance(30 * time.Second)
	if _, err := r.Renew(ctx, dev, nodeA, time.Minute); err != nil {
		t.Fatalf("A could not renew its own lease: %v", err)
	}
	c.advance(45 * time.Second)
	if _, err := r.Lookup(ctx, dev); err != nil {
		t.Fatalf("the lease lapsed despite a renew: %v", err)
	}
}

func TestALeaseExpires(t *testing.T) {
	t.Parallel()
	c := newClock()
	r := ownership.NewMemory(c.now)
	ctx := context.Background()

	if _, err := r.Claim(ctx, dev, nodeA, 30*time.Second); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	c.advance(31 * time.Second)

	if _, err := r.Lookup(ctx, dev); !errors.Is(err, ownership.ErrNotHeld) {
		t.Fatalf("an expired lease answered %v, want ErrNotHeld", err)
	}
	// And renewing it is refused rather than silently resurrecting it: by the clock,
	// another node was free to take the device, so "I still hold this" is not true.
	if _, err := r.Renew(ctx, dev, nodeA, time.Minute); !errors.Is(err, ownership.ErrNotHeld) {
		t.Fatalf("an expired lease was renewed: %v", err)
	}
}

// A restarted replica keeps the same node identity, so it reclaims its own devices as
// they reconnect instead of waiting out leases it set before it died.
func TestTheSameNodeReclaimsWithoutWaiting(t *testing.T) {
	t.Parallel()
	r := ownership.NewMemory(newClock().now)
	ctx := context.Background()

	mustClaim(t, r, dev, nodeA)
	if _, err := r.Claim(ctx, dev, nodeA, time.Minute); err != nil {
		t.Fatalf("a node could not reclaim its own device: %v", err)
	}
	if l, _ := r.Lookup(ctx, dev); l.Node != nodeA {
		t.Fatalf("held by %q after reclaim, want %q", l.Node, nodeA)
	}
}

func TestReleasingWhatIsNotHeldIsNotAnError(t *testing.T) {
	t.Parallel()
	r := ownership.NewMemory(newClock().now)
	if err := r.Release(context.Background(), dev, nodeA); err != nil {
		t.Fatalf("releasing an absent lease: %v", err)
	}
}

func TestMissingArgumentsAreRefused(t *testing.T) {
	t.Parallel()
	r := ownership.NewMemory(newClock().now)
	ctx := context.Background()
	if _, err := r.Claim(ctx, "", nodeA, time.Minute); err == nil {
		t.Fatal("claimed a device with no id")
	}
	if _, err := r.Claim(ctx, dev, "", time.Minute); err == nil {
		t.Fatal("claimed a device for no node")
	}
}

func mustClaim(t *testing.T, r ownership.Registry, deviceID, node string) {
	t.Helper()
	if _, err := r.Claim(context.Background(), deviceID, node, time.Minute); err != nil {
		t.Fatalf("%s claiming %s: %v", node, deviceID, err)
	}
}
