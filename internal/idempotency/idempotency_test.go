package idempotency_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/idempotency"
)

const (
	alice = "alice@example.com"
	bob   = "bob@example.com"
	key   = "3f0c1e8a"
	print = "sha256:treadmill-4821/shell"
)

func begin(t *testing.T, s idempotency.Store, principal, k, fp string) (idempotency.Record, bool) {
	t.Helper()
	rec, replay, err := s.Begin(context.Background(), principal, k, fp)
	if err != nil {
		t.Fatalf("Begin(%s): %v", principal, err)
	}
	return rec, replay
}

func TestAFirstRequestOwnsTheKeyAndARetryReplaysIt(t *testing.T) {
	t.Parallel()
	s := idempotency.NewMemory(0, nil)
	ctx := context.Background()

	if _, replay := begin(t, s, alice, key, print); replay {
		t.Fatal("the first request was treated as a replay")
	}
	if err := s.Complete(ctx, alice, key, "sess_1"); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	rec, replay := begin(t, s, alice, key, print)
	if !replay {
		t.Fatal("the retry was not recognised as a replay")
	}
	if rec.SessionID != "sess_1" {
		t.Fatalf("the replay named session %q, want sess_1", rec.SessionID)
	}
}

// Two concurrent attempts is the ordinary case, not the exotic one, and a
// check-then-act would let both through to open two sessions.
func TestASecondAttemptWhileTheFirstRunsIsRefused(t *testing.T) {
	t.Parallel()
	s := idempotency.NewMemory(0, nil)

	begin(t, s, alice, key, print)
	if _, _, err := s.Begin(context.Background(), alice, key, print); !errors.Is(err, idempotency.ErrInFlight) {
		t.Fatalf("a concurrent attempt answered %v, want ErrInFlight", err)
	}
}

// The property, under the concurrency it exists for: exactly one of many simultaneous
// attempts may do the work.
func TestExactlyOneOfManyConcurrentAttemptsWins(t *testing.T) {
	t.Parallel()
	s := idempotency.NewMemory(0, nil)

	const racers = 32
	var wg sync.WaitGroup
	var mu sync.Mutex
	owners, inflight := 0, 0

	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, replay, err := s.Begin(context.Background(), alice, key, print)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil && !replay:
				owners++
			case errors.Is(err, idempotency.ErrInFlight):
				inflight++
			default:
				t.Errorf("unexpected outcome: replay=%v err=%v", replay, err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if owners != 1 {
		t.Fatalf("%d attempts owned the key, want exactly 1", owners)
	}
	if inflight != racers-1 {
		t.Fatalf("%d attempts were told in-flight, want %d", inflight, racers-1)
	}
}

// Papering over this hands somebody a shell on the wrong device.
func TestTheSameKeyWithADifferentRequestIsRefused(t *testing.T) {
	t.Parallel()
	s := idempotency.NewMemory(0, nil)
	ctx := context.Background()

	begin(t, s, alice, key, print)
	if err := s.Complete(ctx, alice, key, "sess_1"); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	_, _, err := s.Begin(ctx, alice, key, "sha256:treadmill-9999/shell")
	if !errors.Is(err, idempotency.ErrFingerprintMismatch) {
		t.Fatalf("a reused key with a different body answered %v, want ErrFingerprintMismatch", err)
	}
}

// Two callers picking the same key is not a coincidence, it is a certainty: "1",
// "retry" and a hardcoded uuid all happen. Neither may see the other's session.
func TestKeysAreNamespacedByPrincipal(t *testing.T) {
	t.Parallel()
	s := idempotency.NewMemory(0, nil)
	ctx := context.Background()

	begin(t, s, alice, key, print)
	if err := s.Complete(ctx, alice, key, "sess_alice"); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	// Bob's identical key is unseen, not a replay of Alice's, and not in flight.
	rec, replay := begin(t, s, bob, key, print)
	if replay {
		t.Fatalf("Bob's request replayed Alice's session %q", rec.SessionID)
	}
	if err := s.Complete(ctx, bob, key, "sess_bob"); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	if rec, _ := begin(t, s, alice, key, print); rec.SessionID != "sess_alice" {
		t.Fatalf("Alice's key now names %q, want sess_alice", rec.SessionID)
	}
	if rec, _ := begin(t, s, bob, key, print); rec.SessionID != "sess_bob" {
		t.Fatalf("Bob's key names %q, want sess_bob", rec.SessionID)
	}
}

// A separator that could appear in a principal would let one caller's key collide with
// another's. NUL cannot, which is why it is the separator.
func TestAPrincipalCannotBeMadeToCollideWithAnothersKey(t *testing.T) {
	t.Parallel()
	s := idempotency.NewMemory(0, nil)
	ctx := context.Background()

	begin(t, s, alice, key, print)
	if err := s.Complete(ctx, alice, key, "sess_alice"); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	// The composition a naive separator gets wrong: a principal carrying the separator
	// itself. Refused outright, so the joined form cannot be forged into another
	// caller's.
	if _, _, err := s.Begin(ctx, alice+"\x00"+key, "x", print); err == nil {
		t.Fatal("a principal containing the separator was accepted")
	}
	if _, _, err := s.Begin(ctx, alice, key+"\x00x", print); err == nil {
		t.Fatal("a key containing the separator was accepted")
	}
}

// The common failure is a device that did not answer — precisely when a client should be
// able to retry with the same key.
func TestAFailedAttemptFreesItsKey(t *testing.T) {
	t.Parallel()
	s := idempotency.NewMemory(0, nil)
	ctx := context.Background()

	begin(t, s, alice, key, print)
	if err := s.Release(ctx, alice, key); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, replay := begin(t, s, alice, key, print); replay {
		t.Fatal("a released key replayed instead of running again")
	}
}

// Release is on the deferred path, so it runs after success too. It must not undo the
// record it just made.
func TestReleaseAfterCompleteDoesNotUndoIt(t *testing.T) {
	t.Parallel()
	s := idempotency.NewMemory(0, nil)
	ctx := context.Background()

	begin(t, s, alice, key, print)
	if err := s.Complete(ctx, alice, key, "sess_1"); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if err := s.Release(ctx, alice, key); err != nil {
		t.Fatalf("Release: %v", err)
	}

	rec, replay := begin(t, s, alice, key, print)
	if !replay || rec.SessionID != "sess_1" {
		t.Fatalf("the record was lost: replay=%v session=%q", replay, rec.SessionID)
	}
}

func TestARecordExpires(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 4, 9, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	s := idempotency.NewMemory(time.Hour, clock)
	ctx := context.Background()

	begin(t, s, alice, key, print)
	if err := s.Complete(ctx, alice, key, "sess_1"); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	now = now.Add(time.Hour + time.Second)

	if _, replay := begin(t, s, alice, key, print); replay {
		t.Fatal("an expired record still replayed")
	}
}

// A handler that dies without completing or releasing must not wedge the key forever.
func TestAnAbandonedAttemptDoesNotWedgeTheKey(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 4, 9, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	s := idempotency.NewMemory(time.Hour, clock)

	begin(t, s, alice, key, print) // and then nothing: the handler died here.
	now = now.Add(time.Hour + time.Second)

	if _, replay := begin(t, s, alice, key, print); replay {
		t.Fatal("an abandoned key replayed rather than running")
	}
}

func TestMissingArgumentsAreRefused(t *testing.T) {
	t.Parallel()
	s := idempotency.NewMemory(0, nil)
	ctx := context.Background()
	if _, _, err := s.Begin(ctx, "", key, print); err == nil {
		t.Error("Begin accepted an empty principal")
	}
	if _, _, err := s.Begin(ctx, alice, "", print); err == nil {
		t.Error("Begin accepted an empty key")
	}
}
