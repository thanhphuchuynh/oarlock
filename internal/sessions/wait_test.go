package sessions_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/sessions"
)

func waitFixture(t *testing.T) (*sessions.Memory, string) {
	t.Helper()
	m := sessions.NewMemory(sessions.Limits{PerDevice: 5, PerPrincipal: 5}, nil)
	row := &sessions.Session{
		ID: "sess_1", DeviceID: "treadmill-4821", Profile: "shell",
		Principal: "phuc@example.com", State: sessions.StateWaking,
	}
	if err := m.Create(context.Background(), row); err != nil {
		t.Fatal(err)
	}
	return m, row.ID
}

func TestWaitForStateReturnsWhenTheStateMoves(t *testing.T) {
	t.Parallel()
	m, id := waitFixture(t)

	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		done <- m.WaitForState(ctx, id, sessions.StateWaking)
	}()

	// The waiter is parked (or about to be); the write must wake it either way, which
	// is what taking the channel under the lock guarantees.
	if err := m.Update(context.Background(), id, func(s *sessions.Session) error {
		s.State = sessions.StateAttached
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("WaitForState: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a state change did not wake the waiter")
	}
}

// Finish is the transition a waiter most needs, because it is the last one: missing it
// means blocking to a deadline for a state machine that has stopped.
func TestFinishWakesAWaiter(t *testing.T) {
	t.Parallel()
	m, id := waitFixture(t)

	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		done <- m.WaitForState(ctx, id, sessions.StateWaking)
	}()

	if err := m.Finish(context.Background(), id,
		sessions.Result{CloseReason: "operator_close"}); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("WaitForState: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Finish did not wake the waiter")
	}
}

// A state the caller has already passed is not something to wait for.
func TestWaitForStateReturnsAtOnceWhenAlreadyDifferent(t *testing.T) {
	t.Parallel()
	m, id := waitFixture(t)
	if err := m.Update(context.Background(), id, func(s *sessions.Session) error {
		s.State = sessions.StateAttached
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.WaitForState(ctx, id, sessions.StateWaking); err != nil {
		t.Fatalf("WaitForState: %v", err)
	}
}

func TestWaitForStateHonoursItsContext(t *testing.T) {
	t.Parallel()
	m, id := waitFixture(t)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := m.WaitForState(ctx, id, sessions.StateWaking)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitForState answered %v, want DeadlineExceeded", err)
	}
}

func TestWaitForStateOnAnUnknownSession(t *testing.T) {
	t.Parallel()
	m, _ := waitFixture(t)
	err := m.WaitForState(context.Background(), "sess_nope", sessions.StateWaking)
	if !errors.Is(err, sessions.ErrNotFound) {
		t.Fatalf("WaitForState answered %v, want ErrNotFound", err)
	}
}

// A write to another session must not be mistaken for this one moving. The store wakes
// every waiter on any change — deliberately, because the bookkeeping to avoid it costs
// more than the string comparison it saves — so the re-check is what makes that safe.
func TestAnotherSessionsChangeDoesNotEndTheWait(t *testing.T) {
	t.Parallel()
	m, id := waitFixture(t)
	other := &sessions.Session{
		ID: "sess_2", DeviceID: "rower-9001", Profile: "shell",
		Principal: "phuc@example.com", State: sessions.StateWaking,
	}
	if err := m.Create(context.Background(), other); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		done <- m.WaitForState(ctx, id, sessions.StateWaking)
	}()

	if err := m.Update(context.Background(), other.ID, func(s *sessions.Session) error {
		s.State = sessions.StateAttached
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("another session's change ended the wait: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the waiter never returned")
	}
}
