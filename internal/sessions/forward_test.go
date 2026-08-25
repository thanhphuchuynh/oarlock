package sessions_test

import (
	"context"
	"errors"
	"testing"

	"github.com/oarlock/oarlock/internal/sessions"
)

func forwardRow(id, device, principal string) *sessions.Session {
	return &sessions.Session{ID: id, DeviceID: device, Principal: principal,
		Profile: sessions.ProfileTCP, State: sessions.StateAttached}
}

// TestForwardDoesNotConsumeTheDeviceSlot: `ssh -L` must not lock out the shell somebody
// needs in order to fix whatever they are forwarding to.
func TestForwardDoesNotConsumeTheDeviceSlot(t *testing.T) {
	ctx := context.Background()
	m := sessions.NewMemory(sessions.Limits{PerDevice: 1, PerPrincipal: 5}, nil)

	if err := m.Create(ctx, forwardRow("f1", "dev", "phuc")); err != nil {
		t.Fatalf("first forward: %v", err)
	}
	if err := m.Create(ctx, row("s1", "dev", "phuc")); err != nil {
		t.Fatalf("a live forward blocked the shell: %v", err)
	}
	// And the other way round: a live shell must not block a forward either.
	if err := m.Create(ctx, forwardRow("f2", "dev", "phuc")); err != nil {
		t.Fatalf("a live shell blocked a forward: %v", err)
	}
}

// TestTheDeviceSlotStillHoldsForRealSessions: splitting the cap must not weaken the
// guarantee it was split out of.
func TestTheDeviceSlotStillHoldsForRealSessions(t *testing.T) {
	ctx := context.Background()
	m := sessions.NewMemory(sessions.Limits{PerDevice: 1, PerPrincipal: 5}, nil)

	if err := m.Create(ctx, row("s1", "dev", "phuc")); err != nil {
		t.Fatal(err)
	}
	err := m.Create(ctx, row("s2", "dev", "amir"))
	if !errors.Is(err, sessions.ErrLimit) {
		t.Fatalf("a second shell on one device: got %v, want ErrLimit", err)
	}
}

// TestForwardsHaveTheirOwnCap: unbounded is not the alternative to sharing a cap.
func TestForwardsHaveTheirOwnCap(t *testing.T) {
	ctx := context.Background()
	m := sessions.NewMemory(sessions.Limits{
		PerDevice: 1, PerPrincipal: 5, TCPConnsPerDevice: 2}, nil)

	if err := m.Create(ctx, forwardRow("f1", "dev", "phuc")); err != nil {
		t.Fatal(err)
	}
	if err := m.Create(ctx, forwardRow("f2", "dev", "phuc")); err != nil {
		t.Fatal(err)
	}
	err := m.Create(ctx, forwardRow("f3", "dev", "phuc"))
	if !errors.Is(err, sessions.ErrLimit) {
		t.Fatalf("a third forward past a cap of two: got %v, want ErrLimit", err)
	}
	// The per-device cap for forwards is per *device*: another device is unaffected.
	if err := m.Create(ctx, forwardRow("f4", "other", "phuc")); err != nil {
		t.Fatalf("a forward on a second device: %v", err)
	}
}

// TestForwardsDoNotConsumeThePrincipalCap: the per-principal cap is five, and one
// browser page load through a forward is six connections. Counting them there would make
// the feature fail on its most ordinary use.
func TestForwardsDoNotConsumeThePrincipalCap(t *testing.T) {
	ctx := context.Background()
	m := sessions.NewMemory(sessions.Limits{
		PerDevice: 1, PerPrincipal: 2, TCPConnsPerDevice: 16}, nil)

	for _, id := range []string{"f1", "f2", "f3", "f4", "f5", "f6"} {
		if err := m.Create(ctx, forwardRow(id, "dev", "phuc")); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
	}
	// The principal's real sessions are still capped at two.
	if err := m.Create(ctx, row("s1", "a", "phuc")); err != nil {
		t.Fatal(err)
	}
	if err := m.Create(ctx, row("s2", "b", "phuc")); err != nil {
		t.Fatal(err)
	}
	if err := m.Create(ctx, row("s3", "c", "phuc")); !errors.Is(err, sessions.ErrLimit) {
		t.Fatalf("a third session past a per-principal cap of two: got %v", err)
	}
}

// TestClosedForwardsFreeTheirSlot: a cap that only ever fills up is a cap that bricks
// the device — which is the failure mode the live_device column produced in production.
func TestClosedForwardsFreeTheirSlot(t *testing.T) {
	ctx := context.Background()
	m := sessions.NewMemory(sessions.Limits{
		PerDevice: 1, PerPrincipal: 5, TCPConnsPerDevice: 1}, nil)

	if err := m.Create(ctx, forwardRow("f1", "dev", "phuc")); err != nil {
		t.Fatal(err)
	}
	if err := m.Create(ctx, forwardRow("f2", "dev", "phuc")); !errors.Is(err, sessions.ErrLimit) {
		t.Fatalf("the cap did not hold: %v", err)
	}
	if err := m.Finish(ctx, "f1", sessions.Result{CloseReason: "operator_close"}); err != nil {
		t.Fatal(err)
	}
	if err := m.Create(ctx, forwardRow("f3", "dev", "phuc")); err != nil {
		t.Fatalf("a closed forward did not free its slot: %v", err)
	}
}
