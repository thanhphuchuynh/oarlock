package sqlitestore_test

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

func shellRow(id, device, principal string) *sessions.Session {
	return &sessions.Session{ID: id, DeviceID: device, Principal: principal,
		Profile: "shell", State: sessions.StateAttached}
}

// TestForwardDoesNotClaimTheUniqueIndex is the one that matters most here.
//
// With PerDevice == 1 the device's slot is a partial UNIQUE INDEX on live_device, not
// merely a count — so a `tcp` row that claimed it would be refused by the database
// itself, and the shell would be locked out at a level no counting change could reach.
func TestForwardDoesNotClaimTheUniqueIndex(t *testing.T) {
	ctx := context.Background()
	s := open(t, sessions.Limits{PerDevice: 1, PerPrincipal: 5})

	if err := s.Create(ctx, forwardRow("f1", "dev", "phuc")); err != nil {
		t.Fatalf("first forward: %v", err)
	}
	if err := s.Create(ctx, forwardRow("f2", "dev", "phuc")); err != nil {
		t.Fatalf("second forward on the same device: %v", err)
	}
	if err := s.Create(ctx, shellRow("s1", "dev", "phuc")); err != nil {
		t.Fatalf("two live forwards blocked the shell: %v", err)
	}
}

// TestUpdatingAForwardDoesNotClaimTheIndex: Update rewrites live_device on every call,
// so a forward that survives a state change must not pick the slot up on the way.
func TestUpdatingAForwardDoesNotClaimTheIndex(t *testing.T) {
	ctx := context.Background()
	s := open(t, sessions.Limits{PerDevice: 1, PerPrincipal: 5})

	if err := s.Create(ctx, forwardRow("f1", "dev", "phuc")); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, shellRow("s1", "dev", "phuc")); err != nil {
		t.Fatal(err)
	}
	// The shell holds the slot. Touching the forward must not take it away.
	if err := s.Update(ctx, "f1", func(row *sessions.Session) error {
		row.BytesIn = 4096
		return nil
	}); err != nil {
		t.Fatalf("updating a live forward: %v", err)
	}
	if err := s.Update(ctx, "s1", func(row *sessions.Session) error {
		row.BytesIn = 1
		return nil
	}); err != nil {
		t.Fatalf("the shell lost its own slot to a forward: %v", err)
	}
}

// TestTheDeviceSlotStillHoldsInSQLite: splitting the cap must not weaken the guarantee.
func TestTheDeviceSlotStillHoldsInSQLite(t *testing.T) {
	ctx := context.Background()
	s := open(t, sessions.Limits{PerDevice: 1, PerPrincipal: 5})

	if err := s.Create(ctx, shellRow("s1", "dev", "phuc")); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, shellRow("s2", "dev", "amir")); !errors.Is(err, sessions.ErrLimit) {
		t.Fatalf("a second shell on one device: got %v, want ErrLimit", err)
	}
}

// TestForwardsHaveTheirOwnCapInSQLite.
func TestForwardsHaveTheirOwnCapInSQLite(t *testing.T) {
	ctx := context.Background()
	s := open(t, sessions.Limits{PerDevice: 1, PerPrincipal: 5, TCPConnsPerDevice: 2})

	if err := s.Create(ctx, forwardRow("f1", "dev", "phuc")); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, forwardRow("f2", "dev", "phuc")); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, forwardRow("f3", "dev", "phuc")); !errors.Is(err, sessions.ErrLimit) {
		t.Fatalf("a third forward past a cap of two: got %v, want ErrLimit", err)
	}
}

// TestSQLAgreesWithHoldsDevice pins the two definitions together.
//
// The SQL predicate and sessions.HoldsDevice are written in different languages in
// different files, and a drift between them is silent: the count would disagree with the
// index, and one profile would be capped by neither.
//
// Run at PerDevice 2 as well as 1, and that is the whole point of the second case. At 1
// the partial unique index enforces the slot on its own, so a drifted count predicate is
// invisible — an earlier version of this test passed with the predicate deliberately
// broken. Above 1 the index is not populated at all (see the schema comment on
// live_device) and the count is the only enforcement there is.
func TestSQLAgreesWithHoldsDevice(t *testing.T) {
	ctx := context.Background()
	profiles := []string{"shell", "exec", "file", "tcp", "log", "sshpass"}

	for _, cap := range []int{1, 2} {
		for _, profile := range profiles {
			s := open(t, sessions.Limits{
				PerDevice: cap, PerPrincipal: 50, TCPConnsPerDevice: 50})

			// Fill the device to its cap, then ask for one more.
			var err error
			for i := 0; i <= cap; i++ {
				err = s.Create(ctx, &sessions.Session{
					ID: string(rune('a' + i)), DeviceID: "dev", Principal: "phuc",
					Profile: profile, State: sessions.StateAttached})
				if i < cap && err != nil {
					t.Fatalf("cap %d, profile %q: session %d: %v", cap, profile, i, err)
				}
			}

			blocked := errors.Is(err, sessions.ErrLimit)
			if want := sessions.HoldsDevice(profile); blocked != want {
				verb := "allowed"
				if blocked {
					verb = "refused"
				}
				t.Fatalf("cap %d, profile %q: the store %s the session past the cap, "+
					"HoldsDevice says it holds the device = %v (err: %v)",
					cap, profile, verb, want, err)
			}
		}
	}
}
