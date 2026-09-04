package sqlitestore_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/sessions"
	"github.com/oarlock/oarlock/internal/sessions/sqlitestore"
)

func open(t *testing.T, l sessions.Limits) *sqlitestore.Store {
	t.Helper()
	// A file rather than :memory:, so each test gets its own database and the
	// shared-cache in-memory mode cannot leak rows between them.
	s, err := sqlitestore.Open(filepath.Join(t.TempDir(), "sessions.db"), l, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Shutdown() })
	return s
}

func row(id, device, principal string) *sessions.Session {
	return &sessions.Session{ID: id, DeviceID: device, Principal: principal,
		Profile: "shell", Mode: "dispatch", State: sessions.StateAttached}
}

// TestSameContractAsMemory runs the parts of the interface both stores implement, so
// swapping SQLite in for the in-memory ledger cannot change behaviour quietly.
func TestSameContractAsMemory(t *testing.T) {
	ctx := context.Background()
	for name, s := range map[string]sessions.Store{
		"memory": sessions.NewMemory(sessions.Limits{PerDevice: 1, PerPrincipal: 2}, nil),
		"sqlite": open(t, sessions.Limits{PerDevice: 1, PerPrincipal: 2}),
	} {
		t.Run(name, func(t *testing.T) {
			if err := s.Create(ctx, row("s1", "dev-1", "admin@mail.com")); err != nil {
				t.Fatal(err)
			}
			got, err := s.Get(ctx, "s1")
			if err != nil {
				t.Fatal(err)
			}
			if got.Principal != "admin@mail.com" || got.Profile != "shell" {
				t.Errorf("row: %+v", got)
			}
			// Never blank: an unrecorded session must be queryable as a fact.
			if got.RecordingState != sessions.NotRecorded {
				t.Errorf("recording state %q", got.RecordingState)
			}
			if got.CreatedAt.IsZero() {
				t.Error("no creation timestamp")
			}

			// Duplicate id.
			if err := s.Create(ctx, row("s1", "dev-9", "x")); !errors.Is(err, sessions.ErrExists) {
				t.Errorf("duplicate: got %v, want ErrExists", err)
			}
			// Per-device cap.
			if err := s.Create(ctx, row("s2", "dev-1", "other")); !errors.Is(err, sessions.ErrLimit) {
				t.Errorf("per-device: got %v, want ErrLimit", err)
			}
			// Per-principal cap.
			if err := s.Create(ctx, row("s3", "dev-2", "admin@mail.com")); err != nil {
				t.Fatal(err)
			}
			if err := s.Create(ctx, row("s4", "dev-3", "admin@mail.com")); !errors.Is(err, sessions.ErrLimit) {
				t.Errorf("per-principal: got %v, want ErrLimit", err)
			}

			// Finish frees the device's slot.
			code := 7
			if err := s.Finish(ctx, "s1", sessions.Result{
				CloseReason: "device_close", ExitCode: &code, BytesOut: 4096}); err != nil {
				t.Fatal(err)
			}
			if err := s.Create(ctx, row("s5", "dev-1", "someone")); err != nil {
				t.Fatalf("the slot did not free: %v", err)
			}

			done, err := s.Get(ctx, "s1")
			if err != nil {
				t.Fatal(err)
			}
			if done.State != sessions.StateClosed || done.CloseReason != "device_close" {
				t.Errorf("finished row: %+v", done)
			}
			if done.ExitCode == nil || *done.ExitCode != 7 || done.BytesOut != 4096 {
				t.Errorf("result lost: %+v", done)
			}
			if done.ClosedAt.IsZero() {
				t.Error("no close timestamp")
			}
			if done.Live() {
				t.Error("a closed session reports as live")
			}
			// The first reason is the true one.
			if err := s.Finish(ctx, "s1", sessions.Result{CloseReason: "transport_error"}); err != nil {
				t.Fatal(err)
			}
			again, _ := s.Get(ctx, "s1")
			if again.CloseReason != "device_close" {
				t.Errorf("close reason was overwritten: %q", again.CloseReason)
			}

			if _, err := s.Get(ctx, "nope"); !errors.Is(err, sessions.ErrNotFound) {
				t.Errorf("missing row: got %v, want ErrNotFound", err)
			}
		})
	}
}

// TestConcurrentCreateHasExactlyOneWinner is what "atomic, not check-then-act" means
// for a real database. Two operators opening a shell on the same device in the same
// second is the race this exists to lose gracefully.
func TestConcurrentCreateHasExactlyOneWinner(t *testing.T) {
	ctx := context.Background()
	for round := range 25 {
		s := open(t, sessions.Limits{PerDevice: 1, PerPrincipal: 100})
		var wins, limited atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				err := s.Create(ctx, row(fmt.Sprintf("s%d", i), "dev-1", "a"))
				switch {
				case err == nil:
					wins.Add(1)
				case errors.Is(err, sessions.ErrLimit):
					limited.Add(1)
				default:
					t.Errorf("unexpected error: %v", err)
				}
			}()
		}
		close(start)
		wg.Wait()
		if got := wins.Load(); got != 1 {
			t.Fatalf("round %d: %d creates succeeded, want exactly 1", round, got)
		}
		// Everyone else was told why, rather than getting a corrupted state or a
		// driver error they cannot act on.
		if got := limited.Load(); got != 7 {
			t.Errorf("round %d: %d refusals, want 7", round, got)
		}
	}
}

// TestStaleLiveRowStillHoldsTheSlot: a caller that forgets to finish a row must not
// silently free the device.
//
// Note what this does *not* prove: the partial unique index cannot be triggered
// through the public API, because the transaction's count refuses first. That is what
// a backstop is for — it catches a bug in the counting logic, and a bug we have not
// written yet cannot be tested from outside.
func TestStaleLiveRowStillHoldsTheSlot(t *testing.T) {
	ctx := context.Background()
	s := open(t, sessions.Limits{PerDevice: 1, PerPrincipal: 100})
	if err := s.Create(ctx, row("s1", "dev-1", "a")); err != nil {
		t.Fatal(err)
	}
	// Reaching around the counting logic the way a bug would: mark the first row
	// closed *without* releasing its live slot, then try to insert another.
	if err := s.Update(ctx, "s1", func(r *sessions.Session) error {
		// State stays live, so live_device stays set; this simulates a caller that
		// forgot to finish a row.
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, row("s2", "dev-1", "b")); !errors.Is(err, sessions.ErrLimit) {
		t.Fatalf("got %v, want ErrLimit", err)
	}
}

func TestPersistsAcrossReopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.db")

	s1, err := sqlitestore.Open(path, sessions.Limits{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.Create(ctx, row("s1", "dev-1", "a")); err != nil {
		t.Fatal(err)
	}
	if err := s1.Finish(ctx, "s1", sessions.Result{CloseReason: "operator_close"}); err != nil {
		t.Fatal(err)
	}
	if err := s1.Shutdown(); err != nil {
		t.Fatal(err)
	}

	// The point of SQLite over the in-memory ledger: a restart does not lose the
	// account of what happened.
	s2, err := sqlitestore.Open(path, sessions.Limits{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Shutdown()
	got, err := s2.Get(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if got.CloseReason != "operator_close" || got.State != sessions.StateClosed {
		t.Errorf("row did not survive: %+v", got)
	}
}

func TestFinishLiveReleasesSlotsAfterRestart(t *testing.T) {
	ctx := context.Background()
	s := open(t, sessions.Limits{PerDevice: 1, PerPrincipal: 5})
	if err := s.Create(ctx, row("stale", "dev-1", "operator")); err != nil {
		t.Fatal(err)
	}

	n, err := s.FinishLive(ctx, "gateway_shutdown")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("finished %d live sessions, want 1", n)
	}
	got, err := s.Get(ctx, "stale")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != sessions.StateClosed || got.CloseReason != "gateway_shutdown" || got.ClosedAt.IsZero() {
		t.Fatalf("stale row was not finalised: %+v", got)
	}
	if err := s.Create(ctx, row("replacement", "dev-1", "operator")); err != nil {
		t.Fatalf("stale row still holds the device slot: %v", err)
	}
}

// TestEveryCloseReasonRoundTrips walks the closed set from ARCHITECTURE § 6. A reason
// that cannot be stored is a reason the UI can never show.
func TestEveryCloseReasonRoundTrips(t *testing.T) {
	ctx := context.Background()
	reasons := []string{
		"operator_close", "device_close", "idle_timeout", "max_duration",
		"admin_kill", "revoked", "authz_unavailable", "recorder_failed",
		"device_offline", "transport_error", "gateway_shutdown", "policy_denied",
		"policy_conflict",
	}
	s := open(t, sessions.Limits{PerDevice: 1, PerPrincipal: 100})
	for i, reason := range reasons {
		id := fmt.Sprintf("s%02d", i)
		dev := fmt.Sprintf("dev-%02d", i)
		if err := s.Create(ctx, row(id, dev, "a")); err != nil {
			t.Fatal(err)
		}
		if err := s.Finish(ctx, id, sessions.Result{CloseReason: reason}); err != nil {
			t.Fatal(err)
		}
		got, err := s.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if got.CloseReason != reason {
			t.Errorf("%q round-tripped as %q", reason, got.CloseReason)
		}
	}
	closed, _, err := s.List(ctx, sessions.Query{State: sessions.StateClosed})
	if err != nil {
		t.Fatal(err)
	}
	if len(closed) != len(reasons) {
		t.Errorf("%d closed rows, want %d", len(closed), len(reasons))
	}
}

func TestRecordingStateIsAlwaysWritten(t *testing.T) {
	ctx := context.Background()
	s := open(t, sessions.Limits{PerDevice: 1, PerPrincipal: 100})

	// Profiles that are never recorded must still say so in the row, so an
	// unrecorded session is a fact you can query for rather than one to notice.
	for i, profile := range []string{"file", "tcp", "sshpass"} {
		r := row(fmt.Sprintf("s%d", i), fmt.Sprintf("dev-%d", i), "a")
		r.Profile = profile
		r.RecordingState = sessions.NotRecorded
		if err := s.Create(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	rec := row("s9", "dev-9", "a")
	rec.RecordingState = sessions.Recorded
	if err := s.Create(ctx, rec); err != nil {
		t.Fatal(err)
	}

	unrecorded, _, err := s.List(ctx, sessions.Query{})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range unrecorded {
		if r.RecordingState == "" {
			t.Errorf("%s has a blank recording state", r.ID)
		}
		if r.RecordingState == sessions.NotRecorded {
			n++
		}
	}
	if n != 3 {
		t.Errorf("%d unrecorded rows, want 3", n)
	}
}

func TestListFiltersAndPaginates(t *testing.T) {
	ctx := context.Background()
	base := time.Now()
	n := 0
	s, err := sqlitestore.Open(filepath.Join(t.TempDir(), "s.db"),
		sessions.Limits{PerDevice: 10, PerPrincipal: 10},
		func() time.Time { n++; return base.Add(time.Duration(n) * time.Second) })
	if err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown()

	for i := range 6 {
		r := row(fmt.Sprintf("s%d", i), fmt.Sprintf("dev-%d", i%2), fmt.Sprintf("op-%d", i%3))
		if err := s.Create(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Finish(ctx, "s0", sessions.Result{CloseReason: "operator_close"}); err != nil {
		t.Fatal(err)
	}

	live, _, err := s.List(ctx, sessions.Query{Live: true})
	if err != nil || len(live) != 5 {
		t.Fatalf("live: %d rows, err=%v", len(live), err)
	}
	byDevice, _, _ := s.List(ctx, sessions.Query{DeviceID: "dev-0"})
	if len(byDevice) != 3 {
		t.Errorf("by device: %d", len(byDevice))
	}
	byOp, _, _ := s.List(ctx, sessions.Query{Principal: "op-1"})
	if len(byOp) != 2 {
		t.Errorf("by principal: %d", len(byOp))
	}

	page1, next, _ := s.List(ctx, sessions.Query{Limit: 2})
	if len(page1) != 2 || next == "" {
		t.Fatalf("page 1: %d rows, next=%q", len(page1), next)
	}
	page2, _, _ := s.List(ctx, sessions.Query{Limit: 2, After: next})
	if len(page2) == 0 || page2[0].ID == page1[0].ID {
		t.Errorf("page 2 overlaps page 1")
	}
}

func TestCreateValidates(t *testing.T) {
	ctx := context.Background()
	s := open(t, sessions.Limits{})
	for name, r := range map[string]*sessions.Session{
		"nil":       nil,
		"no id":     {DeviceID: "d"},
		"no device": {ID: "s"},
	} {
		if err := s.Create(ctx, r); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestUpdateUnknown(t *testing.T) {
	ctx := context.Background()
	s := open(t, sessions.Limits{})
	err := s.Update(ctx, "nope", func(*sessions.Session) error { return nil })
	if !errors.Is(err, sessions.ErrNotFound) {
		t.Errorf("got %v, want ErrNotFound", err)
	}
}

// TestPerDeviceCapAboveOne covers the configuration that used to be silently
// unenforced: liveness came from the column that only exists when the cap is one, so
// any other value meant no cap at all.
func TestPerDeviceCapAboveOne(t *testing.T) {
	ctx := context.Background()
	s := open(t, sessions.Limits{PerDevice: 2, PerPrincipal: 100})

	if err := s.Create(ctx, row("s1", "dev-1", "a")); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, row("s2", "dev-1", "b")); err != nil {
		t.Fatalf("the second session was refused with a cap of 2: %v", err)
	}
	if err := s.Create(ctx, row("s3", "dev-1", "c")); !errors.Is(err, sessions.ErrLimit) {
		t.Fatalf("the third session: got %v, want ErrLimit", err)
	}
	// And Live queries still work, because liveness is the state and not the guard.
	live, _, err := s.List(ctx, sessions.Query{Live: true, DeviceID: "dev-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 2 {
		t.Errorf("%d live rows, want 2", len(live))
	}
	if err := s.Finish(ctx, "s1", sessions.Result{CloseReason: "operator_close"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, row("s4", "dev-1", "d")); err != nil {
		t.Fatalf("the slot did not free: %v", err)
	}
}

// TestRejectedReleasesTheSlot: a session that never opened still gets a row, and it
// must not hold the device hostage.
func TestRejectedReleasesTheSlot(t *testing.T) {
	ctx := context.Background()
	s := open(t, sessions.Limits{PerDevice: 1, PerPrincipal: 100})
	if err := s.Create(ctx, row("s1", "dev-1", "a")); err != nil {
		t.Fatal(err)
	}
	if err := s.Update(ctx, "s1", func(r *sessions.Session) error {
		r.State = sessions.StateRejected
		r.CloseReason = "doorbell_failed"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, row("s2", "dev-1", "b")); err != nil {
		t.Fatalf("a rejected session still holds the slot: %v", err)
	}
}
