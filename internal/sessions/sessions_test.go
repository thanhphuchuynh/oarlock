package sessions_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/sessions"
)

func row(id, device, principal string) *sessions.Session {
	return &sessions.Session{ID: id, DeviceID: device, Principal: principal,
		Profile: "shell", State: sessions.StateAttached}
}

func TestCreateAndGet(t *testing.T) {
	ctx := context.Background()
	s := sessions.NewMemory(sessions.Limits{}, nil)
	if err := s.Create(ctx, row("s1", "dev-1", "admin@mail.com")); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Principal != "admin@mail.com" || got.DeviceID != "dev-1" {
		t.Errorf("row: %+v", got)
	}
	// An unrecorded session must be a fact you can query for, not a blank field
	// somebody has to interpret.
	if got.RecordingState != sessions.NotRecorded {
		t.Errorf("recording state %q, want not_recorded", got.RecordingState)
	}
	if got.CreatedAt.IsZero() {
		t.Error("no creation timestamp")
	}
	if _, err := s.Get(ctx, "nope"); !errors.Is(err, sessions.ErrNotFound) {
		t.Errorf("got %v, want ErrNotFound", err)
	}
}

func TestGetReturnsACopy(t *testing.T) {
	ctx := context.Background()
	s := sessions.NewMemory(sessions.Limits{}, nil)
	_ = s.Create(ctx, row("s1", "dev-1", "a"))
	got, _ := s.Get(ctx, "s1")
	got.Principal = "tampered"
	again, _ := s.Get(ctx, "s1")
	if again.Principal != "a" {
		t.Error("Get handed out a mutable reference to the ledger")
	}
}

func TestDuplicateIDIsRefused(t *testing.T) {
	ctx := context.Background()
	s := sessions.NewMemory(sessions.Limits{}, nil)
	_ = s.Create(ctx, row("s1", "dev-1", "a"))
	if err := s.Create(ctx, row("s1", "dev-2", "b")); !errors.Is(err, sessions.ErrExists) {
		t.Fatalf("got %v, want ErrExists", err)
	}
}

// TestPerDeviceLimit: two shells on one device is almost always a mistake, and the
// default of one is enforced rather than hoped for.
func TestPerDeviceLimit(t *testing.T) {
	ctx := context.Background()
	s := sessions.NewMemory(sessions.Limits{PerDevice: 1, PerPrincipal: 10}, nil)
	if err := s.Create(ctx, row("s1", "dev-1", "a")); err != nil {
		t.Fatal(err)
	}
	err := s.Create(ctx, row("s2", "dev-1", "b"))
	if !errors.Is(err, sessions.ErrLimit) {
		t.Fatalf("got %v, want ErrLimit", err)
	}
	// A different device is unaffected.
	if err := s.Create(ctx, row("s3", "dev-2", "b")); err != nil {
		t.Fatal(err)
	}
	// And once the first closes, the slot frees.
	if err := s.Finish(ctx, "s1", sessions.Result{CloseReason: "operator_close"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, row("s4", "dev-1", "c")); err != nil {
		t.Fatalf("the slot did not free after a close: %v", err)
	}
}

func TestPerPrincipalLimit(t *testing.T) {
	ctx := context.Background()
	s := sessions.NewMemory(sessions.Limits{PerDevice: 10, PerPrincipal: 2}, nil)
	for i := range 2 {
		if err := s.Create(ctx, row(fmt.Sprintf("s%d", i), fmt.Sprintf("dev-%d", i), "a")); err != nil {
			t.Fatal(err)
		}
	}
	// Bounds one compromised account.
	if err := s.Create(ctx, row("s9", "dev-9", "a")); !errors.Is(err, sessions.ErrLimit) {
		t.Fatalf("got %v, want ErrLimit", err)
	}
	if err := s.Create(ctx, row("s10", "dev-10", "b")); err != nil {
		t.Fatalf("a different principal was refused: %v", err)
	}
}

// TestConcurrentCreateHasExactlyOneWinner is what "atomic, not check-then-act"
// means under -race: two operators opening a shell on the same device in the same
// second is exactly the race this exists to lose gracefully.
func TestConcurrentCreateHasExactlyOneWinner(t *testing.T) {
	ctx := context.Background()
	for round := range 100 {
		s := sessions.NewMemory(sessions.Limits{PerDevice: 1, PerPrincipal: 100}, nil)
		var wins atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if err := s.Create(ctx, row(fmt.Sprintf("s%d", i), "dev-1", "a")); err == nil {
					wins.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()
		if got := wins.Load(); got != 1 {
			t.Fatalf("round %d: %d creates succeeded, want exactly 1", round, got)
		}
	}
}

// TestCloseReasonIsWrittenOnce: the first reason is the true one, and whatever
// noticed second is a consequence of it.
func TestCloseReasonIsWrittenOnce(t *testing.T) {
	ctx := context.Background()
	s := sessions.NewMemory(sessions.Limits{}, nil)
	_ = s.Create(ctx, row("s1", "dev-1", "a"))

	code := 7
	if err := s.Finish(ctx, "s1", sessions.Result{
		CloseReason: "device_close", ExitCode: &code, BytesOut: 4096}); err != nil {
		t.Fatal(err)
	}
	// A second close — the transport noticing the socket died, say — must not
	// overwrite it.
	if err := s.Finish(ctx, "s1", sessions.Result{CloseReason: "transport_error"}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(ctx, "s1")
	if got.CloseReason != "device_close" {
		t.Errorf("close reason %q, want device_close", got.CloseReason)
	}
	if got.ExitCode == nil || *got.ExitCode != 7 || got.BytesOut != 4096 {
		t.Errorf("result lost: %+v", got)
	}
	if got.ClosedAt.IsZero() {
		t.Error("no close timestamp")
	}
	if got.Live() {
		t.Error("a closed session still reports as live")
	}
}

func TestRejectedIsNotLive(t *testing.T) {
	// A session that never opened still gets a row, so "why did nobody get a shell
	// on that treadmill" has an answer that does not require the logs to survive.
	ctx := context.Background()
	s := sessions.NewMemory(sessions.Limits{PerDevice: 1}, nil)
	_ = s.Create(ctx, row("s1", "dev-1", "a"))
	_ = s.Update(ctx, "s1", func(r *sessions.Session) error {
		r.State = sessions.StateRejected
		r.CloseReason = "doorbell_failed"
		return nil
	})
	got, _ := s.Get(ctx, "s1")
	if got.Live() {
		t.Error("a rejected session reports as live and would hold the device's slot")
	}
	if err := s.Create(ctx, row("s2", "dev-1", "b")); err != nil {
		t.Fatalf("a rejected session still holds the slot: %v", err)
	}
}

func TestUpdateUnknown(t *testing.T) {
	ctx := context.Background()
	s := sessions.NewMemory(sessions.Limits{}, nil)
	err := s.Update(ctx, "nope", func(*sessions.Session) error { return nil })
	if !errors.Is(err, sessions.ErrNotFound) {
		t.Errorf("got %v, want ErrNotFound", err)
	}
	if err := s.Finish(ctx, "nope", sessions.Result{}); !errors.Is(err, sessions.ErrNotFound) {
		t.Errorf("Close: got %v, want ErrNotFound", err)
	}
}

func TestListFiltersAndPaginates(t *testing.T) {
	ctx := context.Background()
	base := time.Now()
	n := 0
	s := sessions.NewMemory(sessions.Limits{PerDevice: 10, PerPrincipal: 10},
		func() time.Time { n++; return base.Add(time.Duration(n) * time.Second) })

	for i := range 6 {
		r := row(fmt.Sprintf("s%d", i), fmt.Sprintf("dev-%d", i%2), fmt.Sprintf("op-%d", i%3))
		if err := s.Create(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.Finish(ctx, "s0", sessions.Result{CloseReason: "operator_close"})

	live, _, err := s.List(ctx, sessions.Query{Live: true})
	if err != nil || len(live) != 5 {
		t.Fatalf("live: %d rows, err=%v", len(live), err)
	}
	closed, _, _ := s.List(ctx, sessions.Query{State: sessions.StateClosed})
	if len(closed) != 1 || closed[0].ID != "s0" {
		t.Errorf("closed: %v", ids(closed))
	}
	byDevice, _, _ := s.List(ctx, sessions.Query{DeviceID: "dev-0"})
	if len(byDevice) != 3 {
		t.Errorf("by device: %v", ids(byDevice))
	}
	byOp, _, _ := s.List(ctx, sessions.Query{Principal: "op-1"})
	if len(byOp) != 2 {
		t.Errorf("by principal: %v", ids(byOp))
	}

	page1, next, _ := s.List(ctx, sessions.Query{Limit: 2})
	if len(page1) != 2 || next == "" {
		t.Fatalf("page 1: %v next=%q", ids(page1), next)
	}
	page2, _, _ := s.List(ctx, sessions.Query{Limit: 2, After: next})
	if len(page2) != 2 || page2[0].ID == page1[1].ID {
		t.Errorf("page 2 overlaps page 1: %v then %v", ids(page1), ids(page2))
	}
}

func TestCreateValidates(t *testing.T) {
	ctx := context.Background()
	s := sessions.NewMemory(sessions.Limits{}, nil)
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

func ids(rows []*sessions.Session) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.ID
	}
	return out
}
