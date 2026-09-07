package sessions_test

// The range filter is tested against both stores from one table, because the failure
// this increment is most likely to produce is a filter that behaves one way in memory
// and another in SQL — and the console only ever sees one of them.

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/sessions"
	"github.com/oarlock/oarlock/internal/sessions/sqlitestore"
)

// stores returns each implementation under test, already empty.
func stores(t *testing.T) map[string]sessions.Store {
	t.Helper()
	limits := sessions.Limits{PerDevice: 50, PerPrincipal: 50}
	// Open takes (path, limits, now) — see internal/sessions/sqlitestore/sqlitestore.go:104.
	sq, err := sqlitestore.Open(filepath.Join(t.TempDir(), "s.db"), limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Shutdown, not Close. The name is deliberate: the ledger interface already has a
	// Close-shaped method for finalising a session, and one type with both meanings is
	// one somebody calls the wrong one of.
	t.Cleanup(func() { _ = sq.Shutdown() })
	return map[string]sessions.Store{
		"memory": sessions.NewMemory(limits, nil),
		"sqlite": sq,
	}
}

// at builds a session created at a precise instant. The fractional seconds are the
// point: RFC3339Nano drops a zero fraction entirely, so these three rows serialise to
// strings whose lexicographic order is NOT their chronological order.
func at(id string, when time.Time) *sessions.Session {
	return &sessions.Session{
		ID: id, DeviceID: "treadmill-4821", Profile: "shell",
		Principal: "admin@mail.com", State: sessions.StateClosed,
		CreatedAt: when,
	}
}

func TestRangeIsHalfOpenAndSurvivesTheNanoFormat(t *testing.T) {
	base := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	// The boundary second is where the RFC3339Nano trap lives: `exact` serialises with
	// no fraction, `justAfter` with one, and '.' sorts before 'Z'.
	rows := []*sessions.Session{
		at("sess_before", base.Add(-time.Second)),
		at("sess_exact", base),
		at("sess_justafter", base.Add(500*time.Millisecond)),
		at("sess_later", base.Add(48*time.Hour)),
		at("sess_after_until", base.Add(72*time.Hour)),
	}

	for name, store := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			for _, r := range rows {
				cp := *r
				if err := store.Create(ctx, &cp); err != nil {
					t.Fatalf("seeding %s: %v", r.ID, err)
				}
			}

			got, _, err := store.List(ctx, sessions.Query{
				Since: base,
				Until: base.Add(72 * time.Hour),
			})
			if err != nil {
				t.Fatalf("List: %v", err)
			}

			ids := map[string]bool{}
			for _, s := range got {
				ids[s.ID] = true
			}

			// `exact` is in because the interval is closed at the bottom.
			// `justafter` is the regression guard for the format trap.
			// `after_until` is out because the interval is open at the top —
			// which is what lets two adjacent ranges partition without overlap.
			for _, want := range []string{"sess_exact", "sess_justafter", "sess_later"} {
				if !ids[want] {
					t.Errorf("%s missing from the range", want)
				}
			}
			for _, unwanted := range []string{"sess_before", "sess_after_until"} {
				if ids[unwanted] {
					t.Errorf("%s should be outside the range", unwanted)
				}
			}
		})
	}
}

func TestEitherBoundAloneWorks(t *testing.T) {
	base := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	for name, store := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			for _, r := range []*sessions.Session{
				at("sess_old", base.Add(-48*time.Hour)),
				at("sess_new", base.Add(48*time.Hour)),
			} {
				cp := *r
				if err := store.Create(ctx, &cp); err != nil {
					t.Fatal(err)
				}
			}

			onlySince, _, err := store.List(ctx, sessions.Query{Since: base})
			if err != nil {
				t.Fatal(err)
			}
			if len(onlySince) != 1 || onlySince[0].ID != "sess_new" {
				t.Errorf("since alone returned %d rows, want just sess_new", len(onlySince))
			}

			onlyUntil, _, err := store.List(ctx, sessions.Query{Until: base})
			if err != nil {
				t.Fatal(err)
			}
			if len(onlyUntil) != 1 || onlyUntil[0].ID != "sess_old" {
				t.Errorf("until alone returned %d rows, want just sess_old", len(onlyUntil))
			}
		})
	}
}

// ids is defined in sessions_test.go, in this same package.

func sameOrder(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// B2: both stores default to the forward-cursor order (oldest first), and both must
// reverse it the same way when a caller asks for the newest page of a window instead —
// the shape console pages need (DevicePage.tsx, PersonPage.tsx) so a page of more than
// `limit` sessions renders its newest rows rather than its oldest.
func TestNewestOrdersMostRecentFirst(t *testing.T) {
	base := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	seed := []*sessions.Session{
		at("sess_1", base),
		at("sess_2", base.Add(time.Hour)),
		at("sess_3", base.Add(2*time.Hour)),
	}
	for name, store := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			for _, r := range seed {
				cp := *r
				if err := store.Create(ctx, &cp); err != nil {
					t.Fatalf("seeding %s: %v", r.ID, err)
				}
			}

			oldest, _, err := store.List(ctx, sessions.Query{})
			if err != nil {
				t.Fatal(err)
			}
			if want := []string{"sess_1", "sess_2", "sess_3"}; !sameOrder(ids(oldest), want) {
				t.Errorf("default order = %v, want %v (oldest-first)", ids(oldest), want)
			}

			newest, _, err := store.List(ctx, sessions.Query{Newest: true})
			if err != nil {
				t.Fatal(err)
			}
			if want := []string{"sess_3", "sess_2", "sess_1"}; !sameOrder(ids(newest), want) {
				t.Errorf("Newest order = %v, want %v (newest-first)", ids(newest), want)
			}
		})
	}
}

// The cursor's meaning depends on the order that minted it (Query.Newest's own doc
// comment): paging a newest-first list walks backward in time, one page older each
// call, rather than forward. Run against both stores because the ascending path's
// cursor and this one share nothing but shape — a store that gets the descending
// comparison backwards would silently repeat or skip a page instead of failing loudly.
func TestNewestCursorPagesOlderEachTime(t *testing.T) {
	base := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	seed := []*sessions.Session{
		at("sess_1", base),
		at("sess_2", base.Add(time.Hour)),
		at("sess_3", base.Add(2*time.Hour)),
		at("sess_4", base.Add(3*time.Hour)),
	}
	for name, store := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			for _, r := range seed {
				cp := *r
				if err := store.Create(ctx, &cp); err != nil {
					t.Fatalf("seeding %s: %v", r.ID, err)
				}
			}

			first, cursor, err := store.List(ctx, sessions.Query{Newest: true, Limit: 2})
			if err != nil {
				t.Fatal(err)
			}
			if want := []string{"sess_4", "sess_3"}; !sameOrder(ids(first), want) {
				t.Fatalf("first page = %v, want %v", ids(first), want)
			}
			if cursor == "" {
				t.Fatal("expected a next_cursor: two older rows remain")
			}

			second, cursor2, err := store.List(ctx, sessions.Query{
				Newest: true, Limit: 2, After: cursor,
			})
			if err != nil {
				t.Fatal(err)
			}
			if want := []string{"sess_2", "sess_1"}; !sameOrder(ids(second), want) {
				t.Fatalf("second page = %v, want %v", ids(second), want)
			}
			if cursor2 != "" {
				t.Errorf("expected no next_cursor on the last page, got %q", cursor2)
			}
		})
	}
}

// A zero bound is absent, not "the beginning of time" — the same distinction every
// other optional field in Query makes.
func TestZeroBoundsFilterNothing(t *testing.T) {
	base := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	for name, store := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			cp := *at("sess_1", base)
			if err := store.Create(ctx, &cp); err != nil {
				t.Fatal(err)
			}
			got, _, err := store.List(ctx, sessions.Query{})
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 {
				t.Errorf("an empty Query returned %d rows, want 1", len(got))
			}
		})
	}
}
