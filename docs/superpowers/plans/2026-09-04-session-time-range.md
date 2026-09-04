# Session Time Range Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `GET /api/v1/sessions` can be filtered by a time range, so the console can answer "what did this person do last quarter".

**Architecture:** Two fields on `sessions.Query`, parsed from the query string in `apisrv`, implemented in both stores, and documented in the generated OpenAPI. No new concepts and no schema change.

**Tech Stack:** Go 1.25, modernc sqlite, the repo's own OpenAPI generator.

**Spec:** `docs/superpowers/specs/2026-09-04-admin-ui-flow-design.md` § 5

**Scope:** Increment 2 of 4. It ships alone: the API gains a filter whether or not a UI uses it. Increment 3 (the Person page) cannot be built without it.

## Global Constraints

- **No new Go dependencies.** `go.mod` gains nothing.
- **Green from the committed state.** `go build ./... && go test ./...` must pass with nothing uncommitted. A green check that depends on an uncommitted file is a broken commit.
- **`docs/openapi.yaml` is generated.** Never hand-edit it; run `go run ./cmd/oarlock-openapi`. A drift test fails until you do.
- **Half-open interval, `[since, until)`.** Documented on the parameters and asserted by a test. Half-open is what makes a month boundary unambiguous and two adjacent ranges partition without overlap.
- **A malformed value is `400 invalid_argument`**, never a silently ignored filter. A filter that quietly does nothing shows a caller more than they asked for and tells them it is everything.

---

## THE HAZARD — read before writing any comparison

`created_at` is `TEXT` in sqlite, written by `sqlitestore.go:467`:

```go
func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
```

**`RFC3339Nano` trims trailing zeros in the fraction.** So a time with zero nanoseconds has no fractional part at all, and lexicographic order is NOT chronological order:

```
"2026-06-01T00:00:00.5Z"  vs  "2026-06-01T00:00:00Z"
                     ^                          ^
                    '.' = 0x2E                 'Z' = 0x5A
```

`.` sorts before `Z`, so the string for **half a second later** compares as **earlier**. A naive `created_at >= ?` silently drops every row in the boundary second that happens to carry a fraction.

This is not hypothetical: `Create` stamps `created_at` from the wall clock, so most rows have a fraction and rows landing exactly on a second boundary do not.

**Task 2 must make the range filter correct across this.** How is your choice; the test in Task 1 is the arbiter. Options, none of them free:

1. **Normalise the bound.** Format `since` as `…T00:00:00.000000000Z` so any same-second value sorts after it. Keeps the index on `(principal, created_at)`. Fragile and hard to read six months later.
2. **Compare through sqlite's date functions**, e.g. `strftime('%Y-%m-%dT%H:%M:%f', created_at) >= strftime(…, ?)`. Obviously correct, defeats the index.
3. **Filter in Go** after scanning. Simplest to reason about, worst asymptotics, and it breaks `LIMIT` pagination — the store would page before filtering.

Option 3 is a trap: it interacts with the `LIMIT ?` and the `next_cursor`, and a page could come back empty while more matches exist. Do not take it without saying why.

Whatever you choose, **write the comment that explains it**, because the next person will read `>=` and assume string comparison was fine.

`ORDER BY created_at, id` has the same latent flaw today. **Do not fix it in this increment** — it is a pre-existing ordering quirk, not a regression you are introducing, and widening scope inside a filter change is how a refactor hides a behaviour change.

---

## File Structure

| file | responsibility |
|---|---|
| `internal/sessions/sessions.go` | `Since` / `Until` on `Query`; `Memory.List` implements them |
| `internal/sessions/sqlitestore/sqlitestore.go` | the same filter in SQL, correct across the hazard above |
| `internal/apisrv/apisrv.go` | parse `since` / `until` in `listSessions`; 400 on malformed |
| `internal/openapi/openapi.go` | declare both parameters on `listSessions` |
| `docs/openapi.yaml` | regenerated, never hand-edited |
| `internal/sessions/range_test.go` | **new.** The store-level property tests, run against both stores |

---

### Task 1: The time range, in both stores

Test first, and deliberately a **table test over both implementations**, because a filter
that behaves differently in memory and in sqlite is the bug this increment is most likely
to produce. Test and implementation land in one commit — see the note after Step 3.

**Files:**
- Create: `internal/sessions/range_test.go`
- Modify: `internal/sessions/sessions.go` — `Query`, and `Memory.List`
- Modify: `internal/sessions/sqlitestore/sqlitestore.go` — `List`

**Interfaces:**
- Consumes: `sessions.Query` gains `Since`, `Until time.Time` (added in Step 4 below; this test will not compile until then — that is the point).
- Produces: nothing.

- [ ] **Step 1: Write the failing test**

Create `internal/sessions/range_test.go`. It must run every case against **both** `sessions.NewMemory` and `sqlitestore.Open`, so the two cannot drift:

```go
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
```

**Already verified, so you do not have to:** `sessions.Session.CreatedAt` exists
(`sessions.go:69`), and **both** stores stamp it only when it is zero —
`sessions.go:237` and `sqlitestore.go:153` each guard with `if …CreatedAt.IsZero()`. So
the fixture's explicit timestamps survive `Create` in both implementations, which is what
makes this test possible at all.

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/sessions/ -run Range`
Expected: a compile error — `Query` has no field `Since`. That is the correct first failure.

**Do not commit yet.** An earlier draft of this plan made the failing test its own commit,
to make the next one provably the thing that turned it green. That is wrong here: the test
references a field that does not exist, so it does not *compile*, and a commit that does
not build violates this plan's own "green from the committed state" rule and strands
anyone bisecting. The test and the implementation are one commit, at the end of Step 7.

- [ ] **Step 4: Add the fields**

In `internal/sessions/sessions.go`, on `Query`:

```go
	// Since and Until bound the range on CreatedAt, half-open: [Since, Until).
	//
	// Half-open so that two adjacent ranges partition without overlap and a month
	// boundary belongs to exactly one of them. Zero means absent, the same as every
	// other optional field here — not "the beginning of time".
	Since time.Time
	Until time.Time
```

- [ ] **Step 5: Implement it in `Memory.List`**

Alongside the existing filters. `Memory` holds real `time.Time`, so this one is direct — and it is the reference the SQL implementation has to agree with:

```go
		if !q.Since.IsZero() && s.CreatedAt.Before(q.Since) {
			continue
		}
		if !q.Until.IsZero() && !s.CreatedAt.Before(q.Until) {
			continue
		}
```

- [ ] **Step 6: Implement it in `sqlitestore.List`**

**Read the HAZARD section above before writing this.** Add to the `where`/`args` construction, and write the comment explaining why your comparison is correct despite `RFC3339Nano` trimming zero fractions.

- [ ] **Step 7: Run the tests**

Run: `go test ./internal/sessions/...`
Expected: PASS, both sub-tests of every case. **If `memory` passes and `sqlite` fails, you have met the hazard** — that is the test doing its job, not a flaky fixture.

- [ ] **Step 8: Full suite, then commit — test and implementation together**

```bash
go test ./...
git add internal/sessions/
git commit -m "feat(sessions): filter a session list by a half-open time range"
```

---

### Task 2: The API parameters

**Files:**
- Modify: `internal/apisrv/apisrv.go` — `listSessions`
- Modify: `internal/openapi/openapi.go` — the `listSessions` parameters
- Regenerate: `docs/openapi.yaml`
- Test: `internal/apisrv/apisrv_test.go`

**Interfaces:**
- Consumes: `sessions.Query.Since` / `.Until` from Task 1.
- Produces: `?since=` and `?until=`, RFC 3339, on `GET /api/v1/sessions`.

- [ ] **Step 1: Write the failing test**

Add to `internal/apisrv/apisrv_test.go`, following the fixture already there:

```go
// A filter that silently does nothing is worse than one that refuses: the caller is
// shown more than they asked for and told it is everything.
func TestAMalformedTimeRangeIsRefused(t *testing.T) {
	f := newFixture(t, 0)
	for _, q := range []string{"?since=yesterday", "?until=2026-13-45", "?since=1717200000"} {
		resp, body := f.do(t, "GET", apisrv.Prefix+"/sessions"+q, token)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s gave status %d, want 400: %s", q, resp.StatusCode, body)
		}
	}
}

func TestATimeRangeNarrowsTheList(t *testing.T) {
	f := newFixture(t, 0)
	base := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	f.seedAt(t, "s_old", "dev-1", "admin@mail.com", base.Add(-48*time.Hour))
	f.seedAt(t, "s_new", "dev-1", "admin@mail.com", base.Add(48*time.Hour))

	resp, body := f.do(t, "GET",
		apisrv.Prefix+"/sessions?since="+base.Format(time.RFC3339), token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	var out struct {
		Sessions []struct {
			ID string `json:"id"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Sessions) != 1 || out.Sessions[0].ID != "s_new" {
		t.Fatalf("since returned %+v, want just s_new", out.Sessions)
	}
}
```

**`f.seedAt` does not exist — you are adding it.** The fixture's `seed` is
`seed(t, id, device, principal)` (`apisrv_test.go:249`) and hard-codes the rest, so it
cannot place a row in time. Add a `seedAt` beside it that takes a `time.Time` and sets
`CreatedAt`; both stores honour it. Do not reach around the fixture to `f.ledger`
directly — the next test that needs a timestamp should find a helper, not a precedent for
bypassing one.

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/apisrv/ -run TimeRange`
Expected: FAIL — the malformed values are currently ignored, so the status is 200.

- [ ] **Step 3: Parse the parameters**

In `listSessions`, beside the existing `r.URL.Query().Get` calls. RFC 3339. A value that does not parse is `400 invalid_argument` with a detail naming the parameter — reuse the `s.problem(...)` shape already used for `unattended`, which is the closest existing precedent.

- [ ] **Step 4: Declare them in the generated spec**

In `internal/openapi/openapi.go`, where `parametersFor` already special-cases `openSession` and the paging parameters, add `since` and `until` for `listSessions`. Say in the description that the interval is half-open and that the format is RFC 3339 — an SDK author reading only the spec must not have to guess which end is inclusive.

- [ ] **Step 5: Regenerate and verify**

```bash
go run ./cmd/oarlock-openapi
go test ./internal/openapi/
```
Expected: the drift test passes. It fails if you edited `docs/openapi.yaml` by hand.

- [ ] **Step 6: Full suite, then commit**

```bash
go test ./...
git add internal/apisrv/ internal/openapi/ docs/openapi.yaml
git commit -m "feat(api): filter GET /sessions by a half-open time range"
```

---

## Done when

- `GET /api/v1/sessions?since=…&until=…` narrows the list, both bounds optional.
- Both stores agree, proven by one table test that runs against both.
- A malformed bound is a 400, not a silent no-op.
- `docs/openapi.yaml` documents both, regenerated rather than edited.
- `go test ./...` green from the committed state.

## Not in this increment

The `action`/profile facet, glob matching on `device`, and fixing `ORDER BY created_at, id`'s
latent format quirk. All three are named in the spec as deferred; each is its own change.
