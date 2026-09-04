# Person Page Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `/ui/p/{principal}` answers the auditor's two questions on one page — what did this person do, and were they allowed to.

**Architecture:** One new read endpoint mirroring the existing `/devices/{id}/access`, and one new React page replacing the placeholder that currently renders Fleet. No new concepts; both halves have a precedent in the codebase to copy.

**Tech Stack:** Go 1.25, React 19, Tailwind v4, Playwright.

**Spec:** `docs/superpowers/specs/2026-09-04-admin-ui-flow-design.md` § 4
**Mockup:** `docs/superpowers/specs/2026-09-04-admin-ui-flow-mockup.html` — open it; the Person screen is what this builds.

**Scope:** Increment 3 of 4. Depends on increment 2 (`since`/`until`, commits `9a0cef8` and `b0daf2d`), which is done. Increment 4 (the Device page split) is separate and not required by this.

## Global Constraints

*The task-brief generator extracts per-task text only and will not carry this section. Whoever dispatches a task must restate these in the prompt.*

- **No new dependencies**, Go or npm. `dependencies` stays exactly `["asciinema-player"]`.
- **Green from the committed state.** `git stash -u && <checks> && git stash pop` before reporting. A green check depending on an uncommitted file is a broken commit.
- **Design tokens come from `tokens/tokens.json`.** Never edit `web/src/tokens.css`; run `pnpm tokens`. `pnpm tokens:check` must stay green. **Needing a new colour means the design drifted** — the mockup uses only existing tokens.
- **Machine values are monospaced** (`.mono`), per `web/src/main.css:82`. Principal ids, device ids, session ids, timestamps.
- **`docs/openapi.yaml` is generated.** Regenerate with `go run ./cmd/oarlock-openapi`; a drift test fails otherwise.
- **The console is mounted at `/ui/`.** `web/src/router/useRouter.ts` handles this; do not hardcode the prefix anywhere else.

---

## The authorization problem, decided up front

`/devices/{id}/access` requires `plugin.ActionAdminPermissions` (`routes.go:174`). The new principal endpoint mirrors it and requires the same.

**But the spec's primary user is an auditor**, and the demo's `auditor-read` grant carries only `replay` and `observe`. So the auditor — the person this page is *for* — will often be refused the second half of it.

**That is correct and must not be worked around.** Reading who may do what is reading policy, and policy reading is administrative. The resolution is in how the page behaves, not in loosening the endpoint:

**The grants section renders only when it can be read. A 403 hides the section; it does not fail the page.**

This is an established pattern here, not an invention: `tests/console/console.spec.ts` already has a test called *"a device row will not invent an access list it cannot read"*. Follow it.

**Never evaluate policy in the browser.** `plugin.Permission.MatchesPrincipal` (`pkg/plugin/permission.go:132`) is the canonical matcher, and glob-matching principals client-side would let the console show an answer the gateway would not enforce. The endpoint exists precisely so the console never has to guess.

---

## File Structure

| file | responsibility |
|---|---|
| `internal/apisrv/apisrv.go` | `principalAccess` handler, mirroring `deviceAccess` at `:1026` |
| `internal/apisrv/routes.go` | its route-table entry, mirroring `getDeviceAccess` at `:170` |
| `internal/openapi/openapi.go` | its operation id in `schemaFor` if it gets a schema |
| `docs/openapi.yaml` | regenerated |
| `web/src/api.ts` | `principalAccess(id)`, and `sessions()` widened to take a query |
| `web/src/pages/PersonPage.tsx` | **new.** The page. |
| `web/src/App.tsx` | route `person` renders `PersonPage` instead of `Fleet` |
| `tests/console/console.spec.ts` | the e2e tests |

---

### Task 1: The principal access endpoint

**Files:**
- Modify: `internal/apisrv/apisrv.go` — add `principalAccess`
- Modify: `internal/apisrv/routes.go` — add `getPrincipalAccess`
- Modify: `internal/openapi/openapi.go`, regenerate `docs/openapi.yaml`
- Test: `internal/apisrv/admin_test.go`

**Interfaces:**
- Consumes: `plugin.Permission.MatchesPrincipal(id string) bool` (`pkg/plugin/permission.go:132`), `renderPermission`, `permissionJSON` — all already in `apisrv`.
- Produces: `GET /api/v1/principals/{id}/access` → `{ "principal": string, "rules": [...], "admin_actions": [...] }`. Task 3 consumes it.

- [ ] **Step 1: Read the precedent**

Read `deviceAccess` at `internal/apisrv/apisrv.go:1026` and its route entry `getDeviceAccess` at `internal/apisrv/routes.go:170`. **Your handler is that one with the filter changed**, so match its shape, its error handling and its response envelope rather than inventing a parallel style.

Note especially that `admin_actions` travels in the response. The comment there says why: a reader has to separate "can open a shell on this" from "can change this device's record", and the alternative is the console keeping its own copy of the administrative vocabulary. The same reasoning applies to a principal, so carry it.

- [ ] **Step 2: Write the failing test**

In `internal/apisrv/admin_test.go`, using the `adminFixture` already there (it has a real policy store and `f.grant(...)`):

```go
// The Person page's second question — "were they allowed to?" — answered by the gateway
// rather than by the console glob-matching principals for itself. A console that matched
// patterns on its own could show an answer the authorizer would not enforce.
func TestPrincipalAccessListsOnlyMatchingRules(t *testing.T) {
	f := newAdminFixture(t, adminID)
	f.grant(t, &plugin.Permission{
		ID: "oncall", Principals: []string{"*@oncall.example.com"},
		Devices: []string{"*"}, Actions: []string{"shell"},
	})
	f.grant(t, &plugin.Permission{
		ID: "just-sam", Principals: []string{"sam@example.com"},
		Devices: []string{"*"}, Actions: []string{"shell"},
	})

	resp, body := f.do(t, "GET",
		apisrv.Prefix+"/principals/"+url.PathEscape("ana@oncall.example.com")+"/access",
		adminToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	var out struct {
		Principal    string `json:"principal"`
		Rules        []struct{ ID string `json:"id"` } `json:"rules"`
		AdminActions []string `json:"admin_actions"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out.Principal != "ana@oncall.example.com" {
		t.Errorf("principal = %q", out.Principal)
	}
	// The glob matches; the exact rule for somebody else does not.
	ids := map[string]bool{}
	for _, r := range out.Rules {
		ids[r.ID] = true
	}
	if !ids["oncall"] {
		t.Error("the matching glob rule is missing")
	}
	if ids["just-sam"] {
		t.Error("another principal's rule leaked into the answer")
	}
	if len(out.AdminActions) == 0 {
		t.Error("admin_actions must travel with the answer, as it does for a device")
	}
}

// Reading policy is administrative, the same as it is for a device.
func TestPrincipalAccessNeedsTheAdminGrant(t *testing.T) {
	f := newAdminFixture(t) // no config-declared administrators
	resp, _ := f.do(t, "GET",
		apisrv.Prefix+"/principals/"+url.PathEscape("ana@oncall.example.com")+"/access",
		nobodyToken)
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d, want a refusal", resp.StatusCode)
	}
}
```

**Verified for you:** `grant` is `func (f *adminFixture) grant(t *testing.T, p *plugin.Permission)`
(`admin_test.go:117`) and sets `Enabled` itself; `plugin.Permission` has `ID`, `Name`,
`Principals`, `Devices`, `Tags`, `Actions` (`permission.go:16-22`). The test above uses
only fields that exist.

`url.PathEscape` needs `net/url` in the import block — check whether `admin_test.go`
already has it before adding a duplicate.

- [ ] **Step 3: Run it to verify it fails**

Run: `go test ./internal/apisrv/ -run PrincipalAccess`
Expected: 404 — the route does not exist.

- [ ] **Step 4: Implement the handler and the route**

Mirror `deviceAccess`. The filter is `permission.MatchesPrincipal(id)` instead of `permission.AppliesTo(dev)`. There is no registry lookup to do — a principal is a string the authenticator issued, not a row — so the handler is shorter than its model.

Route entry, mirroring `getDeviceAccess`:

```go
{
	ID:     "getPrincipalAccess",
	Method: "GET", Path: "/principals/{id}/access",
	Summary:  "List the rules that apply to one principal.",
	Action:   plugin.ActionAdminPermissions,
	Requires: "Permissions",
	available: has(func(o Options) bool { return o.Permissions != nil }),
	handler:   func(s *Server) handlerFunc { return s.principalAccess },
},
```

Note `Requires` is only `Permissions`, not `Permissions and Registry` — that difference is the point of the previous paragraph.

- [ ] **Step 5: Regenerate the spec and run everything**

```bash
go run ./cmd/oarlock-openapi
go test ./...
```

- [ ] **Step 6: Commit**

```bash
git add internal/apisrv/ internal/openapi/ docs/openapi.yaml
git commit -m "feat(api): list the policy rules that apply to one principal"
```

---

### Task 2: The Person page

**Files:**
- Create: `web/src/pages/PersonPage.tsx`
- Modify: `web/src/api.ts` — `principalAccess(id)` and its type
- Modify: `web/src/App.tsx` — `case "person"` renders `PersonPage`

**Interfaces:**
- Consumes: `GET /principals/{id}/access` (Task 1); `useRouter()`'s `route.facets`.
- Produces: a widened `Client.sessions(query?)` — see Step 2a, which is not optional.
- Produces: nothing further.

- [ ] **Step 1: Look at what you are building**

Open `docs/superpowers/specs/2026-09-04-admin-ui-flow-mockup.html` and click through to the Person screen. **The structure, section order and copy come from there.** It is built on the real tokens, so it is a reference for layout rather than a mood board.

Two stacked sections:

1. **What they did** — the session timeline, live and closed in one list, faceted. Rows link to `/s/{id}`.
2. **What they were allowed to do** — the grants, read-only, with a link to the editor.

- [ ] **Step 2: Add the client method**

In `web/src/api.ts`, beside `deviceAccess(id)` at `:237`, which is its exact model. Encode the id — principals contain `@` and `.`.

- [ ] **Step 2a: Widen `sessions()` — it cannot filter today**

`Client.sessions()` (`api.ts:212`) takes **no arguments** and is hardcoded:

```ts
  sessions(): Promise<{ sessions: Session[] }> {
    return this.call("GET", "/api/v1/sessions?limit=50");
  }
```

So the page cannot ask for one principal's sessions at all. Widen it to take an optional
query — `principal`, `since`, `until`, `device`, `state`, `limit` — building the string
with `URLSearchParams` and omitting empty values, so an absent facet is an absent
parameter rather than `&since=`.

**Optional, and the no-argument call must keep working unchanged.** `App.tsx`'s `refresh()`
calls `client.sessions()` bare and Fleet depends on that behaviour; increment 1's tests
cover it. Widening is additive here — a required parameter would be a second, invisible
task.

The gateway rejects a malformed `since` with a 400 (increment 2), so passing a facet
straight through from the URL is safe: a hand-edited link produces an honest error rather
than a filter that quietly does nothing.

- [ ] **Step 3: Build the page**

`route.facets` carries `since`, `until`, `device`, `state` (see `web/src/router/routes.ts`). Pass them to the sessions call. **Default to the last 30 days** when no `since` is present, per the spec — and put that default in the URL via `navigate(..., { replace: true })` so the view a person is looking at is always the view its URL describes. A default that lives only in component state is a link that does not reproduce what the sender saw.

**The grants section renders only if the call succeeds.** On a 403, omit the section entirely — no empty state, no error panel. The page's first question is still fully answered, and an auditor without `admin:permissions` gets a working page rather than a broken one. `tests/console/console.spec.ts`'s *"a device row will not invent an access list it cannot read"* is the precedent; read it first.

- [ ] **Step 4: Wire the route**

In `App.tsx`, `case "person"` currently falls through to `Fleet` alongside `search` and `device`. Split `person` out. **Leave `device` on `Fleet`** — that is increment 4, and doing it here would make this task unreviewable.

- [ ] **Step 5: Verify**

```bash
pnpm tokens:check && pnpm typecheck && pnpm test
```
182 tests pass today; this task adds none, so 182 must still pass.

- [ ] **Step 6: Commit**

```bash
git add web/src/
git commit -m "feat(console): a person page — what they did, and what they may do"
```

---

### Task 3: The tests

**Files:**
- Modify: `tests/console/console.spec.ts`

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Add the tests**

In `tests/console/console.spec.ts` — **not a new file**; its `beforeAll` starts the real gateway and agent, and its helpers (`signIn`, `openRow`, `waitFor`) are file-local and unexported.

1. **A person page reached by URL lists that person's sessions.** Open a session as `admin@mail.com`, then `page.goto` `/ui/p/admin%40mail.com` and assert the session appears.
2. **The facets are in the URL and narrow the list.** Navigate with `?since=` in the future and assert the list is empty; a link is only a link if it reproduces the view.
3. **A person with no `admin:permissions` sees the timeline and no grants section.** `visitor@example.com` (token `visitor-token-long-enough-for-the-check`) has a shell grant and no admin rights. Assert the sessions section renders **and** the grants section is absent — not an error panel.

Test 3 is the one that matters most: it is the page's behaviour for the user the page is for.

- [ ] **Step 2: Prove they fail for the right reason**

Break each thing under test in turn, confirm the matching test fails, restore. Report how you checked. A test that passes whether or not the feature works is worse than no test — this plan's predecessor shipped two such tests and both had to be rewritten.

- [ ] **Step 3: Full suite and commit**

```bash
pnpm test
git add tests/
git commit -m "test(console): the person page answers both questions, or one honestly"
```

---

## Done when

- `/ui/p/{principal}` lists that person's sessions, faceted, with the facets in the URL.
- The grants section appears when readable and is silently absent when not.
- Policy matching happens only on the server.
- `go test ./...` and `pnpm test` both green from the committed state.

## Not in this increment

The Device page split (increment 4), the `action` facet, glob device matching, and any
change to the permission editor.
