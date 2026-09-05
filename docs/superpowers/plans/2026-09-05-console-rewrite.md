# Console Rewrite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace all 3,924 lines of `web/src` with a console built to the approved mockup, losing no capability.

**Architecture:** Two addressable spines — people and devices — sharing a session timeline and a grants panel, which the current code duplicates. A thin auth shell, a route switch, six pages, and a small set of shared components.

**Tech Stack:** React 19, TypeScript strict, Tailwind v4, Playwright. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-04-admin-ui-flow-design.md`
**Mockup:** `docs/superpowers/specs/2026-09-04-admin-ui-flow-mockup.html`

**Scope:** A full rewrite, decided by the product owner. Everything under `web/src` is deleted and rebuilt. All 3,924 lines are committed, so `git checkout HEAD~ -- web/src` restores any of it.

---

## THE INVENTORY — the reason this plan exists

**The mockup is a flow mockup, not a feature inventory.** It shows Search, Person, Device, Session and two stubs. The console does far more, and a rewrite "to the mockup" that skips this section will silently delete working features.

Nothing below may disappear without the product owner saying so.

### The 23 API methods the console calls today

```
setToken          sshInfo           sessions          session
devices           createDevice      updateDevice      deleteDevice
deviceAccess      disconnectAgent   permissions       createPermission
updatePermission  deletePermission  principalAccess   open
renewAttach       observe           kill              sqlSchema
sqlQuery
```

Every one is a capability a person uses. `api.ts` is a typed contract against a generated
OpenAPI document — **rewriting it is the highest-risk part of this plan**, because a
silently wrong field name fails at runtime, not at build. Copy it method by method,
checking each against `docs/openapi.yaml`.

### The 24 test hooks

```
sign-in  fleet  fleet-summary  open  reason  waits  terminal  replay  failure
open-by-id  open-by-id-device  open-by-id-reason  open-by-id-submit
device-access  device-access-reach  device-access-admin
permissions  permissions-refused  run-sql  sql-explorer
person-page  person-sessions  person-access  person-facets
```

These are the seams the 185-test suite grips. **Keep every name.** The rewrite changes the
markup behind them, not the contract with the tests — that is what lets the existing suite
tell you whether the rewrite lost something, which is the only safety net a rewrite has.

Where the new structure has no equivalent for one, that is a feature being dropped: stop
and say so rather than deleting the hook.

### The four dialogs

| dialog | where today | what it does |
|---|---|---|
| Device form | `App.tsx:1104` | add and edit a device |
| Open by id | `App.tsx:1167` | open a shell on a device by typing its id |
| SSH client | `SSHAccess.tsx:54` | the pinned local `ssh` command, host key download |
| Permission editor | `Permissions.tsx:303` | add and edit a policy rule |

### Capabilities not visible in the mockup at all

Sign-in (token **and** OIDC, with the reload-keeps-you-signed-in behaviour), sign-out,
device add/edit/disable/delete, agent disconnect, session kill, observe (watch a live
session read-only), replay with its integrity verdict, the SQL explorer's schema browser,
the recorded/unrecorded disclosure, and the failure screens for the whole closed condition
set.

---

## Global Constraints

*The task-brief generator extracts per-task text only and will not carry this section. Whoever dispatches a task must restate it.*

- **No new dependencies.** `dependencies` stays exactly `["asciinema-player"]`.
- **Design tokens come from `tokens/tokens.json`.** Never edit `web/src/tokens.css` —
  it is generated. `pnpm tokens:check` must stay green. **Needing a new colour means the
  design drifted**; the mockup uses only existing tokens.
- **Machine values are monospaced** (`.mono`): principals, device ids, session ids,
  timestamps, fingerprints.
- **Green from the committed state**, and note that `pnpm test` now builds the console
  first (`63f93a8`), so it tests what is committed rather than what was last built.
- **Do not hardcode `/ui`.** The router derives the mount prefix; `app.go` mounts it.
- **The whole suite must pass at every task boundary.** A rewrite whose tests are
  "temporarily red" is a rewrite nobody can tell is finished.

---

## File Structure

| file | responsibility |
|---|---|
| `web/src/main.tsx` | mount |
| `web/src/api.ts` | the typed client — all 23 methods |
| `web/src/App.tsx` | auth shell and route switch **only**; target under 200 lines |
| `web/src/router/routes.ts` | pure parse/format, unit-testable in Node |
| `web/src/router/useRouter.ts` | `useSyncExternalStore` over the History API |
| `web/src/pages/SearchPage.tsx` | the home: resolves to a person or a device |
| `web/src/pages/PersonPage.tsx` | timeline + grants, for a principal |
| `web/src/pages/DevicePage.tsx` | timeline + grants + shell + admin, for a device |
| `web/src/pages/SessionPage.tsx` | terminal, or player, or failure |
| `web/src/pages/PermissionsPage.tsx` | the policy editor |
| `web/src/pages/SqlPage.tsx` | the SQL explorer |
| `web/src/components/SignIn.tsx` | token and OIDC |
| `web/src/components/Timeline.tsx` | **shared** session list — person and device |
| `web/src/components/Grants.tsx` | **shared** grants panel, four states |
| `web/src/components/Facets.tsx` | the facet chips, reading and writing the URL |
| `web/src/components/Waits.tsx` | the wait/steps panel |
| `web/src/components/dialogs/*.tsx` | the four dialogs above |

**`Timeline` and `Grants` being shared is the point of the rewrite.** Today `Fleet.tsx`
and `PersonPage.tsx` each carry their own copy of a grants panel, and the two have already
drifted — the person one was written from a mockup, the device one from the API. One
component, two callers.

---

## Task order

Each task ends with the full suite green. **Tasks 1-6 do not edit tests.** If a test fails,
the rewrite lost something — that is the signal, and deleting the signal is the one thing
that makes a rewrite unreviewable.

New files land beside the old ones; each old file is deleted as its replacement lands.

---

### Task 1: The contract layer

**Files:** `web/src/api.ts`, `web/src/router/routes.ts`, `web/src/router/useRouter.ts`, `web/src/main.tsx`

No UI. Rewrite the client and the router.

- `api.ts` carries all 23 methods from the inventory. **Check each against
  `docs/openapi.yaml`** — it is generated from the route table, so it is the authority on
  field names. A wrong name here fails at runtime, not at build, which is why this is the
  riskiest file in the plan.
- `router/` keeps its existing contract: `parsePath`, `formatPath`, `Route`, and a
  `useRouter()` returning `{ route, navigate }` over `useSyncExternalStore`. The 11 unit
  tests in `tests/unit/router.spec.ts` must pass unchanged — they are the specification.
- **`pushState` does not fire `popstate`.** The route lives in one module-level store read
  through `useSyncExternalStore`, never per-component `useState`, or every subscriber but
  the navigating one goes stale. `getSnapshot` must return a memoised value or React loops.
- The mount prefix is derived at load, not hardcoded.

**Ends with the FULL suite green — 185 passing.** An earlier draft excused this task from
the console tests. That was wrong: this task preserves both modules' exported contracts, so
the old `App.tsx` keeps working against the new files and every test should still pass. If
the suite goes red here, a contract changed, and that is precisely the thing worth
discovering in the smallest task rather than the largest.

### Task 2: Shell and sign-in

**Files:** `web/src/App.tsx`, `web/src/components/SignIn.tsx`

The auth shell — token in `sessionStorage`, OIDC, sign-out, reload-keeps-you-signed-in —
plus the nav and the route switch. `App.tsx` target: under 200 lines.

`tests/console/login.spec.ts` is the arbiter and **must not be edited**. Keep the `sign-in`
hook.

### Task 3: The shared panels and their two callers

**Files:** `web/src/components/{Timeline,Grants,Facets,Waits}.tsx`,
`web/src/pages/{PersonPage,DevicePage}.tsx`

An earlier draft made the shared components their own task. That was wrong: components
nothing imports are dead code, the suite stays green trivially, and nothing verifies them.
A task is the smallest unit that carries its own test cycle, so the shared panels ship with
both their callers.

**This is the first task a user can see, and the structural reason for the whole rewrite.**
`Fleet.tsx` and `pages/PersonPage.tsx` each carry their own grants panel today and the two
have already drifted — the person one written from the mockup, the device one from the API.
After this task there is one `Grants` with two callers, and one `Timeline` with two callers.

`Grants` has four states — loading, refused, failed, ready. **Refused names the action
required and never renders an empty list.** On a person page an empty list reads as "this
person is permitted nothing", which is a false statement rather than a blank space.
`Fleet.tsx:343-376` is the implementation that gets this right; read it.

`DevicePage` takes over what `Fleet.tsx`'s expanded row does: open a shell, who can reach
it, who administers it, recent sessions. The fleet *list* stays in `Fleet.tsx` for now and
moves to `SearchPage` in Task 4.

Hooks that must survive by name: `person-page`, `person-sessions`, `person-access`,
`person-facets`, `device-access`, `device-access-reach`, `device-access-admin`, `open`,
`reason`, `waits`.

### Task 4: Search, and the nav

**Files:** `web/src/pages/SearchPage.tsx`, `web/src/App.tsx`

The search-first home from the mockup, resolving to a person or a device. The nav shrinks
from four tabs to three — Search, Permissions, SQL — with `Fleet.tsx` deleted once
`SearchPage` carries the device list. Hooks: `fleet`, `fleet-summary`.

### Task 5: Session page

**Files:** `web/src/pages/SessionPage.tsx`

Terminal, player, failure — chosen by session state, one URL for all three so a link
pasted while a session is live still resolves after it closes. Carries the
recorded/unrecorded disclosure and the replay integrity verdict. Hooks: `terminal`,
`replay`, `failure`, `waits`.

### Task 6: Permissions, SQL, and the four dialogs

**Files:** `web/src/pages/{PermissionsPage,SqlPage}.tsx`, `web/src/components/dialogs/*.tsx`

The four dialogs from the inventory: device form, open-by-id, SSH client, permission
editor. Hooks: `permissions`, `permissions-refused`, `sql-explorer`, `run-sql`,
`open-by-id*`.

**Delete every remaining old file** in this task. `web/src` should contain only what the
File Structure table lists.

### Task 7: Reconcile the tests

Only after 1-6. Any test that must change is a feature that moved: list each one and why.
A test deleted without an explanation is a capability deleted without one.

## Done when

- `pnpm test` green, with every test hook still present.
- No capability from the inventory is missing.
- `App.tsx` is an auth shell and a route switch, nothing else.
- `Timeline` and `Grants` each exist once.
