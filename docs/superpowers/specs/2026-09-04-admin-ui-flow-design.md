# Admin console — flow redesign

**Date:** 2026-09-04
**Status:** design approved, not implemented
**Approach:** B — two spines, people and devices

---

## 1. Why

The console today is four flat tabs (`fleet | sessions | permissions | sql`) plus a
modal-ish `View` state machine (`list → opening → terminal | replay | failed`), both held
in `useState` inside a 1077-line `App.tsx`. There is no router and no URL state; the whole
`dependencies` list is `["asciinema-player"]`.

Three consequences, all confirmed by reading the code:

- **No deep links.** A session, a recording, a filtered view — none can be linked to.
- **No back button.** Escaping a terminal is a button, not browser navigation.
- **Reload loses your place.** You return to the Fleet tab with the `View` reset.

For a product whose differentiator is *evidence* — signed, hash-chained recordings that
verify offline — "paste the link to this recording into the ticket" is a core workflow and
is currently impossible.

## 2. Who this is for, and what they ask

Decided with the product owner:

- **Primary user: the auditor.** Someone answering *who touched this device, when, and
  what did they do*.
- **They arrive with a person and a time window.** *"What did contractor@partner do on our
  PCI devices last quarter?"* Device and action are facets on that query, not the entry.
- **Live sessions stay, evidence-first.** A live session and a closed one are two states of
  one object, not two features. Attach, observe and reattach are preserved but do not set
  the layout.

The auditor's *second* question is always **"and were they supposed to be able to?"** This
is why the design puts grants on the entity pages: today that answer requires leaving the
session and hunting in a separate tab.

## 3. Route model

```
/                          search — the only screen with no entity
/p/{principal}             Person: what they did, what they may do
/d/{device}                Device: what was done to it, who may reach it
/s/{session}               Session: header, live terminal or player, evidence
/permissions               policy editor
/sql                       SQL explorer, unchanged
```

`{principal}` is `encodeURIComponent`-encoded: ids contain `@` and `.`, which are legal in
a path segment but must survive round-tripping.

**Facets live in the query string**, so a filtered view is a link:

```
/p/contractor@partner.example.com?since=2026-06-01&until=2026-09-01&device=treadmill-4821
```

Recognised parameters: `since`, `until`, `device`, `state`, `cursor`.

**What the API supports today, checked rather than assumed:**

| facet | today |
|---|---|
| `device` | **exact match only** — `sessions.Query` compares `s.DeviceID != q.DeviceID`. No globbing. |
| `state`, `cursor` | supported |
| `since`, `until` | **do not exist** — added in increment 2, see § 5 |
| `action` / profile | **does not exist.** `sessions.Query` has no profile field at all. Deferred; see § 5. |

A glob device facet (`treadmill-*`) reads well in a mock and is not implementable against
the current store. If it is wanted, it is a further server change and its own increment —
do not put it in the UI first and discover this later.

### A live session and a closed one share one URL

`/s/{id}` renders a terminal or a player depending on the session's state. The rejected
alternative — separate `/s/{id}` and `/s/{id}/recording` — means a link pasted into a
ticket *while the session is live* breaks when it closes. A URL that survives the
transition is the property evidence needs, so state picks the component, not the route.

### No server change is required

`cmd/oarlockd/app/ui/ui.go` already serves `index.html` for unknown paths, so the History
API works as-is.

## 4. The pages

### `/p/{principal}` — Person — the only genuinely new build

Nothing in the console today is principal-shaped. Two stacked sections:

1. **What they did.** Session timeline, live and closed in one list, defaulting to the last
   30 days. Faceted by date and state, and by device as an exact id — **not** by action,
   which § 3 records as unsupported and § 5 defers. Rows link to `/s/{id}`.
2. **What they were allowed to do.** Grants matching this principal, **read-only**, with a
   link to the editor.

### `/d/{device}` — Device — promote what exists

`Fleet.tsx` already renders this as an expanded row: "Open a shell", "Recent sessions",
"Who can reach it", "Who can administer it". The work is to lift it to a route, add the
date facets, and paginate sessions properly rather than showing "recent". "Open a shell"
stays — it is the operator affordance and costs one button.

### `/s/{session}` — Session — lift out of `App.tsx`

The `View` union's `terminal`, `replay` and `failed` states become one page whose body is
chosen by session state.

- **Header** — principal, device, profile, opened at, close reason, recording verdict.
- **Body** — live terminal, or player, or the failure screen.
- **Footer** — evidence: signature, hash chain, verified export.

### What happens to the four tabs

| today | becomes |
|---|---|
| Fleet | device *list* at `/`, feeding `/d/{id}` |
| Sessions | absorbed — a session list with no entity is search results |
| Permissions | stays, as the policy **editor** only |
| SQL Explorer | unchanged |

Nav shrinks from four peers to **search, Permissions, SQL**. Search is the home screen and
resolves to a person or a device.

**The permission editor is not absorbed.** Writing policy is an admin's job, not an
auditor's; folding a mutation dialog into an evidence page would be a mistake. Only the
*read* view of grants moves onto entity pages.

## 5. Server changes

**The API cannot answer the primary query today.** `sessions.Query` carries `DeviceID`,
`Principal`, `State`, `Live`, `Unattended` — and no time range.

Required:

- `Since` and `Until` (`time.Time`) on `sessions.Query`.
- Parse `since` / `until` in `apisrv.listSessions` as RFC 3339. Half-open `[since, until)`.
  A malformed value is `400 invalid_argument`, not a silent ignore.
- Implement the filter in **both** stores: `sessions.Memory` and `internal/sessions/sqlitestore`.
- Regenerate `docs/openapi.yaml`. The drift test fails until this is done.

This is a slice of Go work underneath a UI change. It must land before the Person page.

**Deferred, and deliberately not in the first pass:**

- **A profile/action facet.** `sessions.Query` has no profile field. Adding one is the same
  shape of change as `Since`/`Until` and can follow once the flow is proven.
- **Glob matching on `device`.** Exact match only today. Wanted for *"all our PCI
  treadmills"*, but it is a store-level change in two implementations and belongs behind
  the flow that justifies it.

## 6. Decomposition of `App.tsx`

| state today | goes to |
|---|---|
| `token`, `client`, `me`, `login` | **root** — the auth shell, survives navigation |
| `view`, `adminPage` | **deleted** — the router replaces both |
| `sessions`, `devices`, `listError`, `refresh(scope)` | **each page**, fetching for its own route params |
| `deviceDialog`, `openByID`, inline `DeviceForm` | move with their component |

`refresh(scope)` and the `AdminPage` enum **dissolve entirely**. They exist only because
one component owns all the data; once a page fetches for its own params there is nothing
to scope. This is the largest simplification in the design and it falls out of routing
rather than being designed for.

## 7. The router — hand-rolled

Decided: no `react-router-dom`. The project hand-encodes Prometheus text format rather
than take `client_golang`, and six static routes do not justify reversing that for the
front end.

Requirements, roughly 60 lines over the History API:

- Parse `location.pathname` into `{ route, params }` against the six patterns above.
- `navigate(path, { replace? })` → `history.pushState` / `replaceState` + notify.
- Subscribe to `popstate` so the back button works.
- Expose the parsed `URLSearchParams` for facets, and a setter that rewrites the query
  string **without** touching the path.
- Encode and decode `{principal}` with `encodeURIComponent` / `decodeURIComponent`.
- Unknown path → render the search screen; do not 404 inside the SPA.

Out of scope: nested routes, route guards, lazy boundaries beyond the existing
`lazy`/`Suspense` usage, scroll restoration.

## 8. Build order

Four increments, each shippable on its own.

| # | increment | ships |
|---|---|---|
| 1 | Routing foundation: router, six routes, session lifted out of `View`, root keeps auth, pages fetch their own data | deep links, back button, reload keeps your place |
| 2 | `Since`/`Until` through `sessions.Query`, both stores, `listSessions`, OpenAPI | the primary auditor query becomes answerable |
| 3 | Person page `/p/{principal}` | the differentiating flow |
| 4 | Device page: split `Fleet.tsx` into list + page; nav shrinks | addressable devices |

**2 must precede 3** — a Person page without a date filter cannot answer the question
auditors arrive with. **4 goes last**: it is the riskiest split and adds the least new
value, because the content already exists and merely isn't addressable.

## 9. Testing

- **`Fleet.tsx`'s "Open a shell" flow has no coverage today.** The Playwright suite covers
  login and console basics. Increment 4 is exactly the split that would break it silently.
  **Write that coverage before increment 4, not after.**
- Router: unit tests for parse, encode/decode of principals with `@` and `.`, and that an
  unknown path renders search rather than throwing.
- `Since`/`Until`: store-level tests in both implementations, including the half-open
  boundary, plus a `400` for a malformed value.
- Deep links: a Playwright test that loads `/s/{id}` cold and renders the session.

## 10. Constraints held

- Design tokens flow `tokens/tokens.json` → `web/src/tokens.css`, CI-checked by
  `pnpm tokens:check`. This redesign is structural; **no new tokens should be required**,
  and a new colour would mean the design drifted.
- `docs/openapi.yaml` is generated with a drift test. Increment 2 must regenerate it.
- The gateway's SPA fallback already exists; no Go change is needed for routing itself.

## 11. Explicitly out of scope

- The permission **editor**'s own UX. It stays as-is.
- SQL Explorer.
- Any change to `@oarlock/terminal` or the embedding story.
- Mobile layout beyond what the existing responsive classes already give.
- Search across recording *contents* — this is metadata search only.
