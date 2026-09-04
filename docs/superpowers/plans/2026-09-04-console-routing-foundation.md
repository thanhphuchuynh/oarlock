# Console Routing Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the admin console real URLs, so a session, a recording and a filtered view can be linked to, the back button works, and a reload keeps your place.

**Architecture:** A hand-rolled router in two halves — a DOM-free module that parses and formats paths (unit-testable in Node) and a React hook that drives the History API. `App.tsx`'s `View` union and `AdminPage` enum are deleted; routes replace both. The session becomes its own page component instead of a modal state.

**Tech Stack:** React 19, TypeScript, Tailwind v4, Playwright (`@playwright/test` is also the Node unit-test runner). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-04-admin-ui-flow-design.md`

**Scope:** This is increment 1 of 4. Increments 2 (`Since`/`Until` in the Go API), 3 (Person page) and 4 (Device page split) get their own plans. This one ships on its own: after it, every screen has a URL.

## Global Constraints

- **No new npm dependencies.** `dependencies` is `["asciinema-player"]` and stays that way. Decided in the spec § 7: the project hand-encodes Prometheus text format rather than take `client_golang`, and six static routes do not justify reversing that.
- **Design tokens come from `tokens/tokens.json` → `web/src/tokens.css`.** Never edit `tokens.css`; run `pnpm tokens`. `pnpm tokens:check` must stay green. This increment is structural — **needing a new colour means the design drifted.**
- **Machine values are monospaced** (`.mono`), per `web/src/main.css:82`.
- **Six routes, exactly:** `/`, `/p/{principal}`, `/d/{device}`, `/s/{session}`, `/permissions`, `/sql`.
- **`{principal}` is `encodeURIComponent`-encoded** — ids contain `@` and `.`.
- **`/s/{id}` serves both live and closed sessions.** State picks the component, never the route.
- **The gateway needs no change.** `cmd/oarlockd/app/ui/ui.go:45` already serves `index.html` for unknown paths.
- **Every task ends green:** `pnpm tokens:check && pnpm typecheck && pnpm test:unit`.
- **The router's state lives in one external store, read with `useSyncExternalStore`.**
  Not `useState` per component: `pushState` does not fire `popstate`, so a per-component
  copy leaves every subscriber but the navigating one stale. Task 5 tests this.

---

## File Structure

| file | responsibility |
|---|---|
| `web/src/router/routes.ts` | **new.** Pure. Parse a path into a route, format a route into a path. No DOM, no React — so it is unit-testable in Node, the way `@oarlock/terminal/disclosure` is. |
| `web/src/router/useRouter.ts` | **new.** React hook over the History API: current route, `navigate`, `popstate`, query params. The only file that touches `window`. |
| `web/src/pages/SessionPage.tsx` | **new.** The `terminal` / `replay` / `failed` states of the old `View` union, as one page keyed on session state. |
| `web/src/App.tsx` | **modify.** Shrinks to the auth shell plus a route switch. `view`, `adminPage`, `refresh(scope)` are deleted. |
| `tests/unit/router.spec.ts` | **new.** Parsing, formatting, principal round-tripping, unknown paths. |
| `tests/console/deeplink.spec.ts` | **new.** Cold-load `/s/{id}` against a real gateway. |

Files that change together live together, so the router's two halves share a directory and the pages get their own. `Fleet.tsx`, `Permissions.tsx`, `SQLExplorer.tsx`, `SessionList.tsx`, `SSHAccess.tsx`, `Waits.tsx` are **not touched** in this increment.

---

### Task 1: Pure route parsing

**Files:**
- Create: `web/src/router/routes.ts`
- Test: `tests/unit/router.spec.ts`

**Interfaces:**
- Consumes: nothing.
- Produces: `type Route`, `parsePath(pathname: string, search?: string): Route`, `formatPath(route: Route): string`. Task 2 and Task 4 both import these.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/router.spec.ts`:

```ts
// The router's parsing half is DOM-free on purpose, so it is tested in Node rather
// than in a browser — the same reason @oarlock/terminal/disclosure has its own subpath.

import { test, expect } from "@playwright/test";
import { parsePath, formatPath } from "../../web/src/router/routes";

test.describe("parsePath", () => {
  test("the root is search", () => {
    expect(parsePath("/")).toEqual({ kind: "search" });
  });

  test("a person route decodes its principal", () => {
    expect(parsePath("/p/admin%40mail.com")).toEqual({
      kind: "person", principal: "admin@mail.com", facets: {},
    });
  });

  test("a device route", () => {
    expect(parsePath("/d/treadmill-4821")).toEqual({
      kind: "device", device: "treadmill-4821", facets: {},
    });
  });

  test("a session route", () => {
    expect(parsePath("/s/sess_iw31he82d8gg")).toEqual({
      kind: "session", session: "sess_iw31he82d8gg",
    });
  });

  test("the static routes", () => {
    expect(parsePath("/permissions")).toEqual({ kind: "permissions" });
    expect(parsePath("/sql")).toEqual({ kind: "sql" });
  });

  test("facets come off the query string", () => {
    expect(parsePath("/p/admin%40mail.com", "?since=2026-06-01&device=treadmill-4821"))
      .toEqual({
        kind: "person", principal: "admin@mail.com",
        facets: { since: "2026-06-01", device: "treadmill-4821" },
      });
  });

  test("an unknown facet is dropped rather than carried", () => {
    expect(parsePath("/d/rower-9001", "?nonsense=1&since=2026-01-01").facets)
      .toEqual({ since: "2026-01-01" });
  });

  // An unknown path must not throw inside the SPA. The gateway serves index.html for
  // everything, so a typo in a pasted link arrives here, not as a 404.
  test("an unknown path falls back to search", () => {
    expect(parsePath("/nope/whatever")).toEqual({ kind: "search" });
    expect(parsePath("")).toEqual({ kind: "search" });
  });
});

test.describe("formatPath", () => {
  test("a principal is encoded so @ and . survive", () => {
    expect(formatPath({ kind: "person", principal: "admin@mail.com", facets: {} }))
      .toBe("/p/admin%40mail.com");
  });

  test("facets are appended in a stable order", () => {
    expect(formatPath({
      kind: "person", principal: "a@b.com",
      facets: { until: "2026-09-01", since: "2026-06-01" },
    })).toBe("/p/a%40b.com?since=2026-06-01&until=2026-09-01");
  });

  test("round-trips a principal with characters that need encoding", () => {
    const route = { kind: "person" as const, principal: "o'brien+test@corp.example", facets: {} };
    expect(parsePath(formatPath(route))).toEqual(route);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm test:unit`
Expected: FAIL — `Cannot find module '../../web/src/router/routes'`

- [ ] **Step 3: Write the implementation**

Create `web/src/router/routes.ts`:

```ts
// Route parsing, with no DOM and no React.
//
// Split out so it can be tested in Node: the same reason the terminal package puts its
// disclosure policy behind its own subpath. Everything that touches `window` lives in
// useRouter.ts, and this file is the part with the decisions in it.

export type Facets = Partial<Record<"since" | "until" | "device" | "state" | "cursor", string>>;

export type Route =
  | { kind: "search" }
  | { kind: "person"; principal: string; facets: Facets }
  | { kind: "device"; device: string; facets: Facets }
  | { kind: "session"; session: string }
  | { kind: "permissions" }
  | { kind: "sql" };

// The closed set. An unrecognised parameter is dropped rather than carried, so a link
// cannot smuggle state the UI never validated.
const FACET_KEYS = ["since", "until", "device", "state", "cursor"] as const;

function readFacets(search: string): Facets {
  const out: Facets = {};
  const params = new URLSearchParams(search);
  for (const key of FACET_KEYS) {
    const value = params.get(key);
    if (value) out[key] = value;
  }
  return out;
}

export function parsePath(pathname: string, search = ""): Route {
  const parts = pathname.split("/").filter(Boolean);

  if (parts.length === 0) return { kind: "search" };
  if (parts.length === 1 && parts[0] === "permissions") return { kind: "permissions" };
  if (parts.length === 1 && parts[0] === "sql") return { kind: "sql" };

  if (parts.length === 2) {
    // decodeURIComponent throws on a malformed sequence — a hand-edited URL should land
    // on search, not crash the app.
    let id: string;
    try {
      id = decodeURIComponent(parts[1]!);
    } catch {
      return { kind: "search" };
    }
    if (!id) return { kind: "search" };
    if (parts[0] === "p") return { kind: "person", principal: id, facets: readFacets(search) };
    if (parts[0] === "d") return { kind: "device", device: id, facets: readFacets(search) };
    if (parts[0] === "s") return { kind: "session", session: id };
  }

  return { kind: "search" };
}

export function formatPath(route: Route): string {
  switch (route.kind) {
    case "search":
      return "/";
    case "permissions":
      return "/permissions";
    case "sql":
      return "/sql";
    case "session":
      return "/s/" + encodeURIComponent(route.session);
    case "person":
      return "/p/" + encodeURIComponent(route.principal) + query(route.facets);
    case "device":
      return "/d/" + encodeURIComponent(route.device) + query(route.facets);
  }
}

// Stable order, because the URL is something people paste to each other and compare.
// Two views of the same thing must produce byte-identical links.
function query(facets: Facets): string {
  const params = new URLSearchParams();
  for (const key of FACET_KEYS) {
    const value = facets[key];
    if (value) params.set(key, value);
  }
  const s = params.toString();
  return s ? "?" + s : "";
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm test:unit`
Expected: PASS, 11 tests

- [ ] **Step 5: Typecheck and commit**

```bash
pnpm typecheck
git add web/src/router/routes.ts tests/unit/router.spec.ts
git commit -m "feat(console): pure route parsing, testable without a browser"
```

---

### Task 2: The router hook

**Files:**
- Create: `web/src/router/useRouter.ts`
- Test: covered by Task 5, which asserts two subscribers stay in step. Mocking `window.history` in Node would test the mock, but the multi-subscriber invariant is real and needs a browser.

**Interfaces:**
- Consumes: `Route`, `parsePath`, `formatPath` from Task 1.
- Produces: `useRouter(): { route: Route; navigate(to: Route | string, opts?: { replace?: boolean }): void }`. Task 3 and Task 4 import this.

- [ ] **Step 1: Write the implementation**

Create `web/src/router/useRouter.ts`:

```ts
import { useCallback, useSyncExternalStore } from "react";
import { formatPath, parsePath, type Route } from "./routes";

// One store for the whole app, because the URL is one thing.
//
// The obvious version of this hook keeps the route in useState and calls setRoute inside
// navigate(). That is a bug the moment two components call useRouter(): pushState does
// not fire popstate, so only the component that navigated learns about it and every
// other one renders the previous route forever. useSyncExternalStore is the primitive
// for exactly this shape — one external source, every subscriber on one snapshot.

const listeners = new Set<() => void>();

function emit() {
  for (const listener of listeners) listener();
}

// getSnapshot must return a referentially stable value or React re-renders forever, and
// parsePath builds a fresh object every call. So the parse is memoised on the URL
// string, which is the route's actual identity.
let cachedURL: string | null = null;
let cachedRoute: Route = { kind: "search" };

function snapshot(): Route {
  const url = window.location.pathname + window.location.search;
  if (url !== cachedURL) {
    cachedURL = url;
    cachedRoute = parsePath(window.location.pathname, window.location.search);
  }
  return cachedRoute;
}

// One popstate listener for N components rather than one each: the listener is attached
// when the first subscriber arrives and removed when the last leaves.
function subscribe(onChange: () => void): () => void {
  if (listeners.size === 0) window.addEventListener("popstate", emit);
  listeners.add(onChange);
  return () => {
    listeners.delete(onChange);
    if (listeners.size === 0) window.removeEventListener("popstate", emit);
  };
}

// useSyncExternalStore requires a server snapshot. The console is client-rendered, but
// returning the client one would touch `window` where it may not exist.
const serverSnapshot = (): Route => ({ kind: "search" });

export function useRouter() {
  const route = useSyncExternalStore(subscribe, snapshot, serverSnapshot);

  const navigate = useCallback((to: Route | string, opts?: { replace?: boolean }) => {
    const path = typeof to === "string" ? to : formatPath(to);
    if (path === window.location.pathname + window.location.search) return;
    if (opts?.replace) window.history.replaceState(null, "", path);
    else window.history.pushState(null, "", path);
    // pushState does not fire popstate. This line is what tells every subscriber.
    emit();
    // A new page starts at the top. Without this, following a link from halfway down a
    // session list lands you halfway down the next page.
    window.scrollTo(0, 0);
  }, []);

  return { route, navigate };
}
```

- [ ] **Step 2: Typecheck**

Run: `pnpm typecheck`
Expected: no errors

- [ ] **Step 3: Commit**

```bash
git add web/src/router/useRouter.ts
git commit -m "feat(console): a hand-rolled router over the History API"
```

---

### Task 3: Extract the session page

**Files:**
- Create: `web/src/pages/SessionPage.tsx`
- Modify: `web/src/App.tsx` — the `terminal`, `replay` and `failed` branches of the `View` switch move out.

**Interfaces:**
- Consumes: nothing from Tasks 1–2 yet; this task is a pure extraction so it can be reviewed on its own.
- Produces: `SessionPage(props: { session: Session; attach?: Attach; cast?: string; verdict?: Verdict; readOnly: boolean; watching?: string; onClose(): void })`. Task 4 renders it.

- [ ] **Step 1: Read what is being moved**

Read `web/src/App.tsx` and locate the JSX for the `terminal`, `replay` and `failed` cases (the branches that today render around `setView({ kind: "list" })` at lines ~616, ~656, ~694). Note every prop each branch reads from `App`'s state.

- [ ] **Step 2: Create the page with the same markup**

Create `web/src/pages/SessionPage.tsx` exporting `SessionPage`. Move the three branches in verbatim, choosing between them on the session's state rather than on a `View` tag:

```tsx
import type { Attach, Condition, Session, Verdict } from "../api";

export type SessionPageProps = {
  session: Session;
  attach?: Attach;          // present while the session is live
  cast?: string;            // present once a recording exists
  verdict?: Verdict;
  readOnly: boolean;
  watching?: string;
  failure?: { condition: Condition; detail: string; reference: string };
  onClose(): void;
};

// One page, three bodies. Which one renders is a fact about the session, not a route —
// so a link pasted into a ticket while a session is live still resolves after it ends.
export function SessionPage(props: SessionPageProps) {
  if (props.failure) return <FailedBody {...props.failure} onClose={props.onClose} />;
  if (props.attach) return <TerminalBody {...props} attach={props.attach} />;
  if (props.cast) return <ReplayBody {...props} cast={props.cast} />;
  return <FailedBody
    condition="not_found" detail="No recording for this session." reference=""
    onClose={props.onClose} />;
}
```

`TerminalBody`, `ReplayBody` and `FailedBody` are the three existing `View` branches
moved into this file **verbatim** — same class names, same markup, same props they read
from `App` today (around `App.tsx:616`, `:656` and `:694`). **This task changes no
visual output**, which is what makes Step 4 a meaningful check.

- [ ] **Step 3: Render it from App's existing switch**

In `App.tsx`, replace the three inlined branches with `<SessionPage ... onClose={() => setView({ kind: "list" })} />`. The `View` union still exists at this point — it is deleted in Task 4.

- [ ] **Step 4: Verify nothing changed**

Run: `pnpm tokens:check && pnpm typecheck && pnpm test`
Expected: PASS, all 163 existing tests. A failure here means the extraction changed behaviour.

- [ ] **Step 5: Commit**

```bash
git add web/src/pages/SessionPage.tsx web/src/App.tsx
git commit -m "refactor(console): lift the session out of App's View union"
```

---

### Task 4: Replace both state machines with routes

**Files:**
- Modify: `web/src/App.tsx`

**Interfaces:**
- Consumes: `useRouter` (Task 2), `SessionPage` (Task 3).
- Produces: nothing further; this is the last structural task.

- [ ] **Step 1: Delete the navigation state**

In `App.tsx`, remove `const [view, setView] = useState<View>(...)`, `const [adminPage, setAdminPage] = useState<AdminPage>("fleet")`, the `View` type, the `AdminPage` type and the `pages` array. Add `const { route, navigate } = useRouter();`.

- [ ] **Step 2: Switch on the route**

```tsx
switch (route.kind) {
  // Fleet keeps exactly the props App passes it today. Person and device render it
  // unchanged for now; increments 3 and 4 replace these two arms.
  case "search":
  case "person":
  case "device":
    return <Fleet client={client.current} devices={devices} onOpen={open} />;
  case "session":
    return <SessionPage {...sessionProps} onClose={() => navigate({ kind: "search" })} />;
  case "permissions":
    return <Permissions client={client.current} />;
  case "sql":
    return <SQLExplorer client={client.current} />;
}
```

Copy each component's prop list from its current call site in `App.tsx` rather than
inventing one; this task is a rewiring, and a changed prop here is a behaviour change
hiding inside a refactor.

Person and device deliberately render the existing `Fleet` for now. **This increment ships URLs, not new pages** — the pages arrive in increments 3 and 4, and pretending otherwise here would make this task unreviewable.

- [ ] **Step 3: Replace `refresh(scope)`**

Delete `refresh(scope: AdminPage | "all")`. Each rendered component fetches what it needs in its own `useEffect`, keyed on the route's params. The `AdminPage`-shaped scope argument has no meaning once no single component owns all the data.

- [ ] **Step 4: Point the nav at routes**

Replace the four tab buttons with three links that call `navigate({ kind: "search" })`, `navigate({ kind: "permissions" })`, `navigate({ kind: "sql" })`.

- [ ] **Step 5: Verify**

Run: `pnpm tokens:check && pnpm typecheck && pnpm test`
Expected: PASS. If `tests/console/*` fails, a test asserted on tab-clicking; update the test to navigate by URL — that is the point of the change, not a regression.

- [ ] **Step 6: Commit**

```bash
git add web/src/App.tsx
git commit -m "feat(console): routes replace the View union and the AdminPage tabs"
```

---

### Task 5: Prove a cold deep link works

**Files:**
- Create: `tests/console/deeplink.spec.ts`

**Interfaces:**
- Consumes: everything above.
- Produces: nothing.

- [ ] **Step 1: Write the failing test**

Model the setup on the existing `tests/console/login.spec.ts` — it already starts a real gateway. Create `tests/console/deeplink.spec.ts`:

```ts
// The whole point of the increment, asserted once: a URL pasted into a ticket resolves
// on a cold load. Before this change every screen was reachable only by clicking from
// the Fleet tab, so this test could not have been written at all.

import { test, expect } from "@playwright/test";

test("a session URL resolves on a cold load", async ({ page }) => {
  const id = await openASessionAndReturnItsID(page);   // helper, per login.spec.ts
  await page.goto(`/s/${id}`);
  await expect(page.getByText(id)).toBeVisible();
});

test("the back button returns to where you were", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("link", { name: "Permissions" }).click();
  await expect(page).toHaveURL(/\/permissions$/);
  await page.goBack();
  await expect(page).toHaveURL(/\/$/);
});

test("an unknown path renders search rather than an error", async ({ page }) => {
  await page.goto("/nope/whatever");
  await expect(page.getByRole("heading")).toBeVisible();
});

// The sidebar and the page body both read the route. With the route held in useState
// per component this passes on first load and fails after navigating, because pushState
// does not fire popstate and only one of them would have been told.
test("every subscriber sees the same route after navigating", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("link", { name: "Permissions" }).click();
  await expect(page).toHaveURL(/\/permissions$/);
  await expect(page.getByRole("link", { name: "Permissions" })).toHaveClass(/on/);
  await expect(page.getByRole("heading", { name: "Permissions" })).toBeVisible();
});
```

- [ ] **Step 2: Run it to verify it fails**

Run: `pnpm exec playwright test --project=console deeplink`
Expected: FAIL before Task 4 is merged; PASS after.

- [ ] **Step 3: Run the whole suite**

Run: `pnpm test`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add tests/console/deeplink.spec.ts
git commit -m "test(console): a deep link resolves cold, and the back button works"
```

---

## Done when

- Every screen has a URL, and pasting one into a fresh tab renders it.
- Browser back and forward work.
- `App.tsx` no longer contains `View`, `AdminPage` or `refresh(scope)`.
- `pnpm test` is green, `dependencies` is still `["asciinema-player"]`.

## Not in this increment

Person page, Device page split, `Since`/`Until` in the Go API, the search screen's actual search. `/p/` and `/d/` route correctly and render the existing Fleet component; increments 3 and 4 fill them in.
