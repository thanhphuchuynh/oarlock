// The Person page — the two questions an auditor actually arrives with: what did this
// person do, and were they allowed to. Nothing in the console before this was
// principal-shaped; everything here is organised around the person rather than around a
// session list or a permission table.
//
// Two stacked sections, in the order the design puts them: what happened, then whether it
// was permitted — using the same `Timeline` and `Grants` the Device page uses. That
// sharing is the point: this page and `Fleet.tsx`'s expanded row used to each carry their
// own copy of the grants panel, and the two had already drifted. One component now, two
// callers.

import { useEffect, useState } from "react";
import { ApiError, type Client, type Session } from "../api";
import type { Facets, Route } from "../router/routes";
import { Grants, type GrantsState } from "../components/Grants";
import { Timeline, type TimelineState } from "../components/Timeline";
import { FacetBar, type FacetSpec } from "../components/Facets";

type Navigate = (to: Route, opts?: { replace?: boolean }) => void;

// The default window, put into the URL rather than kept only in component state — see the
// effect below.
const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;

const FACET_SPECS: readonly FacetSpec[] = [
  { key: "since", label: "since" },
  { key: "until", label: "until" },
  { key: "device", label: "device" },
  { key: "state", label: "state" },
];

export function PersonPage({
  client,
  principal,
  facets,
  navigate,
  onOpenSession,
}: {
  client: Client;
  principal: string;
  facets: Facets;
  navigate: Navigate;
  onOpenSession: (session: Session) => Promise<void>;
}) {
  // Default to the last 30 days when no `since` facet is present, and land the default in
  // the URL rather than leaving it in state. A default that lives only here produces a
  // link that does not reproduce what the sender was looking at — the same reason every
  // other facet already round-trips through `route.facets` instead of local state.
  useEffect(() => {
    if (facets.since) return;
    // Midnight UTC, not "now minus thirty days". The old value carried milliseconds, so
    // it changed on every load and no two visits to this page produced the same URL —
    // which quietly broke the property the whole design rests on: that the view a person
    // is looking at is a link they can send. A window that starts on a day boundary is
    // also the one an auditor means when they say "the last month".
    const start = new Date(Date.now() - THIRTY_DAYS_MS);
    const since = `${start.toISOString().slice(0, 10)}T00:00:00Z`;
    navigate({ kind: "person", principal, facets: { ...facets, since } }, { replace: true });
  }, [facets, navigate, principal]);

  const [sessions, setSessions] = useState<TimelineState>({ kind: "loading" });
  // Bumped by the Timeline's own "Try again": a plain re-run of the effect below, on
  // demand, rather than a second copy of the fetch a retry button can call directly.
  const [sessionsRetry, setSessionsRetry] = useState(0);

  useEffect(() => {
    // Waits for the effect above to land `since` in the URL. The very first render of a
    // bare `/p/{id}` has no `since` yet; fetching unbounded here would just be redone the
    // moment the default arrives.
    if (!facets.since) return;
    // Captured once, outside the closure below: TypeScript's narrowing of `!facets.since`
    // does not reach inside the async IIFE, since the property access — not this local —
    // is what the check refined.
    const since = facets.since;
    // B3: a superseded request used to win the race — clearing a facet or a fast retry
    // fired a second request while the first was still in flight, and whichever settled
    // last overwrote state with its answer regardless of which one was current. Guarded
    // the same way `SessionRoute`'s own cold load is: a `cancelled` flag closed over by
    // this effect's own async call, set by its cleanup the moment a newer run starts.
    let cancelled = false;
    setSessions({ kind: "loading" });
    void (async () => {
      try {
        const { sessions: rows } = await client.sessions({
          principal,
          since,
          ...(facets.until ? { until: facets.until } : {}),
          ...(facets.device ? { device: facets.device } : {}),
          ...(facets.state ? { state: facets.state } : {}),
          limit: 100,
          // Newest-first from the gateway, not sorted here after the fact: a window
          // with more than 100 sessions has more than one page, and a client-side sort
          // of a bounded page cannot recover the rows the page never contained (B2).
          newest: true,
        });
        if (!cancelled) setSessions({ kind: "ready", sessions: rows });
      } catch (error) {
        if (!cancelled) setSessions({ kind: "failed", error });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [client, principal, facets.since, facets.until, facets.device, facets.state, sessionsRetry]);

  const [access, setAccess] = useState<GrantsState>({ kind: "loading" });
  const [accessRetry, setAccessRetry] = useState(0);

  useEffect(() => {
    // Same guard as the sessions load above, and for the same reason (B3): this panel
    // has its own retry button and its own subject, so it can race independently of the
    // timeline beside it.
    let cancelled = false;
    setAccess({ kind: "loading" });
    void (async () => {
      try {
        const result = await client.principalAccess(principal);
        if (!cancelled) {
          setAccess({ kind: "ready", rules: result.rules, adminActions: result.admin_actions });
        }
      } catch (caught) {
        if (cancelled) return;
        if (caught instanceof ApiError && caught.code === "not_authorized") {
          setAccess({ kind: "refused", error: caught });
          return;
        }
        setAccess({
          kind: "failed",
          message: caught instanceof Error ? caught.message : String(caught),
        });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [client, principal, accessRetry]);

  return (
    <div className="grid gap-8" data-testid="person-page">
      <div>
        <p className="label">Person</p>
        <h1 className="mono text-xl font-semibold">{principal}</h1>
      </div>

      <section className="grid gap-3">
        <h2 className="text-lg font-semibold">
          What they did{" "}
          <span className="text-sm font-normal text-fg-muted">
            — the timeline, live and closed in one list
          </span>
        </h2>
        <FacetBar
          facets={facets}
          specs={FACET_SPECS}
          testId="person-facets"
          onClear={(key) => {
            const rest = { ...facets };
            delete rest[key];
            navigate({ kind: "person", principal, facets: rest });
          }}
        />
        <div className="panel">
          <Timeline
            state={sessions}
            onRetry={() => setSessionsRetry((n) => n + 1)}
            onOpenSession={onOpenSession}
            testId="person-sessions"
            variant="person"
          />
        </div>
      </section>

      <section className="grid gap-3">
        <h2 className="text-lg font-semibold">
          What they were allowed to do{" "}
          <span className="text-sm font-normal text-fg-muted">
            — read-only; the answer to "was this permitted?"
          </span>
        </h2>
        <Grants
          state={access}
          onRetry={() => setAccessRetry((n) => n + 1)}
          testId="person-access"
          variant="person"
          subject={principal}
        />
        <div>
          <button className="btn btn-quiet" onClick={() => navigate({ kind: "permissions" })}>
            Open the policy editor →
          </button>
        </div>
      </section>
    </div>
  );
}
