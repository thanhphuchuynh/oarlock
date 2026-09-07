// One session, three bodies, and how it gets whichever one applies — moved from
// `App.tsx` verbatim, along with the two click handlers that mint the ticket `SessionRoute`
// can then pick up instead of re-fetching it.
//
// `/s/{id}` loads its own data: fetch the session, and branch on what it is. A live
// session mints an attach ticket the same way a reload would (renewAttach is refused to
// anyone but the session's own operator, so this is exactly the ticket an owner
// reattaching gets); a closed, recorded one fetches the cast; anything else is the failed
// body. A `bypass` from a click that already minted the right ticket — including a Watch
// ticket renewAttach could never grant — is used once and then forgotten, so a later visit
// to the same URL (a reload, the back button) goes through the same fetch as a pasted
// link.
//
// `App.tsx` still owns `opening`, `bypass` and `failure`: they gate the whole page body
// (the nav rail has to stay reachable while any of them is on screen — see App.tsx's own
// popstate handling for why), so they live above every page rather than inside one of
// them. This file owns the logic that fills them in.

import { useEffect, useState } from "react";
import { get as getCondition, type Condition } from "@oarlock/terminal/conditions";
import type { Verdict } from "@oarlock/terminal";
import { ApiError, type Attach, type Client, type Session } from "../api";
import { Waits, type Step } from "../components/Waits";
import { SessionPage } from "./SessionPage";
import type { Route } from "../router/routes";

type Navigate = (to: Route, opts?: { replace?: boolean }) => void;

// What each click handler below already produced, waiting to be picked up the one time
// its route is reached — see the file comment for why this exists at all.
export type SessionBypass =
  | { sessionID: string; kind: "live"; session: Session; attach: Attach; readOnly: boolean; watching?: string }
  | { sessionID: string; kind: "replay"; session: Session; cast: string; verdict?: Verdict };

/** The wait between clicking Shell and having a session id to route to. */
export type Opening = { device: string; steps: Step[]; reference?: string };

/** The one place that reads a recording — the click that already has the `Session` row,
 *  and the cold load of `/s/{id}` that has only its id. Kept as a fetch rather than a
 *  `Client` method because it returns a raw cast file next to the JSON, same as before. */
export async function fetchRecording(token: string, sessionID: string): Promise<{ cast: string; verdict?: Verdict }> {
  const res = await fetch(`/api/v1/recordings/${encodeURIComponent(sessionID)}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) {
    const body: unknown = await res.json().catch(() => ({}));
    throw new ApiError(res.status, body as Record<string, unknown>);
  }
  return (await res.json()) as { cast: string; verdict?: Verdict };
}

/** Opening a shell on a device — the "Open" button on `DevicePage`, and the submit of
 *  `OpenByIdDialog` on `SearchPage`. Both call this the same way; the caller's own dialog
 *  or reason field is its business, not this function's. */
export async function openSession(params: {
  client: Client;
  device: string;
  reason: string;
  me: string;
  setMe: (principal: string) => void;
  setOpening: (opening: Opening | null) => void;
  setBypass: (bypass: SessionBypass | null) => void;
  navigate: Navigate;
  refresh: () => void;
}): Promise<void> {
  const { client, device, reason, me, setMe, setOpening, setBypass, navigate, refresh } = params;
  if (!device) return;

  // The two named waits. The first is already true by the time this runs — the API
  // accepted the request, which means authorisation passed — so it starts done rather
  // than pretending to work.
  const steps: Step[] = [
    { key: "auth", label: `Authorised as ${me || "you"}`, state: "done" },
    { key: "wake", label: `Waking ${device}…`, state: "waiting", budget: "up to 30s" },
    { key: "tunnel", label: "Opening the tunnel", state: "pending" },
  ];
  setOpening({ device, steps });

  try {
    const { session, attach } = await client.open(device, reason, { cols: 120, rows: 32 });
    setMe(session.principal);
    setOpening({
      device,
      steps: steps.map((s) =>
        s.key === "wake"
          ? { ...s, label: `${device} answered`, state: "done" }
          : s.key === "tunnel"
            ? { ...s, state: "waiting" as const, budget: "a moment" }
            : s,
      ),
    });
    // The steps disappear on success: they are scaffolding for a wait, not a log. What
    // opened this session already has its ticket, so the route that renders it does not
    // have to mint a second one.
    setBypass({ sessionID: session.id, kind: "live", session, attach, readOnly: false });
    setOpening(null);
    navigate({ kind: "session", session: session.id });
    refresh();
  } catch (err) {
    const e = err instanceof ApiError ? err : null;
    const condition = e?.condition ?? getCondition("internal");
    // The step that failed *is* the diagnosis, so the failure replaces its own line
    // rather than appearing as a banner somewhere else.
    setOpening({
      device,
      ...(e?.reference ? { reference: e.reference } : {}),
      steps: steps.map((s) =>
        s.key === "wake"
          ? { ...s, state: "failed" as const, failure: condition, ...(e?.detail ? { detail: e.detail } : {}) }
          : s,
      ),
    });
  }
}

/** Opening a session from its own row on the Person or Device page's timeline: attach
 *  (falling back to observe exactly the way a cold link to somebody else's live session
 *  already does — see `SessionRoute`'s own cold load below), or fetch the recording to
 *  replay. Mints whatever ticket that takes and hands it to `/s/{id}` as a bypass, so the
 *  route's own cold-load fetch is not repeated the moment it mounts.
 *
 *  Deliberately does not report to any top-level failure state: `Timeline`'s `SessionRow`
 *  awaits this promise and renders whatever it rejects with in place — on the row that
 *  made the offer — rather than replacing the whole page for a refusal that belongs to
 *  one line of a list. */
export async function openSessionRow(params: {
  client: Client;
  token: string;
  session: Session;
  setBypass: (bypass: SessionBypass | null) => void;
  navigate: Navigate;
}): Promise<void> {
  const { client, token, session, setBypass, navigate } = params;
  if (session.live) {
    try {
      const a = await client.renewAttach(session.id);
      setBypass({ sessionID: session.id, kind: "live", session, attach: a, readOnly: false });
    } catch (err) {
      // A `not_found` here, after the row itself already proved the session exists,
      // can only mean this principal is not its operator — the same fact the cold
      // load below falls back on `observe` for.
      if (!(err instanceof ApiError) || err.code !== "not_found") throw err;
      const a = await client.observe(session.id);
      setBypass({
        sessionID: session.id,
        kind: "live",
        session,
        attach: a,
        readOnly: true,
        watching: session.principal,
      });
    }
    navigate({ kind: "session", session: session.id });
    return;
  }
  if (session.recording_state === "recorded") {
    // The verdict comes from the gateway, which is the only place that has the manifest
    // and a key the deployment trusts. If it did not send one, the player renders
    // "unverified" — which is the honest answer, and not the same as fine.
    const { cast, verdict } = await fetchRecording(token, session.id);
    setBypass({ sessionID: session.id, kind: "replay", session, cast, ...(verdict ? { verdict } : {}) });
    navigate({ kind: "session", session: session.id });
    return;
  }
  // Nothing to check first: a closed, unrecorded session has no permission question to
  // ask, only the fact that there is nothing to replay — which `SessionPage`'s own cold
  // load renders as itself, not as a failure (see B1). No bypass to mint either: the
  // route's cold fetch below reaches the identical state a pasted link would.
  navigate({ kind: "session", session: session.id });
}

type SessionRouteState =
  | { kind: "loading" }
  | { kind: "live"; session: Session; attach: Attach; readOnly: boolean; watching?: string }
  | { kind: "replay"; session: Session; cast: string; verdict?: Verdict }
  // A closed session with nothing to replay — a fact about the session, never a failure.
  // See B1: this used to collapse into `failed`, which discarded the session it was
  // reporting on and told the reader it did not exist.
  | { kind: "unrecorded"; session: Session }
  | { kind: "failed"; condition: Condition; detail: string; reference: string };

export function SessionRoute({
  client,
  token,
  id,
  bypass,
  onConsumeBypass,
  onBack,
  refresh,
}: {
  client: Client;
  token: string;
  id: string;
  bypass: SessionBypass | null;
  onConsumeBypass: () => void;
  onBack: () => void;
  /** Refreshes the fleet page's session/device lists — void refresh() from App. */
  refresh: () => void;
}) {
  const [state, setState] = useState<SessionRouteState>({ kind: "loading" });

  useEffect(() => {
    if (bypass && bypass.sessionID === id) {
      setState(
        bypass.kind === "live"
          ? {
              kind: "live",
              session: bypass.session,
              attach: bypass.attach,
              readOnly: bypass.readOnly,
              ...(bypass.watching ? { watching: bypass.watching } : {}),
            }
          : { kind: "replay", session: bypass.session, cast: bypass.cast, ...(bypass.verdict ? { verdict: bypass.verdict } : {}) },
      );
      onConsumeBypass();
      return;
    }

    let cancelled = false;
    setState({ kind: "loading" });
    void (async () => {
      try {
        const session = await client.session(id);
        if (cancelled) return;
        if (session.live) {
          // The session's own operator reattaches — `renewAttach` is refused to anyone
          // else (apisrv.go's renewAttach: "Only the operator who opened it"). Try that
          // first rather than pre-judging ownership from client-side state: `me` is
          // only ever learned from opening a session yourself or an OIDC handoff, so on
          // a cold link — the case this route exists for — it is routinely still ""
          // when this runs, same as every other principal's `me` would be. Ownership
          // is a fact the gateway already has to check, so ask it.
          //
          // A `not_found` here, after `client.session(id)` already proved the session
          // exists, can only mean this principal is not its operator (renewAttach's
          // check happens before it mints or revokes anything, so a non-owner's attempt
          // costs nothing) — the same fact Fleet's own Watch button already acts on by
          // minting through `observe` instead (api.ts's `observe`, not `renewAttach`).
          // So the deep link falls back to the ticket that button would have minted,
          // with the same shape: read-only, watching whoever the session belongs to.
          try {
            const attach = await client.renewAttach(id);
            if (!cancelled) setState({ kind: "live", session, attach, readOnly: false });
          } catch (err) {
            if (!(err instanceof ApiError) || err.code !== "not_found") throw err;
            const attach = await client.observe(id);
            if (!cancelled) {
              setState({ kind: "live", session, attach, readOnly: true, watching: session.principal });
            }
          }
          return;
        }
        if (session.recording_state === "recorded") {
          const { cast, verdict } = await fetchRecording(token, id);
          if (!cancelled) setState({ kind: "replay", session, cast, ...(verdict ? { verdict } : {}) });
          return;
        }
        // Closed and never recorded is a fact about this session, not a failure to
        // report — see B1. The session exists (the fetch above just proved it) and its
        // row is what brought the reader here, so it renders as itself: header,
        // metadata, and a panel saying plainly there is nothing to replay.
        if (!cancelled) {
          setState({ kind: "unrecorded", session });
        }
      } catch (err) {
        if (cancelled) return;
        const e = err instanceof ApiError ? err : null;
        setState({
          kind: "failed",
          condition: e?.condition ?? getCondition("internal"),
          detail: e?.detail ?? String(err),
          reference: e?.reference ?? "",
        });
      }
    })();
    return () => {
      cancelled = true;
    };
    // `bypass` is deliberately not a dependency beyond the id check above: it is consumed
    // at most once, the moment its own route is reached, never re-applied to a later
    // render of the same id.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [client, token, id]);

  if (state.kind === "loading") {
    return <Waits steps={[{ key: "session", label: "Loading the session…", state: "waiting" }]} />;
  }

  if (state.kind === "live") {
    return (
      <SessionPage
        session={state.session}
        attach={state.attach}
        readOnly={state.readOnly}
        {...(state.watching ? { watching: state.watching } : {})}
        onClose={onBack}
        onLeave={() => {
          onBack();
          refresh();
        }}
        onSessionEnded={refresh}
        renewTicket={() => client.renewAttach(state.session.id).then((a) => a.ticket)}
      />
    );
  }

  if (state.kind === "replay") {
    return (
      <SessionPage
        session={state.session}
        cast={state.cast}
        {...(state.verdict ? { verdict: state.verdict } : {})}
        readOnly={false}
        onClose={onBack}
        onLeave={onBack}
        onSessionEnded={() => {}}
        renewTicket={() => client.renewAttach(state.session.id).then((a) => a.ticket)}
      />
    );
  }

  if (state.kind === "unrecorded") {
    return (
      <SessionPage
        session={state.session}
        readOnly={false}
        onClose={onBack}
        onLeave={onBack}
        onSessionEnded={() => {}}
        renewTicket={() => Promise.reject(new Error("renewTicket has no session to renew a ticket for"))}
      />
    );
  }

  return (
    <SessionPage
      readOnly={false}
      failure={{ condition: state.condition, detail: state.detail, reference: state.reference }}
      onClose={onBack}
      onLeave={onBack}
      onSessionEnded={() => {}}
      renewTicket={() => Promise.reject(new Error("renewTicket has no session to renew a ticket for"))}
    />
  );
}
