// The admin console.
//
// It was written as a reference implementation — a demonstration of the arrangement — and
// that is no longer what it is. It is how this fleet is administered, so it is built as
// the product surface it turned out to be: devices, sessions, policy and the operational
// database, each on its own page, organised around the object rather than around the API
// endpoint that returns it.
//
// What it still owes the component it embeds: the disclosure, the waits, the failure
// screens and the replay verdict all come from the places the component and the gateway
// already agree on — pkg/condition, the generated conditions table, the gateway's own
// verifier — rather than being re-stated here where they could drift. An integrator
// embedding `<Terminal>` inherits none of this file, and should not have to.

import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { get as getCondition, type Condition } from "@oarlock/terminal/conditions";
import type { Verdict } from "@oarlock/terminal";
import {
  ApiError,
  Client,
  endSession,
  type Attach,
  type Device,
  type Session,
} from "./api";
import { Fleet } from "./Fleet";
import { Permissions } from "./Permissions";
import { SSHAccess } from "./SSHAccess";
import { SQLExplorer } from "./SQLExplorer";
import { Waits, type Step } from "./Waits";
import { SessionPage } from "./pages/SessionPage";
import { PersonPage } from "./pages/PersonPage";
import { useRouter } from "./router/useRouter";
import { SignIn } from "./components/SignIn";

const tokenKey = "oarlock.token";

// The three destinations left on the nav rail once routes replace the tabs. "Sessions"
// has no route of its own — a session is reached from its device's own row, from a
// person's page, or by the link in `route.session` — so it is not a page here either.
type NavPage = "search" | "permissions" | "sql";

const pages: { id: NavPage; label: string; blurb: string }[] = [
  { id: "search", label: "Fleet", blurb: "Devices, who can reach them, and what has been run on them." },
  { id: "permissions", label: "Permissions", blurb: "Who may perform which actions on which devices." },
  { id: "sql", label: "SQL Explorer", blurb: "Read-only access to operational SQLite data." },
];

// What a click on Attach, Watch, Replay or "open a shell" already produced, waiting to be
// picked up the one time its route is reached. `/s/{id}` always loads its own data (see
// `SessionRoute` below) — that is what lets a pasted link work cold — but a ticket already
// in hand needs no second round trip, and `renewAttach` is refused to anyone but the
// session's own operator (internal/apisrv/apisrv.go's renewAttach: "Only the operator who
// opened it"), which is exactly wrong for a Watch ticket minted for somebody else's
// session. So the click handlers below keep minting through the endpoint that already
// grants the right thing, and hand the result to the route rather than re-deriving it.
type SessionBypass =
  | { sessionID: string; kind: "live"; session: Session; attach: Attach; readOnly: boolean; watching?: string }
  | { sessionID: string; kind: "replay"; session: Session; cast: string; verdict?: Verdict };

export function App() {
  // The token lives in sessionStorage, not localStorage: a shared secret in a browser
  // should not outlive the tab it was typed into. It is also a development mechanism —
  // static tokens refuse to start outside dev — and a real deployment authenticates the
  // browser through its own login.
  const [token, setToken] = useState(() => sessionStorage.getItem(tokenKey) ?? "");
  const client = useRef(new Client("", token));
  client.current.setToken(token);

  const { route, navigate } = useRouter();

  const [sessions, setSessions] = useState<Session[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [me, setMe] = useState("");
  const [listError, setListError] = useState<Condition | null>(null);
  const [deviceDialog, setDeviceDialog] = useState<Device | "new" | null>(null);
  // Opening by typed id is the secondary path: it is how you reach a device whose row is
  // not in front of you, and how an unregistered id gets its own failure screen instead
  // of being unreachable through the UI.
  const [openByID, setOpenByID] = useState<{ device: string; reason: string } | null>(null);
  // The wait between clicking Shell and having a session id to route to — there is no URL
  // for "a device is waking up", so this stays local state rather than a route.
  const [opening, setOpening] = useState<{ device: string; steps: Step[]; reference?: string } | null>(null);
  // The full-page failure screen for an action taken from the fleet page (kill, disable,
  // delete, and the like) — as before, it replaces whatever page it interrupted.
  const [failure, setFailure] = useState<{ condition: Condition; detail: string; reference: string } | null>(null);
  // A ticket a click just minted, waiting for `/s/{id}`'s render to pick it up once. See
  // `SessionBypass` above for why this exists at all.
  const [bypass, setBypass] = useState<SessionBypass | null>(null);

  // What each poll asks for, and how often.
  //
  // Three lists on a four-second timer was 45 requests a minute doing nothing, against a
  // default API budget of 120 — more than a third of an operator's allowance spent on an
  // idle tab, and enough to start collecting 429s with a second tab open. Two changes.
  //
  // **Ask for what is on screen.** Permissions and SQL Explorer are not live views, so
  // they poll nothing at all; the fleet page asks for both lists it renders.
  //
  // **Stop asking for `/agents`.** The gateway computes `device.connected` from exactly
  // the list that endpoint returns, so fetching both was the same duplication the fleet
  // page used to show: one fact, two sources, and a window where they disagree.
  const refresh = useCallback(async () => {
    if (!token) return;
    try {
      const [live, fleet] = await Promise.all([client.current.sessions(), client.current.devices()]);
      setSessions(live.sessions);
      setDevices(fleet.devices);
      setListError(null);
      if (live.sessions.length > 0 && !me) setMe(live.sessions[0]!.principal);
    } catch (err) {
      setListError(err instanceof ApiError ? err.condition : getCondition("internal"));
    }
  }, [token, me]);

  useEffect(() => {
    void refresh();
    // A page that renders neither list has nothing to poll for. The person page fetches
    // its own, principal-scoped session list instead of reading this one.
    const rendersFleet = route.kind === "search" || route.kind === "device";
    if (!rendersFleet) return;
    const t = setInterval(() => {
      // A background tab polling a rate-limited API is pure waste.
      if (document.hidden) return;
      void refresh();
    }, 4000);
    // A tab coming back to the front is behind by however long it was away, so it asks
    // for everything once rather than waiting out the interval.
    const onVisible = () => {
      if (!document.hidden) void refresh();
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      clearInterval(t);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [refresh, route.kind]);

  function saveToken(t: string) {
    sessionStorage.setItem(tokenKey, t);
    setToken(t);
  }

  // Handed to <SignIn>: a token exists now, from a completed OIDC handoff (which also
  // names the principal the provider vouched for) or a pasted static one (principal
  // unknown until the fleet's own session list supplies it — see `refresh` above).
  function signedIn(t: string, principal: string) {
    if (principal) setMe(principal);
    saveToken(t);
  }

  // The browser's own Back/Forward is the one way to change `route` that `goToPage`
  // cannot reach — it fires `popstate` directly, never a click on the nav rail — so a
  // wedged wait or failure survived it exactly as it survived everything else before this
  // fix. A `useEffect` keyed on `[route]` would also catch this, but it would catch
  // `attach`/`observe`/`replay`'s own navigate calls too, and those need to be left
  // alone: Fleet stays mounted while one of them is in flight (none of them touch
  // `opening`), so clicking Shell on another device while a Watch ticket is still
  // pending is reachable, and a route-keyed effect clearing `opening` there tears a wait
  // that is genuinely still pending out from under `openSession` — reproduced: the
  // in-flight open's *later* resolution calls `setOpening` again, unmounting the very
  // `SessionRoute` the popstate-style clear had just revealed and replacing it with a
  // stale, unrelated wait/failure screen while the URL still names the session. Listening
  // for `popstate` specifically reaches Back/Forward without going anywhere near that
  // path, because `pushState` — what every one of those calls uses — never fires it.
  useEffect(() => {
    const onPopState = () => {
      setOpening(null);
      setFailure(null);
    };
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  async function openSession(device: string, reason: string) {
    if (!device) return;
    setOpenByID(null);

    // The two named waits. The first is already true by the time this runs — the API
    // accepted the request, which means authorisation passed — so it starts done rather
    // than pretending to work.
    const steps: Step[] = [
      { key: "auth", label: `Authorised as ${me || "you"}`, state: "done" },
      {
        key: "wake",
        label: `Waking ${device}…`,
        state: "waiting",
        budget: "up to 30s",
      },
      { key: "tunnel", label: "Opening the tunnel", state: "pending" },
    ];
    setOpening({ device, steps });

    try {
      const { session, attach } = await client.current.open(device, reason, {
        cols: 120,
        rows: 32,
      });
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
      void refresh();
    } catch (err) {
      const e = err instanceof ApiError ? err : null;
      const condition = e?.condition ?? getCondition("internal");
      // The step that failed *is* the diagnosis, so the failure replaces its own line
      // rather than appearing as a banner somewhere else.
      setOpening({
        device,
        // `exactOptionalPropertyTypes` is on, so an absent field is absent rather than
        // present-and-undefined. That is the setting doing its job: "there is no
        // reference" and "the reference is undefined" are the same thing to a reader and
        // different things to a renderer.
        ...(e?.reference ? { reference: e.reference } : {}),
        steps: steps.map((s) =>
          s.key === "wake"
            ? {
                ...s,
                state: "failed" as const,
                failure: condition,
                ...(e?.detail ? { detail: e.detail } : {}),
              }
            : s,
        ),
      });
    }
  }

  async function attach(s: Session) {
    try {
      const a = await client.current.renewAttach(s.id);
      setBypass({ sessionID: s.id, kind: "live", session: s, attach: a, readOnly: false });
      navigate({ kind: "session", session: s.id });
    } catch (err) {
      fail(err);
    }
  }

  async function observe(s: Session) {
    try {
      const a = await client.current.observe(s.id);
      setBypass({
        sessionID: s.id,
        kind: "live",
        session: s,
        attach: a,
        readOnly: true,
        watching: s.principal,
      });
      navigate({ kind: "session", session: s.id });
    } catch (err) {
      fail(err);
    }
  }

  async function replay(s: Session) {
    try {
      const { cast, verdict } = await fetchRecording(s.id);
      // The verdict comes from the gateway, which is the only place that has the manifest
      // and a key the deployment trusts. If it did not send one, the player renders
      // "unverified" — which is the honest answer, and not the same as fine.
      setBypass({ sessionID: s.id, kind: "replay", session: s, cast, ...(verdict ? { verdict } : {}) });
      navigate({ kind: "session", session: s.id });
    } catch (err) {
      fail(err);
    }
  }

  // The one place that reads a recording — the click that already has the `Session` row,
  // and the cold load of `/s/{id}` that has only its id. Kept as a fetch rather than a
  // `Client` method because it returns a raw cast file next to the JSON, same as before.
  async function fetchRecording(sessionID: string): Promise<{ cast: string; verdict?: Verdict }> {
    const res = await fetch(`/api/v1/recordings/${encodeURIComponent(sessionID)}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) {
      const body: unknown = await res.json().catch(() => ({}));
      throw new ApiError(res.status, body as Record<string, unknown>);
    }
    return (await res.json()) as { cast: string; verdict?: Verdict };
  }

  async function kill(s: Session) {
    // States the consequence rather than asking a question.
    if (!confirm(`End the session on ${s.device_id}?\n\nThe operator's shell closes ` +
      `immediately and the recording is finalised. This cannot be undone.`)) {
      return;
    }
    try {
      await client.current.kill(s.id, "admin_kill");
      void refresh();
    } catch (err) {
      fail(err);
    }
  }

  async function disconnectAgent(deviceID: string) {
    if (!confirm(`Stop ${deviceID}?\n\nThe agent exits on that device. ` +
      `Start oarlock-agent there again to reconnect it.`)) {
      return;
    }
    try {
      await client.current.disconnectAgent(deviceID);
      void refresh();
    } catch (err) {
      fail(err);
    }
  }

  async function createDevice(input: DeviceForm): Promise<string | null> {
    try {
      await client.current.createDevice(devicePayload(input));
      await refresh();
      return null;
    } catch (err) {
      return deviceOperationError(err);
    }
  }

  async function updateDevice(input: DeviceForm): Promise<string | null> {
    try {
      await client.current.updateDevice(input.id, devicePayload(input));
      await refresh();
      return null;
    } catch (err) {
      return deviceOperationError(err);
    }
  }

  async function toggleDevice(candidate: Device) {
    const enabled = candidate.enabled !== false;
    if (enabled && !confirm(`Disable ${candidate.id}?\n\nNew shells will be refused and a connected agent will be stopped. Session history remains available.`)) {
      return;
    }
    const input = formFromDevice(candidate);
    const error = await updateDevice({ ...input, enabled: !enabled });
    if (error) {
      fail(new Error(error));
    }
  }

  async function deleteDevice(deviceID: string) {
    if (!confirm(`Delete ${deviceID}?\n\nExisting sessions stay in the ledger, but new sessions cannot target this device until it is added again.`)) {
      return;
    }
    try {
      await client.current.deleteDevice(deviceID);
      void refresh();
    } catch (err) {
      fail(err);
    }
  }

  function fail(err: unknown) {
    const e = err instanceof ApiError ? err : null;
    setFailure({
      condition: e?.condition ?? getCondition("internal"),
      detail: e?.detail ?? String(err),
      reference: e?.reference ?? "",
    });
  }

  // Nothing past this point is rendered until there is a token: SignIn owns everything
  // about getting one (which flavour to show, the OIDC handoff, the pasted-token form).
  if (!token) {
    return <SignIn onSignedIn={signedIn} />;
  }

  const signOut = () => {
    // The gateway first, then this tab. It holds nothing durable — no server-side
    // session — but the one-hop cookies should not outlive a deliberate sign-out.
    void endSession();
    sessionStorage.removeItem(tokenKey);
    setToken("");
  };

  // The nav rail renders unconditionally — it is meant to stay reachable even while a
  // wait or a full-page failure owns the body — so it is the one gesture that has to
  // clear what it is leaving behind. `View` used to hold "which screen" and "am I mid
  // flow" in one variable, so `setView({kind:"list"})` cleared both at once; splitting
  // that into `route` + `opening` + `failure` means the nav click has to make both
  // assignments itself rather than getting the second one for free.
  //
  // This is deliberately *not* a `useEffect` on `[route]`: `attach`, `observe` and
  // `replay` also navigate to a session, and `observe`'s ticket can resolve while an
  // unrelated `openSession` wait is genuinely still in flight (click Watch, then click
  // Shell on another device before the watch ticket lands). An effect keyed on `route`
  // cannot tell "the operator just escaped a dead screen" from "some other in-flight
  // action just finished and happened to navigate" — it would clear the still-live wait
  // out from under `openSession`, which is the exact "replacing one bug with a worse
  // one" this fix has to avoid. Clearing only at the rail's own click handler reaches
  // every case the review reproduced without touching those other flows.
  function goToPage(id: NavPage) {
    setOpening(null);
    setFailure(null);
    navigate({ kind: id });
  }

  // Device still renders the fleet page unchanged — increment 4 gives it its own page.
  // Person has its own page now, but both count as "on the fleet page" for the chrome
  // below: reaching either means having drilled in from Fleet, and neither is a separate
  // top-level destination on the nav rail.
  const section: NavPage = route.kind === "person" || route.kind === "device" ? "search" : (route.kind as NavPage);
  const current = pages.find((p) => p.id === section)!;
  const rendersFleet = route.kind === "search" || route.kind === "device";
  // The title, blurb, sheet index and per-page toolbar belong to the three list-like
  // pages. The wait, the session page and the full-page failure each carry their own
  // heading (or none), exactly as the View union's non-"list" members did.
  const showChrome = !opening && !failure && route.kind !== "session";

  return (
    <div className="min-h-screen bg-bg lg:grid lg:grid-cols-[13.5rem_minmax(0,1fr)]">
      <aside className="hidden border-r border-border bg-bg-raised lg:sticky lg:top-0 lg:flex lg:h-screen lg:flex-col lg:p-4">
        <div className="border-b border-border-strong px-2 pb-3">
          <div className="flex items-center gap-2.5">
            <span className="grid size-8 shrink-0 place-items-center border border-border-strong text-[11px] font-semibold leading-none tracking-[0.08em]">
              A<br />O
            </span>
            {/* Two lines, the way a title block stacks a name: one line of letterspaced
                caps does not fit a 13.5rem rail beside the monogram, and the product's
                own name arriving truncated is the worst thing on the sheet. */}
            <span className="text-[13px] font-semibold uppercase leading-tight tracking-[0.1em]">
              Oarlock
            </span>
          </div>
          <p className="label mt-2">gateway-terminated ssh</p>
        </div>
        <nav className="mt-5 grid gap-1 text-sm" aria-label="Admin navigation">
          {pages.map((page) => (
            <button
              key={page.id}
              className={`nav-item text-left ${section === page.id ? "nav-item-active" : ""}`}
              onClick={() => goToPage(page.id)}
            >
              {page.label}
            </button>
          ))}
        </nav>
        <div className="mt-auto border-t border-border px-2 pt-4">
          <p className="mono truncate text-sm text-fg-muted">{me || "operator"}</p>
          <button className="mt-2 text-sm font-medium text-fg-muted hover:text-fg" onClick={signOut}>
            Sign out
          </button>
        </div>
      </aside>

      <main className="min-w-0">
        <div className="border-b border-border bg-bg-raised lg:hidden">
          <div className="flex items-center justify-between px-4 py-3">
            <div className="flex items-center gap-2.5">
              <span className="grid size-8 shrink-0 place-items-center border border-border-strong text-[11px] font-semibold leading-none tracking-[0.08em]">
                A<br />O
              </span>
              <span className="text-[13px] font-semibold uppercase tracking-[0.14em]">
                Oarlock
              </span>
            </div>
            <button className="btn" onClick={signOut}>Sign out</button>
          </div>
          <nav className="flex gap-1 overflow-x-auto px-4 pb-3 text-sm" aria-label="Admin navigation">
            {pages.map((page) => (
              <button
                key={page.id}
                className={`nav-item whitespace-nowrap ${section === page.id ? "nav-item-active" : ""}`}
                onClick={() => goToPage(page.id)}
              >
                {page.label}
              </button>
            ))}
          </nav>
        </div>

        <div className="mx-auto flex max-w-[90rem] flex-col gap-6 p-4 sm:p-6 lg:p-8">
          {/* One header per page. The panels below used to repeat it, so every screen
              said the same thing twice in two type sizes. */}
          <header className="flex flex-wrap items-start justify-between gap-4 border-b border-border-strong pb-4">
            <div className="min-w-0">
              <h1 className="text-xl font-semibold">
                {showChrome ? current.label : "Oarlock"}
              </h1>
              {showChrome && (
                <p className="mt-1 text-sm text-fg-muted">{current.blurb}</p>
              )}
            </div>
            {/* The title block. A sheet says which one it is out of how many, and the
                navigation on the left is that index — so the number is wayfinding rather
                than an ornament counting sections. */}
            {showChrome && (
              <p className="label shrink-0 text-right leading-relaxed">
                <span className="block text-fg">
                  Sheet {pages.findIndex((p) => p.id === section) + 1} of {pages.length}
                </span>
                File no. OARLOCK-v0
              </p>
            )}
            {showChrome && rendersFleet && (
              <div className="flex gap-2">
                <button
                  className="btn"
                  onClick={() => setOpenByID({ device: "", reason: "" })}
                  data-testid="open-by-id"
                >
                  Open by id…
                </button>
                <button className="btn btn-primary" onClick={() => setDeviceDialog("new")}>
                  Add device
                </button>
              </div>
            )}
          </header>

          {showChrome && (
            <>
              {listError && (
                <p className="rounded-md border border-state-refused/50 bg-bg-raised p-4" role="alert">
                  <span className="font-semibold">{listError.headline}</span>{" "}
                  <span className="text-fg-muted">{listError.nextAction}</span>
                </p>
              )}

              {rendersFleet && (
                <Fleet
                  client={client.current}
                  devices={devices}
                  sessions={sessions}
                  me={me}
                  onOpen={(id, why) => void openSession(id, why)}
                  onEdit={(candidate) => setDeviceDialog(candidate)}
                  onToggle={(candidate) => void toggleDevice(candidate)}
                  onDelete={(id) => void deleteDevice(id)}
                  onStopAgent={(id) => void disconnectAgent(id)}
                  onAttach={(session) => void attach(session)}
                  onObserve={(session) => void observe(session)}
                  onReplay={(session) => void replay(session)}
                  onKill={(session) => void kill(session)}
                />
              )}

              {route.kind === "person" && (
                <PersonPage
                  client={client.current}
                  principal={route.principal}
                  facets={route.facets}
                  navigate={navigate}
                />
              )}

              {route.kind === "permissions" && <Permissions client={client.current} />}
              {route.kind === "sql" && <SQLExplorer client={client.current} />}

              {deviceDialog && (
                <DeviceDrawer
                  {...(deviceDialog === "new" ? {} : { device: deviceDialog })}
                  onClose={() => setDeviceDialog(null)}
                  onSave={deviceDialog === "new" ? createDevice : updateDevice}
                />
              )}

              {openByID && (
                <OpenByIDDialog
                  value={openByID}
                  onChange={setOpenByID}
                  onClose={() => setOpenByID(null)}
                  onOpen={() => void openSession(openByID.device, openByID.reason)}
                />
              )}
            </>
          )}

          {opening && (
            <section className="flex flex-col gap-4" data-testid="waits">
              <Waits steps={opening.steps} {...(opening.reference ? { reference: opening.reference } : {})} />
              <div>
                <button className="btn" onClick={() => setOpening(null)}>
                  Back
                </button>
              </div>
            </section>
          )}

          {route.kind === "session" && !opening && !failure && (
            <SessionRoute
              client={client.current}
              id={route.session}
              bypass={bypass}
              onConsumeBypass={() => setBypass(null)}
              fetchRecording={fetchRecording}
              onBack={() => navigate({ kind: "search" })}
              refresh={() => void refresh()}
            />
          )}

          {failure && (
            <SessionPage
              readOnly={false}
              failure={failure}
              onClose={() => setFailure(null)}
              onLeave={() => setFailure(null)}
              onSessionEnded={() => {}}
              renewTicket={() =>
                Promise.reject(new Error("renewTicket has no session to renew a ticket for"))
              }
            />
          )}
        </div>
      </main>
    </div>
  );
}

// One session, three bodies, and how it gets whichever one applies.
//
// `/s/{id}` loads its own data: fetch the session, and branch on what it is. A live
// session mints an attach ticket the same way a reload would (renewAttach is refused to
// anyone but the session's own operator, so this is exactly the ticket an owner reattaching
// gets); a closed, recorded one fetches the cast; anything else is the failed body. A
// `bypass` from a click that already minted the right ticket — including a Watch ticket
// renewAttach could never grant — is used once and then forgotten, so a later visit to the
// same URL (a reload, the back button) goes through the same fetch as a pasted link.
type SessionRouteState =
  | { kind: "loading" }
  | { kind: "live"; session: Session; attach: Attach; readOnly: boolean; watching?: string }
  | { kind: "replay"; session: Session; cast: string; verdict?: Verdict }
  | { kind: "failed"; condition: Condition; detail: string; reference: string };

function SessionRoute({
  client,
  id,
  bypass,
  onConsumeBypass,
  fetchRecording,
  onBack,
  refresh,
}: {
  client: Client;
  id: string;
  bypass: SessionBypass | null;
  onConsumeBypass: () => void;
  fetchRecording: (sessionID: string) => Promise<{ cast: string; verdict?: Verdict }>;
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
          const { cast, verdict } = await fetchRecording(id);
          if (!cancelled) setState({ kind: "replay", session, cast, ...(verdict ? { verdict } : {}) });
          return;
        }
        if (!cancelled) {
          setState({
            kind: "failed",
            condition: getCondition("not_found"),
            detail: "No recording for this session.",
            reference: "",
          });
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
  }, [client, id]);

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

type DeviceForm = {
  id: string;
  platform: Device["platform"];
  mode: NonNullable<Device["mode"]>;
  keys: string;
  retiredKeys: string;
  tags: string;
  profiles: string;
  enabled: boolean;
  allowPassthrough: boolean;
};

const emptyDeviceForm: DeviceForm = {
  id: "",
  platform: "android",
  mode: "dispatch",
  keys: "",
  retiredKeys: "",
  tags: "",
  profiles: "shell",
  enabled: true,
  allowPassthrough: false,
};

function splitList(value: string): string[] {
  return value.split(",").map((s) => s.trim()).filter(Boolean);
}

function parseTags(value: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of splitList(value)) {
    const [key, ...rest] = part.split("=");
    const name = key?.trim();
    if (!name) continue;
    out[name] = rest.join("=").trim();
  }
  return out;
}

function formatEditableTags(tags: Record<string, string> | undefined): string {
  return Object.entries(tags ?? {}).map(([key, value]) => `${key}=${value}`).join(", ");
}

function formFromDevice(device: Device): DeviceForm {
  return {
    id: device.id,
    platform: device.platform,
    mode: device.mode ?? "",
    keys: (device.keys ?? []).join(", "),
    retiredKeys: (device.retired_keys ?? []).join(", "),
    tags: formatEditableTags(device.tags),
    profiles: (device.profiles ?? []).join(", "),
    enabled: device.enabled !== false,
    allowPassthrough: device.allow_passthrough === true,
  };
}

function devicePayload(input: DeviceForm): Partial<Device> {
  return {
    id: input.id.trim(),
    platform: input.platform,
    mode: input.mode,
    keys: splitList(input.keys),
    retired_keys: splitList(input.retiredKeys),
    tags: parseTags(input.tags),
    profiles: splitList(input.profiles),
    enabled: input.enabled,
    allow_passthrough: input.allowPassthrough,
  };
}

function deviceOperationError(error: unknown): string {
  if (error instanceof ApiError) return error.detail || error.message;
  return error instanceof Error ? error.message : String(error);
}

function DeviceFormEditor({
  initial,
  editing,
  onSave,
  onDone,
}: {
  initial: DeviceForm;
  editing: boolean;
  onSave: (input: DeviceForm) => Promise<string | null>;
  onDone: () => void;
}) {
  const [form, setForm] = useState<DeviceForm>(initial);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  return (
    <form
      className="grid gap-4"
      onSubmit={async (e) => {
        e.preventDefault();
        setSaving(true);
        setError("");
        const saveError = await onSave(form);
        setSaving(false);
        if (!saveError) {
          onDone();
        } else {
          setError(saveError);
        }
      }}
    >
      <FieldLabel label="Device ID">
        <input
          className="field mono"
          placeholder="treadmill-4821"
          value={form.id}
          onChange={(e) => setForm({ ...form, id: e.target.value })}
          disabled={editing}
          required
        />
      </FieldLabel>
      <div className="grid grid-cols-2 gap-3">
        <FieldLabel label="Platform">
          <select
            className="field"
            value={form.platform}
            onChange={(e) => setForm({ ...form, platform: e.target.value as Device["platform"] })}
          >
            <option value="android">Android</option>
            <option value="linux">Linux</option>
            <option value="container">Container</option>
            <option value="other">Other</option>
          </select>
        </FieldLabel>
        <FieldLabel label="Mode">
          <select
            className="field"
            value={form.mode}
            onChange={(e) => setForm({ ...form, mode: e.target.value as DeviceForm["mode"] })}
          >
            <option value="dispatch">Dispatch</option>
            <option value="persistent">Persistent</option>
            <option value="">Platform default</option>
          </select>
        </FieldLabel>
      </div>
      <FieldLabel label="Public keys">
        <textarea
          className="field mono"
          placeholder="ssh-ed25519..."
          rows={3}
          value={form.keys}
          onChange={(e) => setForm({ ...form, keys: e.target.value })}
        />
        <span className="text-sm text-fg-faint">Comma-separated authorized public keys.</span>
      </FieldLabel>
      <FieldLabel label="Retired keys">
        <textarea
          className="field mono"
          placeholder="Keys that must no longer authenticate"
          rows={2}
          value={form.retiredKeys}
          onChange={(e) => setForm({ ...form, retiredKeys: e.target.value })}
        />
      </FieldLabel>
      <FieldLabel label="Profiles">
        <input
          className="field"
          placeholder="shell"
          value={form.profiles}
          onChange={(e) => setForm({ ...form, profiles: e.target.value })}
        />
      </FieldLabel>
      <FieldLabel label="Tags">
        <input
          className="field"
          placeholder="fleet=qa"
          value={form.tags}
          onChange={(e) => setForm({ ...form, tags: e.target.value })}
        />
      </FieldLabel>
      <label className="flex items-start justify-between gap-4 rounded-md border border-border p-3">
        <span>
          <span className="block text-sm font-medium">Enabled</span>
          <span className="block text-sm text-fg-muted">Allow agent authentication and new sessions.</span>
        </span>
        <input
          type="checkbox"
          className="mt-1 size-4 accent-current"
          checked={form.enabled}
          onChange={(event) => setForm({ ...form, enabled: event.target.checked })}
        />
      </label>
      <label className="flex items-start justify-between gap-4 rounded-md border border-border p-3">
        <span>
          <span className="block text-sm font-medium">Allow passthrough</span>
          <span className="block text-sm text-fg-muted">Permit explicitly unrecorded sessions for this device.</span>
        </span>
        <input
          type="checkbox"
          className="mt-1 size-4 accent-current"
          checked={form.allowPassthrough}
          onChange={(event) => setForm({ ...form, allowPassthrough: event.target.checked })}
        />
      </label>
      {error && (
        <p className="rounded-md border border-state-refused/50 p-3 text-sm text-state-refused" role="alert">
          {error}
        </p>
      )}
      <div className="flex justify-end gap-2 border-t border-border pt-4">
        <button className="btn" type="button" onClick={onDone}>Cancel</button>
        <button className="btn btn-primary" type="submit" disabled={saving}>
          {saving ? "Saving..." : editing ? "Save changes" : "Add device"}
        </button>
      </div>
    </form>
  );
}

function DeviceDrawer({
  device,
  onClose,
  onSave,
}: {
  device?: Device;
  onClose: () => void;
  onSave: (input: DeviceForm) => Promise<string | null>;
}) {
  useEffect(() => {
    function closeOnEscape(event: KeyboardEvent) {
      if (event.key === "Escape") onClose();
    }
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/35" role="presentation" onMouseDown={onClose}>
      <section
        className="h-full w-full max-w-md overflow-y-auto border-l border-border bg-bg-raised p-6 shadow-2xl"
        role="dialog"
        aria-modal="true"
        aria-labelledby="device-dialog-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <div className="mb-6 flex items-start justify-between gap-4">
          <div>
            <h2 id="device-dialog-title" className="text-lg font-semibold">
              {device ? "Edit device" : "Add device"}
            </h2>
            <p className="mt-1 text-sm text-fg-muted">
              {device ? `Update ${device.id} without losing its session history.` : "Register a target before its agent connects."}
            </p>
          </div>
          <button className="icon-btn" onClick={onClose} aria-label="Close add device dialog" title="Close">
            <span aria-hidden="true">x</span>
          </button>
        </div>
        <DeviceFormEditor
          initial={device ? formFromDevice(device) : emptyDeviceForm}
          editing={Boolean(device)}
          onSave={onSave}
          onDone={onClose}
        />
      </section>
    </div>
  );
}

// Opening a shell on a device id you typed.
//
// The secondary path, on purpose: from the fleet list you pick a row and never retype an
// id, which is where the old permanent form strip went. This is for the id you already
// know and the row you cannot see — a fleet longer than a page, or an id that is not
// registered at all, which is a journey worth keeping reachable because the gateway has a
// screen for it.
function OpenByIDDialog({
  value,
  onChange,
  onClose,
  onOpen,
}: {
  value: { device: string; reason: string };
  onChange: (next: { device: string; reason: string }) => void;
  onClose: () => void;
  onOpen: () => void;
}) {
  useEffect(() => {
    function closeOnEscape(event: KeyboardEvent) {
      if (event.key === "Escape") onClose();
    }
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [onClose]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/35 p-4 sm:items-center"
      role="presentation"
      onMouseDown={onClose}
    >
      <form
        className="w-full max-w-md rounded-lg border border-border bg-bg-raised p-6 shadow-2xl"
        role="dialog"
        aria-modal="true"
        aria-labelledby="open-by-id-title"
        onMouseDown={(event) => event.stopPropagation()}
        onSubmit={(event) => {
          event.preventDefault();
          onOpen();
        }}
      >
        <h2 id="open-by-id-title" className="text-lg font-semibold">
          Open by device id
        </h2>
        <p className="mt-1 text-sm text-fg-muted">
          For a device that is not in front of you. The session is recorded and attributed
          the same way either way.
        </p>
        <div className="mt-4 grid gap-3">
          <FieldLabel label="Device id">
            <input
              className="field mono"
              placeholder="treadmill-4821"
              value={value.device}
              onChange={(event) => onChange({ ...value, device: event.target.value })}
              data-testid="open-by-id-device"
              autoFocus
            />
          </FieldLabel>
          <FieldLabel label="Reason">
            <input
              className="field"
              placeholder="ticket or reason"
              value={value.reason}
              onChange={(event) => onChange({ ...value, reason: event.target.value })}
              data-testid="open-by-id-reason"
            />
          </FieldLabel>
        </div>
        <div className="mt-5 flex justify-end gap-2 border-t border-border pt-4">
          <button className="btn" type="button" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn btn-primary"
            type="submit"
            disabled={!value.device.trim()}
            data-testid="open-by-id-submit"
          >
            Open
          </button>
        </div>
      </form>
    </div>
  );
}

function FieldLabel({
  label,
  className = "",
  children,
}: {
  label: string;
  className?: string;
  children: ReactNode;
}) {
  return (
    <label className={"flex flex-col gap-1 " + className}>
      <span className="text-[11px] font-semibold uppercase tracking-wider text-fg-faint">
        {label}
      </span>
      {children}
    </label>
  );
}
