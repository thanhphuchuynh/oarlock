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
  collectHandoff,
  endSession,
  loginMode,
  type Attach,
  type Device,
  type LoginMode,
  type Session,
} from "./api";
import { SessionList } from "./SessionList";
import { Fleet } from "./Fleet";
import { Permissions } from "./Permissions";
import { SSHAccess } from "./SSHAccess";
import { SQLExplorer } from "./SQLExplorer";
import { Waits, type Step } from "./Waits";
import { SessionPage } from "./pages/SessionPage";

type View =
  | { kind: "list" }
  | { kind: "opening"; device: string; steps: Step[]; reference?: string }
  | { kind: "terminal"; session: Session; attach: Attach; readOnly: boolean; watching?: string }
  | { kind: "replay"; session: Session; cast: string; verdict: Verdict | undefined }
  | { kind: "failed"; condition: Condition; detail: string; reference: string };

const tokenKey = "oarlock.token";

type AdminPage = "fleet" | "sessions" | "permissions" | "sql";

const pages: { id: AdminPage; label: string; blurb: string }[] = [
  { id: "fleet", label: "Fleet", blurb: "Devices, who can reach them, and what has been run on them." },
  { id: "sessions", label: "Sessions", blurb: "Every session the gateway has brokered, and why." },
  { id: "permissions", label: "Permissions", blurb: "Who may perform which actions on which devices." },
  { id: "sql", label: "SQL Explorer", blurb: "Read-only access to operational SQLite data." },
];

export function App() {
  // The token lives in sessionStorage, not localStorage: a shared secret in a browser
  // should not outlive the tab it was typed into. It is also a development mechanism —
  // static tokens refuse to start outside dev — and a real deployment authenticates the
  // browser through its own login.
  const [token, setToken] = useState(() => sessionStorage.getItem(tokenKey) ?? "");
  const client = useRef(new Client("", token));
  client.current.setToken(token);

  const [view, setView] = useState<View>({ kind: "list" });
  const [sessions, setSessions] = useState<Session[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [me, setMe] = useState("");
  // undefined until the gateway has answered. See the sign-in screen below.
  const [login, setLogin] = useState<LoginMode | undefined>();
  const [listError, setListError] = useState<Condition | null>(null);
  const [deviceDialog, setDeviceDialog] = useState<Device | "new" | null>(null);
  // Opening by typed id is the secondary path: it is how you reach a device whose row is
  // not in front of you, and how an unregistered id gets its own failure screen instead
  // of being unreachable through the UI.
  const [openByID, setOpenByID] = useState<{ device: string; reason: string } | null>(null);
  const [adminPage, setAdminPage] = useState<AdminPage>("fleet");

  // What each poll asks for, and how often.
  //
  // Three lists on a four-second timer was 45 requests a minute doing nothing, against a
  // default API budget of 120 — more than a third of an operator's allowance spent on an
  // idle tab, and enough to start collecting 429s with a second tab open. Two changes.
  //
  // **Ask for what is on screen.** Permissions and SQL Explorer are not live views, so
  // they poll nothing at all; the other two ask only for the lists they render.
  //
  // **Stop asking for `/agents`.** The gateway computes `device.connected` from exactly
  // the list that endpoint returns, so fetching both was the same duplication the fleet
  // page used to show: one fact, two sources, and a window where they disagree.
  const refresh = useCallback(async (scope: AdminPage | "all" = "all") => {
    if (!token) return;
    try {
      const wantsDevices = scope === "all" || scope === "fleet";
      const [live, fleet] = await Promise.all([
        client.current.sessions(),
        wantsDevices ? client.current.devices() : Promise.resolve(null),
      ]);
      setSessions(live.sessions);
      if (fleet) setDevices(fleet.devices);
      setListError(null);
      if (live.sessions.length > 0 && !me) setMe(live.sessions[0]!.principal);
    } catch (err) {
      setListError(err instanceof ApiError ? err.condition : getCondition("internal"));
    }
  }, [token, me]);

  useEffect(() => {
    void refresh();
    // A page that renders neither list has nothing to poll for.
    if (adminPage !== "fleet" && adminPage !== "sessions") return;
    const t = setInterval(() => {
      // A background tab polling a rate-limited API is pure waste.
      if (document.hidden) return;
      void refresh(adminPage);
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
  }, [refresh, adminPage]);

  // Two things happen before anything is rendered, and only when there is no token yet.
  //
  // The handoff first: this load may be the redirect back from a completed sign-in, and
  // the cookie waiting for us is redeemable exactly once. Then the mode, so the right
  // screen appears if there was no handoff.
  useEffect(() => {
    if (token) return;
    let cancelled = false;
    void (async () => {
      const handed = await collectHandoff();
      if (cancelled) return;
      if (handed) {
        setMe(handed.principal);
        saveToken(handed.token);
        return;
      }
      const mode = await loginMode();
      if (!cancelled) setLogin(mode);
    })();
    return () => {
      cancelled = true;
    };
  }, [token]);

  function saveToken(t: string) {
    sessionStorage.setItem(tokenKey, t);
    setToken(t);
  }

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
    setView({ kind: "opening", device, steps });

    try {
      const { session, attach } = await client.current.open(device, reason, {
        cols: 120,
        rows: 32,
      });
      setMe(session.principal);
      setView({
        kind: "opening",
        device,
        steps: steps.map((s) =>
          s.key === "wake"
            ? { ...s, label: `${device} answered`, state: "done" }
            : s.key === "tunnel"
              ? { ...s, state: "waiting" as const, budget: "a moment" }
              : s,
        ),
      });
      // The steps disappear on success: they are scaffolding for a wait, not a log.
      setView({ kind: "terminal", session, attach, readOnly: false });
      void refresh();
    } catch (err) {
      const e = err instanceof ApiError ? err : null;
      const condition = e?.condition ?? getCondition("internal");
      // The step that failed *is* the diagnosis, so the failure replaces its own line
      // rather than appearing as a banner somewhere else.
      setView({
        kind: "opening",
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
      setView({ kind: "terminal", session: s, attach: a, readOnly: false });
    } catch (err) {
      fail(err);
    }
  }

  async function observe(s: Session) {
    try {
      const a = await client.current.observe(s.id);
      setView({
        kind: "terminal",
        session: s,
        attach: a,
        readOnly: true,
        watching: s.principal,
      });
    } catch (err) {
      fail(err);
    }
  }

  async function replay(s: Session) {
    try {
      const res = await fetch(`/api/v1/recordings/${encodeURIComponent(s.id)}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) {
        const body: unknown = await res.json().catch(() => ({}));
        throw new ApiError(res.status, body as Record<string, unknown>);
      }
      const payload = (await res.json()) as { cast: string; verdict?: Verdict };
      // The verdict comes from the gateway, which is the only place that has the manifest
      // and a key the deployment trusts. If it did not send one, the player renders
      // "unverified" — which is the honest answer, and not the same as fine.
      setView({ kind: "replay", session: s, cast: payload.cast, verdict: payload.verdict });
    } catch (err) {
      fail(err);
    }
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
    setView({
      kind: "failed",
      condition: e?.condition ?? getCondition("internal"),
      detail: e?.detail ?? String(err),
      reference: e?.reference ?? "",
    });
  }

  if (!token) {
    // Nothing is rendered until the gateway has said how to sign in. A console that
    // guessed would show the wrong screen for a moment on every single load, and the
    // wrong screen here is "paste a secret" — the one habit this flow exists to remove.
    if (login === undefined) {
      return (
        <main className="mx-auto max-w-lg p-8">
          <h1 className="pb-2 text-xl font-semibold">Oarlock</h1>
          <p className="text-fg-muted">Checking how this gateway signs you in…</p>
        </main>
      );
    }
    if (login === "oidc") {
      return (
        <main className="mx-auto max-w-lg p-8">
          <h1 className="pb-2 text-xl font-semibold">Oarlock</h1>
          <p className="pb-4 text-fg-muted">
            Sign in with your identity provider. This gateway never sees your password or
            your second factor.
          </p>
          {/* A link, not a fetch: the whole point is a top-level navigation the browser
              can follow to the provider and back. `return_to` brings you to the page you
              were heading for — the gateway accepts only a path on its own origin. */}
          <a
            className="btn btn-primary inline-flex"
            href={`/auth/login?return_to=${encodeURIComponent(location.pathname + location.hash)}`}
            data-testid="sign-in"
          >
            Sign in
          </a>
        </main>
      );
    }
    return (
      <main className="mx-auto max-w-lg p-8">
        <h1 className="pb-2 text-xl font-semibold">Oarlock</h1>
        <p className="pb-4 text-fg-muted">
          Paste an API token to continue. This is a development mechanism — static tokens
          are long-lived shared secrets and the gateway refuses them outside{" "}
          <code className="mono">dev</code>. Configure{" "}
          <code className="mono">auth.kind: oidc</code> and a sign-in button replaces this.
        </p>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const t = new FormData(e.currentTarget).get("token");
            if (typeof t === "string" && t) saveToken(t);
          }}
          className="flex flex-col gap-3"
        >
          <input name="token" className="field mono" placeholder="token" autoFocus />
          <button className="btn btn-primary" type="submit">
            Continue
          </button>
        </form>
      </main>
    );
  }

  const signOut = () => {
    // The gateway first, then this tab. It holds nothing durable — no server-side
    // session — but the one-hop cookies should not outlive a deliberate sign-out.
    void endSession();
    sessionStorage.removeItem(tokenKey);
    setToken("");
  };

  function showAdmin(page: AdminPage) {
    setView({ kind: "list" });
    setAdminPage(page);
  }

  const current = pages.find((p) => p.id === adminPage)!;

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
              className={`nav-item text-left ${adminPage === page.id ? "nav-item-active" : ""}`}
              onClick={() => showAdmin(page.id)}
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
                className={`nav-item whitespace-nowrap ${adminPage === page.id ? "nav-item-active" : ""}`}
                onClick={() => showAdmin(page.id)}
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
                {view.kind === "list" ? current.label : "Oarlock"}
              </h1>
              {view.kind === "list" && (
                <p className="mt-1 text-sm text-fg-muted">{current.blurb}</p>
              )}
            </div>
            {/* The title block. A sheet says which one it is out of how many, and the
                navigation on the left is that index — so the number is wayfinding rather
                than an ornament counting sections. */}
            {view.kind === "list" && (
              <p className="label shrink-0 text-right leading-relaxed">
                <span className="block text-fg">
                  Sheet {pages.findIndex((p) => p.id === adminPage) + 1} of {pages.length}
                </span>
                File no. OARLOCK-v0
              </p>
            )}
            {view.kind === "list" && adminPage === "fleet" && (
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

          {view.kind === "list" && (
            <>
              {listError && (
                <p className="rounded-md border border-state-refused/50 bg-bg-raised p-4" role="alert">
                  <span className="font-semibold">{listError.headline}</span>{" "}
                  <span className="text-fg-muted">{listError.nextAction}</span>
                </p>
              )}

              {adminPage === "fleet" && (
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

              {adminPage === "sessions" && (
                <section className="panel" id="sessions">
                  <div className="panel-header">
                    <p className="text-sm text-fg-muted">
                      <span className="font-semibold text-fg">{sessions.length}</span> recorded
                      {" · "}
                      {sessions.filter((s) => s.live).length} live now
                    </p>
                  </div>
                  <SessionList
                    sessions={sessions}
                    me={me}
                    onAttach={(s) => void attach(s)}
                    onObserve={(s) => void observe(s)}
                    onReplay={(s) => void replay(s)}
                    onKill={(s) => void kill(s)}
                  />
                </section>
              )}

              {adminPage === "permissions" && <Permissions client={client.current} />}
              {adminPage === "sql" && <SQLExplorer client={client.current} />}

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

          {view.kind === "opening" && (
            <section className="flex flex-col gap-4" data-testid="waits">
              <Waits steps={view.steps} {...(view.reference ? { reference: view.reference } : {})} />
              <div>
                <button className="btn" onClick={() => setView({ kind: "list" })}>
                  Back
                </button>
              </div>
            </section>
          )}

          {view.kind === "terminal" && (
            <SessionPage
              session={view.session}
              attach={view.attach}
              readOnly={view.readOnly}
              {...(view.watching ? { watching: view.watching } : {})}
              onClose={() => setView({ kind: "list" })}
              onLeave={() => {
                setView({ kind: "list" });
                void refresh();
              }}
              onSessionEnded={() => void refresh()}
              renewTicket={() =>
                client.current.renewAttach(view.session.id).then((a) => a.ticket)
              }
            />
          )}

          {view.kind === "replay" && (
            <SessionPage
              session={view.session}
              cast={view.cast}
              {...(view.verdict ? { verdict: view.verdict } : {})}
              readOnly={false}
              onClose={() => setView({ kind: "list" })}
              onLeave={() => setView({ kind: "list" })}
              onSessionEnded={() => {}}
              renewTicket={() =>
                client.current.renewAttach(view.session.id).then((a) => a.ticket)
              }
            />
          )}

          {view.kind === "failed" && (
            <SessionPage
              readOnly={false}
              failure={{
                condition: view.condition,
                detail: view.detail,
                reference: view.reference,
              }}
              onClose={() => setView({ kind: "list" })}
              onLeave={() => setView({ kind: "list" })}
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
