// The reference console.
//
// It is a demo and a reference implementation: an integrator embeds `<Terminal>` in their
// own product and inherits none of this. What it has to demonstrate is the arrangement —
// that the disclosure, the waits, the failure screens and the replay verdict all come from
// the same places the component and the gateway already agree on, rather than being
// re-stated here where they could drift.

import { lazy, Suspense, useCallback, useEffect, useRef, useState } from "react";
import { Terminal } from "@oarlock/react";

// The replay player is loaded on demand. It carries its own terminal emulator, and most
// sessions are never replayed — making every page load pay for it would be charging the
// common case for the rare one.
const Player = lazy(async () => {
  const mod = await import("@oarlock/react/player");
  return { default: mod.Player };
});
import { get as getCondition, type Condition } from "@oarlock/terminal/conditions";
import type { Verdict } from "@oarlock/terminal";
import { ApiError, Client, type Agent, type Attach, type Device, type Session } from "./api";
import { SessionList } from "./SessionList";
import { Waits, type Step } from "./Waits";

type View =
  | { kind: "list" }
  | { kind: "opening"; device: string; steps: Step[]; reference?: string }
  | { kind: "terminal"; session: Session; attach: Attach; readOnly: boolean; watching?: string }
  | { kind: "replay"; session: Session; cast: string; verdict: Verdict | undefined }
  | { kind: "failed"; condition: Condition; detail: string; reference: string };

const tokenKey = "oarlock.token";

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
  const [agents, setAgents] = useState<Agent[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [device, setDevice] = useState("");
  const [reason, setReason] = useState("");
  const [me, setMe] = useState("");
  const [listError, setListError] = useState<Condition | null>(null);

  const refresh = useCallback(async () => {
    if (!token) return;
    try {
      const [{ sessions }, { agents }, { devices }] = await Promise.all([
        client.current.sessions(),
        client.current.agents(),
        client.current.devices(),
      ]);
      setSessions(sessions);
      setAgents(agents);
      setDevices(devices);
      setListError(null);
      if (sessions.length > 0 && !me) setMe(sessions[0]!.principal);
    } catch (err) {
      setListError(err instanceof ApiError ? err.condition : getCondition("internal"));
    }
  }, [token, me]);

  useEffect(() => {
    void refresh();
    const t = setInterval(() => void refresh(), 4000);
    return () => clearInterval(t);
  }, [refresh]);

  function saveToken(t: string) {
    sessionStorage.setItem(tokenKey, t);
    setToken(t);
  }

  async function openSession() {
    if (!device) return;

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
        reference: e?.reference,
        steps: steps.map((s) =>
          s.key === "wake"
            ? { ...s, state: "failed" as const, failure: condition, detail: e?.detail }
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

  async function disconnectAgent(agent: Agent) {
    if (!confirm(`Stop ${agent.device_id}?\n\nThe agent exits on that device. ` +
      `Start oarlock-agent there again to reconnect it.`)) {
      return;
    }
    try {
      await client.current.disconnectAgent(agent.device_id);
      void refresh();
    } catch (err) {
      fail(err);
    }
  }

  async function createDevice(input: DeviceForm) {
    try {
      await client.current.createDevice({
        id: input.id.trim(),
        platform: input.platform,
        mode: input.mode,
        keys: splitList(input.keys),
        tags: parseTags(input.tags),
        profiles: splitList(input.profiles),
      });
      setDevice(input.id.trim());
      void refresh();
    } catch (err) {
      fail(err);
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
    return (
      <main className="mx-auto max-w-lg p-8">
        <h1 className="pb-2 text-xl font-semibold">Oarlock</h1>
        <p className="pb-4 text-fg-muted">
          Paste an API token to continue. This is a development mechanism — static tokens
          are long-lived shared secrets and the gateway refuses them outside{" "}
          <code className="mono">dev</code>. A real deployment authenticates you through
          its own sign-in.
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

  return (
    <main className="mx-auto flex max-w-6xl flex-col gap-6 p-6">
      <header className="flex flex-wrap items-baseline justify-between gap-3">
        <h1 className="text-xl font-semibold">Oarlock</h1>
        <div className="flex items-center gap-3 text-sm text-fg-muted">
          {me && <span className="mono">{me}</span>}
          <button
            className="btn"
            onClick={() => {
              sessionStorage.removeItem(tokenKey);
              setToken("");
            }}
          >
            Sign out
          </button>
        </div>
      </header>

      {view.kind === "list" && (
        <>
          <section className="flex flex-col gap-3 rounded-md border border-border bg-bg-raised p-4">
            <h2 className="font-semibold">Open a shell</h2>
            <div className="flex flex-wrap gap-3">
              <input
                className="field mono max-w-xs"
                placeholder="device id"
                value={device}
                onChange={(e) => setDevice(e.target.value)}
                data-testid="device"
              />
              <input
                className="field max-w-md"
                placeholder="why — a ticket number, a sentence"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                data-testid="reason"
              />
              <button
                className="btn btn-primary"
                onClick={() => void openSession()}
                data-testid="open"
              >
                Shell
              </button>
            </div>
            <p className="text-xs text-fg-faint">
              The reason costs you nothing and turns the session list from a log into an
              explanation.
            </p>
          </section>

          {listError && (
            <p className="rounded-md border border-state-refused bg-bg-raised p-4">
              <span className="font-semibold">{listError.headline}</span>{" "}
              <span className="text-fg-muted">{listError.nextAction}</span>
            </p>
          )}

          <section
            className="flex flex-col gap-3 rounded-md border border-border bg-bg-raised p-4"
            data-testid="admin-agents"
          >
            <div className="flex flex-wrap items-baseline justify-between gap-3">
              <div>
                <h2 className="font-semibold">Admin</h2>
                <p className="text-xs text-fg-muted">
                  Connected agent control channels on this gateway node.
                </p>
              </div>
              <span className="mono text-xs text-fg-faint">
                {agents.length} connected
              </span>
            </div>
            <AgentList agents={agents} onDisconnect={(a) => void disconnectAgent(a)} />
            <DeviceCreateForm onCreate={(input) => void createDevice(input)} />
            <DeviceList devices={devices} onDelete={(id) => void deleteDevice(id)} />
          </section>

          <section className="flex flex-col gap-3">
            <h2 className="font-semibold">Sessions</h2>
            <SessionList
              sessions={sessions}
              me={me}
              onAttach={(s) => void attach(s)}
              onObserve={(s) => void observe(s)}
              onReplay={(s) => void replay(s)}
              onKill={(s) => void kill(s)}
            />
          </section>
        </>
      )}

      {view.kind === "opening" && (
        <section className="flex flex-col gap-4" data-testid="waits">
          <Waits steps={view.steps} reference={view.reference} />
          <div>
            <button className="btn" onClick={() => setView({ kind: "list" })}>
              Back
            </button>
          </div>
        </section>
      )}

      {view.kind === "terminal" && (
        <section className="flex flex-col gap-3" data-testid="terminal">
          <div className="flex items-center justify-between gap-3">
            <span className="mono text-sm text-fg-muted">{view.session.id}</span>
            <button
              className="btn"
              onClick={() => {
                setView({ kind: "list" });
                void refresh();
              }}
            >
              Leave
            </button>
          </div>
          <Terminal
            url={view.attach.url}
            ticket={view.attach.ticket}
            device={view.session.device_id}
            principal={view.session.principal}
            {...(view.readOnly ? { readOnly: true } : {})}
            renewTicket={() =>
              client.current.renewAttach(view.session.id).then((a) => a.ticket)
            }
            onClosed={() => void refresh()}
            style={{ height: "70vh" }}
          />
        </section>
      )}

      {view.kind === "replay" && (
        <section className="flex flex-col gap-3" data-testid="replay">
          <div className="flex items-center justify-between gap-3">
            <span className="mono text-sm text-fg-muted">{view.session.id}</span>
            <button className="btn" onClick={() => setView({ kind: "list" })}>
              Back
            </button>
          </div>
          <Suspense
            fallback={<p className="text-fg-muted">Loading the player…</p>}
          >
            <Player
              cast={view.cast}
              verdict={view.verdict}
              sessionID={view.session.id}
              style={{ height: "70vh" }}
            />
          </Suspense>
        </section>
      )}

      {view.kind === "failed" && (
        <section
          className="rounded-md border border-state-refused bg-bg-raised p-5"
          data-testid="failure"
          role="alert"
        >
          <h2 className="pb-1 text-lg font-semibold">{view.condition.headline}</h2>
          {view.condition.nextAction && (
            <p className="pb-3 text-fg-muted">{view.condition.nextAction}</p>
          )}
          <dl className="mono grid grid-cols-[auto_1fr] gap-x-3 text-xs text-fg-faint">
            <dt className="not-mono">Reason</dt>
            <dd className="select-all">{view.condition.id}</dd>
            {view.reference && (
              <>
                <dt className="not-mono">Reference (for support)</dt>
                <dd className="select-all">{view.reference}</dd>
              </>
            )}
          </dl>
          <div className="pt-4">
            <button className="btn" onClick={() => setView({ kind: "list" })}>
              Back
            </button>
          </div>
        </section>
      )}
    </main>
  );
}

type DeviceForm = {
  id: string;
  platform: Device["platform"];
  mode: NonNullable<Device["mode"]>;
  keys: string;
  tags: string;
  profiles: string;
};

const emptyDeviceForm: DeviceForm = {
  id: "",
  platform: "android",
  mode: "dispatch",
  keys: "",
  tags: "",
  profiles: "shell",
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

function DeviceCreateForm({ onCreate }: { onCreate: (input: DeviceForm) => void }) {
  const [form, setForm] = useState<DeviceForm>(emptyDeviceForm);
  return (
    <form
      className="grid gap-3 border-t border-border pt-4 md:grid-cols-[minmax(12rem,1fr)_10rem_10rem_minmax(12rem,1fr)_minmax(10rem,1fr)_auto]"
      onSubmit={(e) => {
        e.preventDefault();
        onCreate(form);
        setForm(emptyDeviceForm);
      }}
    >
      <input
        className="field mono"
        placeholder="device id"
        value={form.id}
        onChange={(e) => setForm({ ...form, id: e.target.value })}
        required
      />
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
      <select
        className="field"
        value={form.mode}
        onChange={(e) => setForm({ ...form, mode: e.target.value as DeviceForm["mode"] })}
      >
        <option value="dispatch">Dispatch</option>
        <option value="persistent">Persistent</option>
        <option value="">Default</option>
      </select>
      <input
        className="field mono"
        placeholder="public keys"
        value={form.keys}
        onChange={(e) => setForm({ ...form, keys: e.target.value })}
      />
      <input
        className="field"
        placeholder="tags"
        value={form.tags}
        onChange={(e) => setForm({ ...form, tags: e.target.value })}
      />
      <button className="btn btn-primary" type="submit">
        Add
      </button>
      <input
        className="field md:col-span-2"
        placeholder="profiles"
        value={form.profiles}
        onChange={(e) => setForm({ ...form, profiles: e.target.value })}
      />
    </form>
  );
}

function DeviceList({
  devices,
  onDelete,
}: {
  devices: Device[];
  onDelete: (id: string) => void;
}) {
  if (devices.length === 0) {
    return (
      <p className="rounded-md border border-border bg-bg-raised p-4 text-fg-muted">
        No devices are registered.
      </p>
    );
  }
  return (
    <div className="overflow-x-auto rounded-md border border-border bg-bg">
      <table className="w-full border-collapse text-left">
        <thead className="bg-bg-raised text-xs uppercase tracking-wider text-fg-faint">
          <tr>
            <th className="px-3 py-2 font-medium">Device</th>
            <th className="px-3 py-2 font-medium">Platform</th>
            <th className="px-3 py-2 font-medium">Mode</th>
            <th className="px-3 py-2 font-medium">Keys</th>
            <th className="px-3 py-2 font-medium">State</th>
            <th className="px-3 py-2" />
          </tr>
        </thead>
        <tbody>
          {devices.map((device) => (
            <tr className="border-t border-border align-middle" key={device.id}>
              <td className="mono px-3 py-2">{device.id}</td>
              <td className="px-3 py-2 capitalize">{device.platform}</td>
              <td className="px-3 py-2">{device.resolved_mode}</td>
              <td className="mono px-3 py-2 text-xs">{device.keys?.length ?? 0}</td>
              <td className="px-3 py-2">
                <span
                  className={
                    "inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wider " +
                    (device.connected ? "text-state-recorded" : "text-fg-faint")
                  }
                >
                  <span className="size-1.5 rounded-full bg-current" aria-hidden="true" />
                  {device.connected ? "Connected" : "Offline"}
                </span>
              </td>
              <td className="px-3 py-2 text-right">
                <button className="btn btn-danger" onClick={() => onDelete(device.id)}>
                  Delete
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AgentList({
  agents,
  onDisconnect,
}: {
  agents: Agent[];
  onDisconnect: (agent: Agent) => void;
}) {
  if (agents.length === 0) {
    return (
      <p className="rounded-md border border-border bg-bg-raised p-4 text-fg-muted">
        No agents are connected to this gateway node.
      </p>
    );
  }
  return (
    <div className="overflow-x-auto rounded-md border border-border bg-bg">
      <table className="w-full border-collapse text-left">
        <thead className="bg-bg-raised text-xs uppercase tracking-wider text-fg-faint">
          <tr>
            <th className="px-3 py-2 font-medium">Device</th>
            <th className="px-3 py-2 font-medium">State</th>
            <th className="px-3 py-2" />
          </tr>
        </thead>
        <tbody>
          {agents.map((agent) => (
            <tr className="border-t border-border align-middle" key={agent.device_id}>
              <td className="mono px-3 py-2">{agent.device_id}</td>
              <td className="px-3 py-2">
                <span className="inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wider text-state-recorded">
                  <span className="size-1.5 rounded-full bg-current" aria-hidden="true" />
                  Connected
                </span>
              </td>
              <td className="px-3 py-2 text-right">
                <button className="btn btn-danger" onClick={() => onDisconnect(agent)}>
                  Stop
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
