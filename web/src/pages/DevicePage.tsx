// The Device page — what the fleet list's expanded row used to answer inline, given a URL
// of its own: open a shell, who can reach it, who administers it, what has been done on
// it, and the same edit/disable/delete/stop-agent admin actions the row carried. It shares
// the same `Timeline` and `Grants` the Person page uses rather than keeping a second copy
// of either that could drift from it, exactly the way the old `Fleet.tsx` and
// `PersonPage.tsx` had already drifted from each other.
//
// The list at `/` now links straight here instead of expanding in place — this is the only
// place any of this renders any more, which is why the admin row below (absent from Task
// 3's version of this file) had to move in with it.

import { useEffect, useState } from "react";
import { ApiError, type Client, type Device, type Session } from "../api";
import type { Facets, Route } from "../router/routes";
import { Grants, type GrantsState } from "../components/Grants";
import { Timeline, type TimelineState } from "../components/Timeline";
import { FacetBar, type FacetSpec } from "../components/Facets";
import { SshClientDialog } from "../components/dialogs/SshClientDialog";
import { DeviceDialog, devicePayload, formFromDevice, type DeviceForm } from "../components/dialogs/DeviceDialog";

type Navigate = (to: Route, opts?: { replace?: boolean }) => void;

// Same default as the Person page, and for the same reason: a window that only ever lived
// in state would show a colleague a different page than the link promised them.
const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;

const FACET_SPECS: readonly FacetSpec[] = [
  { key: "since", label: "since" },
  { key: "until", label: "until" },
  { key: "state", label: "state" },
];

export function DevicePage({
  client,
  device,
  devices,
  facets,
  navigate,
  onOpen,
  onOpenSession,
  refresh,
  onFail,
}: {
  client: Client;
  device: string;
  /** The already-polled fleet list — there is no single-device endpoint on the wire, so
   *  this is the only source for the device's own platform, connection and enablement. */
  devices: readonly Device[];
  facets: Facets;
  navigate: Navigate;
  onOpen: (device: string, reason: string) => void;
  /** Attaches, watches or replays a row from the timeline below — see `Timeline`'s own
   *  prop of the same name for why this is a promise the row awaits rather than a plain
   *  navigation. */
  onOpenSession: (session: Session) => Promise<void>;
  /** Reloads the fleet lists — after an edit, a toggle, a stopped agent or a kill, so the
   *  rest of the console sees the same fact this page just acted on. */
  refresh: () => void;
  /** The full-page failure screen — reserved for an admin action refused or erroring out,
   *  same as it always was; this page still cannot render that screen itself; only App's
   *  nav rail has to stay reachable underneath it. */
  onFail: (err: unknown) => void;
}) {
  const info = devices.find((d) => d.id === device);
  const [editing, setEditing] = useState(false);

  // Default to the last 30 days when no `since` facet is present, landed in the URL rather
  // than kept only in state — see the identical effect on the Person page.
  useEffect(() => {
    if (facets.since) return;
    const since = new Date(Date.now() - THIRTY_DAYS_MS).toISOString();
    navigate({ kind: "device", device, facets: { ...facets, since } }, { replace: true });
  }, [facets, navigate, device]);

  const [sessions, setSessions] = useState<TimelineState>({ kind: "loading" });
  // Bumped by the Timeline's own "Try again": a plain re-run of the effect below, on
  // demand, rather than a second copy of the fetch a retry button can call directly.
  const [sessionsRetry, setSessionsRetry] = useState(0);

  useEffect(() => {
    // Waits for the effect above to land `since` in the URL, same as the Person page.
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
          device,
          since,
          ...(facets.until ? { until: facets.until } : {}),
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
  }, [client, device, facets.since, facets.until, facets.state, sessionsRetry]);

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
        const result = await client.deviceAccess(device);
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
  }, [client, device, accessRetry]);

  const [reason, setReason] = useState("");
  const disabled = info?.enabled === false;

  // The device's own admin actions — edit, disable/enable, stop its agent, delete, and
  // ending a live session from the timeline below — moved in from `App.tsx`: this page
  // already held `client`, so the only thing missing was somewhere to put a refusal
  // (`onFail`, still the App-level full-page failure screen) and somewhere to reload the
  // fleet lists afterwards (`refresh`).
  async function saveEdit(input: DeviceForm): Promise<string | null> {
    try {
      await client.updateDevice(input.id.trim(), devicePayload(input));
      refresh();
      return null;
    } catch (err) {
      return err instanceof ApiError ? err.detail || err.message : String(err);
    }
  }

  async function toggle() {
    if (!info) return;
    const enabled = info.enabled !== false;
    if (enabled && !confirm(`Disable ${info.id}?\n\nNew shells will be refused and a connected agent will be stopped. Session history remains available.`)) {
      return;
    }
    const error = await saveEdit({ ...formFromDevice(info), enabled: !enabled });
    if (error) onFail(new Error(error));
  }

  async function stopAgent() {
    if (!confirm(`Stop ${device}?\n\nThe agent exits on that device. Start oarlock-agent there again to reconnect it.`)) {
      return;
    }
    try {
      await client.disconnectAgent(device);
      refresh();
    } catch (err) {
      onFail(err);
    }
  }

  async function remove() {
    if (!confirm(`Delete ${device}?\n\nExisting sessions stay in the ledger, but new sessions cannot target this device until it is added again.`)) {
      return;
    }
    try {
      await client.deleteDevice(device);
      refresh();
    } catch (err) {
      onFail(err);
    }
  }

  async function kill(session: Session) {
    if (!confirm(`End the session on ${session.device_id}?\n\nThe operator's shell closes ` +
      `immediately and the recording is finalised. This cannot be undone.`)) {
      return;
    }
    try {
      await client.kill(session.id, "admin_kill");
      refresh();
    } catch (err) {
      onFail(err);
    }
  }

  return (
    <div className="grid gap-8" data-testid="device-page" data-device={device}>
      <div>
        <p className="label">Device</p>
        <h1 className="mono text-xl font-semibold">{device}</h1>
        <p className="mt-1 text-sm text-fg-muted" data-testid="device-summary">
          {info ? <DeviceSummary device={info} /> : "Not in the registry yet."}
        </p>
      </div>

      <div>
        <h2 className="row-section-title">Open a shell</h2>
        {disabled ? (
          <p className="mt-2 text-sm text-fg-muted">
            This device is disabled. Sessions and handshakes are refused until it is enabled
            again; its history is kept.
          </p>
        ) : (
          <div className="mt-2 flex flex-col gap-2 sm:flex-row">
            <input
              className="field sm:max-w-xs"
              placeholder="ticket or reason"
              aria-label="Reason"
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              data-testid="reason"
            />
            <div className="flex gap-2">
              <button
                className="btn btn-primary"
                onClick={() => onOpen(device, reason)}
                data-testid="open"
              >
                Open
              </button>
              <SshClientDialog client={client} device={device} />
            </div>
          </div>
        )}
      </div>

      {/* The device's own admin actions — edit, disable/enable, stop its agent, delete —
          moved in from the fleet list's expanded row, which no longer exists: this is the
          only place left that renders them. Absent for an id with no registry entry, same
          as the shell box above has nothing to open for one. */}
      {info && (
        <div className="flex flex-wrap items-center gap-1 border-t border-border pt-3">
          <button className="btn btn-quiet" onClick={() => setEditing(true)}>
            Edit
          </button>
          <button className="btn btn-quiet" onClick={() => void toggle()}>
            {disabled ? "Enable" : "Disable"}
          </button>
          {/* Only while there is a channel to stop, and taken from the device's own
              connection state rather than a second list of the same fact. */}
          {info.connected && (
            <button className="btn btn-quiet" onClick={() => void stopAgent()}>
              Stop agent
            </button>
          )}
          <button className="btn btn-danger ml-auto" onClick={() => void remove()}>
            Delete
          </button>
        </div>
      )}

      <section className="grid gap-3">
        <h2 className="text-lg font-semibold">What was done to it</h2>
        <FacetBar
          facets={facets}
          specs={FACET_SPECS}
          testId="device-facets"
          onClear={(key) => {
            const rest = { ...facets };
            delete rest[key];
            navigate({ kind: "device", device, facets: rest });
          }}
        />
        <div className="panel">
          <Timeline
            state={sessions}
            onRetry={() => setSessionsRetry((n) => n + 1)}
            onOpenSession={onOpenSession}
            testId="device-sessions"
            variant="device"
            onKill={(session) => void kill(session)}
          />
        </div>
      </section>

      <Grants
        state={access}
        onRetry={() => setAccessRetry((n) => n + 1)}
        testId="device-access"
        variant="device"
        subject={device}
      />

      {editing && info && (
        <DeviceDialog device={info} onClose={() => setEditing(false)} onSave={saveEdit} />
      )}
    </div>
  );
}

function DeviceSummary({ device }: { device: Device }) {
  const online = device.enabled !== false && device.connected;
  const word = device.enabled === false ? "disabled" : device.connected ? "connected" : "offline";
  return (
    <>
      {device.platform} · {device.resolved_mode} ·{" "}
      <span className={online ? "text-state-recorded" : ""}>{word}</span>
      {device.profiles?.length ? ` · profiles ${device.profiles.join(" ")}` : ""}
    </>
  );
}
