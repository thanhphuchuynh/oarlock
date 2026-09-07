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

import { useCallback, useEffect, useState } from "react";
import { ApiError, type Client, type Device, type Session } from "../api";
import type { Facets, Route } from "../router/routes";
import { Grants, type GrantsState } from "../components/Grants";
import { Timeline, type TimelineState } from "../components/Timeline";
import { FacetBar, type FacetSpec } from "../components/Facets";
import { SSHAccess } from "../SSHAccess";

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
  onEdit,
  onToggle,
  onDelete,
  onStopAgent,
  onKill,
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
  /** The device form dialog, opened for this device rather than for a new one. */
  onEdit: (device: Device) => void;
  onToggle: (device: Device) => void;
  onDelete: (id: string) => void;
  onStopAgent: (deviceID: string) => void;
  onKill: (session: Session) => void;
}) {
  const info = devices.find((d) => d.id === device);

  // Default to the last 30 days when no `since` facet is present, landed in the URL rather
  // than kept only in state — see the identical effect on the Person page.
  useEffect(() => {
    if (facets.since) return;
    const since = new Date(Date.now() - THIRTY_DAYS_MS).toISOString();
    navigate({ kind: "device", device, facets: { ...facets, since } }, { replace: true });
  }, [facets, navigate, device]);

  const [sessions, setSessions] = useState<TimelineState>({ kind: "loading" });

  const loadSessions = useCallback(async () => {
    // Waits for the effect above to land `since` in the URL, same as the Person page.
    if (!facets.since) return;
    setSessions({ kind: "loading" });
    try {
      const { sessions: rows } = await client.sessions({
        device,
        since: facets.since,
        ...(facets.until ? { until: facets.until } : {}),
        ...(facets.state ? { state: facets.state } : {}),
        limit: 100,
      });
      setSessions({ kind: "ready", sessions: rows });
    } catch (error) {
      setSessions({ kind: "failed", error });
    }
  }, [client, device, facets.since, facets.until, facets.state]);

  useEffect(() => {
    void loadSessions();
  }, [loadSessions]);

  const [access, setAccess] = useState<GrantsState>({ kind: "loading" });

  const loadAccess = useCallback(async () => {
    setAccess({ kind: "loading" });
    try {
      const result = await client.deviceAccess(device);
      setAccess({ kind: "ready", rules: result.rules, adminActions: result.admin_actions });
    } catch (caught) {
      if (caught instanceof ApiError && caught.code === "not_authorized") {
        setAccess({ kind: "refused", error: caught });
        return;
      }
      setAccess({
        kind: "failed",
        message: caught instanceof Error ? caught.message : String(caught),
      });
    }
  }, [client, device]);

  useEffect(() => {
    void loadAccess();
  }, [loadAccess]);

  const [reason, setReason] = useState("");
  const disabled = info?.enabled === false;

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
              <SSHAccess client={client} device={device} />
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
          <button className="btn btn-quiet" onClick={() => onEdit(info)}>
            Edit
          </button>
          <button className="btn btn-quiet" onClick={() => onToggle(info)}>
            {disabled ? "Enable" : "Disable"}
          </button>
          {/* Only while there is a channel to stop, and taken from the device's own
              connection state rather than a second list of the same fact. */}
          {info.connected && (
            <button className="btn btn-quiet" onClick={() => onStopAgent(device)}>
              Stop agent
            </button>
          )}
          <button className="btn btn-danger ml-auto" onClick={() => onDelete(device)}>
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
            onRetry={() => void loadSessions()}
            onOpenSession={onOpenSession}
            testId="device-sessions"
            variant="device"
            onKill={onKill}
          />
        </div>
      </section>

      <Grants
        state={access}
        onRetry={() => void loadAccess()}
        testId="device-access"
        variant="device"
        subject={device}
      />
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
