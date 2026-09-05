// The search-first home — the mockup's "Who, or what?" Every answer starts with a person
// or a device, so the top of this page is a single box that resolves whatever you type
// straight to that page: a `sess_…` id opens the session, an id already in the fleet opens
// the device's own page, anything else is treated as a principal. That is new — the
// console had no way to jump straight to a person before this page existed.
//
// Below it is the device list `Fleet.tsx` used to own: one row per device, opened inline
// rather than linked away, because `openRow` in the browser suite drives this exact
// accordion — Open a shell, who can reach it, recent sessions, all inside the row you
// clicked. What changes is the access panel: it was Fleet's own copy of the grants
// vocabulary, and is now the same `Grants` the Person and Device pages already share. That
// was the second of the two duplicated grants panels the plan calls out; this is where it
// closes. `DeviceSessions` stays its own thing on purpose — its Attach/Watch/Replay/End
// buttons act immediately, in place, which is a different job from `Timeline`'s "go look at
// the session's own page" rows, and nothing here asks it to become that.

import { useCallback, useEffect, useState } from "react";
import {
  ApiError,
  Client,
  type Device,
  type Session,
} from "../api";
import { SSHAccess } from "../SSHAccess";
import { Grants, type GrantsState } from "../components/Grants";
import type { Route } from "../router/routes";

type Navigate = (to: Route, opts?: { replace?: boolean }) => void;
type StateFilter = "all" | "online" | "offline" | "disabled";

/** What a typed lookup resolves to. Always something: a `sess_…` id is a session, an id
 *  already in the fleet is that device, and anything else is assumed to be a principal —
 *  there is no API to check whether a person exists, and the Person page already answers
 *  "nobody by that name has done anything" by simply having nothing in its timeline. */
type Target = { kind: "person" | "device" | "session"; id: string };

function classify(raw: string, devices: readonly Device[]): Target | null {
  const id = raw.trim();
  if (!id) return null;
  if (id.startsWith("sess_")) return { kind: "session", id };
  if (devices.some((d) => d.id === id)) return { kind: "device", id };
  return { kind: "person", id };
}

function resolveTo(navigate: Navigate, target: Target) {
  if (target.kind === "session") {
    navigate({ kind: "session", session: target.id });
  } else if (target.kind === "device") {
    navigate({ kind: "device", device: target.id, facets: {} });
  } else {
    navigate({ kind: "person", principal: target.id, facets: {} });
  }
}

export interface SearchPageProps {
  client: Client;
  devices: readonly Device[];
  sessions: readonly Session[];
  me: string;
  navigate: Navigate;
  onOpen: (device: string, reason: string) => void;
  onEdit: (device: Device) => void;
  onToggle: (device: Device) => void;
  onDelete: (id: string) => void;
  onStopAgent: (deviceID: string) => void;
  onAttach: (session: Session) => void;
  onObserve: (session: Session) => void;
  onReplay: (session: Session) => void;
  onKill: (session: Session) => void;
}

export function SearchPage(props: SearchPageProps) {
  const { devices, sessions, navigate } = props;
  const [query, setQuery] = useState("");
  const [stateFilter, setStateFilter] = useState<StateFilter>("all");
  const [open, setOpen] = useState<string | null>(null);
  const [lookup, setLookup] = useState("");

  const online = devices.filter((d) => d.enabled !== false && d.connected).length;
  const live = sessions.filter((s) => s.live).length;

  const visible = devices.filter((device) => {
    const needle = query.trim().toLowerCase();
    if (needle && !matchesQuery(device, needle)) return false;
    switch (stateFilter) {
      case "online":
        return device.enabled !== false && device.connected;
      case "offline":
        return device.enabled !== false && !device.connected;
      case "disabled":
        return device.enabled === false;
      default:
        return true;
    }
  });

  const target = classify(lookup, devices);

  return (
    <div className="grid gap-6">
      <section className="panel p-6" data-testid="search-hero">
        <h2 className="text-lg font-semibold">Who, or what?</h2>
        <p className="mt-1 text-sm text-fg-muted">
          Every answer here starts with a person or a device.
        </p>
        <form
          className="mt-4 flex flex-col gap-2 sm:flex-row"
          onSubmit={(event) => {
            event.preventDefault();
            if (!target) return;
            resolveTo(navigate, target);
            setLookup("");
          }}
        >
          <input
            className="field sm:flex-1"
            placeholder="A person, a device id, or a session id"
            aria-label="Search"
            value={lookup}
            onChange={(event) => setLookup(event.target.value)}
          />
          <button className="btn btn-primary" type="submit" disabled={!target}>
            Go
          </button>
        </form>
        {target && (
          <p className="mt-2 text-sm text-fg-faint">
            Enter opens the {target.kind} page for <span className="mono">{target.id}</span>.
          </p>
        )}
      </section>

      <section className="panel" data-testid="fleet">
        {/* The plate's own heading. Without it the page jumps h2 to h3 at the first
            expanded row, which is a real gap for anyone navigating by headings. */}
        <h2 className="sr-only">Devices</h2>
        <div className="panel-header flex-wrap">
          {/* The counts, as a sentence in the header rather than four numbers in large
              type. They are context for the list, not the point of the page. */}
          <p className="text-sm text-fg-muted" data-testid="fleet-summary">
            <span className="font-semibold text-fg">{devices.length}</span>
            {devices.length === 1 ? " device" : " devices"}
            {" · "}
            {online} online
            {" · "}
            {live} live {live === 1 ? "session" : "sessions"}
          </p>
          <div className="flex w-full gap-2 sm:w-auto">
            <input
              className="field min-w-0 sm:w-56"
              placeholder="Search devices"
              aria-label="Search devices"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
            <select
              className="field w-auto"
              aria-label="Filter by state"
              value={stateFilter}
              onChange={(event) => setStateFilter(event.target.value as StateFilter)}
            >
              <option value="all">All states</option>
              <option value="online">Online</option>
              <option value="offline">Offline</option>
              <option value="disabled">Disabled</option>
            </select>
          </div>
        </div>

        {visible.length === 0 ? (
          <p className="border-t border-border p-8 text-center text-fg-muted">
            {devices.length === 0
              ? "No devices are registered. Add one and its agent can dial in."
              : "No devices match this search."}
          </p>
        ) : (
          <ul className="border-t border-border">
            {visible.map((device) => (
              <li key={device.id} className="border-b border-border last:border-b-0">
                <DeviceRow
                  {...props}
                  device={device}
                  expanded={open === device.id}
                  onExpand={() => setOpen(open === device.id ? null : device.id)}
                />
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

function matchesQuery(device: Device, needle: string): boolean {
  const haystack = [
    device.id,
    device.platform,
    device.resolved_mode,
    ...(device.profiles ?? []),
    ...Object.entries(device.tags ?? {}).map(([k, v]) => `${k}=${v}`),
  ];
  return haystack.some((value) => value.toLowerCase().includes(needle));
}

function DeviceRow({
  client,
  device,
  sessions,
  me,
  expanded,
  onExpand,
  onOpen,
  onEdit,
  onToggle,
  onDelete,
  onStopAgent,
  onAttach,
  onObserve,
  onReplay,
  onKill,
}: SearchPageProps & {
  device: Device;
  expanded: boolean;
  onExpand: () => void;
}) {
  const [reason, setReason] = useState("");
  const [access, setAccess] = useState<GrantsState | undefined>();
  const mine = sessions.filter((s) => s.device_id === device.id);
  const liveHere = mine.filter((s) => s.live);
  const disabled = device.enabled === false;

  const loadAccess = useCallback(async () => {
    setAccess({ kind: "loading" });
    try {
      const result = await client.deviceAccess(device.id);
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
  }, [client, device.id]);

  // Loaded when the row is first opened, not with the page: on a fleet of two hundred
  // this would otherwise be two hundred policy evaluations to render a list.
  useEffect(() => {
    if (expanded && access === undefined) void loadAccess();
  }, [expanded, access, loadAccess]);

  const region = `device-${device.id}`;
  return (
    <div data-device={device.id}>
      <button
        type="button"
        className="row-toggle"
        aria-expanded={expanded}
        aria-controls={region}
        onClick={onExpand}
      >
        <StateDot device={device} />
        <span className="min-w-0 flex-1">
          {/* A device id never wraps. Broken over two lines the hyphen in
              "treadmill-4821" reads as an em-dash, and a device id that looks like a
              different device id is the one typo that matters here. */}
          <span className="mono block truncate font-medium">{device.id}</span>
          <span className="block truncate text-sm text-fg-muted">
            {device.platform} · {device.resolved_mode}
            {device.profiles?.length ? ` · ${device.profiles.join(" ")}` : ""}
          </span>
        </span>
        {/* Never colour alone: the dot has a word beside it at every width. */}
        <span className="shrink-0 text-sm text-fg-muted">{stateWord(device)}</span>
        {liveHere.length > 0 && (
          <span className="border border-state-recorded px-2 py-0.5 text-[11px] font-semibold uppercase tracking-[0.14em] text-state-recorded">
            {liveHere.length} live
          </span>
        )}
        <span aria-hidden="true" className="text-fg-faint">
          {expanded ? "▴" : "▾"}
        </span>
      </button>

      {expanded && (
        <div
          id={region}
          className="grid gap-5 border-t border-border bg-bg py-4 pl-4 pr-4 shadow-[inset_3px_0_0_var(--oarlock-fg-faint)] sm:pl-7"
        >
          {/* Opening a shell starts from the device, so there is no id to retype and no
              id to get wrong. The reason is the only thing this form needs. */}
          <div>
            <h3 className="row-section-title">Open a shell</h3>
            {disabled ? (
              <p className="mt-2 text-sm text-fg-muted">
                This device is disabled. Sessions and handshakes are refused until it is
                enabled again; its history is kept.
              </p>
            ) : (
              <div className="mt-2 flex flex-col gap-2 sm:flex-row">
                <input
                  className="field sm:flex-1"
                  placeholder="ticket or reason"
                  aria-label="Reason"
                  value={reason}
                  onChange={(event) => setReason(event.target.value)}
                  data-testid="reason"
                />
                <div className="flex gap-2">
                  <button
                    className="btn btn-primary"
                    onClick={() => onOpen(device.id, reason)}
                    data-testid="open"
                  >
                    Open
                  </button>
                  <SSHAccess client={client} device={device.id} />
                </div>
              </div>
            )}
          </div>

          <Grants
            state={access ?? { kind: "loading" }}
            onRetry={() => void loadAccess()}
            testId="device-access"
            variant="device"
            subject={device.id}
          />

          <div>
            <h3 className="row-section-title">Recent sessions</h3>
            <DeviceSessions
              sessions={mine}
              me={me}
              onAttach={onAttach}
              onObserve={onObserve}
              onReplay={onReplay}
              onKill={onKill}
            />
          </div>

          {/* Routine actions read as text; the one that destroys a record is separated
              from them and is the only coloured thing here. */}
          <div className="flex flex-wrap items-center gap-1 border-t border-border pt-3">
            <button className="btn btn-quiet" onClick={() => onEdit(device)}>
              Edit
            </button>
            <button className="btn btn-quiet" onClick={() => onToggle(device)}>
              {disabled ? "Enable" : "Disable"}
            </button>
            {/* Only while there is a channel to stop, and taken from the device's own
                connection state rather than a second list of the same fact. */}
            {device.connected && (
              <button className="btn btn-quiet" onClick={() => onStopAgent(device.id)}>
                Stop agent
              </button>
            )}
            <button
              className="btn btn-danger ml-auto"
              onClick={() => onDelete(device.id)}
            >
              Delete
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function stateWord(device: Device): string {
  if (device.enabled === false) return "Disabled";
  return device.connected ? "Online" : "Offline";
}

/** Nothing important is only a colour: the dot is paired with a word in the row. */
function StateDot({ device }: { device: Device }) {
  const tone =
    device.enabled === false
      ? "text-state-refused"
      : device.connected
        ? "bg-state-recorded"
        : "text-fg-faint";
  // A square mark, not a dot: nothing on a drawing sheet is round, and a filled versus
  // hollow square is a second channel the colour does not have to carry alone.
  const filled = device.enabled !== false && device.connected;
  return (
    <span className="grid size-6 shrink-0 place-items-center" aria-hidden="true">
      <span
        className={`size-2.5 border ${filled ? tone : "border-current bg-transparent"} ${
          filled ? "border-transparent" : ""
        }`}
      />
    </span>
  );
}

function DeviceSessions({
  sessions,
  me,
  onAttach,
  onObserve,
  onReplay,
  onKill,
}: {
  sessions: readonly Session[];
  me: string;
  onAttach: (s: Session) => void;
  onObserve: (s: Session) => void;
  onReplay: (s: Session) => void;
  onKill: (s: Session) => void;
}) {
  if (sessions.length === 0) {
    return (
      <p className="mt-2 text-sm text-fg-muted">
        Nothing has been opened on this device yet.
      </p>
    );
  }
  // Newest first, and only the recent few: the whole history has its own page, and a row
  // that expands into fifty sessions is a row nobody expands twice.
  const rows = [...sessions]
    .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at))
    .slice(0, 5);
  return (
    <ul className="mt-2 grid gap-1.5">
      {rows.map((s) => (
        <li
          key={s.id}
          className="flex flex-col gap-1 border-b border-border/60 pb-1.5 last:border-b-0 last:pb-0 sm:flex-row sm:items-baseline sm:gap-x-2"
        >
          <span className="flex min-w-0 flex-wrap items-baseline gap-x-2">
            <span className="shrink-0 text-sm text-fg-faint" title={s.created_at}>
              {relative(s.created_at)}
            </span>
            <span className="mono min-w-0 break-all text-sm text-fg-muted">{s.principal}</span>
            <span
              className={`shrink-0 text-[11px] font-semibold uppercase tracking-wider ${
                s.recording_state === "recorded"
                  ? "text-state-recorded"
                  : "text-state-unrecorded"
              }`}
            >
              {s.recording_state === "recorded" ? "Recorded" : "Not recorded"}
            </span>
          </span>
          {/* The reason wraps rather than truncating to three characters. It is the field
              that says why somebody was on this machine. */}
          <span className="min-w-0 flex-1 text-sm text-fg-muted sm:truncate">
            {s.reason || <span className="text-fg-faint">opened over ssh</span>}
          </span>
          <span className="flex shrink-0 gap-1">
            {s.live && s.principal === me && (
              <button className="btn btn-quiet" onClick={() => onAttach(s)}>
                Attach
              </button>
            )}
            {s.live && s.principal !== me && (
              <button className="btn btn-quiet" onClick={() => onObserve(s)}>
                Watch
              </button>
            )}
            {s.recording_state === "recorded" && !s.live && (
              <button className="btn btn-quiet" onClick={() => onReplay(s)}>
                Replay
              </button>
            )}
            {s.live && (
              <button className="btn btn-danger" onClick={() => onKill(s)}>
                End
              </button>
            )}
          </span>
        </li>
      ))}
    </ul>
  );
}

function relative(iso: string): string {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "";
  const secs = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.round(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.round(secs / 3600)}h ago`;
  return `${Math.round(secs / 86400)}d ago`;
}
