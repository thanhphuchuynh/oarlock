// The fleet, organised around the thing you actually work with.
//
// The page this replaced had the same device in two panels — a "Device registry" table
// whose STATE column said ONLINE, and a "Live agents" table that existed to say ONLINE
// again — above a stat row that repeated in large type what both tables already showed,
// above a shell form that asked you to retype a device id you were looking at. Four
// places to read one device's state, and none of them answered the question an
// administrator actually arrives with: who can reach this thing, and what has been done
// on it.
//
// So: one row per device, and everything about that device inside it. Connection state is
// a property of the row, because that is what it is. Opening a shell starts from the
// device rather than from a text field. "Who can reach it" is answered by the gateway,
// with the authorisation backend's own matcher, because a second copy of glob-and-tag
// matching in this file would drift and would drift towards lying.

import { useCallback, useEffect, useState } from "react";
import {
  ApiError,
  Client,
  type Device,
  type DeviceAccess,
  type Permission,
  type Session,
} from "./api";
import { SSHAccess } from "./SSHAccess";

type StateFilter = "all" | "online" | "offline" | "disabled";

/** What the access panel knows, per device. Loaded when a row is first opened. */
type Access =
  | { kind: "loading" }
  | { kind: "refused"; error: ApiError }
  | { kind: "failed"; message: string }
  | { kind: "rules"; access: DeviceAccess };

export interface FleetProps {
  client: Client;
  devices: readonly Device[];
  sessions: readonly Session[];
  me: string;
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

export function Fleet(props: FleetProps) {
  const { devices, sessions } = props;
  const [query, setQuery] = useState("");
  const [stateFilter, setStateFilter] = useState<StateFilter>("all");
  const [open, setOpen] = useState<string | null>(null);

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

  return (
    <section className="panel" data-testid="fleet">
      {/* The plate's own heading. Without it the page jumps h1 to h3 at the first
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
}: FleetProps & {
  device: Device;
  expanded: boolean;
  onExpand: () => void;
}) {
  const [reason, setReason] = useState("");
  const [access, setAccess] = useState<Access | undefined>();
  const mine = sessions.filter((s) => s.device_id === device.id);
  const liveHere = mine.filter((s) => s.live);
  const disabled = device.enabled === false;

  const loadAccess = useCallback(async () => {
    setAccess({ kind: "loading" });
    try {
      setAccess({ kind: "rules", access: await client.deviceAccess(device.id) });
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

          <AccessPanel access={access} onRetry={() => void loadAccess()} />

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

function AccessPanel({ access, onRetry }: { access: Access | undefined; onRetry: () => void }) {
  if (access === undefined || access.kind === "loading") {
    return (
      <div data-testid="device-access">
        <h3 className="row-section-title">Who can reach it</h3>
        <p className="mt-2 text-sm text-fg-muted">Evaluating the policy…</p>
      </div>
    );
  }
  if (access.kind === "refused") {
    return (
      <div data-testid="device-access">
        <h3 className="row-section-title">Who can reach it</h3>
        {/* A device administrator who cannot read the policy is a real configuration, not
            an error. Saying which grant is missing beats an empty list, which would read
            as "nobody can reach this". */}
        <p className="mt-2 text-sm text-fg-muted">
          {access.error.condition.headline}{" "}
          <span className="text-fg-faint">
            Seeing who can reach a device needs <span className="mono">admin:permissions</span>{" "}
            on <span className="mono">gateway</span>.
          </span>
        </p>
      </div>
    );
  }
  if (access.kind === "failed") {
    return (
      <div data-testid="device-access">
        <h3 className="row-section-title">Who can reach it</h3>
        <p className="mt-2 text-sm text-state-refused" role="alert">
          {access.message}{" "}
          <button className="underline" onClick={onRetry}>
            Try again
          </button>
        </p>
      </div>
    );
  }

  // Reaching a device and administering it are different sentences about a person, so
  // they are different lists. Grouped by the vocabulary the gateway sent rather than a
  // copy of it kept here: `admin:devices` is not a way to reach a device, and showing it
  // under "who can reach it" said something untrue about whoever held it.
  const admin = new Set(access.access.admin_actions);
  const reach = access.access.rules.filter((rule) =>
    rule.actions.some((action) => action === "*" || !admin.has(action)),
  );
  const administer = access.access.rules.filter((rule) =>
    rule.actions.some((action) => action === "*" || admin.has(action)),
  );

  return (
    <div className="grid gap-4" data-testid="device-access">
      <div data-testid="device-access-reach">
        <h3 className="row-section-title">Who can reach it</h3>
        {reach.length === 0 ? (
          <p className="mt-2 text-sm text-fg-muted">
            No rule lets anybody open a session on this device.
          </p>
        ) : (
          <ul className="mt-2 grid gap-1.5">
            {reach.map((rule) => (
              <AccessRule key={rule.id} rule={rule} admin={admin} kind="reach" />
            ))}
          </ul>
        )}
      </div>
      {administer.length > 0 && (
        <div data-testid="device-access-admin">
          <h3 className="row-section-title">Who can administer it</h3>
          <ul className="mt-2 grid gap-1.5">
            {administer.map((rule) => (
              <AccessRule key={rule.id} rule={rule} admin={admin} kind="administer" />
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function AccessRule({
  rule,
  admin,
  kind,
}: {
  rule: Permission;
  admin: ReadonlySet<string>;
  kind: "reach" | "administer";
}) {
  const deny = rule.effect === "deny";
  const off = !rule.enabled;
  // Only the actions this list is about. A rule granting `shell` and `admin:kill` says
  // something different in each place, and printing both lists in both places is how a
  // reader stops trusting either.
  const shown = rule.actions.filter((action) => {
    if (action === "*") return true;
    return kind === "administer" ? admin.has(action) : !admin.has(action);
  });
  return (
    <li
      className={`flex flex-wrap items-baseline gap-x-2 gap-y-0.5 text-sm ${off ? "opacity-50" : ""}`}
      data-rule={rule.id}
    >
      {/* Deny first in the list and named in the row, because it outranks every allow
          wherever it appears. A reader scanning for "can they" must not have to reach the
          end to find the one line that reverses the rest. */}
      <span
        className={`shrink-0 text-[11px] font-semibold uppercase tracking-wider ${
          deny ? "text-state-refused" : "text-state-recorded"
        }`}
      >
        {deny ? "Denied" : "Allowed"}
      </span>
      <span className="mono min-w-0 break-all">{rule.principals.join(", ")}</span>
      <span className="mono text-sm text-fg-muted">
        {shown.includes("*") ? "every action" : shown.join(" ")}
      </span>
      {limitsOf(rule) && <span className="text-sm text-fg-faint">{limitsOf(rule)}</span>}
      {deny && rule.reason && (
        <span className="text-sm text-state-refused">— {rule.reason}</span>
      )}
      {off && <span className="text-sm text-fg-faint">— rule disabled, not consulted</span>}
    </li>
  );
}

/** Grant limits only tighten, so they are worth showing where the grant is read. */
function limitsOf(rule: Permission): string {
  const parts: string[] = [];
  if (rule.max_duration) parts.push(`max ${rule.max_duration}`);
  if (rule.idle) parts.push(`idle ${rule.idle}`);
  if (rule.ttl) parts.push(`re-checked every ${rule.ttl}`);
  return parts.join(" · ");
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
