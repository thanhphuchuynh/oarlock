// The search-first home — the mockup's "Who, or what?" Every answer starts with a person
// or a device, so the top of this page is a single box that resolves whatever you type
// straight to that page: a `sess_…` id opens the session, an id already in the fleet opens
// the device's own page, anything else is treated as a principal. That is new — the
// console had no way to jump straight to a person before this page existed.
//
// Below it is the device list: one row per device, each a **link** to `/d/{id}` — nothing
// expands here any more. Every question that row used to answer inline (open a shell, who
// can reach it, who administers it, recent sessions) is `DevicePage`'s job now, built in
// Task 3 and reachable at that URL. Keeping a second, in-place copy of that page inside an
// accordion was the thing this task existed to remove: `DevicePage` was a page nothing
// linked to, and this list linking to it is what closes that gap.

import { useState } from "react";
import type { Device, Session } from "../api";
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
  devices: readonly Device[];
  sessions: readonly Session[];
  navigate: Navigate;
}

export function SearchPage({ devices, sessions, navigate }: SearchPageProps) {
  const [query, setQuery] = useState("");
  const [stateFilter, setStateFilter] = useState<StateFilter>("all");
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
        {/* The plate's own heading. Every row below is a link straight to `/d/{id}`, so
            there is no expanded content to jump the heading level for any more. */}
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
                <DeviceLink device={device} sessions={sessions} navigate={navigate} />
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

/** One row, one link. Everything the old accordion answered in place — open a shell, who
 *  can reach the device, who administers it, its recent sessions — is a question `/d/{id}`
 *  answers now, so a row here has nothing left to do but say what the device is and take
 *  you there. */
function DeviceLink({
  device,
  sessions,
  navigate,
}: {
  device: Device;
  sessions: readonly Session[];
  navigate: Navigate;
}) {
  const liveHere = sessions.filter((s) => s.device_id === device.id && s.live).length;
  return (
    <button
      type="button"
      className="flex w-full items-center gap-3 p-4 text-left hover:bg-bg-raised/60"
      data-device={device.id}
      onClick={() => navigate({ kind: "device", device: device.id, facets: {} })}
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
      {liveHere > 0 && (
        <span className="border border-state-recorded px-2 py-0.5 text-[11px] font-semibold uppercase tracking-[0.14em] text-state-recorded">
          {liveHere} live
        </span>
      )}
      <span aria-hidden="true" className="text-fg-faint">
        ›
      </span>
    </button>
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
