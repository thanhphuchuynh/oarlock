// The session list. A log turned into an explanation by one free-text field.

import { get as getCondition } from "@oarlock/terminal/conditions";
import type { Session } from "./api";

function relative(iso: string): string {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "";
  const secs = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.round(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.round(secs / 3600)}h ago`;
  return `${Math.round(secs / 86400)}d ago`;
}

function Badge({ children, tone }: { children: React.ReactNode; tone: string }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-[0.14em] ${tone}`}
    >
      <span className="size-1.5 bg-current" aria-hidden="true" />
      {children}
    </span>
  );
}

export function SessionList({
  sessions,
  onAttach,
  onObserve,
  onReplay,
  onKill,
  me,
}: {
  sessions: readonly Session[];
  onAttach: (s: Session) => void;
  onObserve: (s: Session) => void;
  onReplay: (s: Session) => void;
  onKill: (s: Session) => void;
  me: string;
}) {
  if (sessions.length === 0) {
    // Empty states say what would fill them, rather than being a blank panel.
    return (
      <p className="border-t border-border p-8 text-center text-fg-muted">
        No sessions yet. Open one from the Fleet page and it will appear here, with who
        opened it and why.
      </p>
    );
  }

  // Newest first. An operator opening this wants the session they just started, or the
  // one that just failed — not the oldest row in the table.
  const rows = [...sessions].sort(
    (a, b) => Date.parse(b.created_at) - Date.parse(a.created_at),
  );

  return (
    <div className="overflow-x-auto border-t border-border">
      <table className="w-full border-collapse text-left">
        <thead className="bg-bg-raised text-sm uppercase tracking-wider text-fg-faint">
          <tr>
            {/* Header and cell breakpoints have to agree. They did not: `State` was
                always shown while its cell was hidden below `sm`, so on a phone the
                recording badge sat under a STATE heading — the two columns swapped
                silently at 640px. */}
            <th className="px-3 py-2 font-medium">Session</th>
            <th className="px-3 py-2 font-medium">State</th>
            <th className="px-3 py-2 font-medium">Recording</th>
            <th className="px-3 py-2" />
          </tr>
        </thead>
        <tbody>
          {rows.map((s) => {
            const recorded = s.recording_state === "recorded";
            const cond = s.close_reason ? getCondition(s.close_reason) : undefined;
            return (
              <tr
                key={s.id}
                className="border-t border-border align-top hover:bg-bg-raised/60"
                data-session={s.id}
              >
                {/* Device, operator and time in one cell rather than three columns that
                    get hidden one by one. A phone used to keep the device id — repeated
                    down the whole table — and drop precisely the fields that tell two
                    rows apart. */}
                <td className="px-3 py-2">
                  {/* Machine values do not wrap. Broken across two lines the hyphen in
                      "treadmill-4821" reads as an em-dash, which makes a device id look
                      like a different device id. The table scrolls instead. */}
                  <div className="mono whitespace-nowrap font-medium">{s.device_id}</div>
                  <div className="mt-0.5 flex flex-wrap items-baseline gap-x-2 text-sm text-fg-muted">
                    <span className="mono">{s.principal}</span>
                    {/* Relative at rest, absolute on hover: an auditor needs the instant,
                        an operator needs "recently". */}
                    <span className="text-fg-faint" title={s.created_at}>
                      {relative(s.created_at)}
                    </span>
                  </div>
                  {/* The reason lives here and only here. It also had a column of its
                      own, hidden below `xl` — the same sentence rendered twice, which is
                      how a reader ends up looking at the copy that is switched off.
                      Only the API takes a reason, so an ssh session has none: said as
                      "opened over ssh" rather than left blank, because an empty cell
                      reads as missing data and this is not missing, it is not
                      applicable. */}
                  <div className="mt-1 max-w-[48ch] text-sm text-fg-muted">
                    {s.reason || <span className="text-fg-faint">opened over ssh</span>}
                  </div>
                </td>
                <td className="px-3 py-2">
                  {s.live ? (
                    <Badge tone="text-state-recorded">Live</Badge>
                  ) : (
                    // `items-start`, or the flex column stretches a pill into a
                    // column-wide bar that stops reading as a badge.
                    <span className="flex flex-col items-start gap-1">
                      <Badge tone="text-state-ended">{s.state}</Badge>
                      {/* The close reason in the operator's words, not the wire code —
                          and the code beside it, because somebody reporting a problem
                          should be able to say which one. */}
                      {cond && (
                        <span className="text-sm text-fg-muted" title={s.close_reason}>
                          {cond.headline}
                        </span>
                      )}
                    </span>
                  )}
                </td>
                <td className="px-3 py-2">
                  {/* Never hidden at any width, and never only a colour: whether a
                      session was recorded is not a detail to drop on a small screen. */}
                  <Badge tone={recorded ? "text-state-recorded" : "text-state-unrecorded"}>
                    {recorded ? "Recorded" : "Not recorded"}
                  </Badge>
                </td>
                <td className="px-3 py-2">
                  <div className="flex flex-wrap justify-end gap-1">
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
                    {recorded && !s.live && (
                      <button className="btn btn-quiet" onClick={() => onReplay(s)}>
                        Replay
                      </button>
                    )}
                    {s.live && (
                      <button className="btn btn-danger" onClick={() => onKill(s)}>
                        End
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
