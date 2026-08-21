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
      className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wider ${tone}`}
    >
      <span className="size-1.5 rounded-full bg-current" aria-hidden="true" />
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
      <p className="rounded-md border border-border bg-bg-raised p-6 text-fg-muted">
        No sessions yet. Open one on a device above and it will appear here, with who
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
    <div className="overflow-x-auto rounded-md border border-border">
      <table className="w-full border-collapse text-left">
        <thead className="bg-bg-raised text-xs uppercase tracking-wider text-fg-faint">
          <tr>
            <th className="px-3 py-2 font-medium">Device</th>
            <th className="px-3 py-2 font-medium">State</th>
            <th className="px-3 py-2 font-medium">Recording</th>
            <th className="px-3 py-2 font-medium">Operator</th>
            <th className="px-3 py-2 font-medium">Why</th>
            <th className="px-3 py-2 font-medium">When</th>
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
                className="border-t border-border align-top"
                data-session={s.id}
              >
                {/* Machine values do not wrap. Broken across two lines the hyphen in
                    "treadmill-4821" reads as an em-dash, which makes a device id look
                    like a different device id. The table scrolls instead. */}
                <td className="mono whitespace-nowrap px-3 py-2">{s.device_id}</td>
                <td className="px-3 py-2">
                  {s.live ? (
                    <Badge tone="text-state-recorded">Live</Badge>
                  ) : (
                    <span className="flex flex-col gap-1">
                      <Badge tone="text-state-ended">{s.state}</Badge>
                      {/* The close reason in the operator's words, not the wire code —
                          and the code beside it, because somebody reporting a problem
                          should be able to say which one. */}
                      {cond && (
                        <span className="text-xs text-fg-muted" title={s.close_reason}>
                          {cond.headline}
                        </span>
                      )}
                    </span>
                  )}
                </td>
                <td className="px-3 py-2">
                  {/* Nothing important is only a colour: every state carries a word. */}
                  <Badge tone={recorded ? "text-state-recorded" : "text-state-unrecorded"}>
                    {recorded ? "Recorded" : "Not recorded"}
                  </Badge>
                </td>
                <td className="mono px-3 py-2 text-fg-muted">{s.principal}</td>
                <td className="max-w-[28ch] px-3 py-2 text-fg-muted">
                  {/* Only the API takes a reason, so an ssh session has none. Said as
                      "opened over ssh" rather than left blank: an empty cell reads as
                      missing data, and this is not missing, it is not applicable. */}
                  {s.reason || (
                    <span className="text-fg-faint">
                      {s.principal && !s.reason ? "opened over ssh" : "—"}
                    </span>
                  )}
                </td>
                <td className="px-3 py-2 text-fg-muted" title={s.created_at}>
                  {/* Relative at rest, absolute on hover: an auditor needs the instant,
                      an operator needs "recently". */}
                  {relative(s.created_at)}
                </td>
                <td className="px-3 py-2">
                  <div className="flex flex-wrap justify-end gap-2">
                    {s.live && s.principal === me && (
                      <button className="btn" onClick={() => onAttach(s)}>
                        Attach
                      </button>
                    )}
                    {s.live && s.principal !== me && (
                      <button className="btn" onClick={() => onObserve(s)}>
                        Watch
                      </button>
                    )}
                    {recorded && !s.live && (
                      <button className="btn" onClick={() => onReplay(s)}>
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
