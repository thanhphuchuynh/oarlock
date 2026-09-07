// The session list — shared between the Person and Device pages. What changes between
// them is which side of a session is already fixed by the page you are on: the principal,
// on the Person page, or the device, on the Device page. So the column that varies row to
// row is whichever one *isn't* already fixed — the other one would just repeat the page's
// own heading.
//
// A row's click is not a plain navigation: opening it attaches, watches or replays the
// session, and every one of those is a gateway decision the console does not get to make
// for itself — a `replay` grant an administrator does not hold is exactly as real a
// refusal as an `admin:permissions` one is on `Grants`. So the click asks first
// (`onOpenSession`, owned by the caller because that is where the bypass ticket and the
// router already live) and only leaves this page once the gateway has actually agreed.
// A refusal renders on the row that made the offer — the way `Grants` names the grant
// that is missing rather than rendering an empty list — instead of borrowing the
// full-page failure screen `SessionPage` reserves for a session that cannot be shown at
// all.

import { useState } from "react";
import { get as getCondition, type Condition } from "@oarlock/terminal/conditions";
import { ApiError, type Session } from "../api";

export type TimelineState =
  | { kind: "loading" }
  | { kind: "failed"; error: unknown }
  | { kind: "ready"; sessions: Session[] };

export function Timeline({
  state,
  onRetry,
  onOpenSession,
  testId,
  variant,
  onKill,
}: {
  state: TimelineState;
  onRetry: () => void;
  /** Attaches, watches or replays this session — minting whatever ticket that takes and
   *  navigating there — or rejects with the gateway's own refusal, which the row that
   *  called it renders in place. */
  onOpenSession: (session: Session) => Promise<void>;
  testId: string;
  /** Which column shows the thing that varies. */
  variant: "person" | "device";
  /** Ends a still-live row in place. The old fleet row's "End" button had no other home
   *  once the accordion holding it was removed — optional because ending a session is a
   *  device-scoped admin action; the Person page has no reason to offer it. */
  onKill?: (session: Session) => void;
}) {
  if (state.kind === "loading") {
    return (
      <p className="p-4 text-sm text-fg-muted" data-testid={testId}>
        Loading the timeline…
      </p>
    );
  }
  if (state.kind === "failed") {
    // A malformed `since` gets a 400 from the gateway rather than being silently ignored,
    // precisely so a hand-edited link produces an honest error here instead of a filter
    // that quietly does nothing.
    const condition = state.error instanceof ApiError ? state.error.condition : getCondition("internal");
    return (
      <p className="p-4 text-sm text-state-refused" role="alert" data-testid={testId}>
        {condition.headline}{" "}
        <button type="button" className="underline" onClick={onRetry}>
          Try again
        </button>
      </p>
    );
  }

  const rows = [...state.sessions].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
  if (rows.length === 0) {
    return (
      <p className="p-8 text-center text-sm text-fg-muted" data-testid={testId}>
        No sessions in this window.
      </p>
    );
  }

  const otherLabel = variant === "person" ? "Device" : "Person";

  return (
    <div className="overflow-x-auto" data-testid={testId}>
      <table className="w-full border-collapse text-left text-sm">
        <thead className="bg-bg text-[11px] uppercase tracking-wider text-fg-faint">
          <tr>
            <th className="px-3 py-2 font-medium">Opened</th>
            <th className="px-3 py-2 font-medium">{otherLabel}</th>
            <th className="px-3 py-2 font-medium">Action</th>
            <th className="px-3 py-2 font-medium">Outcome</th>
            <th className="px-3 py-2 font-medium">Recording</th>
            <th className="px-3 py-2" />
          </tr>
        </thead>
        <tbody>
          {rows.map((session) => (
            <SessionRow
              key={session.id}
              session={session}
              onOpenSession={onOpenSession}
              variant={variant}
              {...(onKill ? { onKill } : {})}
            />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SessionRow({
  session,
  onOpenSession,
  variant,
  onKill,
}: {
  session: Session;
  onOpenSession: (session: Session) => Promise<void>;
  variant: "person" | "device";
  onKill?: (session: Session) => void;
}) {
  // Local to this row: two rows opening different sessions at once is ordinary — the
  // fleet is shared — and neither the request in flight nor a refusal about it says
  // anything about a neighbouring row.
  const [pending, setPending] = useState(false);
  const [refused, setRefused] = useState<{ condition: Condition; detail: string } | null>(null);

  const open = () => {
    if (pending) return;
    setRefused(null);
    setPending(true);
    void onOpenSession(session)
      .catch((err: unknown) => {
        const e = err instanceof ApiError ? err : null;
        setRefused({
          condition: e?.condition ?? getCondition("internal"),
          detail: e?.detail ?? String(err),
        });
      })
      .finally(() => setPending(false));
    // No `navigate()` here on success: `onOpenSession` already left for `/s/{id}` once
    // the gateway agreed, which is why this row usually unmounts before the promise
    // above even settles.
  };

  const recorded = session.recording_state === "recorded";
  return (
    <>
      <tr
        className="cursor-pointer border-t border-border align-top hover:bg-bg-raised/60"
        data-session={session.id}
        aria-busy={pending}
        onClick={open}
      >
        <td className="px-3 py-2">
          <span className="mono block whitespace-nowrap text-fg-muted" title={session.created_at}>
            {relative(session.created_at)}
          </span>
        </td>
        <td className="px-3 py-2">
          <span className="mono block whitespace-nowrap">
            {variant === "person" ? session.device_id : session.principal}
          </span>
        </td>
        <td className="px-3 py-2">
          <span className="mono">{session.profile}</span>
          {/* The reason the operator gave, wrapped rather than truncated to three
              characters — it is the field that says why somebody was on this machine, and
              the fleet list's row used to be the only place that said so. */}
          <span className="mt-0.5 block max-w-[16rem] whitespace-normal text-sm text-fg-faint">
            {session.reason || "opened over ssh"}
          </span>
        </td>
        <td className="px-3 py-2">
          <Outcome session={session} />
        </td>
        <td className="px-3 py-2">
          <Badge tone={recorded ? "text-state-recorded" : "text-state-unrecorded"}>
            {recorded ? "Recorded" : "Not recorded"}
          </Badge>
        </td>
        <td className="px-3 py-2">
          <span className="flex items-center justify-end gap-1.5">
            {onKill && session.live && (
              <button
                type="button"
                className="btn btn-danger"
                aria-label={`End session ${session.id}`}
                onClick={(event) => {
                  event.stopPropagation();
                  onKill(session);
                }}
              >
                End
              </button>
            )}
            <button
              type="button"
              className="icon-btn"
              aria-label={`Open session ${session.id}`}
              disabled={pending}
              onClick={(event) => {
                event.stopPropagation();
                open();
              }}
            >
              <span aria-hidden="true">{pending ? "…" : "›"}</span>
            </button>
          </span>
        </td>
      </tr>
      {/* The refusal, in place — beside the row that made the offer, naming the action
          the gateway said was missing, the same way `Grants` names `admin:permissions`
          rather than rendering an empty list. Never a full-page failure: that screen is
          for a session that cannot be shown at all, not for one this row was not allowed
          to open. */}
      {refused && (
        <tr className="border-t border-border/60 bg-bg-raised/60">
          <td colSpan={6} className="px-3 py-2">
            <p className="text-sm text-state-refused" role="alert" data-testid="session-refused">
              {refused.condition.headline}{" "}
              <span className="mono text-fg-muted">{refused.detail}</span>
            </p>
          </td>
        </tr>
      )}
    </>
  );
}

function Outcome({ session }: { session: Session }) {
  if (session.live) {
    return <Badge tone="text-state-recorded">Live</Badge>;
  }
  // The operator-facing sentence, not the wire code — with the code as a title, because
  // somebody reporting a problem should be able to say which one.
  const condition = session.close_reason ? getCondition(session.close_reason) : undefined;
  return (
    <span className="flex flex-col items-start gap-1">
      <Badge tone="text-state-ended">{session.state}</Badge>
      {condition && (
        <span className="text-sm text-fg-muted" title={session.close_reason}>
          {condition.headline}
        </span>
      )}
    </span>
  );
}

function Badge({ children, tone }: { children: React.ReactNode; tone: string }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[0.14em] ${tone}`}
    >
      <span className="size-1.5 bg-current" aria-hidden="true" />
      {children}
    </span>
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
