// The session list — shared between the Person and Device pages. What changes between
// them is which side of a session is already fixed by the page you are on: the principal,
// on the Person page, or the device, on the Device page. So the column that varies row to
// row is whichever one *isn't* already fixed — the other one would just repeat the page's
// own heading.

import { get as getCondition } from "@oarlock/terminal/conditions";
import { ApiError, type Session } from "../api";
import type { Route } from "../router/routes";

type Navigate = (to: Route, opts?: { replace?: boolean }) => void;

export type TimelineState =
  | { kind: "loading" }
  | { kind: "failed"; error: unknown }
  | { kind: "ready"; sessions: Session[] };

export function Timeline({
  state,
  onRetry,
  navigate,
  testId,
  variant,
}: {
  state: TimelineState;
  onRetry: () => void;
  navigate: Navigate;
  testId: string;
  /** Which column shows the thing that varies. */
  variant: "person" | "device";
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
            <SessionRow key={session.id} session={session} navigate={navigate} variant={variant} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SessionRow({
  session,
  navigate,
  variant,
}: {
  session: Session;
  navigate: Navigate;
  variant: "person" | "device";
}) {
  const open = () => navigate({ kind: "session", session: session.id });
  const recorded = session.recording_state === "recorded";
  return (
    <tr
      className="cursor-pointer border-t border-border align-top hover:bg-bg-raised/60"
      data-session={session.id}
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
        <button
          type="button"
          className="icon-btn"
          aria-label={`Open session ${session.id}`}
          onClick={(event) => {
            event.stopPropagation();
            open();
          }}
        >
          <span aria-hidden="true">›</span>
        </button>
      </td>
    </tr>
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
