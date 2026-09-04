// The session page: one URL, three bodies.
//
// `terminal`, `replay` and `failed` used to be three arms of `App`'s `View` union,
// rendered inline in its switch. They move here verbatim — same markup, same class
// names, same behaviour — because Task 4 replaces that union with a router, and by then
// this page must already stand on its own: keyed off what the session actually is
// (attached, recorded, or neither), not off a tag a router no longer produces.
//
// `App` still owns the client and the polling; this file only renders and forwards the
// four callbacks below. That split is why they are four instead of one: `onClose` and
// `onLeave` differ in whether leaving also triggers a refetch, and `onSessionEnded` and
// `renewTicket` exist only because <Terminal> needs them mid-session, before any close
// button is pressed.

import { lazy, Suspense } from "react";
import { Terminal } from "@oarlock/react";
import { get as getCondition, type Condition } from "@oarlock/terminal/conditions";
import type { Verdict } from "@oarlock/terminal";
import type { Attach, Session } from "../api";

// The replay player is loaded on demand: it carries its own terminal emulator, and most
// sessions are never replayed. Moved here from App.tsx along with the branch that was
// its only caller.
const Player = lazy(async () => {
  const mod = await import("@oarlock/react/player");
  return { default: mod.Player };
});

function sameOriginSocketURL(advertised: string): string {
  try {
    const url = new URL(advertised);
    url.protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    url.host = window.location.host;
    return url.toString();
  } catch {
    return advertised;
  }
}

export type SessionPageProps = {
  // Absent for the "failed" case: a top-level failure (killing a session, disabling a
  // device, and the like) has no session of its own to report on.
  session?: Session;
  attach?: Attach; // present while the session is live
  cast?: string; // present once a recording exists
  verdict?: Verdict;
  readOnly: boolean;
  watching?: string;
  failure?: { condition: Condition; detail: string; reference: string };

  /** Back, from the replay and failed screens. Today: setView({ kind: "list" }). */
  onClose(): void;
  /** Leave, from the terminal. Today: setView({ kind: "list" }) AND void refresh(). */
  onLeave(): void;
  /** The Terminal's own onClosed. Today: void refresh(). */
  onSessionEnded(): void;
  /** Backs <Terminal>'s renewTicket. Today: client.renewAttach(session.id).then(a => a.ticket). */
  renewTicket(): Promise<string>;
};

// One page, three bodies. Which one renders is a fact about the session, not a route —
// so a link pasted into a ticket while a session is live still resolves after it ends.
export function SessionPage(props: SessionPageProps) {
  if (props.failure) return <FailedBody {...props.failure} onClose={props.onClose} />;
  if (props.session && props.attach) {
    return <TerminalBody {...props} session={props.session} attach={props.attach} />;
  }
  if (props.session && props.cast) {
    return <ReplayBody {...props} session={props.session} cast={props.cast} />;
  }
  return (
    <FailedBody
      condition={getCondition("not_found")}
      detail="No recording for this session."
      reference=""
      onClose={props.onClose}
    />
  );
}

type TerminalBodyProps = SessionPageProps & { session: Session; attach: Attach };

function TerminalBody(props: TerminalBodyProps) {
  return (
    <section className="flex flex-col gap-3" data-testid="terminal">
      <div className="flex items-center justify-between gap-3">
        <span className="mono text-sm text-fg-muted">{props.session.id}</span>
        <button className="btn" onClick={props.onLeave}>
          Leave
        </button>
      </div>
      <Terminal
        url={sameOriginSocketURL(props.attach.url)}
        ticket={props.attach.ticket}
        device={props.session.device_id}
        principal={props.session.principal}
        {...(props.readOnly ? { readOnly: true } : {})}
        renewTicket={props.renewTicket}
        onClosed={props.onSessionEnded}
        style={{ height: "70vh" }}
      />
    </section>
  );
}

type ReplayBodyProps = SessionPageProps & { session: Session; cast: string };

function ReplayBody(props: ReplayBodyProps) {
  return (
    <section className="flex flex-col gap-3" data-testid="replay">
      <div className="flex items-center justify-between gap-3">
        <span className="mono text-sm text-fg-muted">{props.session.id}</span>
        <button className="btn" onClick={props.onClose}>
          Back
        </button>
      </div>
      <Suspense fallback={<p className="text-fg-muted">Loading the player…</p>}>
        <Player
          cast={props.cast}
          verdict={props.verdict}
          sessionID={props.session.id}
          style={{ height: "70vh" }}
        />
      </Suspense>
    </section>
  );
}

type FailedBodyProps = {
  condition: Condition;
  detail: string;
  reference: string;
  onClose(): void;
};

function FailedBody(props: FailedBodyProps) {
  return (
    <section
      className="rounded-md border border-state-refused bg-bg-raised p-5"
      data-testid="failure"
      role="alert"
    >
      <h2 className="pb-1 text-lg font-semibold">{props.condition.headline}</h2>
      {props.condition.nextAction && (
        <p className="pb-3 text-fg-muted">{props.condition.nextAction}</p>
      )}
      <dl className="mono grid grid-cols-[auto_1fr] gap-x-3 text-sm text-fg-faint">
        <dt className="not-mono">Reason</dt>
        <dd className="select-all">{props.condition.id}</dd>
        {props.reference && (
          <>
            <dt className="not-mono">Reference (for support)</dt>
            <dd className="select-all">{props.reference}</dd>
          </>
        )}
      </dl>
      <div className="pt-4">
        <button className="btn" onClick={props.onClose}>
          Back
        </button>
      </div>
    </section>
  );
}
