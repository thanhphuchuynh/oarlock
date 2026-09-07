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

import { lazy, Suspense, type ReactNode } from "react";
import { Terminal } from "@oarlock/react";
import { get as getCondition, type Condition } from "@oarlock/terminal/conditions";
import { describeVerdict, type Verdict } from "@oarlock/terminal";
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
    <section className="flex flex-col gap-4" data-testid="terminal">
      <div className="flex items-center justify-between gap-3">
        <span className="mono text-sm text-fg-muted">{props.session.id}</span>
        <button className="btn" onClick={props.onLeave}>
          Leave
        </button>
      </div>
      <SessionMeta session={props.session} {...(props.watching ? { watching: props.watching } : {})} />
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
      <LiveEvidence session={props.session} />
    </section>
  );
}

type ReplayBodyProps = SessionPageProps & { session: Session; cast: string };

function ReplayBody(props: ReplayBodyProps) {
  return (
    <section className="flex flex-col gap-4" data-testid="replay">
      <div className="flex items-center justify-between gap-3">
        <span className="mono text-sm text-fg-muted">{props.session.id}</span>
        <button className="btn" onClick={props.onClose}>
          Back
        </button>
      </div>
      <SessionMeta session={props.session} />
      <Suspense fallback={<p className="text-fg-muted">Loading the player…</p>}>
        <Player
          cast={props.cast}
          verdict={props.verdict}
          sessionID={props.session.id}
          style={{ height: "70vh" }}
        />
      </Suspense>
      <EvidencePanel verdict={props.verdict} />
    </section>
  );
}

// The header the mockup asks for: who, what device, when, and — the fact `Grants`
// already treats this way — the answer to a yes/no question stated plainly rather than
// left to be inferred from a colour. Shared by both bodies so a live session and its own
// eventual replay describe themselves the same way.
function SessionMeta({ session, watching }: { session: Session; watching?: string }) {
  const recorded = session.recording_state === "recorded";
  const closeCondition = session.close_reason ? getCondition(session.close_reason) : undefined;
  return (
    <dl className="grid grid-cols-2 gap-px overflow-hidden border border-border bg-border text-sm sm:grid-cols-3 lg:grid-cols-6">
      <MetaCell label="Person">
        <span className="mono">{session.principal}</span>
      </MetaCell>
      <MetaCell label="Device">
        <span className="mono">{session.device_id}</span>
      </MetaCell>
      <MetaCell label="Profile">
        <span className="mono">{session.profile}</span>
      </MetaCell>
      <MetaCell label="Opened">
        <span className="mono">{relative(session.created_at)}</span>
      </MetaCell>
      <MetaCell label={session.live ? "Status" : "Closed"}>
        {session.live ? (
          watching ? (
            <>
              Observing <span className="mono">{watching}</span>
            </>
          ) : (
            "Attached"
          )
        ) : (
          closeCondition?.headline ?? (session.close_reason || "—")
        )}
      </MetaCell>
      <MetaCell label="Recording">
        <span className={recorded ? "text-state-recorded" : "text-state-unrecorded"}>
          {recorded ? (session.live ? "Recording" : "Recorded") : "Not recorded"}
        </span>
      </MetaCell>
    </dl>
  );
}

function MetaCell({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="bg-bg-raised px-3 py-2">
      <dt className="label mb-0.5">{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

// The evidence panel the mockup places after the body, for a session still being
// recorded: there is nothing to verify yet, because the chain is sealed and signed only
// once the session ends. Saying so plainly is the disclosure's own point extended one
// step further — an operator should never have to guess whether "no verdict yet" means
// "nothing to worry about" or "the page forgot to ask".
function LiveEvidence({ session }: { session: Session }) {
  const recorded = session.recording_state === "recorded";
  return (
    <section className="flex items-start gap-3 rounded-md border border-border bg-bg-raised p-4" data-testid="evidence">
      <span aria-hidden="true" className="mt-0.5 text-lg text-fg-faint">
        ◷
      </span>
      <div>
        <h3 className="font-semibold">
          {recorded ? "Recording in progress" : "This session is not being recorded"}
        </h3>
        <p className="mt-0.5 text-sm text-fg-muted">
          {recorded
            ? "The chain is sealed and signed when the session ends. Nothing to verify yet."
            : "No recording exists for this session, so there will be nothing to verify once it ends either."}
        </p>
      </div>
    </section>
  );
}

// The evidence panel for a closed session: the integrity verdict, given the panel the
// mockup shows instead of the strip that used to sit only above the player.
//
// The copy comes from `describeVerdict` — the same function `<Player>` calls internally
// to draw the banner it always renders above itself — so this panel can never tell a
// reader something different about the same recording than the player already did. It is
// not a second opinion; it is the same one, given room of its own the way the mockup
// draws it. What it must never do is decide anything: a status this build does not
// recognise still falls through to the same "could not be verified" reading the shared
// function gives it.
function EvidencePanel({ verdict }: { verdict: Verdict | undefined }) {
  const copy = verdict
    ? describeVerdict(verdict)
    : {
        tone: "broken" as const,
        headline: "This recording could not be verified.",
        body: "No verification result was supplied for this recording.",
      };
  const toneClass =
    copy.tone === "trusted"
      ? "border-state-recorded"
      : copy.tone === "partial"
        ? "border-state-unrecorded"
        : "border-state-refused";
  const iconClass =
    copy.tone === "trusted"
      ? "text-state-recorded"
      : copy.tone === "partial"
        ? "text-state-unrecorded"
        : "text-state-refused";
  const icon = copy.tone === "trusted" ? "✓" : copy.tone === "partial" ? "◐" : "!";

  return (
    <section
      className={`flex items-start gap-3 rounded-md border bg-bg-raised p-4 ${toneClass}`}
      data-testid="evidence"
      role={copy.tone === "trusted" ? "status" : "alert"}
    >
      <span aria-hidden="true" className={`mt-0.5 text-lg ${iconClass}`}>
        {icon}
      </span>
      <div className="min-w-0 flex-1">
        <h3 className="font-semibold">{copy.headline}</h3>
        <p className="mt-0.5 text-sm text-fg-muted">{copy.body}</p>
        {verdict && (
          <dl className="mono mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-xs text-fg-faint">
            <dt className="not-mono">Verdict</dt>
            <dd>{String(verdict.status)}</dd>
            {verdict.events_expected !== undefined && (
              <>
                <dt className="not-mono">Events</dt>
                <dd>
                  {verdict.events_found ?? 0} of {verdict.events_expected}
                </dd>
              </>
            )}
            {verdict.detail && (
              <>
                <dt className="not-mono">Detail</dt>
                <dd>{verdict.detail}</dd>
              </>
            )}
          </dl>
        )}
      </div>
    </section>
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
