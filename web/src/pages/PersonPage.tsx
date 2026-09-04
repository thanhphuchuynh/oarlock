// The Person page — the two questions an auditor actually arrives with: what did this
// person do, and were they allowed to. Nothing in the console before this was
// principal-shaped; everything here is organised around the person rather than around a
// session list or a permission table.
//
// Two stacked sections, in the order the design puts them: what happened, then whether it
// was permitted. The second section is read-only on purpose — writing policy is an
// administrator's job, not an auditor's, and folding a mutation dialog into an evidence
// page would answer a question nobody here is asking.

import { useCallback, useEffect, useState } from "react";
import { get as getCondition } from "@oarlock/terminal/conditions";
import { ApiError, type Client, type Permission, type PrincipalAccess, type Session } from "../api";
import type { Facets, Route } from "../router/routes";

type Navigate = (to: Route, opts?: { replace?: boolean }) => void;

// The default window, put into the URL rather than kept only in component state — see the
// effect below.
const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;

type SessionsState =
  | { kind: "loading" }
  | { kind: "failed"; error: unknown }
  | { kind: "ready"; sessions: Session[] };

/** What the grants section knows. Mirrors `Fleet.tsx`'s per-device `Access` union — see
 *  the comment on `GrantsPanel` for why all four states matter here, sharper than there. */
type Access =
  | { kind: "loading" }
  | { kind: "refused"; error: ApiError }
  | { kind: "failed"; message: string }
  | { kind: "ready"; access: PrincipalAccess };

export function PersonPage({
  client,
  principal,
  facets,
  navigate,
}: {
  client: Client;
  principal: string;
  facets: Facets;
  navigate: Navigate;
}) {
  // Default to the last 30 days when no `since` facet is present, and land the default in
  // the URL rather than leaving it in state. A default that lives only here produces a
  // link that does not reproduce what the sender was looking at — the same reason every
  // other facet already round-trips through `route.facets` instead of local state.
  useEffect(() => {
    if (facets.since) return;
    const since = new Date(Date.now() - THIRTY_DAYS_MS).toISOString();
    navigate({ kind: "person", principal, facets: { ...facets, since } }, { replace: true });
  }, [facets, navigate, principal]);

  const [sessions, setSessions] = useState<SessionsState>({ kind: "loading" });

  const loadSessions = useCallback(async () => {
    // Waits for the effect above to land `since` in the URL. The very first render of a
    // bare `/p/{id}` has no `since` yet; fetching unbounded here would just be redone the
    // moment the default arrives.
    if (!facets.since) return;
    setSessions({ kind: "loading" });
    try {
      const { sessions: rows } = await client.sessions({
        principal,
        since: facets.since,
        ...(facets.until ? { until: facets.until } : {}),
        ...(facets.device ? { device: facets.device } : {}),
        ...(facets.state ? { state: facets.state } : {}),
        limit: 100,
      });
      setSessions({ kind: "ready", sessions: rows });
    } catch (error) {
      setSessions({ kind: "failed", error });
    }
  }, [client, principal, facets.since, facets.until, facets.device, facets.state]);

  useEffect(() => {
    void loadSessions();
  }, [loadSessions]);

  const [access, setAccess] = useState<Access>({ kind: "loading" });

  const loadAccess = useCallback(async () => {
    setAccess({ kind: "loading" });
    try {
      setAccess({ kind: "ready", access: await client.principalAccess(principal) });
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
  }, [client, principal]);

  useEffect(() => {
    void loadAccess();
  }, [loadAccess]);

  return (
    <div className="grid gap-8" data-testid="person-page">
      <div>
        <p className="label">Person</p>
        <h1 className="mono text-xl font-semibold">{principal}</h1>
      </div>

      <section className="grid gap-3">
        <h2 className="text-lg font-semibold">
          What they did{" "}
          <span className="text-sm font-normal text-fg-muted">
            — the timeline, live and closed in one list
          </span>
        </h2>
        <FacetBar principal={principal} facets={facets} navigate={navigate} />
        <div className="panel">
          <SessionTimeline state={sessions} onRetry={() => void loadSessions()} navigate={navigate} />
        </div>
      </section>

      <section className="grid gap-3">
        <h2 className="text-lg font-semibold">
          What they were allowed to do{" "}
          <span className="text-sm font-normal text-fg-muted">
            — read-only; the answer to "was this permitted?"
          </span>
        </h2>
        <GrantsPanel access={access} principal={principal} onRetry={() => void loadAccess()} />
        <div>
          <button className="btn btn-quiet" onClick={() => navigate({ kind: "permissions" })}>
            Open the policy editor →
          </button>
        </div>
      </section>
    </div>
  );
}

// ── the facet bar ──────────────────────────────────────────────────────────────────────

const FACET_LABELS: { key: "since" | "until" | "device" | "state"; label: string }[] = [
  { key: "since", label: "since" },
  { key: "until", label: "until" },
  { key: "device", label: "device" },
  { key: "state", label: "state" },
];

/** The facets currently narrowing the timeline, each removable. Clearing `since` is not
 *  "no lower bound" — the effect above re-lands the 30-day default the moment it is gone —
 *  which is the honest behaviour for a window that always has to mean something. */
function FacetBar({
  principal,
  facets,
  navigate,
}: {
  principal: string;
  facets: Facets;
  navigate: Navigate;
}) {
  const active = FACET_LABELS.filter((f) => facets[f.key]);
  if (active.length === 0) return null;
  return (
    <div className="flex flex-wrap items-center gap-2" data-testid="person-facets">
      {active.map((f) => (
        <span
          key={f.key}
          className="inline-flex items-center gap-1.5 border border-border px-2 py-1 text-sm"
        >
          <span className="text-fg-muted">{f.label}</span>
          <span className="mono">{facets[f.key]}</span>
          <button
            type="button"
            className="text-fg-faint hover:text-fg"
            aria-label={`Clear the ${f.label} filter`}
            onClick={() => {
              const rest = { ...facets };
              delete rest[f.key];
              navigate({ kind: "person", principal, facets: rest });
            }}
          >
            ×
          </button>
        </span>
      ))}
    </div>
  );
}

// ── what they did ─────────────────────────────────────────────────────────────────────

function SessionTimeline({
  state,
  onRetry,
  navigate,
}: {
  state: SessionsState;
  onRetry: () => void;
  navigate: Navigate;
}) {
  if (state.kind === "loading") {
    return (
      <p className="p-4 text-sm text-fg-muted" data-testid="person-sessions">
        Loading the timeline…
      </p>
    );
  }
  if (state.kind === "failed") {
    // Increment 2 made the gateway answer a malformed `since` with a 400 rather than
    // silently ignoring it, precisely so a hand-edited link produces an honest error here
    // instead of a filter that quietly does nothing.
    const condition = state.error instanceof ApiError ? state.error.condition : getCondition("internal");
    return (
      <p className="p-4 text-sm text-state-refused" role="alert" data-testid="person-sessions">
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
      <p className="p-8 text-center text-sm text-fg-muted" data-testid="person-sessions">
        No sessions in this window.
      </p>
    );
  }

  return (
    <div className="overflow-x-auto" data-testid="person-sessions">
      <table className="w-full border-collapse text-left text-sm">
        <thead className="bg-bg text-[11px] uppercase tracking-wider text-fg-faint">
          <tr>
            <th className="px-3 py-2 font-medium">Opened</th>
            <th className="px-3 py-2 font-medium">Device</th>
            <th className="px-3 py-2 font-medium">Action</th>
            <th className="px-3 py-2 font-medium">Outcome</th>
            <th className="px-3 py-2 font-medium">Recording</th>
            <th className="px-3 py-2" />
          </tr>
        </thead>
        <tbody>
          {rows.map((session) => (
            <SessionRow key={session.id} session={session} navigate={navigate} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SessionRow({ session, navigate }: { session: Session; navigate: Navigate }) {
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
        <span className="mono block whitespace-nowrap">{session.device_id}</span>
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
  // somebody reporting a problem should be able to say which one. Same pairing as the
  // fleet page's own session list.
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

// ── what they were allowed to do ──────────────────────────────────────────────────────

/**
 * GrantsPanel mirrors `Fleet.tsx`'s `AccessPanel` (`:340-420`): four states, not two, and
 * a refusal that names the missing grant rather than an empty list.
 *
 * The argument for that is sharper here than it is on a device row. There, an empty list
 * reads as "nobody can reach this device" — bad enough. Here, an empty list reads as "this
 * person is permitted nothing", on a page whose entire purpose is answering whether they
 * were permitted what the section above just showed them doing. A silent or empty section
 * on an audit surface is not a missing feature; it is a false statement about a person.
 * So: never hide this section, and never let a refusal render as though the answer were
 * "nothing".
 */
function GrantsPanel({
  access,
  principal,
  onRetry,
}: {
  access: Access;
  principal: string;
  onRetry: () => void;
}) {
  if (access.kind === "loading") {
    return (
      <div className="panel p-4" data-testid="person-access">
        <p className="text-sm text-fg-muted">Evaluating the policy…</p>
      </div>
    );
  }
  if (access.kind === "refused") {
    return (
      <div className="panel p-4" data-testid="person-access">
        <p className="text-sm text-fg-muted">
          {access.error.condition.headline}{" "}
          <span className="text-fg-faint">
            Seeing what <span className="mono">{principal}</span> is allowed to do needs{" "}
            <span className="mono">admin:permissions</span> on <span className="mono">gateway</span>.
          </span>
        </p>
      </div>
    );
  }
  if (access.kind === "failed") {
    return (
      <div className="panel p-4" data-testid="person-access">
        <p className="text-sm text-state-refused" role="alert">
          {access.message}{" "}
          <button type="button" className="underline" onClick={onRetry}>
            Try again
          </button>
        </p>
      </div>
    );
  }

  const rules = access.access.rules;
  if (rules.length === 0) {
    // Genuinely nothing applies — read with permission to see the real answer, which
    // happens to be empty. Unlike the refused state above, this is not a guess standing in
    // for a fact the reader cannot see; it is the fact.
    return (
      <div className="panel p-4" data-testid="person-access">
        <p className="text-sm text-fg-muted">
          No rule grants or denies <span className="mono">{principal}</span> anything.
        </p>
      </div>
    );
  }

  return (
    <div className="panel p-4" data-testid="person-access">
      <ul className="grid gap-2.5">
        {rules.map((rule) => (
          <GrantRow key={rule.id} rule={rule} />
        ))}
      </ul>
    </div>
  );
}

function GrantRow({ rule }: { rule: Permission }) {
  const deny = rule.effect === "deny";
  const off = !rule.enabled;
  const limits = limitsOf(rule);
  return (
    <li
      className={`border-b border-border/60 pb-2.5 last:border-b-0 last:pb-0 ${off ? "opacity-50" : ""}`}
      data-rule={rule.id}
    >
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 text-sm">
        {/* Deny first — the API already returns denies ahead of allows — and named in the
            row, because it outranks every allow wherever it appears. */}
        <span
          className={`shrink-0 text-[11px] font-semibold uppercase tracking-wider ${
            deny ? "text-state-refused" : "text-state-recorded"
          }`}
        >
          {deny ? "Denied" : "Allowed"}
        </span>
        <span className="mono min-w-0 break-all">{rule.id}</span>
        <span className="mono text-sm text-fg-muted">
          {rule.actions.includes("*") ? "every action" : rule.actions.join(" ")}
        </span>
      </div>
      <p className="mt-0.5 text-sm text-fg-faint">
        <Scope rule={rule} />
        {limits && <> · {limits}</>}
      </p>
      {deny && rule.reason && <p className="text-sm text-state-refused">{rule.reason}</p>}
      {off && <p className="text-sm text-fg-faint">rule disabled, not consulted</p>}
    </li>
  );
}

/** Where a grant reaches, in the same vocabulary the rule was written in: exact device ids
 *  when it names them, the tag it matches on otherwise. Machine values stay monospaced. */
function Scope({ rule }: { rule: Permission }) {
  const anyDevice = rule.devices.length === 0 || (rule.devices.length === 1 && rule.devices[0] === "*");
  if (!anyDevice) {
    return (
      <>
        on <span className="mono">{rule.devices.join(", ")}</span>
      </>
    );
  }
  const tagParts = Object.entries(rule.tags).map(([key, value]) => `${key}=${value}`);
  if (tagParts.length > 0) {
    return (
      <>
        on devices tagged <span className="mono">{tagParts.join(", ")}</span>
      </>
    );
  }
  return <>on any device</>;
}

/** Grant limits only tighten, so they are worth showing where the grant is read. Same
 *  fields Fleet.tsx's AccessPanel shows for a device's rules. */
function limitsOf(rule: Permission): string {
  const parts: string[] = [];
  if (rule.max_duration) parts.push(`max ${rule.max_duration}`);
  if (rule.idle) parts.push(`idle ${rule.idle}`);
  if (rule.ttl) parts.push(`re-checked every ${rule.ttl}`);
  return parts.join(" · ");
}
