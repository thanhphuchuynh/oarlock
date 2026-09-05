// The policy panel — shared between the Person and Device pages, which is the reason this
// rewrite exists. `Fleet.tsx` and the old `PersonPage.tsx` each carried their own copy of
// this panel, and the two had already drifted: the person one written from a mockup, the
// device one from the API. One component now, fed by whichever endpoint its caller calls
// (`client.deviceAccess` or `client.principalAccess`), both of which return the same
// `{ rules, admin_actions }` shape — `admin_actions` travels with the answer so this file
// never keeps its own copy of the administrative vocabulary.
//
// Four states, not two. A device administrator — or a person being audited — who cannot
// read the policy is a real configuration, not an error: the refusal names the action and
// where it is needed, rather than rendering an empty list. An empty list would read as
// "nobody can reach this device" — bad enough — or, on the Person page, "this person is
// permitted nothing", on a page whose whole purpose is answering whether they were
// permitted what the timeline above just showed them doing. A silent or empty section on
// an audit surface is a false statement about a person, not a blank space. So: never hide
// this section, and never let a refusal render as though the answer were "nothing".

import type { ApiError, Permission } from "../api";

export type GrantsState =
  | { kind: "loading" }
  | { kind: "refused"; error: ApiError }
  | { kind: "failed"; message: string }
  | { kind: "ready"; rules: Permission[]; adminActions: string[] };

export function Grants({
  state,
  onRetry,
  testId,
  variant,
  subject,
}: {
  state: GrantsState;
  onRetry: () => void;
  testId: string;
  /** "device": split into who can reach it and who administers it — reaching a device and
   *  administering it are different sentences about a person, so they are different lists.
   *  Each rule shows the principals it matches, since more than one routinely does.
   *  "person": one flat list, already scoped to a single principal, so each rule shows its
   *  own id and the devices it reaches instead of repeating the principal the page is
   *  already about. */
  variant: "person" | "device";
  /** Named in the person wording and the person empty-state. The device wording never
   *  names the device itself (see the refused branch below) but still receives it, so both
   *  callers share one prop shape. */
  subject: string;
}) {
  // Only the device variant carries an internal heading: on the Person page "What they
  // were allowed to do" is the page's own section heading, supplied by the caller: adding a
  // second one here would say the same thing twice. On the Device page there is no such
  // heading yet when this is loading, refused or failed — "who administers it" only
  // appears once the ready state has something to say about it below.
  const heading = variant === "device" ? <h2 className="text-lg font-semibold">Who can reach it</h2> : null;
  const boxClass = variant === "device" ? "panel mt-2 p-4" : "panel p-4";

  if (state.kind === "loading") {
    return (
      <div data-testid={testId}>
        {heading}
        <div className={boxClass}>
          <p className="text-sm text-fg-muted">Evaluating the policy…</p>
        </div>
      </div>
    );
  }

  if (state.kind === "refused") {
    return (
      <div data-testid={testId}>
        {heading}
        <div className={boxClass}>
          <p className="text-sm text-fg-muted">
            {state.error.condition.headline}{" "}
            <span className="text-fg-faint">
              {variant === "device" ? (
                <>
                  Seeing who can reach a device needs{" "}
                  <span className="mono">admin:permissions</span> on{" "}
                  <span className="mono">gateway</span>.
                </>
              ) : (
                <>
                  Seeing what <span className="mono">{subject}</span> is allowed to do needs{" "}
                  <span className="mono">admin:permissions</span> on{" "}
                  <span className="mono">gateway</span>.
                </>
              )}
            </span>
          </p>
        </div>
      </div>
    );
  }

  if (state.kind === "failed") {
    return (
      <div data-testid={testId}>
        {heading}
        <div className={boxClass}>
          <p className="text-sm text-state-refused" role="alert">
            {state.message}{" "}
            <button type="button" className="underline" onClick={onRetry}>
              Try again
            </button>
          </p>
        </div>
      </div>
    );
  }

  if (variant === "person") {
    if (state.rules.length === 0) {
      // Genuinely nothing applies — read with permission to see the real answer, which
      // happens to be empty. Unlike the refused state above, this is not a guess standing
      // in for a fact the reader cannot see; it is the fact.
      return (
        <div className="panel p-4" data-testid={testId}>
          <p className="text-sm text-fg-muted">
            No rule grants or denies <span className="mono">{subject}</span> anything.
          </p>
        </div>
      );
    }
    return (
      <div className="panel p-4" data-testid={testId}>
        <ul className="grid gap-2.5">
          {state.rules.map((rule) => (
            <GrantRow key={rule.id} rule={rule} />
          ))}
        </ul>
      </div>
    );
  }

  // device: grouped by the vocabulary the gateway sent rather than a copy of it kept here —
  // `admin:devices` is not a way to reach a device, and showing it under "who can reach it"
  // would say something untrue about whoever held it.
  const admin = new Set(state.adminActions);
  const reach = state.rules.filter((rule) =>
    rule.actions.some((action) => action === "*" || !admin.has(action)),
  );
  const administer = state.rules.filter((rule) =>
    rule.actions.some((action) => action === "*" || admin.has(action)),
  );

  return (
    <div className="grid gap-4" data-testid={testId}>
      <div data-testid={`${testId}-reach`}>
        <h2 className="text-lg font-semibold">Who can reach it</h2>
        <div className="panel mt-2 p-4">
          {reach.length === 0 ? (
            <p className="text-sm text-fg-muted">
              No rule lets anybody open a session on this device.
            </p>
          ) : (
            <ul className="grid gap-1.5">
              {reach.map((rule) => (
                <AccessRule key={rule.id} rule={rule} admin={admin} kind="reach" />
              ))}
            </ul>
          )}
        </div>
      </div>
      {administer.length > 0 && (
        <div data-testid={`${testId}-admin`}>
          <h2 className="text-lg font-semibold">Who administers it</h2>
          <div className="panel mt-2 p-4">
            <ul className="grid gap-1.5">
              {administer.map((rule) => (
                <AccessRule key={rule.id} rule={rule} admin={admin} kind="administer" />
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}

/** The Person page's row: one rule at a time, already scoped to a single principal, so its
 *  own id and the devices it reaches are the useful facts — not the principal, which is
 *  every row's principal here and would just repeat the page's own heading. */
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

/** The Device page's row: the device is already fixed by the page, so the principals a
 *  rule matches are the useful fact, filtered to only the actions the section it is
 *  rendered under is about — a rule granting `shell` and `admin:kill` says something
 *  different in each place, and printing both lists in both places is how a reader stops
 *  trusting either. */
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
  const shown = rule.actions.filter((action) => {
    if (action === "*") return true;
    return kind === "administer" ? admin.has(action) : !admin.has(action);
  });
  return (
    <li
      className={`flex flex-wrap items-baseline gap-x-2 gap-y-0.5 text-sm ${off ? "opacity-50" : ""}`}
      data-rule={rule.id}
    >
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
      {deny && rule.reason && <span className="text-sm text-state-refused">— {rule.reason}</span>}
      {off && <span className="text-sm text-fg-faint">— rule disabled, not consulted</span>}
    </li>
  );
}

/** Grant limits only tighten, so they are worth showing where the grant is read. Shared by
 *  both rows above. */
function limitsOf(rule: Permission): string {
  const parts: string[] = [];
  if (rule.max_duration) parts.push(`max ${rule.max_duration}`);
  if (rule.idle) parts.push(`idle ${rule.idle}`);
  if (rule.ttl) parts.push(`re-checked every ${rule.ttl}`);
  return parts.join(" · ");
}
