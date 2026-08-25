// The integrity verdict that sits above a replay.
//
// # Why it is not a prop
//
// A recording is evidence. The whole mechanism — the hash chain, the signed manifest, the
// checkpoints — exists so that somebody reading a session afterwards can tell whether
// what they are reading is what happened. That guarantee is worth nothing if the answer is
// rendered optionally: a player that shows a tampered recording exactly like an intact one
// is a player that launders it.
//
// So `<Player>` renders this above itself, always, and there is no prop that removes it.
// An integrator who wants their own layout gets the verdict exported separately — and
// still cannot get a player without one.
//
// # Why the statuses are not collapsed into "bad"
//
// The five outcomes send somebody to different places. A truncation usually means a
// process died — the recording is honest as far as it goes, and often that is far enough.
// An alteration means somebody edited the file, which is a different conversation
// entirely. A bad signature means the manifest is not ours, which may mean the recording
// belongs to a different deployment rather than that anything was tampered with. Rolling
// those into one red banner would throw away the distinction the verifier worked to make.

/** The verifier's own vocabulary, from internal/record/verify.go. */
export type VerdictStatus = "valid" | "truncated" | "altered" | "bad_signature" | "malformed";

export interface Verdict {
  readonly status: VerdictStatus | string;
  readonly ok: boolean;
  readonly events_found?: number;
  readonly events_expected?: number;
  /** The highest event count that verified against a checkpoint. */
  readonly last_good_checkpoint?: number;
  /** The verifier's own sentence, if it produced one. Never the headline. */
  readonly detail?: string;
}

export interface VerdictCopy {
  readonly headline: string;
  readonly body: string;
  /** "trusted" | "partial" | "broken" — what the chrome should look like. */
  readonly tone: "trusted" | "partial" | "broken";
}

// Partial on purpose. Indexing a total Record<string, …> yields a function that is
// never undefined, which makes the guards below dead code by the types even though the
// runtime relies on them: a status this build does not recognise has no entry here, and
// the fallback at the end of describe() is what withholds the claim of integrity. The
// type has to admit the miss for that promise to be checked rather than merely intended.
const copy: Partial<Record<string, (v: Verdict) => VerdictCopy>> = {
  valid: (v) => ({
    tone: "trusted",
    headline: "This recording is intact.",
    body:
      `All ${v.events_expected ?? v.events_found ?? 0} events verify against the signed ` +
      `manifest. Nothing has been added, removed or edited since the session ended.`,
  }),

  truncated: (v) => {
    const found = v.events_found ?? 0;
    const expected = v.events_expected ?? 0;
    const good = v.last_good_checkpoint ?? 0;
    // The distinction that makes this status worth having: everything present is
    // intact, so the reader knows how much of it they can rely on.
    const upTo = good > 0
      ? `Everything up to event ${good} verifies.`
      : `What is present verifies, but the file stops before the first checkpoint, so ` +
        `there is no signed marker to confirm how much survived.`;
    return {
      tone: "partial",
      headline: "This recording is incomplete.",
      body:
        `${found} of ${expected} events are present. ${upTo} ` +
        `A recording usually ends early because the process writing it stopped — a ` +
        `restart, a crash — rather than because somebody changed it.`,
    };
  },

  altered: (v) => ({
    tone: "broken",
    headline: "This recording does not match what was signed.",
    body:
      `The contents no longer hash to the value in the manifest` +
      (v.last_good_checkpoint
        ? `, and the last checkpoint that verified was at event ${v.last_good_checkpoint}. `
        : `. `) +
      `Something was edited, added or removed after the session ended. Treat it as ` +
      `evidence of tampering rather than as a record of the session.`,
  }),

  bad_signature: () => ({
    tone: "broken",
    headline: "This recording’s manifest isn’t signed by the expected key.",
    body:
      `The manifest may belong to a different deployment, or its signature may have ` +
      `been replaced. Until it verifies against a key you trust, nothing it says about ` +
      `the recording — including the session it claims to be — can be relied on.`,
  }),

  malformed: () => ({
    tone: "broken",
    headline: "This file isn’t a readable recording.",
    body:
      `It could not be parsed as an asciicast, so there is nothing to verify and ` +
      `nothing to play.`,
  }),
};

/**
 * describe turns a verdict into the sentences shown above the player.
 *
 * An unrecognised status is treated as *not* verified. That direction is deliberate: a
 * verifier newer than this client is a reason to withhold the claim of integrity, never a
 * reason to imply it.
 */
export function describe(v: Verdict): VerdictCopy {
  const f = copy[v.status];
  if (f && v.status === "valid" && !v.ok) {
    // A verdict that says "valid" but not ok is a contradiction, and the safe reading of
    // a contradiction about integrity is the pessimistic one.
    return {
      tone: "broken",
      headline: "This recording could not be confirmed.",
      body:
        `The verifier reported "valid" without confirming it, which should not happen. ` +
        `Treat the recording as unverified.`,
    };
  }
  if (f) return f(v);
  return {
    tone: "broken",
    headline: "This recording could not be verified.",
    body:
      `The gateway reported a verification result this build does not recognise ` +
      `(${v.status || "no status"}). Nothing here confirms the recording is intact.`,
  };
}

export interface VerdictHandle {
  readonly el: HTMLElement;
  readonly copy: VerdictCopy;
  dispose(): void;
}

const el = <K extends keyof HTMLElementTagNameMap>(
  tag: K,
  cls?: string,
  text?: string,
): HTMLElementTagNameMap[K] => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
};

export interface VerdictOptions {
  readonly verdict: Verdict;
  /** Shown monospaced, because it is a machine value. */
  readonly sessionID?: string;
}

export function createVerdictBanner(opts: VerdictOptions): VerdictHandle {
  const c = describe(opts.verdict);
  const root = el("div", "oarlock-verdict");
  root.dataset["oarlockTone"] = c.tone;
  root.dataset["oarlockStatus"] = String(opts.verdict.status);
  // A statement about evidence, announced rather than merely drawn.
  root.setAttribute("role", c.tone === "trusted" ? "status" : "alert");

  root.append(el("h2", "oarlock-verdict__headline", c.headline));
  root.append(el("p", "oarlock-verdict__body", c.body));

  const meta = el("dl", "oarlock-verdict__meta");
  const pair = (k: string, v: string) => {
    meta.append(el("dt", "oarlock-verdict__label", k));
    meta.append(el("dd", "oarlock-verdict__value oarlock-mono", v));
  };
  if (opts.sessionID) pair("Session", opts.sessionID);
  pair("Verdict", String(opts.verdict.status));
  if (opts.verdict.events_expected !== undefined) {
    pair("Events", `${opts.verdict.events_found ?? 0} of ${opts.verdict.events_expected}`);
  }
  // The verifier's own sentence, kept below the copy and visibly secondary — the same
  // rule as a gateway's error message: useful for a report, never the thing somebody
  // reads to find out what happened.
  if (opts.verdict.detail) {
    meta.append(el("dt", "oarlock-verdict__label", "Detail"));
    meta.append(el("dd", "oarlock-verdict__value", opts.verdict.detail));
  }
  root.append(meta);

  return { el: root, copy: c, dispose: () => root.remove() };
}
