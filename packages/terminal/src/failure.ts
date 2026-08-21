// The failure screen: one server condition, one screen.
//
// The rule from the UX spec, as code: "A screen renders exactly one server condition.
// The UI never infers, never combines, never guesses. A state with no condition behind it
// is a bug, not a design decision."
//
// So this takes a condition id and renders that condition. There is no "something went
// wrong" path that several codes fall into, because the failure mode being designed
// against is an operator confidently believing the wrong thing — and the worst version of
// that is being shown "your access was revoked" when the truth was "we couldn't check".

import { get, type Condition } from "./conditions.js";

export interface FailureOptions {
  /** The wire code, from an ERROR frame or a CLOSE reason. */
  readonly code: string;
  /**
   * The gateway's own message, if it sent one.
   *
   * Shown small, below the copy, and never in place of it: the protocol says `message`
   * is for humans and logs and is never parsed, so it cannot be the thing an operator
   * reads to find out what happened.
   */
  readonly message?: string;
  /** The correlation id, for a support report. */
  readonly reference?: string;
  /** The session this was about, shown monospaced because it is a machine value. */
  readonly sessionID?: string;
  /** Offered only when the condition is retryable. */
  readonly onRetry?: () => void;
  /** Called when the operator dismisses the screen. */
  readonly onDismiss?: () => void;
}

export interface FailureHandle {
  readonly el: HTMLElement;
  readonly condition: Condition;
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

export function createFailureScreen(opts: FailureOptions): FailureHandle {
  const c = get(opts.code);

  const root = el("div", "oarlock-fail");
  root.setAttribute("role", "alert");
  root.dataset["oarlockCondition"] = c.id;
  root.dataset["oarlockFault"] = c.fault;
  root.dataset["oarlockAudience"] = c.audience;

  const panel = el("div", "oarlock-fail__panel");
  panel.append(el("h2", "oarlock-fail__headline", c.headline));
  if (c.nextAction) {
    panel.append(el("p", "oarlock-fail__next", c.nextAction));
  }

  // The gateway's own words, if it sent any. Below the copy and visibly secondary,
  // because a message that varies with the server's mood must not be the sentence an
  // operator navigates by.
  if (opts.message) {
    const detail = el("p", "oarlock-fail__detail", opts.message);
    panel.append(detail);
  }

  const meta = el("dl", "oarlock-fail__meta");
  const pair = (label: string, value: string, mono = true) => {
    meta.append(el("dt", "oarlock-fail__label", label));
    const dd = el("dd", mono ? "oarlock-fail__value oarlock-mono" : "oarlock-fail__value", value);
    meta.append(dd);
    return dd;
  };

  // Machine values are monospaced everywhere, so they read as values rather than prose.
  if (opts.sessionID) pair("Session", opts.sessionID);
  // The code is shown even on an operator-facing screen. Not as the headline — never as
  // the headline — but an operator reporting a problem should be able to say which one,
  // and a support engineer should not have to guess from a paraphrase.
  pair("Reason", c.id);
  if (opts.reference) {
    // Labelled *for support*: present for the report, not shouted at the operator.
    pair("Reference (for support)", opts.reference);
  }
  if (meta.childElementCount > 0) panel.append(meta);

  const actions = el("div", "oarlock-fail__actions");
  if (opts.onDismiss) {
    const dismiss = el("button", "oarlock-fail__dismiss", "Close");
    dismiss.type = "button";
    dismiss.addEventListener("click", () => opts.onDismiss?.());
    actions.append(dismiss);
  }
  // Offered only where trying again could work. A retry button on `revoked` invites an
  // operator to keep pressing it at a decision that will not change.
  if (c.retryable && opts.onRetry) {
    const retry = el("button", "oarlock-fail__retry", "Try again");
    retry.type = "button";
    retry.addEventListener("click", () => opts.onRetry?.());
    actions.append(retry);
  }
  if (actions.childElementCount > 0) panel.append(actions);

  root.append(panel);
  return { el: root, condition: c, dispose: () => root.remove() };
}
