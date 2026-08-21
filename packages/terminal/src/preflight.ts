// The blocking acknowledgement in front of a session that is not recorded.
//
// Deliberate friction, in exactly one place. The routine path — a recorded, gateway-mode
// session — never sees this, because friction spent on the common case is friction
// nobody reads. An unrecorded session is not the common case, and an operator who is
// about to work unrecorded should have to notice.

import type { GateCopy } from "./disclosure.js";

export interface PreflightHandle {
  readonly el: HTMLElement;
  dispose(): void;
}

export interface PreflightOptions {
  readonly copy: GateCopy;
  readonly onAcknowledge: () => void;
  readonly onCancel?: () => void;
}

export function createPreflightGate(opts: PreflightOptions): PreflightHandle {
  const { copy } = opts;
  const root = document.createElement("div");
  root.className = "oarlock-gate";
  root.setAttribute("role", "alertdialog");
  root.setAttribute("aria-modal", "true");

  const panel = document.createElement("div");
  panel.className = "oarlock-gate__panel";

  const h = document.createElement("h2");
  h.className = "oarlock-gate__headline";
  h.textContent = copy.headline;
  const hid = `oarlock-gate-h-${Math.random().toString(36).slice(2, 8)}`;
  h.id = hid;
  root.setAttribute("aria-labelledby", hid);

  const body = document.createElement("p");
  body.className = "oarlock-gate__body";
  body.textContent = copy.body;

  const list = document.createElement("ul");
  list.className = "oarlock-gate__detail";
  for (const line of copy.detail) {
    const li = document.createElement("li");
    li.textContent = line;
    list.append(li);
  }

  const actions = document.createElement("div");
  actions.className = "oarlock-gate__actions";

  // The affirmative button states the consequence rather than asking a question:
  // "Continue without a recording", not "OK".
  const go = document.createElement("button");
  go.type = "button";
  go.className = "oarlock-gate__go";
  go.textContent = copy.acknowledge;
  go.addEventListener("click", () => opts.onAcknowledge());

  const cancel = document.createElement("button");
  cancel.type = "button";
  cancel.className = "oarlock-gate__cancel";
  cancel.textContent = "Cancel";
  cancel.addEventListener("click", () => opts.onCancel?.());

  actions.append(cancel, go);
  panel.append(h, body, list, actions);
  root.append(panel);

  // Focus lands on Cancel, not on the way through. A gate whose affirmative button is
  // focused is a gate that a stray Enter — from the terminal the operator was just
  // typing in — walks straight past.
  queueMicrotask(() => cancel.focus());

  return { el: root, dispose: () => root.remove() };
}
