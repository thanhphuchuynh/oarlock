// The status bar: the four facts, stated without being asked.
//
// It never disappears, never scrolls, never collapses, and has no dismissal affordance
// at all — it is the one element in the product with none. Everything else on screen is
// subordinate to an operator not being confidently wrong about their situation.

import { facts, type Facts, type FactsInput } from "./disclosure.js";

export interface StatusBarHandle {
  readonly el: HTMLElement;
  update(input: FactsInput): void;
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

export function createStatusBar(input: FactsInput): StatusBarHandle {
  const root = el("div", "oarlock-bar");
  // A live region: an operator on a screen reader has to learn that a session started
  // being observed without watching for it.
  root.setAttribute("role", "status");
  root.setAttribute("aria-live", "polite");

  const device = el("span", "oarlock-bar__device oarlock-mono");
  const recording = el("span", "oarlock-bar__badge oarlock-bar__badge--recording");
  const observed = el("span", "oarlock-bar__badge oarlock-bar__badge--observed");
  const readOnly = el("span", "oarlock-bar__badge oarlock-bar__badge--readonly");
  const principal = el("span", "oarlock-bar__principal oarlock-mono");
  const connection = el("span", "oarlock-bar__conn");

  root.append(readOnly, device, recording, observed,
    el("span", "oarlock-bar__spacer"), principal, connection);

  const render = (f: Facts) => {
    device.textContent = f.device;
    device.title = f.device;

    // Nothing important is only a colour: the state carries a word, always, and the
    // dot is decoration on top of it.
    recording.textContent = f.recording.label;
    recording.dataset["state"] = f.recording.recorded ? "recorded" : "unrecorded";

    // "Who else is watching" is shown only while true. A permanent "nobody is
    // watching" would be a claim the component cannot actually make.
    if (f.observers.length > 0) {
      observed.hidden = false;
      observed.textContent =
        f.observers.length === 1
          ? `OBSERVED by ${f.observers[0]}`
          : `OBSERVED by ${f.observers.length} people`;
      observed.title = f.observers.join(", ");
    } else {
      observed.hidden = true;
      observed.textContent = "";
      observed.removeAttribute("title");
    }

    // A watcher's own bar leads with READ-ONLY, before the device: it is the first thing
    // they need to know about their own situation, and putting it after the device id
    // would make it read as a property of the device.
    if (f.readOnly.on) {
      readOnly.hidden = false;
      readOnly.textContent = f.readOnly.watching
        ? `${f.readOnly.label} · watching ${f.readOnly.watching}`
        : f.readOnly.label;
    } else {
      readOnly.hidden = true;
      readOnly.textContent = "";
    }

    principal.textContent = f.principal;
    connection.textContent = f.connection.label;
    connection.dataset["state"] = f.connection.state;
  };

  render(facts(input));

  return {
    el: root,
    update: (next) => render(facts(next)),
    dispose: () => root.remove(),
  };
}
