// The disclosure policy: whether a terminal may be shown at all, and what has to be
// said while it is.
//
// # Why this is in the core and not in the React component
//
// R-001 is the only risk in this epic the gateway cannot mitigate alone. The gateway
// can put `recording` and `mode` in READY, but it cannot make a browser render them —
// an integrator who composes their own chrome, or who uses `<StatusBar>` and forgets
// the gate, ships a terminal that looks exactly like a normal terminal for a session
// nobody is recording. That is the product's central failure mode: false confidence.
//
// So the decision lives in the framework-agnostic core, where every surface — the React
// `<Terminal>`, the vanilla `mount()`, and any wrapper written later — has to route
// through it. A wrapper can style the gate. It cannot decline to have one.
//
// The one way past it is `acknowledgeUnrecordedWithoutPrompt`, named for its
// consequence rather than its mechanism, so that reaching for it is a decision rather
// than a convenience.

import type { Ready } from "./frame.js";

/** A reason the operator has to be told before a terminal appears. */
export type Concern = "unrecorded" | "passthrough";

export interface Session {
  /** false, or absent, means the session is not being recorded. */
  readonly recording?: boolean;
  /** "gateway" — the gateway can read the stream — or "passthrough" — it cannot. */
  readonly mode?: string;
}

export interface DisclosureInput {
  /**
   * What READY said. Undefined before READY arrives, which is deliberately *not*
   * treated as "fine": see `concernsOf`.
   */
  readonly session: Session | undefined;
  /** The operator clicked through the gate. */
  readonly acknowledged?: boolean;
  /**
   * Ship an unrecorded or passthrough session with no gate. The prop is named for
   * what it does to the operator, not for what it does to the component.
   */
  readonly acknowledgeUnrecordedWithoutPrompt?: boolean;
}

export interface GateCopy {
  readonly headline: string;
  readonly body: string;
  readonly detail: readonly string[];
  readonly acknowledge: string;
}

export interface DisclosureVerdict {
  readonly concerns: readonly Concern[];
  /** May the terminal be rendered? */
  readonly terminal: boolean;
  /** Must the blocking acknowledgement be rendered instead? */
  readonly gate: boolean;
  readonly copy: GateCopy | null;
}

/**
 * concernsOf lists what is true about a session that an operator must be told.
 *
 * A session we know nothing about counts as unrecorded. The pessimistic default is the
 * point: a dropped field, a gateway that predates the field, a mock that forgets it,
 * all fail towards saying too much rather than too little. Falling the other way would
 * make a missing byte indistinguishable from a promise.
 */
export function concernsOf(s: Session | undefined): Concern[] {
  const out: Concern[] = [];
  if (!s || s.recording !== true) out.push("unrecorded");
  if (s && s.mode === "passthrough") out.push("passthrough");
  return out;
}

const copyFor = (concerns: readonly Concern[]): GateCopy => {
  const passthrough = concerns.includes("passthrough");
  const unrecorded = concerns.includes("unrecorded");

  // Flat and specific, per the copy rules: name the thing and the consequence. Never
  // "Warning", never a code as the headline.
  if (passthrough && unrecorded) {
    return {
      headline: "This session is not recorded and cannot be",
      body:
        "The gateway is passing bytes through without reading them, so nothing is " +
        "recorded and nothing can be replayed later.",
      detail: [
        "No recording will exist for this session.",
        "The gateway cannot see what you type or what comes back.",
        "The session still appears in the session list, with its mode.",
      ],
      acknowledge: "Continue without a recording",
    };
  }
  if (passthrough) {
    return {
      headline: "The gateway cannot read this session",
      body:
        "This device is in passthrough mode. Bytes are relayed without being read, " +
        "so the gateway can account for the session but not for its contents.",
      detail: [
        "The gateway cannot see what you type or what comes back.",
        "Contents are not available for replay or review.",
      ],
      acknowledge: "Continue in passthrough",
    };
  }
  return {
    headline: "This session is not being recorded",
    body:
      "Nothing you do here will be replayable afterwards. If this session is part of " +
      "an incident, there will be no record of it beyond the session list.",
    detail: [
      "No recording will exist for this session.",
      "The session, its device and its duration are still logged.",
    ],
    acknowledge: "Continue without a recording",
  };
};

/**
 * decide answers the only question that matters before rendering: may this terminal be
 * shown, and if not, what has to be said first.
 */
export function decide(input: DisclosureInput): DisclosureVerdict {
  const concerns = concernsOf(input.session);
  if (concerns.length === 0) {
    return { concerns, terminal: true, gate: false, copy: null };
  }
  const cleared = input.acknowledged === true || input.acknowledgeUnrecordedWithoutPrompt === true;
  return {
    concerns,
    terminal: cleared,
    gate: !cleared,
    copy: cleared ? null : copyFor(concerns),
  };
}

// ── the status bar's four facts ─────────────────────────────────────────────────

export interface Facts {
  readonly device: string;
  readonly recording: { readonly recorded: boolean; readonly label: string };
  readonly principal: string;
  /** Present only while true — an empty list renders nothing at all. */
  readonly observers: readonly string[];
  readonly connection: ConnectionLabel;
  /** Set on a watcher's own bar (FR13), never on the operator's. */
  readonly readOnly: { readonly on: boolean; readonly label: string; readonly watching: string };
}

export type ConnectionState = "connecting" | "attached" | "reconnecting" | "closed";

export interface ConnectionLabel {
  readonly state: ConnectionState;
  readonly label: string;
}

const connectionLabels: Record<ConnectionState, string> = {
  connecting: "Connecting",
  attached: "Live",
  reconnecting: "Reconnecting",
  closed: "Ended",
};

export interface FactsInput {
  readonly device: string;
  readonly principal: string;
  readonly session: Session | undefined;
  readonly state: ConnectionState;
  readonly observers?: readonly string[];
  /** This connection is a watcher's. */
  readonly readOnly?: boolean;
  /** Whose session is being watched. */
  readonly watching?: string;
}

/**
 * facts assembles what the status bar states without being asked.
 *
 * Nothing important is only a colour, so every state carries a word: RECORDED,
 * NOT RECORDED, PASSTHROUGH. A bar that showed a green dot and no text would be
 * unreadable to a colour-blind operator and invisible in a screenshot.
 */
export function facts(input: FactsInput): Facts {
  const concerns = concernsOf(input.session);
  const label = concerns.includes("passthrough")
    ? "PASSTHROUGH"
    : concerns.includes("unrecorded")
      ? "NOT RECORDED"
      : "RECORDED";
  return {
    device: input.device,
    recording: { recorded: concerns.length === 0, label },
    principal: input.principal,
    observers: input.observers ?? [],
    connection: { state: input.state, label: connectionLabels[input.state] },
    readOnly: {
      on: input.readOnly === true,
      label: "READ-ONLY",
      watching: input.watching ?? "",
    },
  };
}

/** sessionOf narrows a READY to the part the disclosure cares about. */
export function sessionOf(ready: Ready): Session {
  return { recording: ready.recording, mode: ready.mode };
}
