// The harness's stub gateway and the window API the component tests drive.

import "@oarlock/terminal/oarlock.css";

import { mount, type MountHandle, type MountOptions } from "@oarlock/terminal";
import { conditions } from "@oarlock/terminal/conditions";
import { mountPlayer, type PlayerHandle } from "@oarlock/terminal/player";
import "@oarlock/terminal/player.css";
import verdictFixtures from "../fixtures/recordings/verdicts.json";
import {
  FrameType,
  decode,
  decodeJSON,
  encodeData,
  encodeJSON,
  type Open,
  type WebSocketLike,
} from "@oarlock/terminal";

/** A WebSocket the test controls both ends of. */
class StubSocket implements WebSocketLike {
  binaryType = "arraybuffer";
  onopen: ((ev: unknown) => void) | null = null;
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  onerror: ((ev: unknown) => void) | null = null;
  onclose: ((ev: { code: number; reason: string }) => void) | null = null;

  /** Everything the component sent, decoded, for assertions. */
  readonly sent: { type: number; text: string }[] = [];
  opened: Open | null = null;

  send(data: ArrayBufferView | ArrayBuffer | string): void {
    const bytes =
      typeof data === "string"
        ? new TextEncoder().encode(data)
        : data instanceof ArrayBuffer
          ? new Uint8Array(data)
          : new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    const f = decode(bytes);
    const text = new TextDecoder().decode(f.payload);
    this.sent.push({ type: f.type, text });
    if (f.type === FrameType.Open) this.opened = decodeJSON<Open>(f);
  }

  close(code = 1000, reason = ""): void {
    this.onclose?.({ code, reason });
  }

  // ── the test's side ───────────────────────────────────────────────────────────
  open(): void {
    this.onopen?.({});
  }
  deliver(msg: Uint8Array): void {
    this.onmessage?.({ data: msg.buffer.slice(msg.byteOffset, msg.byteOffset + msg.byteLength) });
  }
}

export interface HarnessReady {
  session_id?: string;
  scrollback_len?: number;
  recording?: boolean;
  mode?: string;
}

interface RecordingFixture {
  name: string;
  status: string;
  ok: boolean;
  events_found: number;
  events_expected: number;
  last_good_checkpoint: number;
  cast: string;
  manifest: string;
  public_key: string;
  note: string;
}

interface Harness {
  /** Mount the replay player against one of the generated fixtures. */
  play(name: string, opts?: { withoutVerdict?: boolean }): void;
  /** What the verdict banner above the player says. */
  verdict(): { tone: string; status: string; headline: string; body: string; meta: string[] } | null;
  /** The fixture names, so a test can walk all of them. */
  recordings(): string[];
  mount(opts: Partial<MountOptions> & { ready?: HarnessReady | null }): void;
  /** How many times the component asked for a fresh ticket, and what it got. */
  renewals: string[];
  /** The tickets the component actually presented, in order. */
  tickets(): string[];
  /** Send READY, with whatever the test wants in it. */
  ready(r?: HarnessReady): void;
  /** Send raw device output. */
  write(text: string): void;
  /** Send an ERROR frame, as the gateway would. */
  error(e: { code: string; message?: string; retryable?: boolean }): void;
  /** Send a THROTTLE frame. */
  throttle(dropped: number, profile?: string): void;
  /** Send an EXIT frame. */
  exit(code: number): void;
  /** Send an OBSERVERS frame — the gateway telling the operator who is watching. */
  observers(list: { principal: string; since?: string }[]): void;
  /** What the observer list looked like each time it changed. */
  observerLists: string[][];
  /** Send a CLOSE frame — the gateway ending the session. */
  closeFromGateway(reason: string): void;
  /** Kill the socket the way a dropped network does: no CLOSE, just gone. */
  dropSocket(reason?: string): void;
  /** What the failure screen currently shows, if anything. */
  failure(): { condition: string; fault: string; headline: string; next: string; meta: string[] } | null;
  retries: number;
  /** The operator-facing condition ids, from the generated table. */
  operatorConditions(): string[];
  throttles: { dropped_bytes: number; profile?: string }[];
  exits: { code: number }[];
  /** Everything the component sent. */
  sent(): { type: number; text: string }[];
  /** The OPEN frame's parsed body, to prove the ticket travelled in it. */
  opened(): Open | null;
  titleAsks: { title: string; applied: boolean }[];
  clipboardRefusals: number;
  errors: { code: string; message: string }[];
  states: string[];
  cancelled: number;
  dispose(): void;
}

let player: PlayerHandle | null = null;
let socket: StubSocket | null = null;
let sockets: StubSocket[] = [];
let handle: MountHandle | null = null;

const harness: Harness = {
  titleAsks: [],
  renewals: [],
  clipboardRefusals: 0,
  errors: [],
  states: [],
  cancelled: 0,
  throttles: [],
  exits: [],
  observerLists: [],
  retries: 0,

  mount(opts) {
    harness.dispose();
    harness.titleAsks = [];
    harness.renewals = [];
    harness.clipboardRefusals = 0;
    harness.errors = [];
    harness.states = [];
    harness.cancelled = 0;
    harness.throttles = [];
    harness.exits = [];
    harness.observerLists = [];
    harness.retries = 0;

    const host = document.getElementById("host")!;
    sockets = [];
    // A fresh stub per dial, so a re-dial after a ticket renewal is a genuinely new
    // connection presenting a genuinely new OPEN — which is the thing under test.
    const make = () => {
      const next = new StubSocket();
      sockets.push(next);
      socket = next;
      queueMicrotask(() => next.open());
      return next;
    };

    const { ready, ...rest } = opts;
    handle = mount(host, {
      url: "wss://stub.invalid/ws/attach",
      ticket: "stub-ticket-abcdef",
      device: "treadmill-4821",
      principal: "admin@mail.com",
      socket: () => make(),
      onTitle: (title, applied) => harness.titleAsks.push({ title, applied }),
      onClipboardRefused: () => (harness.clipboardRefusals += 1),
      onError: (f) => harness.errors.push({ code: f.code, message: f.message }),
      onState: (st) => harness.states.push(st),
      onCancelled: () => (harness.cancelled += 1),
      onThrottle: (t) => harness.throttles.push(t),
      onObservers: (l) => harness.observerLists.push(l.map((o) => o.principal)),
      onRetry: () => (harness.retries += 1),
      onExit: (e) => harness.exits.push(e),
      ...rest,
    } as MountOptions);

    if (ready !== null) {
      // The stub opens on a microtask, so READY has to wait for the OPEN to have gone.
      void Promise.resolve().then(() => {
        if (ready !== null) harness.ready(ready ?? undefined);
      });
    }
  },

  ready(r) {
    socket?.deliver(
      encodeJSON(FrameType.Ready, {
        session_id: "sess_stub",
        scrollback_len: 0,
        recording: true,
        mode: "gateway",
        ...r,
      }),
    );
  },

  write(text) {
    socket?.deliver(encodeData(new TextEncoder().encode(text)));
  },

  // These deliver real frames rather than calling the component's callbacks, so the
  // decode path is under test too: a field renamed in the codec has to show up here.
  error(e) {
    socket?.deliver(encodeJSON(FrameType.Error, { retryable: false, ...e }));
  },

  throttle(dropped, profile) {
    socket?.deliver(
      encodeJSON(FrameType.Throttle, { dropped_bytes: dropped, ...(profile ? { profile } : {}) }),
    );
  },

  exit(code) {
    socket?.deliver(encodeJSON(FrameType.Exit, { code, signal: null }));
  },

  observers(list) {
    socket?.deliver(encodeJSON(FrameType.Observers, { observers: list }));
  },

  closeFromGateway(reason) {
    socket?.deliver(encodeJSON(FrameType.Close, { reason }));
  },

  dropSocket(reason = "wifi") {
    // No CLOSE frame: the gateway keeps the session attached and the ring keeps
    // filling, which is exactly the case the component has to treat as a reconnect
    // rather than an end.
    socket?.close(1006, reason);
  },

  failure() {
    const el = document.querySelector<HTMLElement>(".oarlock-fail");
    if (!el) return null;
    return {
      condition: el.dataset["oarlockCondition"] ?? "",
      fault: el.dataset["oarlockFault"] ?? "",
      headline: el.querySelector(".oarlock-fail__headline")?.textContent ?? "",
      next: el.querySelector(".oarlock-fail__next")?.textContent ?? "",
      meta: [...el.querySelectorAll(".oarlock-fail__label, .oarlock-fail__value")].map(
        (n) => n.textContent ?? "",
      ),
    };
  },

  play(name, opts = {}) {
    player?.dispose();
    const host = document.getElementById("player-host")!;
    host.replaceChildren();
    const fx = (verdictFixtures.recordings as RecordingFixture[]).find((r) => r.name === name);
    if (!fx) throw new Error(`no recording fixture named ${name}`);
    const cast = new TextDecoder().decode(
      Uint8Array.from(atob(fx.cast), (c) => c.charCodeAt(0)),
    );
    player = mountPlayer(host, {
      cast,
      // The point of the `withoutVerdict` case: a caller who supplies nothing gets the
      // unverified banner, not a player with no banner at all.
      verdict: opts.withoutVerdict
        ? undefined
        : {
            status: fx.status,
            ok: fx.ok,
            events_found: fx.events_found,
            events_expected: fx.events_expected,
            last_good_checkpoint: fx.last_good_checkpoint,
          },
      sessionID: "sess_fixture",
    });
  },

  verdict() {
    const el = document.querySelector<HTMLElement>(".oarlock-verdict");
    if (!el) return null;
    return {
      tone: el.dataset["oarlockTone"] ?? "",
      status: el.dataset["oarlockStatus"] ?? "",
      headline: el.querySelector(".oarlock-verdict__headline")?.textContent ?? "",
      body: el.querySelector(".oarlock-verdict__body")?.textContent ?? "",
      meta: [...el.querySelectorAll(".oarlock-verdict__label, .oarlock-verdict__value")].map(
        (n) => n.textContent ?? "",
      ),
    };
  },

  recordings: () => (verdictFixtures.recordings as RecordingFixture[]).map((r) => r.name),

  operatorConditions: () =>
    conditions.filter((c) => c.audience === "operator").map((c) => c.id),

  sent: () => socket?.sent ?? [],
  opened: () => socket?.opened ?? null,
  tickets: () => sockets.map((s) => s.opened?.ticket ?? "").filter(Boolean),

  dispose() {
    player?.dispose();
    player = null;
    handle?.dispose();
    handle = null;
    socket = null;
    sockets = [];
    document.getElementById("host")!.replaceChildren();
  },
};

declare global {
  interface Window {
    harness: Harness;
    react: import("./react.js").ReactHarness;
  }
}
window.harness = harness;

// The React surface shares this stub gateway, so a React test can drive the same frames.
const { install } = await import("./react.js");
window.react = install(() => {
  const next = new StubSocket();
  sockets.push(next);
  socket = next;
  queueMicrotask(() => next.open());
  return next;
});
