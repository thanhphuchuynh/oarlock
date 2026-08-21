// The socket half of the component: one WebSocket, one session, typed events.
//
// Server state is the truth and this holds almost none of it. There is no client-side
// mirror of the gateway's session state machine, because two state machines disagree
// eventually and the browser's copy is the one that would be wrong.

import {
  FrameType,
  MaxFrame,
  ProtocolError,
  decode,
  decodeJSON,
  encodeData,
  encodeJSON,
  frameName,
  type CloseMsg,
  type ErrorMsg,
  type ExitMsg,
  type PTY,
  type Observer,
  type ObserversMsg,
  type Ready,
  type ThrottleMsg,
} from "./frame.js";
import type { ConnectionState } from "./disclosure.js";

/**
 * Subprotocol is the negotiated WebSocket subprotocol for wire version v0.
 *
 * The gateway *requires* it — a client that does not offer it is refused at the upgrade
 * with `client did not offer "oarlock.v0"`. That is deliberate: the subprotocol is how the
 * wire version is negotiated before a byte of protocol is exchanged, so a v1 gateway can
 * refuse a v0 client at the handshake rather than six frames later.
 *
 * This was missing until the component was pointed at a real gateway for the first time.
 * Every component test injects a stub socket — which is right for testing frame handling,
 * and means the real handshake had never run.
 */
export const Subprotocol = "oarlock.v0";

/**
 * A failure an operator has to be able to act on.
 *
 * `code` comes from the gateway's closed set (ARCHITECTURE § 6) and is what a UI
 * switches on; `message` is prose for humans and is never parsed. The distinction
 * matters most for the pair the epic keeps calling out: `revoked` and
 * `authz_unavailable` must not render as the same screen, because "your access was
 * removed" and "we could not check your access" send someone to different places.
 */
export interface SessionFailure {
  readonly code: string;
  readonly message: string;
  readonly retryable: boolean;
}

export interface SessionEvents {
  onState?: (state: ConnectionState) => void;
  onReady?: (ready: Ready) => void;
  /** Raw bytes for the terminal. The array is a view and must not be retained. */
  onData?: (bytes: Uint8Array) => void;
  onError?: (failure: SessionFailure) => void;
  onExit?: (exit: ExitMsg) => void;
  onThrottle?: (t: ThrottleMsg) => void;
  /** The session is over. `reason` is from the closed set. */
  onClosed?: (reason: string) => void;
  /**
   * Who is watching, whenever it changes (FR13).
   *
   * The whole list, never a delta: a client that missed one frame would otherwise show
   * a watcher who has left, or miss one who arrived, and be wrong about the single fact
   * this exists to convey. An empty array means nobody, and is sent — the indicator has
   * to be able to go away.
   */
  onObservers?: (observers: readonly Observer[]) => void;
}

export interface SessionOptions extends SessionEvents {
  /** The attach endpoint from the API's `attach.url`. */
  readonly url: string;
  /** A single-use attach ticket. Never put one in a URL. */
  readonly ticket: string;
  readonly pty?: PTY;
  readonly profile?: string;
  /**
   * Fetches a fresh attach ticket, by calling the integrator's own backend.
   *
   * Tickets are single-use and live 60 s, so the ordinary things a browser does — a
   * reload, a handshake that loses a race, sitting on the response for a minute — leave
   * it holding a dead credential. The component asks for another rather than reporting
   * a failure the operator cannot act on.
   *
   * It is a callback rather than a stored token because that is what makes a reconnect
   * re-check authorisation: the request goes through the integrator's backend, which is
   * where the decision was made, instead of resuming on the strength of an old one.
   */
  readonly renewTicket?: () => Promise<string>;
  /**
   * Reconnect automatically when the socket drops mid-session.
   *
   * On by default, because a dropped connection is the normal case rather than a
   * failure: the gateway keeps the session attached, holds what the device produced in
   * a ring, and replays it on return. An operator who loses wifi mid-command should
   * discover that nothing happened.
   *
   * Requires renewTicket — the ticket that got them here was spent on the way in, and
   * fetching another through the integrator's backend is what makes the reconnect
   * re-check authorisation rather than resume on an old decision.
   */
  readonly reconnect?: boolean;
  /** How many reconnect attempts before giving up. Default 6. */
  readonly maxReconnects?: number;
  /** Injected in tests; defaults to the platform WebSocket. */
  readonly socket?: (url: string) => WebSocketLike;
}

/** The slice of WebSocket this needs, so a test can supply one. */
export interface WebSocketLike {
  binaryType: string;
  onopen: ((ev: unknown) => void) | null;
  onmessage: ((ev: { data: unknown }) => void) | null;
  onerror: ((ev: unknown) => void) | null;
  onclose: ((ev: { code: number; reason: string }) => void) | null;
  send(data: ArrayBufferView | ArrayBuffer | string): void;
  close(code?: number, reason?: string): void;
}

const RESIZE_INTERVAL_MS = 100;

export class OarlockSession {
  #ws: WebSocketLike | null = null;
  #state: ConnectionState = "connecting";
  #ready: Ready | null = null;
  #opts: SessionOptions;
  #closedLocally = false;
  #ticket: string;
  #renewed = false;
  #reconnects = 0;
  #reconnecting = false;
  #dropped = 0;
  #lastResize: { cols: number; rows: number } | null = null;
  #resizeTimer: ReturnType<typeof setTimeout> | null = null;
  #resizeSentAt = 0;

  constructor(opts: SessionOptions) {
    this.#opts = opts;
    this.#ticket = opts.ticket;
  }

  get state(): ConnectionState {
    return this.#state;
  }

  get ready(): Ready | null {
    return this.#ready;
  }

  /** connect opens the socket and sends OPEN. */
  connect(): void {
    if (this.#ws) throw new Error("already connected");
    this.#dial();
  }

  #dial(): void {
    const factory =
      this.#opts.socket ??
      ((u: string) => new WebSocket(u, [Subprotocol]) as unknown as WebSocketLike);
    const ws = factory(this.#opts.url);
    ws.binaryType = "arraybuffer";
    this.#ws = ws;
    this.#setState("connecting");

    ws.onopen = () => {
      // The ticket travels in the OPEN frame body, never in the URL: a URL reaches
      // proxy logs, browser history and Referer headers, and a single-use secret in a
      // log is a multi-use secret.
      this.#send(
        encodeJSON(FrameType.Open, {
          ticket: this.#ticket,
          profile: this.#opts.profile ?? "shell",
          ...(this.#opts.pty ? { pty: this.#opts.pty } : {}),
        }),
      );
    };

    ws.onmessage = (ev) => this.#receive(ev.data);

    ws.onerror = () => {
      // A transport error carries no code of its own, and inventing one would put a
      // word in the gateway's mouth. onclose follows and reports what happened.
    };

    ws.onclose = (ev) => {
      if (this.#state === "closed" || this.#closedLocally) {
        if (!this.#closedLocally) return;
        this.#finish(ev.reason || "connection_lost");
        return;
      }
      // The gateway keeps the session attached when a browser drops, so a lost socket
      // is a reconnect rather than an end. Reporting it as an error first would put a
      // failure in front of an operator for something about to fix itself.
      if (this.#canReconnect()) {
        void this.#reconnectSoon(ev.reason);
        return;
      }
      this.#opts.onError?.({
        code: "connection_lost",
        message: ev.reason || "The connection to the gateway closed.",
        retryable: true,
      });
      this.#finish(ev.reason || "connection_lost");
    };
  }

  /** write sends operator keystrokes. */
  write(bytes: Uint8Array | string): void {
    const body = typeof bytes === "string" ? new TextEncoder().encode(bytes) : bytes;
    this.#send(encodeData(body));
  }

  /**
   * resize reports a window change, coalesced.
   *
   * Dragging a browser edge produces hundreds of events and the PTY needs only the
   * last, so at most one goes out per 100 ms with the final size always sent. Without
   * the trailing send the terminal ends up one drag out of date, which looks exactly
   * like a resize that did not work.
   */
  resize(cols: number, rows: number): void {
    if (cols <= 0 || rows <= 0) return;
    if (this.#lastResize && this.#lastResize.cols === cols && this.#lastResize.rows === rows) {
      return;
    }
    this.#lastResize = { cols, rows };
    const now = Date.now();
    const since = now - this.#resizeSentAt;
    if (since >= RESIZE_INTERVAL_MS) {
      this.#flushResize();
      return;
    }
    if (this.#resizeTimer === null) {
      this.#resizeTimer = setTimeout(() => {
        this.#resizeTimer = null;
        this.#flushResize();
      }, RESIZE_INTERVAL_MS - since);
    }
  }

  /** signal is the stop button, not interactive Ctrl-C (that is 0x03 inside DATA). */
  signal(signal: string): void {
    this.#send(encodeJSON(FrameType.Signal, { signal }));
  }

  /** close ends the session politely. */
  close(reason = "operator_close"): void {
    if (this.#closedLocally || this.#state === "closed") return;
    this.#closedLocally = true;
    try {
      this.#send(encodeJSON(FrameType.Close, { reason }));
    } catch {
      /* the socket may already be gone; the CLOSE is a courtesy */
    }
    this.#ws?.close(1000, reason);
    this.#finish(reason);
  }

  #flushResize(): void {
    const r = this.#lastResize;
    if (!r) return;
    this.#resizeSentAt = Date.now();
    this.#send(encodeJSON(FrameType.Resize, r));
  }

  /**
   * send writes a frame, or drops it if there is no socket.
   *
   * Dropping rather than throwing, because the callers are event handlers — a keystroke,
   * a ResizeObserver firing during a reconnect — and an exception out of one of those is
   * an unhandled rejection in somebody's application, not a diagnosis.
   *
   * Dropping rather than *queueing* is a deliberate departure from the journey sketch in
   * the UX spec, which says input queues while reconnecting. A terminal is not a text
   * field: the far end interprets bytes in context, so keystrokes typed into a dead
   * socket and replayed eight seconds later can land in a different context entirely —
   * a pager that has exited, a confirmation prompt that has moved on. Losing the
   * characters is visible (nothing echoes, and the screen is dimmed to say why);
   * delivering them somewhere unintended is not.
   */
  #send(msg: Uint8Array): void {
    if (msg.length > MaxFrame) throw new ProtocolError("frame over the ceiling");
    const ws = this.#ws;
    if (!ws) {
      this.#dropped++;
      return;
    }
    ws.send(msg);
  }

  /** dropped is how many frames were discarded because no socket was attached. */
  get dropped(): number {
    return this.#dropped;
  }

  #receive(data: unknown): void {
    let bytes: Uint8Array;
    if (data instanceof ArrayBuffer) bytes = new Uint8Array(data);
    else if (data instanceof Uint8Array) bytes = data;
    else {
      // A text message on a binary protocol is a peer that is not speaking Oarlock.
      this.#opts.onError?.({
        code: "protocol_error",
        message: "The gateway sent a text message on a binary protocol.",
        retryable: false,
      });
      return;
    }

    let f;
    try {
      f = decode(bytes);
    } catch (e) {
      this.#opts.onError?.({
        code: "protocol_error",
        message: e instanceof Error ? e.message : String(e),
        retryable: false,
      });
      return;
    }

    switch (f.type) {
      case FrameType.Data:
      case FrameType.DataErr:
        this.#opts.onData?.(f.payload);
        return;

      case FrameType.Ready: {
        const ready = decodeJSON<Ready>(f);
        this.#ready = ready;
        // A session that reconnects successfully has spent none of its budget: the
        // limit is on consecutive failures, not on a long session's lifetime.
        this.#reconnects = 0;
        // READY carries the initial watcher list, so an operator attaching to a session
        // that is already watched is told now rather than on the next change.
        this.#opts.onObservers?.(ready.observers ?? []);
        this.#opts.onReady?.(ready);
        this.#setState("attached");
        return;
      }

      case FrameType.Error: {
        const e = decodeJSON<ErrorMsg>(f);
        const code = e.code || "internal";

        // A ticket refused *before* READY is the case the renewal endpoint exists for:
        // single-use plus 60 s means a reload or a slow operator arrives with a dead
        // credential, and reporting that to them as a failure would be reporting our own
        // design. Renew once and re-dial; a second refusal is a real answer.
        //
        // Only before READY, and only once. After READY the session is live and a
        // refusal means something else; and a renewal loop against a gateway that
        // refuses everything is a denial-of-service we would be running on ourselves.
        if (
          (code === "ticket_invalid" || code === "ticket_expired") &&
          this.#ready === null &&
          !this.#renewed &&
          this.#opts.renewTicket
        ) {
          this.#renewed = true;
          void this.#renewAndRedial(code);
          return;
        }

        this.#opts.onError?.({
          code,
          message: e.message ?? "",
          retryable: e.retryable === true,
        });
        return;
      }

      case FrameType.Observers:
        this.#opts.onObservers?.(decodeJSON<ObserversMsg>(f).observers ?? []);
        return;

      case FrameType.Throttle:
        this.#opts.onThrottle?.(decodeJSON<ThrottleMsg>(f));
        return;

      case FrameType.Exit:
        this.#opts.onExit?.(decodeJSON<ExitMsg>(f));
        return;

      case FrameType.Close:
        this.#finish(decodeJSON<CloseMsg>(f).reason || "closed");
        return;

      default:
        // Session-scoped types may be skipped: the worst case is one session missing
        // a feature the gateway has and we do not. Anything else is a peer confusion
        // worth surfacing rather than swallowing.
        if ((f.type & 0xf0) !== 0x00) {
          this.#opts.onError?.({
            code: "protocol_error",
            message: `${frameName(f.type)} does not belong on a session connection`,
            retryable: false,
          });
        }
        return;
    }
  }

  async #renewAndRedial(afterCode: string): Promise<void> {
    const previous = this.#ws;
    // Detached before closing, so the socket's own onclose does not report a connection
    // the component deliberately gave up on.
    if (previous) {
      previous.onclose = null;
      previous.onmessage = null;
      previous.onopen = null;
      try {
        previous.close(1000, "renewing the ticket");
      } catch {
        /* already gone */
      }
    }
    this.#ws = null;

    try {
      this.#ticket = await this.#opts.renewTicket!();
    } catch (err) {
      // The integrator's backend said no, which is a real answer: the operator's
      // authorisation may have been withdrawn since the session opened.
      this.#opts.onError?.({
        code: afterCode,
        message:
          err instanceof Error
            ? `Could not get a fresh ticket: ${err.message}`
            : "Could not get a fresh ticket.",
        retryable: false,
      });
      this.#finish(afterCode);
      return;
    }
    if (this.#closedLocally || this.#state === "closed") return;
    this.#dial();
  }

  #canReconnect(): boolean {
    return (
      this.#opts.reconnect !== false &&
      this.#opts.renewTicket !== undefined &&
      this.#ready !== null && // before READY there is no session to come back to
      this.#reconnects < (this.#opts.maxReconnects ?? 6)
    );
  }

  /**
   * reconnectSoon fetches a fresh ticket and re-dials, with a backoff.
   *
   * The backoff is not politeness: a gateway that just dropped every operator — a
   * deploy, a pod eviction — gets every browser back at once, and a fleet reconnecting
   * in lockstep is a self-inflicted thundering herd. The jitter is what breaks the
   * lockstep, so it is a third of the delay rather than a decoration.
   */
  async #reconnectSoon(why: string): Promise<void> {
    if (this.#reconnecting) return;
    this.#reconnecting = true;
    this.#reconnects++;
    this.#ws = null;
    this.#setState("reconnecting");

    const base = Math.min(500 * 2 ** (this.#reconnects - 1), 8_000);
    const delay = base * (2 / 3) + Math.random() * (base / 3);
    await new Promise((r) => setTimeout(r, delay));
    if (this.#closedLocally || this.#isClosed()) {
      this.#reconnecting = false;
      return;
    }

    try {
      this.#ticket = await this.#opts.renewTicket!();
    } catch (err) {
      // The backend declining is a real answer: the operator's authorisation may have
      // been withdrawn while they were away, which is exactly what re-checking on
      // reconnect is for.
      this.#reconnecting = false;
      this.#opts.onError?.({
        code: "not_authorized",
        message:
          err instanceof Error
            ? `Could not resume the session: ${err.message}`
            : "Could not resume the session.",
        retryable: false,
      });
      this.#finish(why || "connection_lost");
      return;
    }

    this.#reconnecting = false;
    if (this.#closedLocally || this.#isClosed()) return;
    this.#dial();
  }

  // Read through a method rather than inline: after an await, TypeScript's narrowing
  // of #state is stale, and it will tell you the comparison is unnecessary while the
  // value can genuinely have changed under you.
  #isClosed(): boolean {
    return this.#state === "closed";
  }

  #setState(s: ConnectionState): void {
    if (this.#state === s) return;
    this.#state = s;
    this.#opts.onState?.(s);
  }

  #finish(reason: string): void {
    if (this.#resizeTimer !== null) {
      clearTimeout(this.#resizeTimer);
      this.#resizeTimer = null;
    }
    if (this.#state === "closed") return;
    this.#setState("closed");
    this.#opts.onClosed?.(reason);
  }
}
