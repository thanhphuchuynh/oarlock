// mount() — the framework-agnostic terminal.
//
// The React `<Terminal>` is a thin wrapper over this, which is deliberate: the
// disclosure rules are enforced here, once, so that every wrapper inherits them and no
// wrapper can be written that loses them.

import { createTerminal, type TerminalHandle, type XtermOptions } from "./xterm.js";
import { createStatusBar, type StatusBarHandle } from "./statusbar.js";
import { createPreflightGate, type PreflightHandle } from "./preflight.js";
import { createFailureScreen, type FailureHandle } from "./failure.js";
import { decide, sessionOf, type ConnectionState, type Session } from "./disclosure.js";
import { OarlockSession, type SessionFailure } from "./session.js";
import type { ExitMsg, Observer, PTY, Ready, ThrottleMsg } from "./frame.js";

export interface MountOptions extends XtermOptions {
  readonly url: string;
  readonly ticket: string;
  /** The device id, for the status bar. The bar states which device, always. */
  readonly device: string;
  /** The operator this session is attributed to. */
  readonly principal: string;
  readonly pty?: PTY;
  readonly profile?: string;
  /** Fetches a fresh attach ticket from the integrator's backend. See SessionOptions. */
  readonly renewTicket?: () => Promise<string>;
  /** Reconnect automatically when the socket drops. On by default. */
  readonly reconnect?: boolean;
  /** How many reconnect attempts before giving up. */
  readonly maxReconnects?: number;
  /** Named for its consequence: ship an unrecorded session with no gate. */
  readonly acknowledgeUnrecordedWithoutPrompt?: boolean;
  /**
   * Watch a session read-only instead of driving it (FR13).
   *
   * The gateway says so too, in READY, and the component believes the gateway — this
   * only exists so a host can render the read-only chrome before READY arrives. Input is
   * disabled rather than ignored: a keystroke that silently does nothing is worse than
   * one that cannot be typed.
   */
  readonly readOnly?: boolean;

  onState?: (state: ConnectionState) => void;
  onReady?: (ready: Ready) => void;
  onObservers?: (observers: readonly Observer[]) => void;
  onThrottle?: (t: ThrottleMsg) => void;
  onExit?: (e: ExitMsg) => void;
  onError?: (failure: SessionFailure) => void;
  onClosed?: (reason: string) => void;
  /**
   * Render the failure screen for a condition the operator cannot work through.
   *
   * On by default. An integrator who wants their own can turn it off and use the
   * exported `<FailureScreen>` — but the default has to be a screen, because the
   * alternative is a terminal that simply stops with no reason on it.
   */
  readonly failureScreen?: boolean;
  /** Called when the operator presses Try again on a retryable condition. */
  onRetry?: () => void;
  /** The operator declined at the gate. */
  onCancelled?: () => void;
  readonly socket?: (url: string) => import("./session.js").WebSocketLike;
}

export interface MountHandle {
  readonly el: HTMLElement;
  readonly session: OarlockSession;
  /** Null until the gate is cleared — there is no terminal before then. */
  terminal(): TerminalHandle | null;
  dispose(): void;
}

/**
 * How much device output to hold while the gate is up.
 *
 * The gate can only appear once READY has said the session is unrecorded, and by then
 * the device may already be talking. Buffering rather than rendering behind a
 * translucent panel is the point: a gate an operator can read the screen through is
 * decoration. Past the cap the component stops buffering and says so on flush, because
 * a shell stream cut in the middle of an escape sequence is worse than an honest gap.
 */
const GATE_BUFFER_LIMIT = 1 << 20;

export function mount(container: HTMLElement, opts: MountOptions): MountHandle {
  const root = document.createElement("div");
  root.className = "oarlock-term";
  root.dataset["oarlockTheme"] = opts.theme ?? "inherit";
  root.dataset["oarlockState"] = "connecting";

  let state: ConnectionState = "connecting";
  let ready: Ready | null = null;
  let session: Session | undefined;
  let acknowledged = false;
  let observers: string[] = [];
  let readOnly = opts.readOnly === true;
  let watching = "";

  const bar: StatusBarHandle = createStatusBar({
    device: opts.device,
    principal: opts.principal,
    session: undefined,
    state,
    observers,
    ...(readOnly ? { readOnly: true, watching } : {}),
  });

  const screen = document.createElement("div");
  screen.className = "oarlock-screen";

  root.append(bar.el, screen);
  container.append(root);

  let term: TerminalHandle | null = null;
  let gate: PreflightHandle | null = null;
  let held: Uint8Array[] = [];
  let heldBytes = 0;
  let heldDropped = 0;
  let observer: ResizeObserver | null = null;
  let failure: FailureHandle | null = null;

  const refreshBar = () => {
    bar.update({
      device: opts.device,
      principal: opts.principal,
      session,
      state,
      observers,
      ...(readOnly ? { readOnly: true, watching } : {}),
    });
  };

  const oarlockSession = new OarlockSession({
    url: opts.url,
    ticket: opts.ticket,
    ...(opts.pty ? { pty: opts.pty } : {}),
    ...(opts.profile ? { profile: opts.profile } : {}),
    ...(opts.socket ? { socket: opts.socket } : {}),
    ...(opts.renewTicket ? { renewTicket: opts.renewTicket } : {}),
    ...(opts.reconnect !== undefined ? { reconnect: opts.reconnect } : {}),
    ...(opts.maxReconnects !== undefined ? { maxReconnects: opts.maxReconnects } : {}),
    onState: (s) => {
      state = s;
      root.dataset["oarlockState"] = s;
      refreshBar();
      opts.onState?.(s);
    },
    onReady: (r) => {
      ready = r;
      session = sessionOf(r);
      // Read-only can be added but never taken away. The gateway is the authority on
      // what a connection may do — a host that forgot the prop still gets a read-only
      // terminal — and the prop restricts on top of that, for a host that wants a
      // preview pane on a session it could have written to.
      readOnly = r.read_only === true || opts.readOnly === true;
      watching = r.watching ?? "";
      root.dataset["oarlockReadOnly"] = readOnly ? "true" : "false";
      refreshBar();
      opts.onReady?.(r);
      settle();
      // Re-report the size on every READY, not just the first. A window resized while
      // the socket was down leaves the device's PTY at the old dimensions, with the
      // screen wrapping wrongly and nothing to blame it on. A late ResizeObserver
      // sometimes covers this by accident; that is a race, and this is not.
      if (term) {
        const size = term.refit();
        oarlockSession.resize(size.cols, size.rows);
      }
    },
    onData: (bytes) => {
      if (term) {
        term.term.write(new Uint8Array(bytes));
        return;
      }
      if (heldBytes + bytes.length > GATE_BUFFER_LIMIT) {
        heldDropped += bytes.length;
        return;
      }
      // Copied, not retained: the payload is a view onto the socket's buffer.
      held.push(new Uint8Array(bytes));
      heldBytes += bytes.length;
    },
    onObservers: (list) => {
      observers = list.map((o) => o.principal);
      refreshBar();
      opts.onObservers?.(list);
    },
    onError: (f) => {
      opts.onError?.(f);
      showFailure(f.code, f.message);
    },
    onThrottle: (t) => {
      // A THROTTLE on a shell stream is a gateway bug — shell backpressures instead of
      // dropping, precisely because a chunk lost mid escape sequence leaves the screen
      // corrupt until a full redraw. The component cannot repair that, so it says where
      // the hole is rather than letting the operator read a mangled screen as real
      // output.
      term?.term.write(
        `\r\n\x1b[33m[oarlock] ${t.dropped_bytes} bytes were dropped by the gateway` +
          `${t.profile ? ` (profile ${t.profile})` : ""}]\x1b[0m\r\n`,
      );
      opts.onThrottle?.(t);
    },
    onExit: (e) => opts.onExit?.(e),
    onClosed: (reason) => {
      refreshBar();
      opts.onClosed?.(reason);
      // A close reason is a condition too, and the ones an operator most needs to read
      // arrive this way: idle_timeout, admin_kill, revoked mid-session. A terminal that
      // simply stops is the failure this screen exists to prevent.
      showFailure(reason);
    },
  });

  /**
   * showFailure puts exactly one condition on the screen.
   *
   * First one wins. A dropped socket produces a cascade — an ERROR, then a CLOSE, then
   * whatever the transport noticed on the way down — and the *first* of those is the one
   * that says what happened; the rest are consequences. Rendering the last would show an
   * operator "the connection failed" for a session that was revoked.
   */
  function showFailure(code: string, message?: string): void {
    if (opts.failureScreen === false || failure || !code) return;
    // connection_lost while reconnecting is not a screen: the component is handling it,
    // the bar says so, and a modal would make the normal case look like a failure.
    if (code === "connection_lost" && state === "reconnecting") return;

    failure = createFailureScreen({
      code,
      ...(message ? { message } : {}),
      ...(ready?.session_id ? { sessionID: ready.session_id } : {}),
      ...(opts.onRetry
        ? {
            onRetry: () => {
              failure?.dispose();
              failure = null;
              opts.onRetry?.();
            },
          }
        : {}),
    });
    root.append(failure.el);
  }

  /** settle decides what the operator is allowed to see, and shows it. */
  function settle(): void {
    const verdict = decide({
      session,
      acknowledged,
      ...(opts.acknowledgeUnrecordedWithoutPrompt !== undefined
        ? { acknowledgeUnrecordedWithoutPrompt: opts.acknowledgeUnrecordedWithoutPrompt }
        : {}),
    });

    if (verdict.gate && verdict.copy) {
      if (gate) return;
      gate = createPreflightGate({
        copy: verdict.copy,
        onAcknowledge: () => {
          acknowledged = true;
          gate?.dispose();
          gate = null;
          settle();
        },
        onCancel: () => {
          gate?.dispose();
          gate = null;
          oarlockSession.close("operator_declined");
          opts.onCancelled?.();
        },
      });
      root.append(gate.el);
      return;
    }

    if (!verdict.terminal || term) return;
    openTerminal();
  }

  function openTerminal(): void {
    const xtermOpts: XtermOptions = {
      ...(opts.theme ? { theme: opts.theme } : {}),
      ...(opts.fontFamily ? { fontFamily: opts.fontFamily } : {}),
      ...(opts.fontSize ? { fontSize: opts.fontSize } : {}),
      ...(opts.scrollback ? { scrollback: opts.scrollback } : {}),
      ...(opts.allowDeviceClipboardWrites !== undefined
        ? { allowDeviceClipboardWrites: opts.allowDeviceClipboardWrites }
        : {}),
      ...(opts.allowDeviceTitleChanges !== undefined
        ? { allowDeviceTitleChanges: opts.allowDeviceTitleChanges }
        : {}),
      ...(opts.onTitle ? { onTitle: opts.onTitle } : {}),
      ...(opts.onClipboardRefused ? { onClipboardRefused: opts.onClipboardRefused } : {}),
    };
    term = createTerminal(screen, xtermOpts);

    if (heldDropped > 0) {
      // Said in the terminal, where the gap is, rather than in a console nobody reads.
      term.term.write(
        `\r\n\x1b[33m[oarlock] ${heldDropped} bytes of output were dropped while this ` +
          `session was waiting to be acknowledged]\x1b[0m\r\n`,
      );
    }
    for (const chunk of held) term.term.write(chunk);
    held = [];
    heldBytes = 0;
    heldDropped = 0;

    if (readOnly) {
      // Disabled, not ignored — but *readonly* rather than *disabled*, which is a
      // distinction worth being deliberate about.
      //
      // `disabled` on the textarea would remove it from the accessibility tree and from
      // the focus order, so a screen-reader user could no longer read the session they
      // came to watch. `readOnly` keeps it readable and focusable while making it
      // genuinely impossible to type into, which is what the requirement means: a
      // keystroke that silently does nothing is worse than one that cannot be typed.
      term.term.options.disableStdin = true;
      term.term.options.cursorBlink = false;
      const input = screen.querySelector<HTMLTextAreaElement>(".xterm-helper-textarea");
      if (input) {
        input.readOnly = true;
        input.setAttribute("aria-readonly", "true");
      }
    } else {
      term.term.onData((s) => oarlockSession.write(s));
    }
    const size = term.refit();
    oarlockSession.resize(size.cols, size.rows);

    if (typeof ResizeObserver !== "undefined") {
      observer = new ResizeObserver(() => {
        const next = term?.refit();
        if (next) oarlockSession.resize(next.cols, next.rows);
      });
      observer.observe(screen);
    }
  }

  oarlockSession.connect();

  return {
    el: root,
    session: oarlockSession,
    terminal: () => term,
    dispose: () => {
      observer?.disconnect();
      failure?.dispose();
      gate?.dispose();
      term?.dispose();
      oarlockSession.close("operator_close");
      bar.dispose();
      root.remove();
    },
  };
}

/** readyOf is exported for tests and for hosts that keep their own copy of READY. */
export function readyOf(h: MountHandle): Ready | null {
  return h.session.ready;
}
