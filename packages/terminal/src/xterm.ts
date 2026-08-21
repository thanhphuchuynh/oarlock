// The xterm.js half: a terminal, a fit addon, and two sequences deliberately disabled.
//
// # OSC 52 and title reporting are off, on purpose, and not by omission
//
// The device at the far end is the *untrusted* party in this architecture (threat model
// § 6). Two of xterm's optional behaviours hand it something it should not have:
//
//   - **OSC 52** lets the remote end write to the operator's clipboard. A compromised
//     treadmill could replace whatever the operator was about to paste — into a shell,
//     on another machine.
//   - **Title reporting** lets the remote end *read back* the window title, which in a
//     host application is often the customer, the ticket, or the operator's own name.
//
// Both are off by default in the versions we build against, which is exactly why this
// file does not rely on that. R-012 is about a default changing under us during a
// dependency bump: an addon that becomes bundled, a flag that flips. So OSC 52 is
// swallowed by a handler we register ourselves, which cannot be re-enabled by anything
// upstream, and the window-reporting flags are written out explicitly rather than left
// to their defaults.

import { Terminal, type ITerminalOptions } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { palette, type XtermPalette } from "./palette.js";

export interface XtermOptions {
  /** "dark" | "light" | "inherit" — inherit follows the host's colour scheme. */
  readonly theme?: "dark" | "light" | "inherit";
  readonly fontFamily?: string;
  readonly fontSize?: number;
  /** Scrollback lines held in the browser. */
  readonly scrollback?: number;
  /**
   * Let the device write to the operator's clipboard via OSC 52.
   *
   * Named for what it permits rather than for the sequence it enables. Off unless an
   * integrator decides otherwise for a fleet they trust.
   */
  readonly allowDeviceClipboardWrites?: boolean;
  /** Let the device set the host window's title. Off for the same reason. */
  readonly allowDeviceTitleChanges?: boolean;
  /** Called when the device asks for a title, whether or not it is applied. */
  readonly onTitle?: (title: string, applied: boolean) => void;
  /** Called when a clipboard write is refused, so a host can surface it if it wants. */
  readonly onClipboardRefused?: () => void;
}

export interface TerminalHandle {
  readonly term: Terminal;
  readonly fit: FitAddon;
  /** Resize to the container and report the new size. */
  refit(): { cols: number; rows: number };
  dispose(): void;
}

const DEFAULT_FONT =
  '"JetBrains Mono", "SF Mono", ui-monospace, "Cascadia Mono", "Menlo", monospace';

function resolvePalette(theme: XtermOptions["theme"]): XtermPalette {
  if (theme === "light") return palette.light;
  if (theme === "dark") return palette.dark;
  const dark =
    typeof window !== "undefined" &&
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-color-scheme: dark)").matches;
  return dark ? palette.dark : palette.light;
}

/** OSC 52 — the clipboard sequence. */
const OSC_CLIPBOARD = 52;

export function createTerminal(container: HTMLElement, opts: XtermOptions = {}): TerminalHandle {
  const options: ITerminalOptions = {
    fontFamily: opts.fontFamily ?? DEFAULT_FONT,
    fontSize: opts.fontSize ?? 13,
    lineHeight: 1.3,
    scrollback: opts.scrollback ?? 5000,
    cursorBlink: true,
    // A terminal is not a document; screen readers need the explicit affordance.
    screenReaderMode: false,
    allowProposedApi: false,
    // Written out rather than left to defaults. Every one of these is the device
    // asking the browser a question about the operator's window, and the answer is no.
    // Written out rather than left to defaults. Every one of these is the device
    // asking the browser to report on, or manipulate, the operator's window — the
    // `get*` ones read (a title is often the customer or the ticket), the rest move
    // and resize it. The answer to all of them is no, and saying so explicitly is
    // what survives a dependency bump that changes a default (R-012).
    windowOptions: {
      restoreWin: false,
      minimizeWin: false,
      setWinPosition: false,
      setWinSizePixels: false,
      raiseWin: false,
      lowerWin: false,
      refreshWin: false,
      setWinSizeChars: false,
      maximizeWin: false,
      fullscreenWin: false,
      getWinState: false,
      getWinPosition: false,
      getWinSizePixels: false,
      getScreenSizePixels: false,
      getCellSizePixels: false,
      getWinSizeChars: false,
      getScreenSizeChars: false,
      getIconTitle: false,
      getWinTitle: false,
      pushTitle: false,
      popTitle: false,
      setWinLines: false,
    },
    theme: resolvePalette(opts.theme) as NonNullable<ITerminalOptions["theme"]>,
  };

  const term = new Terminal(options);
  const fit = new FitAddon();
  term.loadAddon(fit);
  term.open(container);

  // ── OSC 52: swallowed here, not merely unimplemented upstream ──────────────────
  //
  // Returning true means "handled", so the sequence stops at this handler and never
  // reaches whatever else might come to handle it. If a future xterm bundles clipboard
  // support by default, this still wins, because a registered handler runs first.
  if (opts.allowDeviceClipboardWrites !== true) {
    term.parser.registerOscHandler(OSC_CLIPBOARD, () => {
      opts.onClipboardRefused?.();
      return true;
    });
  }

  // ── the title ─────────────────────────────────────────────────────────────────
  //
  // xterm only tells us the device asked; nothing happens unless somebody applies it.
  // An integrator who wants the title gets it through onTitle and applies it in their
  // own chrome, where they can decide what "the device named this tab" means in their
  // product.
  term.onTitleChange((title) => {
    const applied = opts.allowDeviceTitleChanges === true;
    if (applied && typeof document !== "undefined") document.title = title;
    opts.onTitle?.(title, applied);
  });

  const refit = () => {
    try {
      fit.fit();
    } catch {
      // fit throws while the container is detached or zero-sized, which happens
      // during mount and on a hidden tab. Neither is an error worth surfacing.
    }
    return { cols: term.cols, rows: term.rows };
  };

  return {
    term,
    fit,
    refit,
    dispose: () => term.dispose(),
  };
}
