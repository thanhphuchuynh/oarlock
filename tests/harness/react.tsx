// The React surface, mounted in the same hostile host page.
//
// `<Terminal>` is a thin wrapper and the refusal lives in the core, so this exists to
// prove the wiring rather than the policy: R-001's mitigation is written in terms of
// `<Terminal>`, which is the thing an integrator actually reaches for, and "thin
// wrapper" is a claim worth testing rather than asserting.

import { createElement, type ReactElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { PreflightGate, StatusBar, Terminal } from "@oarlock/react";

let root: Root | null = null;

export interface ReactHarness {
  mountTerminal(opts: Record<string, unknown>): void;
  mountChrome(opts: Record<string, unknown>): void;
  unmount(): void;
}

const host = () => document.getElementById("react-host")!;

export function install(makeSocket: () => unknown): ReactHarness {
  const render = (node: ReactElement) => {
    root?.unmount();
    root = createRoot(host());
    root.render(node);
  };
  return {
    mountTerminal(opts) {
      render(
        createElement(Terminal, {
          url: "wss://stub.invalid/ws/attach",
          ticket: "stub-ticket-abcdef",
          device: "treadmill-4821",
          principal: "admin@mail.com",
          socket: makeSocket,
          ...opts,
        } as never),
      );
    },
    // An integrator building their own chrome: the exported bar and gate, with a bare
    // terminal. The point of the test is that this composition still cannot ship an
    // unacknowledged unrecorded session.
    mountChrome(opts) {
      const session = (opts["session"] ?? { recording: false, mode: "gateway" }) as {
        recording?: boolean;
        mode?: string;
      };
      render(
        createElement(
          "div",
          // Sized the way a host would size it; the gate is an overlay and needs a box.
          { className: "oarlock-term" },
          createElement(StatusBar, {
            device: "treadmill-4821",
            principal: "admin@mail.com",
            session,
            state: "attached",
          } as never),
          createElement(PreflightGate, {
            session,
            onAcknowledge: () => {
              (window as unknown as { chromeAcknowledged: number }).chromeAcknowledged =
                ((window as unknown as { chromeAcknowledged?: number }).chromeAcknowledged ?? 0) + 1;
            },
          } as never),
        ),
      );
    },
    unmount() {
      root?.unmount();
      root = null;
    },
  };
}
