// React wrappers over @oarlock/terminal.
//
// Thin on purpose. Everything that matters — the disclosure decision, the refusal to
// render an unrecorded session without an acknowledgement, OSC 52 being off — lives in
// the core, so this file cannot get it wrong and neither can a wrapper somebody writes
// for another framework.

import { useEffect, useRef, useState } from "react";
import {
  createFailureScreen,
  createPreflightGate,
  createStatusBar,
  decide,
  facts,
  mount,
  type ConnectionState,
  type FactsInput,
  type GateCopy,
  type MountHandle,
  type MountOptions,
  type Ready,
  type SessionFailure,
  type Session,
  type Verdict,
} from "@oarlock/terminal";

export interface TerminalProps extends Omit<MountOptions, "socket"> {
  className?: string;
  style?: React.CSSProperties;
}

/**
 * `<Terminal>` — the whole product for an integrator.
 *
 * It renders its own status bar and, when the session is unrecorded or in passthrough,
 * its own blocking gate. Neither is a prop: an integrator who wants different chrome
 * composes `<StatusBar>` and `<PreflightGate>` themselves, and the core still refuses
 * to hand them a terminal for an unacknowledged unrecorded session.
 */
export function Terminal(props: TerminalProps): React.ReactElement {
  const host = useRef<HTMLDivElement | null>(null);
  const handle = useRef<MountHandle | null>(null);

  // Options are read once at mount, like a WebSocket URL: a component that re-dialled
  // on every prop change would open a second session on a device capped at one.
  const opts = useRef(props);

  useEffect(() => {
    const el = host.current;
    if (!el) return;
    const h = mount(el, opts.current);
    handle.current = h;
    return () => {
      h.dispose();
      handle.current = null;
    };
  }, []);

  return <div ref={host} className={props.className} style={props.style} />;
}

export interface StatusBarProps extends FactsInput {
  className?: string;
}

/**
 * `<StatusBar>` — exported separately so an integrator building their own chrome has a
 * correct one to reach for. Using it does not turn off `<Terminal>`'s own.
 */
export function StatusBar(props: StatusBarProps): React.ReactElement {
  const host = useRef<HTMLDivElement | null>(null);
  const bar = useRef<ReturnType<typeof createStatusBar> | null>(null);
  const { className, ...input } = props;

  useEffect(() => {
    const el = host.current;
    if (!el) return;
    const b = createStatusBar(input as FactsInput);
    bar.current = b;
    el.append(b.el);
    return () => {
      b.dispose();
      bar.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    bar.current?.update(input as FactsInput);
  }, [props.device, props.principal, props.state, props.session, props.observers]);

  return <div ref={host} className={className ?? "oarlock-term"} />;
}

export interface PreflightGateProps {
  readonly session: Session | undefined;
  readonly onAcknowledge: () => void;
  readonly onCancel?: () => void;
  className?: string;
}

/**
 * `<PreflightGate>` — the acknowledgement, for a host that wants to place it itself.
 *
 * Renders nothing when there is nothing to disclose, which is the common case, so it is
 * safe to leave in a tree unconditionally.
 */
export function PreflightGate(props: PreflightGateProps): React.ReactElement | null {
  const host = useRef<HTMLDivElement | null>(null);
  const verdict = decide({ session: props.session });
  const copy: GateCopy | null = verdict.copy;

  useEffect(() => {
    const el = host.current;
    if (!el || !copy) return;
    const g = createPreflightGate({
      copy,
      onAcknowledge: props.onAcknowledge,
      ...(props.onCancel ? { onCancel: props.onCancel } : {}),
    });
    el.append(g.el);
    return () => g.dispose();
  }, [copy?.headline]);

  if (!copy) return null;
  return <div ref={host} className={props.className ?? "oarlock-term"} />;
}

export interface FailureScreenProps {
  /** The wire code, from an ERROR frame or a CLOSE reason. */
  readonly code: string;
  readonly message?: string;
  readonly reference?: string;
  readonly sessionID?: string;
  readonly onRetry?: () => void;
  readonly onDismiss?: () => void;
  className?: string;
}

/**
 * `<FailureScreen>` — one server condition, one screen.
 *
 * Exported for a host that renders its own chrome. The copy comes from the gateway's own
 * table, generated into the package, so a condition the server can emit cannot be a
 * screen this component does not have.
 */
export function FailureScreen(props: FailureScreenProps): React.ReactElement {
  const host = useRef<HTMLDivElement | null>(null);
  const { className, ...opts } = props;

  useEffect(() => {
    const el = host.current;
    if (!el) return;
    const f = createFailureScreen(opts as Parameters<typeof createFailureScreen>[0]);
    el.append(f.el);
    return () => f.dispose();
  }, [props.code, props.message, props.reference, props.sessionID]);

  return <div ref={host} className={className ?? "oarlock-term"} />;
}

/** useSessionState is sugar for the four facts a host's own chrome needs. */
export function useSessionState(): {
  state: ConnectionState;
  ready: Ready | null;
  failure: SessionFailure | null;
  handlers: Pick<MountOptions, "onState" | "onReady" | "onError">;
} {
  const [state, setState] = useState<ConnectionState>("connecting");
  const [ready, setReady] = useState<Ready | null>(null);
  const [failure, setFailure] = useState<SessionFailure | null>(null);
  return {
    state,
    ready,
    failure,
    handlers: { onState: setState, onReady: setReady, onError: setFailure },
  };
}

export { facts, decide };
export type { ConnectionState, FactsInput, MountOptions, Ready, SessionFailure, Session };
export type { Verdict } from "@oarlock/terminal";
