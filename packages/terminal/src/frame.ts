// The wire codec, mirroring pkg/frame.
//
// One byte of type, then the payload. That is the whole header: a frame occupies
// exactly one binary WebSocket message, so the message boundary *is* the frame
// boundary. There is no length field (nothing can claim a size it does not intend to
// send) and no stream id (Oarlock does not multiplex — ADR-024).
//
// Kept deliberately small and dependency-free. It is the one part of the component a
// non-browser consumer might want, and it has to agree with Go byte for byte.

export const FrameType = {
  Data: 0x01,
  DataErr: 0x02,
  Open: 0x03,
  Ready: 0x04,
  Resize: 0x05,
  Signal: 0x06,
  Exit: 0x07,
  Close: 0x08,
  Throttle: 0x09,
  Error: 0x0a,
  Observers: 0x0b,
} as const;

export type FrameType = (typeof FrameType)[keyof typeof FrameType];

const names: Record<number, string> = {
  0x01: "DATA",
  0x02: "DATA_ERR",
  0x03: "OPEN",
  0x04: "READY",
  0x05: "RESIZE",
  0x06: "SIGNAL",
  0x07: "EXIT",
  0x08: "CLOSE",
  0x09: "THROTTLE",
  0x0a: "ERROR",
  0x0b: "OBSERVERS",
};

export function frameName(t: number): string {
  return names[t] ?? `0x${t.toString(16).padStart(2, "0")}`;
}

/** MaxFrame is the protocol-wide ceiling on any single frame (1 MiB). */
export const MaxFrame = 1 << 20;

export interface Frame {
  readonly type: number;
  readonly payload: Uint8Array;
}

export interface PTY {
  cols: number;
  rows: number;
  term?: string;
}

export interface Open {
  ticket: string;
  profile?: string;
  pty?: PTY;
}

export interface Observer {
  principal: string;
  /** RFC 3339, so "watched since before I ran that" is answerable. */
  since?: string;
}

export interface ObserversMsg {
  observers: Observer[];
}

export interface Ready {
  session_id: string;
  scrollback_len: number;
  recording: boolean;
  /** "gateway" — the gateway can read the stream — or "passthrough" — it cannot. */
  mode: string;
  limits?: { rate?: number; max_frame?: number };
  /** Who is already watching, so an operator attaching to a watched session is told
   *  immediately rather than on the next change. */
  observers?: Observer[];
  /** This connection cannot write: disable input rather than accepting keystrokes that
   *  will be silently dropped. */
  read_only?: boolean;
  /** Whose session a watcher is watching. */
  watching?: string;
}

export interface CloseMsg {
  reason: string;
}

export interface ErrorMsg {
  code: string;
  message?: string;
  retryable?: boolean;
}

export interface ThrottleMsg {
  dropped_bytes: number;
  profile?: string;
}

export interface ExitMsg {
  code: number;
  signal?: string | null;
}

const utf8 = new TextEncoder();
const utf8d = new TextDecoder("utf-8", { fatal: false });

/** encode builds one wire message: the type byte followed by the payload. */
export function encode(type: number, payload?: Uint8Array): Uint8Array {
  const body = payload ?? new Uint8Array(0);
  const out = new Uint8Array(1 + body.length);
  out[0] = type;
  out.set(body, 1);
  return out;
}

/** encodeJSON builds a JSON-bodied frame. */
export function encodeJSON(type: number, value: unknown): Uint8Array {
  return encode(type, utf8.encode(JSON.stringify(value)));
}

/** encodeData builds a DATA frame around raw bytes. */
export function encodeData(bytes: Uint8Array): Uint8Array {
  return encode(FrameType.Data, bytes);
}

export class ProtocolError extends Error {}

/**
 * decode splits one wire message.
 *
 * The payload is a *view* onto the caller's buffer, not a copy — the same choice Go
 * makes, for the same reason: DATA is the hot path and a shell session is thousands of
 * small frames. Callers who keep a payload beyond the current turn must copy it.
 */
export function decode(msg: Uint8Array): Frame {
  if (msg.length < 1) throw new ProtocolError("empty frame");
  if (msg.length > MaxFrame) {
    throw new ProtocolError(`frame is ${msg.length} bytes, over the ${MaxFrame} ceiling`);
  }
  const type = msg[0]!;
  if (type === 0) throw new ProtocolError("0x00 is not a frame type");
  return { type, payload: msg.subarray(1) };
}

/** decodeJSON parses a JSON-bodied frame's payload. */
export function decodeJSON<T>(f: Frame): T {
  if (f.payload.length === 0) throw new ProtocolError(`${frameName(f.type)} has no body`);
  try {
    return JSON.parse(utf8d.decode(f.payload)) as T;
  } catch (e) {
    throw new ProtocolError(`${frameName(f.type)} body is not JSON: ${String(e)}`);
  }
}
