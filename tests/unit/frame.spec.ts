// The TypeScript codec has to agree with pkg/frame byte for byte. It is a second
// implementation of a wire format, which is the classic place for a protocol to fork
// quietly: the Go tests pass, the browser tests pass, and the two disagree in
// production.
//
// The vectors here are the wire bytes, written out literally rather than produced by
// the code under test, so a change in either implementation has to be deliberate.

import { test, expect } from "@playwright/test";
import {
  FrameType,
  MaxFrame,
  ProtocolError,
  decode,
  decodeJSON,
  encode,
  encodeData,
  encodeJSON,
  frameName,
} from "@oarlock/terminal/frame";

const bytes = (...b: number[]) => new Uint8Array(b);

test("the header is one byte and nothing else", () => {
  // DATA "hi" is 0x01 'h' 'i'. No length, no stream id, no flags.
  expect([...encodeData(bytes(0x68, 0x69))]).toEqual([0x01, 0x68, 0x69]);
  expect([...encode(FrameType.Close)]).toEqual([0x08]);
});

test("the type bytes match Go", () => {
  expect(FrameType.Data).toBe(0x01);
  expect(FrameType.DataErr).toBe(0x02);
  expect(FrameType.Open).toBe(0x03);
  expect(FrameType.Ready).toBe(0x04);
  expect(FrameType.Resize).toBe(0x05);
  expect(FrameType.Signal).toBe(0x06);
  expect(FrameType.Exit).toBe(0x07);
  expect(FrameType.Close).toBe(0x08);
  expect(FrameType.Throttle).toBe(0x09);
  expect(FrameType.Error).toBe(0x0a);
});

test("names match Go's, because they appear in errors on both sides", () => {
  expect(frameName(0x01)).toBe("DATA");
  expect(frameName(0x02)).toBe("DATA_ERR");
  expect(frameName(0x0a)).toBe("ERROR");
  expect(frameName(0x16)).toBe("0x16");
});

test("decode aliases the caller's buffer rather than copying", () => {
  const wire = bytes(0x01, 0x61, 0x62, 0x63);
  const f = decode(wire);
  expect(f.type).toBe(0x01);
  expect([...f.payload]).toEqual([0x61, 0x62, 0x63]);
  // A view, not a copy: DATA is the hot path and a shell is thousands of small frames.
  wire[1] = 0x7a;
  expect(f.payload[0]).toBe(0x7a);
});

test("0x00 is not a frame type", () => {
  expect(() => decode(bytes(0x00, 0x01))).toThrow(ProtocolError);
});

test("an empty message is not a frame", () => {
  expect(() => decode(new Uint8Array(0))).toThrow(ProtocolError);
});

test("a frame over the ceiling is refused before anything reads it", () => {
  expect(() => decode(new Uint8Array(MaxFrame + 1))).toThrow(/over the/);
});

test("a JSON frame round-trips", () => {
  const wire = encodeJSON(FrameType.Resize, { cols: 132, rows: 38 });
  expect(wire[0]).toBe(0x05);
  expect(decodeJSON<{ cols: number; rows: number }>(decode(wire))).toEqual({
    cols: 132,
    rows: 38,
  });
});

test("READY parses the fields the disclosure depends on", () => {
  const wire = new TextEncoder().encode(
    JSON.stringify({
      session_id: "sess_01J8Z",
      scrollback_len: 4096,
      recording: true,
      mode: "gateway",
      limits: { rate: 262144 },
    }),
  );
  const f = decode(encode(FrameType.Ready, wire));
  const ready = decodeJSON<{ recording: boolean; mode: string; session_id: string }>(f);
  expect(ready.recording).toBe(true);
  expect(ready.mode).toBe("gateway");
  expect(ready.session_id).toBe("sess_01J8Z");
});

test("a body that is not JSON says which frame it was", () => {
  const f = decode(encode(FrameType.Ready, new TextEncoder().encode("{ not json")));
  expect(() => decodeJSON(f)).toThrow(/READY body is not JSON/);
});

test("an empty JSON body is an error, not an empty object", () => {
  expect(() => decodeJSON(decode(encode(FrameType.Ready)))).toThrow(/has no body/);
});

test("UTF-8 survives the round trip", () => {
  const text = "café ✓ 日本語";
  const f = decode(encodeData(new TextEncoder().encode(text)));
  expect(new TextDecoder().decode(f.payload)).toBe(text);
});

test("the subprotocol matches the gateway's", async () => {
  // The gateway refuses an upgrade that does not offer it, so a mismatch is not a
  // degraded connection — it is no connection at all. Asserted against the Go constant's
  // value rather than trusted, because every component test injects a stub socket and so
  // never performs the real handshake: this was missing entirely until the component was
  // pointed at a running gateway.
  const { Subprotocol } = await import("@oarlock/terminal/session");
  expect(Subprotocol).toBe("oarlock.v0");
});
