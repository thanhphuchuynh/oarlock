// The cross-implementation contract test.
//
// tests/fixtures/frames.json is generated from the Go codec (pkg/frame is the
// reference) and asserted here. Two implementations of one wire format is where a
// protocol forks quietly — both test suites pass and the two disagree in production —
// so the bytes themselves are the fixture, not a description of them.

import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { decode, decodeJSON, frameName } from "@oarlock/terminal/frame";

interface Vector {
  name: string;
  type: number;
  wire: string;
  json?: unknown;
  text?: string;
}

const fixture = JSON.parse(
  readFileSync(fileURLToPath(new URL("../fixtures/frames.json", import.meta.url)), "utf8"),
) as { vectors: Vector[] };

test("the fixture has vectors at all", () => {
  // A silently empty fixture would make every test below vacuously pass, which is the
  // failure mode of every data-driven suite.
  expect(fixture.vectors.length).toBeGreaterThan(10);
});

for (const v of fixture.vectors) {
  test(`Go's ${v.name} decodes here`, () => {
    const wire = Uint8Array.from(atob(v.wire), (c) => c.charCodeAt(0));
    const f = decode(wire);
    expect(f.type, `${v.name} is ${frameName(f.type)}`).toBe(v.type);

    if (v.text !== undefined) {
      expect(new TextDecoder().decode(f.payload)).toBe(v.text);
    }
    if (v.json !== undefined) {
      // Field names as well as values: `session_id` arriving as `sessionId` would
      // leave `recording` undefined, which the disclosure policy reads as unrecorded —
      // safe, but silently wrong.
      expect(decodeJSON(f)).toEqual(v.json);
    }
  });
}

test("the three READY shapes the disclosure switches on all parse", () => {
  const byName = new Map(fixture.vectors.map((v) => [v.name, v]));
  for (const [name, recording, mode] of [
    ["ready-recorded", true, "gateway"],
    ["ready-unrecorded", false, "gateway"],
    ["ready-passthrough", false, "passthrough"],
  ] as const) {
    const v = byName.get(name);
    expect(v, `${name} is missing from the fixture`).toBeDefined();
    const f = decode(Uint8Array.from(atob(v!.wire), (c) => c.charCodeAt(0)));
    const ready = decodeJSON<{ recording: boolean; mode: string }>(f);
    expect(ready.recording, name).toBe(recording);
    expect(ready.mode, name).toBe(mode);
  }
});

test("the observer fields survive the crossing", () => {
  const byName = new Map(fixture.vectors.map((v) => [v.name, v]));
  const parse = (name: string) => {
    const v = byName.get(name);
    expect(v, `${name} is missing from the fixture`).toBeDefined();
    return decodeJSON<Record<string, unknown>>(
      decode(Uint8Array.from(atob(v!.wire), (c) => c.charCodeAt(0))),
    );
  };

  const watcher = parse("ready-watcher") as { read_only: boolean; watching: string };
  expect(watcher.read_only).toBe(true);
  expect(watcher.watching).toBe("admin@mail.com");

  const watched = parse("ready-watched") as { observers: { principal: string }[] };
  expect(watched.observers[0]!.principal).toBe("sam@example.com");

  const one = parse("observers-one") as { observers: { principal: string; since: string }[] };
  expect(one.observers).toHaveLength(1);
  expect(one.observers[0]!.since).toBe("2026-08-21T10:14:02Z");

  // The empty list has to arrive as an empty array rather than as null or an absent
  // field: it is how the operator's indicator is told to go away, and a client reading
  // `undefined` there would leave it up forever.
  const none = parse("observers-none") as { observers: unknown };
  expect(Array.isArray(none.observers)).toBe(true);
  expect(none.observers).toHaveLength(0);
});
