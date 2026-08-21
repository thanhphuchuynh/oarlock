// The disclosure policy is the component's security-relevant logic, so it is tested
// where it is cheapest to test exhaustively: as a pure function, in Node.
//
// R-001 in test-design-epic-3.md: an integrator composes the disclosure away and ships
// a terminal that never says the session is unrecorded.

import { test, expect } from "@playwright/test";
// The policy is imported from the DOM-free subpath, which is what lets it be tested
// in Node at all — the package root pulls in xterm.js.
import { concernsOf, decide, facts } from "@oarlock/terminal/disclosure";

test.describe("concerns", () => {
  test("a recorded gateway session has nothing to disclose", () => {
    expect(concernsOf({ recording: true, mode: "gateway" })).toEqual([]);
  });

  test("an unrecorded session is a concern", () => {
    expect(concernsOf({ recording: false, mode: "gateway" })).toEqual(["unrecorded"]);
  });

  test("passthrough is a concern of its own, and implies unrecorded", () => {
    expect(concernsOf({ recording: false, mode: "passthrough" })).toEqual([
      "unrecorded",
      "passthrough",
    ]);
  });

  // The pessimistic default is the whole point: a gateway that predates the field, a
  // dropped key, a mock that forgets it, all have to fail towards saying too much.
  // Falling the other way would make a missing byte indistinguishable from a promise.
  test("a session we know nothing about counts as unrecorded", () => {
    expect(concernsOf(undefined)).toEqual(["unrecorded"]);
    expect(concernsOf({})).toEqual(["unrecorded"]);
    expect(concernsOf({ mode: "gateway" })).toEqual(["unrecorded"]);
  });

  // recording: "true" is not recording: true. A JSON field that arrives as a string
  // must not be read as a promise that the session is recorded.
  test("only a real boolean true counts as recorded", () => {
    expect(concernsOf({ recording: "true" as unknown as boolean })).toEqual(["unrecorded"]);
    expect(concernsOf({ recording: 1 as unknown as boolean })).toEqual(["unrecorded"]);
  });
});

test.describe("the gate", () => {
  test("a recorded session goes straight through", () => {
    const v = decide({ session: { recording: true, mode: "gateway" } });
    expect(v.terminal).toBe(true);
    expect(v.gate).toBe(false);
    expect(v.copy).toBeNull();
  });

  test("an unrecorded session gets no terminal until it is acknowledged", () => {
    const v = decide({ session: { recording: false, mode: "gateway" } });
    expect(v.terminal).toBe(false);
    expect(v.gate).toBe(true);
    expect(v.copy?.headline).toContain("not being recorded");
    // The button states the consequence, not the question.
    expect(v.copy?.acknowledge).toBe("Continue without a recording");
  });

  test("acknowledging clears it", () => {
    const v = decide({ session: { recording: false }, acknowledged: true });
    expect(v.terminal).toBe(true);
    expect(v.gate).toBe(false);
  });

  test("the named opt-out clears it, and is the only other way", () => {
    const v = decide({
      session: { recording: false },
      acknowledgeUnrecordedWithoutPrompt: true,
    });
    expect(v.terminal).toBe(true);
    expect(v.gate).toBe(false);
  });

  test("passthrough gets its own copy, not the unrecorded copy", () => {
    const both = decide({ session: { recording: false, mode: "passthrough" } });
    expect(both.copy?.headline).toContain("not recorded and cannot be");

    const readable = decide({ session: { recording: true, mode: "passthrough" } });
    expect(readable.gate).toBe(true);
    expect(readable.copy?.headline).toContain("cannot read this session");
  });

  // The failure this exists to prevent: a plausible-looking prop that turns the gate
  // off without saying what it costs. Nothing but the two documented keys does.
  test("no other input clears the gate", () => {
    for (const stray of [
      { skipGate: true },
      { acknowledge: true },
      { showPreflight: false },
      { recording: true },
      { acknowledgeUnrecorded: true },
    ]) {
      const v = decide({ session: { recording: false }, ...(stray as object) });
      expect(v.gate, `${JSON.stringify(stray)} must not clear the gate`).toBe(true);
      expect(v.terminal).toBe(false);
    }
  });
});

test.describe("the four facts", () => {
  test("state carries a word, not only a colour", () => {
    expect(facts({
      device: "treadmill-4821",
      principal: "phuc@example.com",
      session: { recording: true, mode: "gateway" },
      state: "attached",
    }).recording.label).toBe("RECORDED");

    expect(facts({
      device: "d", principal: "p",
      session: { recording: false, mode: "gateway" },
      state: "attached",
    }).recording.label).toBe("NOT RECORDED");

    // Passthrough says passthrough. "NOT RECORDED" would be true but would hide the
    // more important fact: nobody *can* record it.
    expect(facts({
      device: "d", principal: "p",
      session: { recording: false, mode: "passthrough" },
      state: "attached",
    }).recording.label).toBe("PASSTHROUGH");
  });

  test("observers are listed only while there are any", () => {
    const none = facts({ device: "d", principal: "p", session: {}, state: "attached" });
    expect(none.observers).toEqual([]);
    const watched = facts({
      device: "d", principal: "p", session: {}, state: "attached",
      observers: ["auditor@example.com"],
    });
    expect(watched.observers).toEqual(["auditor@example.com"]);
  });

  test("connection states each have a word", () => {
    const label = (state: "connecting" | "attached" | "reconnecting" | "closed") =>
      facts({ device: "d", principal: "p", session: {}, state }).connection.label;
    expect(label("connecting")).toBe("Connecting");
    expect(label("attached")).toBe("Live");
    expect(label("reconnecting")).toBe("Reconnecting");
    expect(label("closed")).toBe("Ended");
  });
});
