// The failure vocabulary, checked against the gateway's own table.
//
// packages/terminal/src/conditions.ts is generated from pkg/condition, so these tests are
// not checking that somebody transcribed it correctly — CI checks that. They check the
// properties the *screens* depend on, which the generator cannot enforce: that no two
// conditions collapse into one screen, that the pair this epic is about stays apart, and
// that a retry is only ever offered where retrying could work.

import { test, expect } from "@playwright/test";
import {
  conditions,
  get,
  lookup,
  integratorHeadline,
} from "@oarlock/terminal/conditions";

test("the table is not empty and every row is well formed", () => {
  // A silently empty generated file would make every test below vacuously pass.
  expect(conditions.length).toBeGreaterThan(20);
  for (const c of conditions) {
    expect(c.id, JSON.stringify(c)).not.toBe("");
    expect(c.headline, `${c.id} has no headline`).not.toBe("");
    expect(["error", "close", "error|close"]).toContain(c.kind);
    expect(["operator", "integrator"]).toContain(c.audience);
    expect(["none", "device", "gateway", "principal", "client"]).toContain(c.fault);
  }
});

test("ids are unique", () => {
  const ids = conditions.map((c) => c.id);
  expect(new Set(ids).size).toBe(ids.length);
});

// The rule from the UX spec: a screen renders exactly one server condition. Two
// conditions with the same headline are one screen wearing two names, and the operator
// cannot tell which happened.
test("no two operator conditions render the same screen", () => {
  const seen = new Map<string, string>();
  for (const c of conditions.filter((x) => x.audience === "operator")) {
    const prev = seen.get(c.headline);
    expect(prev, `${prev} and ${c.id} share the headline "${c.headline}"`).toBeUndefined();
    seen.set(c.headline, c.id);
  }
});

test("revoked and authz_unavailable are different screens", () => {
  const revoked = lookup("revoked")!;
  const unavailable = lookup("authz_unavailable")!;
  expect(revoked).toBeDefined();
  expect(unavailable).toBeDefined();

  expect(unavailable.headline).not.toBe(revoked.headline);
  // "your access was removed" and "we could not check your access" send somebody to
  // entirely different places.
  const text = `${unavailable.headline} ${unavailable.nextAction}`.toLowerCase();
  for (const forbidden of ["revoked", "withdrawn", "removed", "no longer have"]) {
    expect(text, `authz_unavailable reads as a revocation: "${text}"`).not.toContain(forbidden);
  }
  expect(unavailable.retryable).toBe(true);
  expect(revoked.retryable).toBe(false);
});

test("a retry is offered only where retrying could work", () => {
  // A retry button on a withdrawn grant invites an operator to keep pressing it at a
  // decision that will not change.
  for (const id of ["revoked", "not_authorized", "policy_denied", "admin_kill"]) {
    expect(lookup(id)!.retryable, `${id} must not be retryable`).toBe(false);
  }
  for (const id of ["device_offline", "doorbell_failed", "authz_unavailable", "gateway_shutdown"]) {
    expect(lookup(id)!.retryable, `${id} should be retryable`).toBe(true);
  }
});

test("a broken doorbell is not reported as an offline device", () => {
  const doorbell = lookup("doorbell_failed")!;
  expect(doorbell.fault).toBe("gateway");
  expect(`${doorbell.headline} ${doorbell.nextAction}`.toLowerCase()).not.toContain("offline");
  expect(doorbell.headline).not.toBe(lookup("device_offline")!.headline);
});

test("integrator conditions share one screen and say so", () => {
  const integrator = conditions.filter((c) => c.audience === "integrator");
  expect(integrator.length).toBeGreaterThan(4);
  for (const c of integrator) {
    // Eight ways of saying "this is a bug in the application you are using" is eight
    // screens nobody reads.
    expect(c.headline, `${c.id}`).toBe(integratorHeadline);
  }
});

test("an unknown code renders as unknown, not as the first row of the table", () => {
  const c = get("invented_next_year");
  expect(c.id).toBe("invented_next_year");
  expect(c.audience).toBe("integrator");
  expect(c.headline).toBe(integratorHeadline);
  expect(lookup("invented_next_year")).toBeUndefined();
  // The specific failure this guards: falling back to conditions[0].
  expect(c.headline).not.toBe(conditions[0]!.headline);
});

test("no headline is a code, and none of them apologise", () => {
  for (const c of conditions) {
    expect(c.headline, c.id).not.toContain("_");
    const text = `${c.headline} ${c.nextAction}`.toLowerCase();
    for (const word of ["sorry", "oops", "unfortunately", "whoops"]) {
      expect(text, `${c.id} apologises`).not.toContain(word);
    }
    expect(c.headline.toLowerCase(), `${c.id} says "error"`).not.toContain("error");
  }
});
