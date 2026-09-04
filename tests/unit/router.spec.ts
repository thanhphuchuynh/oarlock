// The router's parsing half is DOM-free on purpose, so it is tested in Node rather
// than in a browser — the same reason @oarlock/terminal/disclosure has its own subpath.

import { test, expect } from "@playwright/test";
import { parsePath, formatPath } from "../../web/src/router/routes";

test.describe("parsePath", () => {
  test("the root is search", () => {
    expect(parsePath("/")).toEqual({ kind: "search" });
  });

  test("a person route decodes its principal", () => {
    expect(parsePath("/p/admin%40mail.com")).toEqual({
      kind: "person", principal: "admin@mail.com", facets: {},
    });
  });

  test("a device route", () => {
    expect(parsePath("/d/treadmill-4821")).toEqual({
      kind: "device", device: "treadmill-4821", facets: {},
    });
  });

  test("a session route", () => {
    expect(parsePath("/s/sess_iw31he82d8gg")).toEqual({
      kind: "session", session: "sess_iw31he82d8gg",
    });
  });

  test("the static routes", () => {
    expect(parsePath("/permissions")).toEqual({ kind: "permissions" });
    expect(parsePath("/sql")).toEqual({ kind: "sql" });
  });

  test("facets come off the query string", () => {
    expect(parsePath("/p/admin%40mail.com", "?since=2026-06-01&device=treadmill-4821"))
      .toEqual({
        kind: "person", principal: "admin@mail.com",
        facets: { since: "2026-06-01", device: "treadmill-4821" },
      });
  });

  test("an unknown facet is dropped rather than carried", () => {
    // Narrow before reading a variant-specific field. The alternative — widening every
    // Route variant with `facets?: undefined` so the union is uniform — bends a
    // production type to make a test compile.
    const route = parsePath("/d/rower-9001", "?nonsense=1&since=2026-01-01");
    if (route.kind !== "device") throw new Error(`expected a device route, got ${route.kind}`);
    expect(route.facets).toEqual({ since: "2026-01-01" });
  });

  // An unknown path must not throw inside the SPA. The gateway serves index.html for
  // everything, so a typo in a pasted link arrives here, not as a 404.
  test("an unknown path falls back to search", () => {
    expect(parsePath("/nope/whatever")).toEqual({ kind: "search" });
    expect(parsePath("")).toEqual({ kind: "search" });
  });
});

test.describe("formatPath", () => {
  test("a principal is encoded so @ and . survive", () => {
    expect(formatPath({ kind: "person", principal: "admin@mail.com", facets: {} }))
      .toBe("/p/admin%40mail.com");
  });

  test("facets are appended in a stable order", () => {
    expect(formatPath({
      kind: "person", principal: "a@b.com",
      facets: { until: "2026-09-01", since: "2026-06-01" },
    })).toBe("/p/a%40b.com?since=2026-06-01&until=2026-09-01");
  });

  test("round-trips a principal with characters that need encoding", () => {
    const route = { kind: "person" as const, principal: "o'brien+test@corp.example", facets: {} };
    expect(parsePath(formatPath(route))).toEqual(route);
  });
});
