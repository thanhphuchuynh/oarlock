import { defineConfig, devices } from "@playwright/test";

// One runner, two tiers.
//
// `unit` is pure logic in Node — the codec, the disclosure policy — and needs no
// browser. `component` mounts the real component in real Chromium, because xterm.js
// draws to a canvas and measures a DOM: jsdom cannot tell you whether a terminal
// rendered, and a test that cannot tell is worse than no test.
export default defineConfig({
  testDir: "tests",
  fullyParallel: true,
  forbidOnly: !!process.env["CI"],
  retries: 0,
  reporter: process.env["CI"] ? "list" : [["list"]],
  expect: { timeout: 5_000 },
  projects: [
    {
      name: "unit",
      testDir: "tests/unit",
      use: {},
    },
    {
      // Ad-hoc, and deliberately not part of the suite: it drives whatever gateway is
      // already running on :8443, which is a machine's current state rather than a
      // fixture. Run it with `pnpm exec playwright test --project=live`.
      //
      // "Not part of the suite" was only ever a comment. `playwright test` with no filter
      // runs every project, so this one was in `pnpm test` all along, and the suite's
      // result depended on whether a demo gateway happened to be running and whether its
      // binary matched HEAD. It cost a false failure the day a task rewrote this file: the
      // gateway on :8443 had been built two commits earlier. `pnpm test` now names the
      // three projects it wants, so the comment and the behaviour finally agree.
      name: "live",
      testDir: "tests/live",
      use: { ...devices["Desktop Chrome"] },
      workers: 1,
      timeout: 120_000,
    },
    {
      // The console, against a real gateway process. Its own project because it starts
      // and stops processes, so it must not share workers with the component tests.
      name: "console",
      testDir: "tests/console",
      use: { ...devices["Desktop Chrome"] },
      fullyParallel: false,
      workers: 1,
      timeout: 120_000,
    },
    {
      name: "component",
      testDir: "tests/component",
      use: { ...devices["Desktop Chrome"], baseURL: "http://localhost:5178" },
    },
  ],
  webServer: {
    command: "pnpm exec vite dev --mode harness",
    url: "http://localhost:5178",
    reuseExistingServer: !process.env["CI"],
    timeout: 60_000,
  },
});
