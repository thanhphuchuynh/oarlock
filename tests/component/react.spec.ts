// The React surface. Thin by design, which is a claim worth testing.

import { test, expect } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await page.waitForFunction(() => !!window.react);
});

/**
 * mountReact waits for the component to have actually dialled before returning.
 *
 * React runs effects after paint, so page.evaluate returns before <Terminal> has opened
 * its socket — delivering READY straight afterwards races the mount and lands nowhere.
 */
async function mountReact(page: import("@playwright/test").Page, opts: object = {}) {
  await page.evaluate((o) => window.react.mountTerminal(o as never), opts);
  await page.waitForFunction(() => window.harness.tickets().length > 0);
}

test("<Terminal> renders a recorded session", async ({ page }) => {
  await mountReact(page);
  await page.evaluate(() => window.harness.ready({ recording: true, mode: "gateway" }));
  await expect(page.locator("#react-host .oarlock-term .xterm")).toBeVisible();
  await expect(page.locator("#react-host .oarlock-bar__badge--recording")).toHaveText("RECORDED");
});

test("<Terminal> refuses an unrecorded session, exactly as the core does", async ({ page }) => {
  await mountReact(page);
  await page.evaluate(() => window.harness.ready({ recording: false, mode: "gateway" }));

  await expect(page.locator("#react-host .oarlock-gate")).toBeVisible();
  await expect(page.locator("#react-host .xterm")).toHaveCount(0);

  await page.locator("#react-host .oarlock-gate__go").click();
  await expect(page.locator("#react-host .oarlock-term .xterm")).toBeVisible();
});

test("the named opt-out works through the wrapper too", async ({ page }) => {
  await mountReact(page, { acknowledgeUnrecordedWithoutPrompt: true });
  await page.evaluate(() => window.harness.ready({ recording: false, mode: "gateway" }));
  await expect(page.locator("#react-host .oarlock-term .xterm")).toBeVisible();
  await expect(page.locator("#react-host .oarlock-gate")).toHaveCount(0);
  await expect(page.locator("#react-host .oarlock-bar__badge--recording")).toHaveText("NOT RECORDED");
});

// This is R-001's actual scenario: an integrator who wants their own chrome, using the
// separately-exported pieces. The pieces have to be correct on their own.
//
// It is also the test that pins a CSS trap worth naming: with `overflow: hidden` on the
// component root, this composition — a bar and a gate, no terminal, in a container the
// host has not given a height — renders a gate that reports itself visible and cannot be
// clicked, because the panel is clipped out of the box. Clipping belongs on the terminal
// surface. The `click()` below is what catches it; a dispatched event would not.
test("<StatusBar> and <PreflightGate> are correct when composed by hand", async ({ page }) => {
  await page.evaluate(() =>
    window.react.mountChrome({ session: { recording: false, mode: "passthrough" } }),
  );
  await expect(page.locator("#react-host .oarlock-bar__badge--recording")).toHaveText("PASSTHROUGH");
  await expect(page.locator("#react-host .oarlock-gate__headline")).toHaveText(
    "This session is not recorded and cannot be",
  );

  await page.locator("#react-host .oarlock-gate__go").click();
  expect(await page.evaluate(() => (window as never as { chromeAcknowledged: number }).chromeAcknowledged)).toBe(1);
});

test("<PreflightGate> renders nothing when there is nothing to disclose", async ({ page }) => {
  // So it is safe to leave in a tree unconditionally, which is what stops an integrator
  // from writing their own condition and getting it wrong.
  await page.evaluate(() =>
    window.react.mountChrome({ session: { recording: true, mode: "gateway" } }),
  );
  await expect(page.locator("#react-host .oarlock-bar__badge--recording")).toHaveText("RECORDED");
  await expect(page.locator("#react-host .oarlock-gate")).toHaveCount(0);
});
