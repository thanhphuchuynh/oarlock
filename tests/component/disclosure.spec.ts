// R-001, in a real browser: an integrator composes the disclosure away and ships a
// terminal that never says the session is unrecorded.
//
// The unit tests cover the policy. These cover the thing the policy exists for — that
// the component *actually will not render a terminal* — because the failure mode is
// visual: a terminal that looks exactly like a normal terminal for a session nobody is
// recording.

import { test, expect, type Page } from "@playwright/test";

const mount = (page: Page, opts: Record<string, unknown> = {}) =>
  page.evaluate((o) => window.harness.mount(o as never), opts);

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await page.waitForFunction(() => !!window.harness);
});

test("a recorded session gets a terminal and says so", async ({ page }) => {
  await mount(page, { ready: { recording: true, mode: "gateway" } });

  await expect(page.locator(".oarlock-term .xterm")).toBeVisible();
  await expect(page.locator(".oarlock-gate")).toHaveCount(0);
  await expect(page.locator(".oarlock-bar__badge--recording")).toHaveText("RECORDED");
  await expect(page.locator(".oarlock-bar__device")).toHaveText("treadmill-4821");
});

test("an unrecorded session gets no terminal until it is acknowledged", async ({ page }) => {
  await mount(page, { ready: { recording: false, mode: "gateway" } });

  // The gate is up and — the part that matters — there is no terminal behind it. A
  // gate over a live terminal is decoration: the operator can read the screen through
  // it, and a stray keystroke reaches the shell.
  await expect(page.locator(".oarlock-gate")).toBeVisible();
  await expect(page.locator(".xterm")).toHaveCount(0);
  await expect(page.locator(".oarlock-gate__headline")).toHaveText(
    "This session is not being recorded",
  );
  await expect(page.locator(".oarlock-bar__badge--recording")).toHaveText("NOT RECORDED");

  // Focus is on Cancel, not on the way through: a gate whose affirmative button is
  // focused is one that a stray Enter walks straight past.
  await expect(page.locator(".oarlock-gate__cancel")).toBeFocused();

  await page.locator(".oarlock-gate__go").click();
  await expect(page.locator(".oarlock-term .xterm")).toBeVisible();
  await expect(page.locator(".oarlock-gate")).toHaveCount(0);
  // And the bar still says it, after the gate is gone. The gate is the moment; the bar
  // is the whole session.
  await expect(page.locator(".oarlock-bar__badge--recording")).toHaveText("NOT RECORDED");
});

test("passthrough says the gateway cannot read the session, not merely that it is unrecorded", async ({
  page,
}) => {
  await mount(page, { ready: { recording: false, mode: "passthrough" } });
  await expect(page.locator(".oarlock-gate__headline")).toHaveText(
    "This session is not recorded and cannot be",
  );
  await expect(page.locator(".oarlock-bar__badge--recording")).toHaveText("PASSTHROUGH");
});

test("the named opt-out is the only way to skip the gate", async ({ page }) => {
  await mount(page, {
    ready: { recording: false, mode: "gateway" },
    acknowledgeUnrecordedWithoutPrompt: true,
  });
  await expect(page.locator(".oarlock-term .xterm")).toBeVisible();
  await expect(page.locator(".oarlock-gate")).toHaveCount(0);
  // The status bar is not optional even then — there is no prop that removes it.
  await expect(page.locator(".oarlock-bar__badge--recording")).toHaveText("NOT RECORDED");
});

test("a plausible-looking prop does not skip the gate", async ({ page }) => {
  for (const stray of [{ skipGate: true }, { showPreflight: false }, { acknowledged: true }]) {
    await mount(page, { ready: { recording: false, mode: "gateway" }, ...stray });
    await expect(
      page.locator(".oarlock-gate"),
      `${JSON.stringify(stray)} must not clear the gate`,
    ).toBeVisible();
    await expect(page.locator(".xterm")).toHaveCount(0);
  }
});

test("a READY with no recording field is treated as unrecorded", async ({ page }) => {
  // A gateway that predates the field, a proxy that drops it, a mock that forgets it.
  // Falling the other way would make a missing byte indistinguishable from a promise.
  await mount(page, { ready: { session_id: "sess_x", mode: "gateway", recording: undefined } });
  await expect(page.locator(".oarlock-gate")).toBeVisible();
});

test("declining ends the session instead of showing a terminal", async ({ page }) => {
  await mount(page, { ready: { recording: false, mode: "gateway" } });
  await page.locator(".oarlock-gate__cancel").click();

  await expect(page.locator(".xterm")).toHaveCount(0);
  const cancelled = await page.evaluate(() => window.harness.cancelled);
  expect(cancelled).toBe(1);
  // The gateway is told why, so the ledger records a declined session rather than a
  // mysterious disconnect.
  const sent = await page.evaluate(() => window.harness.sent());
  expect(sent.some((f) => f.type === 0x08 && f.text.includes("operator_declined"))).toBe(true);
});

test("device output arriving during the gate is held, not shown", async ({ page }) => {
  await mount(page, { ready: { recording: false, mode: "gateway" } });
  await page.evaluate(() => window.harness.write("SECRET-BEFORE-ACK\r\n"));

  // Nothing rendered, because there is nothing to render into.
  await expect(page.locator(".xterm")).toHaveCount(0);
  expect(await page.locator(".oarlock-term").innerText()).not.toContain("SECRET-BEFORE-ACK");

  // And once acknowledged it is not lost either — the operator sees what the device
  // said while they were reading the gate.
  await page.locator(".oarlock-gate__go").click();
  await expect(page.locator(".oarlock-term .xterm")).toBeVisible();
  await expect(page.locator(".xterm-rows")).toContainText("SECRET-BEFORE-ACK");
});

test("the ticket travels in the OPEN frame, never in the URL", async ({ page }) => {
  await mount(page, { ready: { recording: true, mode: "gateway" } });
  const opened = await page.evaluate(() => window.harness.opened());
  expect(opened?.ticket).toBe("stub-ticket-abcdef");
  // A URL reaches proxy logs, browser history and Referer headers, and a single-use
  // secret in a log is a multi-use secret.
  expect(page.url()).not.toContain("stub-ticket");
});
