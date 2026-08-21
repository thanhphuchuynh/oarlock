// R-012: the device at the far end is the untrusted party, and two of xterm's optional
// behaviours hand it something it should not have.
//
//   - OSC 52 lets it write to the operator's clipboard — replacing whatever they were
//     about to paste, into a shell, on another machine.
//   - Title reporting lets it read back the window title, which in a host application
//     is often the customer, the ticket, or the operator's own name.
//
// Both are off in the versions we build against, which is precisely why these tests
// exist: the risk is a *default changing* under a dependency bump, and a test is the
// only thing that notices that.

import { test, expect, type Page } from "@playwright/test";

const OSC = "\x1b]";
const BEL = "\x07";

const mountLive = async (page: Page, opts: Record<string, unknown> = {}) => {
  await page.evaluate(
    (o) => window.harness.mount({ ready: { recording: true, mode: "gateway" }, ...(o as object) } as never),
    opts,
  );
  await expect(page.locator(".oarlock-term .xterm")).toBeVisible();
};

test.beforeEach(async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.goto("/");
  await page.waitForFunction(() => !!window.harness);
});

test("a device writing OSC 52 does not touch the operator's clipboard", async ({ page }) => {
  // Something the operator was about to paste. On another machine, into a shell.
  await page.evaluate(() => navigator.clipboard.writeText("operator's own clipboard"));
  await mountLive(page);

  // base64("pwned") — the sequence a compromised device would send.
  await page.evaluate(
    ([osc, bel]) => window.harness.write(`${osc}52;c;cHduZWQ=${bel}`),
    [OSC, BEL],
  );
  await page.waitForTimeout(150);

  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(
    "operator's own clipboard",
  );
  // And the host is told, so it can surface a refusal if it wants to.
  expect(await page.evaluate(() => window.harness.clipboardRefusals)).toBeGreaterThan(0);
});

test("the refusal holds for the query form too", async ({ page }) => {
  // OSC 52 with `?` asks the terminal to *send the clipboard back to the device*, which
  // is the read half of the same problem.
  await page.evaluate(() => navigator.clipboard.writeText("secret-in-clipboard"));
  await mountLive(page);
  await page.evaluate(([osc, bel]) => window.harness.write(`${osc}52;c;?${bel}`), [OSC, BEL]);
  await page.waitForTimeout(150);

  const sent = await page.evaluate(() => window.harness.sent());
  const dataOut = sent.filter((f) => f.type === 0x01).map((f) => f.text).join("");
  expect(dataOut).not.toContain("secret-in-clipboard");
  // Not even base64-encoded.
  expect(dataOut).not.toContain(Buffer.from("secret-in-clipboard").toString("base64"));
});

test("the sequence is swallowed rather than printed", async ({ page }) => {
  await mountLive(page);
  await page.evaluate(([osc, bel]) => window.harness.write(`${osc}52;c;cHduZWQ=${bel}ok`), [OSC, BEL]);
  await expect(page.locator(".xterm-rows")).toContainText("ok");
  // A handler that returned false would leave the payload on screen as text, which is
  // harmless but tells the operator the terminal did not understand its own protocol.
  await expect(page.locator(".xterm-rows")).not.toContainText("cHduZWQ");
});

test("clipboard writes can be opted into, per instance", async ({ page }) => {
  await page.evaluate(() => navigator.clipboard.writeText("before"));
  await mountLive(page, { allowDeviceClipboardWrites: true });
  await page.evaluate(([osc, bel]) => window.harness.write(`${osc}52;c;cHduZWQ=${bel}`), [OSC, BEL]);
  await page.waitForTimeout(150);

  // The opt-in exists for a fleet an integrator trusts. What it must not do is hide
  // that it was used: our refusal hook stops firing.
  expect(await page.evaluate(() => window.harness.clipboardRefusals)).toBe(0);
});

test("a device cannot set the host page's title", async ({ page }) => {
  const before = await page.title();
  await mountLive(page);
  await page.evaluate(([osc, bel]) => window.harness.write(`${osc}0;Pwned Title${bel}`), [OSC, BEL]);
  await page.waitForTimeout(150);

  expect(await page.title()).toBe(before);
  // The host is still told the device asked, and that it was not applied — an
  // integrator who wants the title can render it in their own chrome.
  const asks = await page.evaluate(() => window.harness.titleAsks);
  expect(asks).toEqual([{ title: "Pwned Title", applied: false }]);
});

test("a device cannot read the window title back", async ({ page }) => {
  await mountLive(page);
  // CSI 21 t — "report the window title". The answer is no answer.
  await page.evaluate(() => window.harness.write("\x1b[21t"));
  await page.waitForTimeout(150);

  const sent = await page.evaluate(() => window.harness.sent());
  const dataOut = sent.filter((f) => f.type === 0x01).map((f) => f.text).join("");
  expect(dataOut).toBe("");
});

test("a device cannot ask for the window's size or position either", async ({ page }) => {
  await mountLive(page);
  for (const seq of ["\x1b[11t", "\x1b[13t", "\x1b[14t", "\x1b[18t", "\x1b[19t"]) {
    await page.evaluate((s) => window.harness.write(s), seq);
  }
  await page.waitForTimeout(200);

  const sent = await page.evaluate(() => window.harness.sent());
  const dataOut = sent.filter((f) => f.type === 0x01).map((f) => f.text).join("");
  expect(dataOut, "the terminal answered a window query").toBe("");
});
