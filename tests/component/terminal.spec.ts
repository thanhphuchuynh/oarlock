// The terminal itself: keystrokes out, output in, resize, and the failure vocabulary a
// host switches on.

import { test, expect, type Page } from "@playwright/test";

const live = async (page: Page, opts: Record<string, unknown> = {}) => {
  await page.evaluate(
    (o) =>
      window.harness.mount({ ready: { recording: true, mode: "gateway" }, ...(o as object) } as never),
    opts,
  );
  await expect(page.locator(".oarlock-term .xterm")).toBeVisible();
};

const dataOut = async (page: Page) => {
  const sent = await page.evaluate(() => window.harness.sent());
  return sent.filter((f) => f.type === 0x01).map((f) => f.text).join("");
};

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await page.waitForFunction(() => !!window.harness);
});

test("device output is rendered", async ({ page }) => {
  await live(page);
  await page.evaluate(() => window.harness.write("phuc@treadmill-4821:~$ uptime\r\n"));
  await expect(page.locator(".xterm-rows")).toContainText("phuc@treadmill-4821");
});

test("keystrokes reach the gateway as DATA", async ({ page }) => {
  await live(page);
  await page.locator(".xterm-helper-textarea").focus();
  await page.keyboard.type("whoami");
  await page.keyboard.press("Enter");

  const out = await dataOut(page);
  expect(out).toContain("whoami");
  // Enter is carriage return on the wire, not a newline: the device's line discipline
  // is what turns it into one.
  expect(out).toContain("\r");
});

test("Ctrl-C goes as a byte inside DATA, not as a SIGNAL frame", async ({ page }) => {
  await live(page);
  await page.locator(".xterm-helper-textarea").focus();
  await page.keyboard.press("Control+c");

  const sent = await page.evaluate(() => window.harness.sent());
  expect(await dataOut(page)).toContain("\x03");
  // Interactive Ctrl-C is 0x03 interpreted by the far end's line discipline. A SIGNAL
  // frame is the browser's *stop button*, which is a different intent.
  expect(sent.some((f) => f.type === 0x06)).toBe(false);
});

test("the initial size is reported once the terminal exists", async ({ page }) => {
  await live(page);
  const sent = await page.evaluate(() => window.harness.sent());
  const resizes = sent.filter((f) => f.type === 0x05).map((f) => JSON.parse(f.text));
  expect(resizes.length).toBeGreaterThan(0);
  expect(resizes[0].cols).toBeGreaterThan(20);
  expect(resizes[0].rows).toBeGreaterThan(5);
});

test("dragging a window does not flood the gateway with RESIZE", async ({ page }) => {
  await live(page);
  const before = (await page.evaluate(() => window.harness.sent())).filter((f) => f.type === 0x05)
    .length;

  // Fifty sizes in a tight loop, as a drag produces.
  await page.evaluate(async () => {
    const host = document.getElementById("host")!;
    for (let i = 0; i < 50; i++) {
      host.style.width = `${600 + i * 4}px`;
      await new Promise((r) => requestAnimationFrame(r));
    }
  });
  await page.waitForTimeout(400);

  const resizes = (await page.evaluate(() => window.harness.sent())).filter((f) => f.type === 0x05);
  const during = resizes.length - before;
  // Coalesced to at most one per 100 ms. The exact count depends on how long the drag
  // took, so the assertion is that it is nothing like fifty.
  expect(during, `${during} RESIZE frames for 50 size changes`).toBeLessThan(15);

  // And the *last* size is the one the device ends up with — without a trailing send
  // the terminal is permanently one drag out of date, which looks exactly like a
  // resize that did not work.
  const last = JSON.parse(resizes[resizes.length - 1]!.text) as { cols: number; rows: number };
  const actual = await page.evaluate(() => {
    const el = document.querySelector(".xterm-rows");
    return { rows: el?.children.length ?? 0 };
  });
  expect(last.cols).toBeGreaterThan(0);
  expect(last.rows).toBe(actual.rows);
});

test("an ERROR frame surfaces as a code the host can switch on", async ({ page }) => {
  await live(page);
  await page.evaluate(() =>
    window.harness.error({ code: "revoked", message: "Your access was removed." }),
  );
  const errors = await page.evaluate(() => window.harness.errors);
  // `code` is what a UI switches on; `message` is prose and is never parsed.
  expect(errors.at(-1)).toEqual({ code: "revoked", message: "Your access was removed." });
});

test("revoked and authz_unavailable stay distinguishable", async ({ page }) => {
  await live(page);
  await page.evaluate(() => window.harness.error({ code: "revoked", message: "Your access was removed." }));
  await page.evaluate(() =>
    window.harness.error({ code: "authz_unavailable", message: "We could not check your access.", retryable: true }),
  );
  const errors = await page.evaluate(() => window.harness.errors);
  // The pair the epic keeps calling out: "your access was removed" and "we could not
  // check your access" send someone to different places, so they must never collapse
  // into one screen.
  expect(errors.map((e) => e.code)).toEqual(["revoked", "authz_unavailable"]);
});

test("a CLOSE ends the session and the bar says so", async ({ page }) => {
  await live(page);
  await page.evaluate(() => window.harness.closeFromGateway("idle_timeout"));
  await expect(page.locator(".oarlock-bar__conn")).toHaveText("Ended");
  const states = await page.evaluate(() => window.harness.states);
  expect(states.at(-1)).toBe("closed");
});

test("a THROTTLE is reported rather than silently dropped", async ({ page }) => {
  await live(page);
  await page.evaluate(() => window.harness.throttle(8192, "logs"));
  const t = await page.evaluate(() => window.harness.throttles);
  expect(t).toEqual([{ dropped_bytes: 8192, profile: "logs" }]);
});

test("the reconnecting treatment is dimmed, not hidden", async ({ page }) => {
  await live(page);
  // Setting the attribute directly rather than dropping the socket: the reconnect
  // *mechanism* — a fresh ticket, reattach, scrollback replay — is E3.S3. What exists
  // now is the treatment, and it is worth pinning while it is cheap to pin.
  await page.evaluate(() => {
    document.querySelector(".oarlock-term")!.setAttribute("data-oarlock-state", "reconnecting");
  });
  // Polled, not read in the same tick: the value is mid-transition for a frame or two,
  // and reading it immediately measures the animation's start rather than its target.
  // A dropped connection is the normal case, not an error, so the operator can still
  // see the screen they are about to get back — dimmed, never hidden.
  await expect
    .poll(async () =>
      Number(
        await page.locator(".oarlock-screen").evaluate((el) => getComputedStyle(el).opacity),
      ),
    )
    .toBeLessThan(1);
  const settled = Number(
    await page.locator(".oarlock-screen").evaluate((el) => getComputedStyle(el).opacity),
  );
  expect(settled).toBeGreaterThan(0.3);
});

test("an EXIT frame reaches the host, which is what the exec profile needs", async ({ page }) => {
  await live(page);
  await page.evaluate(() => window.harness.exit(130));
  expect(await page.evaluate(() => window.harness.exits)).toEqual([{ code: 130, signal: null }]);
});
