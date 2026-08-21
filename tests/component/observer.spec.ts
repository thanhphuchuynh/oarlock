// FR13 — read-only attachment, from both sides of it.
//
// Two things have to be true at once and they are easy to build separately: the watcher's
// own terminal has to be visibly not theirs to type in, and the person being watched has
// to know who is watching. The second is the one that matters — you behave differently
// when observed, and you are entitled to know — and it is also the one that fails quietly,
// because nothing is broken when an indicator is missing.

import { test, expect, type Page } from "@playwright/test";

const mountLive = async (page: Page, ready: Record<string, unknown> = {}) => {
  await page.evaluate(
    (r) =>
      window.harness.mount({
        ready: { recording: true, mode: "gateway", ...(r as object) },
      } as never),
    ready,
  );
  await expect(page.locator(".oarlock-term .xterm")).toBeVisible();
};

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await page.waitForFunction(() => !!window.harness);
});

// ── the operator being watched ──────────────────────────────────────────────────

test("the operator is told who is watching, by name", async ({ page }) => {
  await mountLive(page);
  await expect(page.locator(".oarlock-bar__badge--observed")).toBeHidden();

  await page.evaluate(() =>
    window.harness.observers([{ principal: "sam@example.com", since: "2026-08-21T10:00:00Z" }]),
  );

  const badge = page.locator(".oarlock-bar__badge--observed");
  await expect(badge).toBeVisible();
  // Named, always. Anonymous observation is not offered at any level of the UI: a badge
  // that could only say "1 watcher" would be one that had thrown the answer away.
  await expect(badge).toHaveText("OBSERVED by sam@example.com");
});

test("the indicator persists for as long as it is true, and then goes", async ({ page }) => {
  await mountLive(page);
  await page.evaluate(() => window.harness.observers([{ principal: "sam@example.com" }]));
  await expect(page.locator(".oarlock-bar__badge--observed")).toBeVisible();

  // Output keeps flowing and the indicator stays. It is not a toast: an operator who
  // looked away for ten seconds must not have missed the only mention of it.
  await page.evaluate(() => window.harness.write("work continues\r\n"));
  await expect(page.locator(".xterm-rows")).toContainText("work continues");
  await expect(page.locator(".oarlock-bar__badge--observed")).toBeVisible();

  // And an explicitly empty list clears it, so the indicator can stop being true.
  await page.evaluate(() => window.harness.observers([]));
  await expect(page.locator(".oarlock-bar__badge--observed")).toBeHidden();
});

test("several watchers are counted, and named on hover", async ({ page }) => {
  await mountLive(page);
  await page.evaluate(() =>
    window.harness.observers([
      { principal: "sam@example.com" },
      { principal: "ana@example.com" },
    ]),
  );
  const badge = page.locator(".oarlock-bar__badge--observed");
  await expect(badge).toHaveText("OBSERVED by 2 people");
  // The names are still there for somebody who wants them — thrown away in the label,
  // not in the DOM.
  await expect(badge).toHaveAttribute("title", "sam@example.com, ana@example.com");
});

test("a watcher arriving is announced to assistive technology", async ({ page }) => {
  // R-014, the risk this design knowingly accepts: the indicator is honest but quiet, so
  // an operator can miss it. For somebody not looking at the screen at all it would
  // otherwise be invisible, which is not a trade-off — it is an omission.
  await mountLive(page);
  const bar = page.locator(".oarlock-bar");
  await expect(bar).toHaveAttribute("role", "status");
  await expect(bar).toHaveAttribute("aria-live", "polite");

  await page.evaluate(() => window.harness.observers([{ principal: "sam@example.com" }]));
  // The name is inside the live region, so the announcement says who.
  await expect(bar).toContainText("sam@example.com");
});

test("the operator's own terminal stays writable while watched", async ({ page }) => {
  await mountLive(page);
  await page.evaluate(() => window.harness.observers([{ principal: "sam@example.com" }]));

  await page.locator(".xterm-helper-textarea").focus();
  await page.keyboard.type("still mine");
  const sent = await page.evaluate(() => window.harness.sent());
  const data = sent.filter((f) => f.type === 0x01).map((f) => f.text).join("");
  // Being watched is not being demoted. Whether an operator may *refuse* observation is
  // a separate product question and deliberately not built; what must not happen is
  // their keyboard quietly changing behaviour because somebody joined.
  expect(data).toContain("still mine");
});

test("READY carries the watchers already present", async ({ page }) => {
  // An operator attaching to a session that is already being watched must not have to
  // wait for the list to change before being told.
  await mountLive(page, { observers: [{ principal: "sam@example.com" }] });
  await expect(page.locator(".oarlock-bar__badge--observed")).toHaveText(
    "OBSERVED by sam@example.com",
  );
});

// ── the watcher's own terminal ──────────────────────────────────────────────────

test("a watcher's terminal says READ-ONLY and names whose it is", async ({ page }) => {
  await mountLive(page, { read_only: true, watching: "phuc@example.com" });

  const badge = page.locator(".oarlock-bar__badge--readonly");
  await expect(badge).toBeVisible();
  await expect(badge).toHaveText("READ-ONLY · watching phuc@example.com");
  await expect(page.locator(".oarlock-term")).toHaveAttribute("data-oarlock-read-only", "true");
});

test("a watcher's input is disabled, not ignored", async ({ page }) => {
  await mountLive(page, { read_only: true, watching: "phuc@example.com" });
  await page.evaluate(() => window.harness.write("$ logcat -d\r\n"));
  await expect(page.locator(".xterm-rows")).toContainText("logcat");

  // A keystroke that silently does nothing is worse than one that cannot be typed: the
  // watcher has no way to tell whether it landed on somebody else's shell.
  //
  // `readOnly` rather than `disabled`, deliberately: `disabled` would take the terminal
  // out of the accessibility tree and the focus order, so somebody using a screen reader
  // could no longer read the session they came to watch.
  const input = await page.evaluate(() => {
    const el = document.querySelector<HTMLTextAreaElement>(".xterm-helper-textarea");
    return { readOnly: el?.readOnly, aria: el?.getAttribute("aria-readonly"), focusable: !el?.disabled };
  });
  expect(input.readOnly).toBe(true);
  expect(input.aria).toBe("true");
  expect(input.focusable, "a watcher must still be able to focus and read it").toBe(true);

  await page.locator(".xterm").click();
  await page.keyboard.type("rm -rf /");
  await page.waitForTimeout(150);
  const sent = await page.evaluate(() => window.harness.sent());
  expect(sent.filter((f) => f.type === 0x01)).toHaveLength(0);
});

test("read-only can only be added, never taken away", async ({ page }) => {
  // A host that forgot the prop still gets a read-only terminal, because READY said so.
  // The gateway is the authority on what a connection may do, and a component that let a
  // prop override that would let an integrator hand somebody a writable pane on a
  // connection the gateway will not accept writes from.
  await mountLive(page, { read_only: true });
  expect(
    await page.evaluate(
      () => document.querySelector<HTMLTextAreaElement>(".xterm-helper-textarea")?.readOnly,
    ),
  ).toBe(true);

  // The prop restricts and only restricts: a host may disable its own input voluntarily
  // — a preview pane, a dashboard — on a session the gateway would accept writes from.
  await page.evaluate(() => window.harness.dispose());
  await page.evaluate(() =>
    window.harness.mount({
      ready: { recording: true, mode: "gateway", read_only: false },
      readOnly: true,
    } as never),
  );
  await expect(page.locator(".oarlock-term .xterm")).toBeVisible();
  expect(
    await page.evaluate(
      () => document.querySelector<HTMLTextAreaElement>(".xterm-helper-textarea")?.readOnly,
    ),
  ).toBe(true);

  // And a plain writable session is plainly writable.
  await page.evaluate(() => window.harness.dispose());
  await mountLive(page);
  expect(
    await page.evaluate(
      () => document.querySelector<HTMLTextAreaElement>(".xterm-helper-textarea")?.readOnly,
    ),
  ).toBe(false);
});

test("a watcher sees the watcher list too, including themselves", async ({ page }) => {
  await mountLive(page, {
    read_only: true,
    watching: "phuc@example.com",
    observers: [{ principal: "sam@example.com" }],
  });
  await expect(page.locator(".oarlock-bar__badge--readonly")).toBeVisible();
  await expect(page.locator(".oarlock-bar__badge--observed")).toHaveText(
    "OBSERVED by sam@example.com",
  );
});
