// Replay, in a browser, against recordings the gateway really produced and really
// damaged.
//
// The one property this file exists to defend: a tampered recording must not look like an
// intact one. Everything else here is in service of that — the verdict cannot be omitted,
// cannot be scrolled past, and cannot be talked into a green banner by a missing field.

import { test, expect } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await page.waitForFunction(() => !!window.harness);
});

test("an intact recording plays, and says it is intact", async ({ page }) => {
  await page.evaluate(() => window.harness.play("valid"));

  const v = await page.evaluate(() => window.harness.verdict());
  expect(v?.tone).toBe("trusted");
  expect(v?.status).toBe("valid");
  expect(v?.headline).toBe("This recording is intact.");

  // A real player, with the recording in it.
  await expect(page.locator(".oarlock-replay .ap-player")).toBeVisible();
  await expect(page.locator(".oarlock-replay__failed")).toHaveCount(0);
});

test("an altered recording is not shown like an intact one", async ({ page }) => {
  await page.evaluate(() => window.harness.play("altered"));

  const v = await page.evaluate(() => window.harness.verdict());
  expect(v?.tone).toBe("broken");
  expect(v?.status).toBe("altered");
  expect(v?.headline).toContain("does not match what was signed");
  expect(v?.body.toLowerCase()).toContain("tampering");

  // It still plays. Withholding the content would be the wrong remedy: an auditor
  // needs to see what the file claims *and* be told it cannot be trusted.
  await expect(page.locator(".oarlock-replay .ap-player")).toBeVisible();
});

test("the verdict is above the player in the document, not merely on top of it", async ({
  page,
}) => {
  await page.evaluate(() => window.harness.play("altered"));

  const order = await page.evaluate(() => {
    const root = document.querySelector(".oarlock-replay")!;
    return [...root.children].map((c) => c.className.split(" ")[0]);
  });
  // Reading order, which is what assistive technology follows and what a screenshot
  // shows. A verdict positioned over the player by CSS alone could be moved below the
  // fold by a host's stylesheet, and read after the recording by a screen reader.
  expect(order[0]).toBe("oarlock-verdict");
  expect(order[1]).toBe("oarlock-replay__stage");

  const banner = (await page.locator(".oarlock-verdict").boundingBox())!;
  const stage = (await page.locator(".oarlock-replay__stage").boundingBox())!;
  expect(banner.y).toBeLessThan(stage.y);
});

test("a caller who supplies no verdict gets 'unverified', not silence", async ({ page }) => {
  await page.evaluate(() => window.harness.play("valid", { withoutVerdict: true }));

  const v = await page.evaluate(() => window.harness.verdict());
  // The failure mode of a missing verdict has to be "we cannot vouch for this", never a
  // blank space where the answer should be — and never the intact banner.
  expect(v).not.toBeNull();
  expect(v?.tone).toBe("broken");
  expect(v?.status).toBe("unverified");
  expect(v?.headline.toLowerCase()).not.toContain("intact");
});

test("a truncated recording reads as incomplete rather than tampered", async ({ page }) => {
  await page.evaluate(() => window.harness.play("truncated-after-checkpoint"));

  const v = await page.evaluate(() => window.harness.verdict());
  expect(v?.tone).toBe("partial");
  expect(v?.headline).toContain("incomplete");
  expect(v?.body.toLowerCase()).not.toContain("tamper");
  // And it says how much of it verifies, which is the difference between a useless
  // warning and a usable one.
  expect(v?.body).toMatch(/up to event \d+/);
});

test("a malformed recording says so instead of showing an empty box", async ({ page }) => {
  await page.evaluate(() => window.harness.play("malformed"));

  const v = await page.evaluate(() => window.harness.verdict());
  expect(v?.tone).toBe("broken");
  expect(v?.status).toBe("malformed");
  expect(v?.headline).toContain("isn’t a readable recording");
});

test("the verdict is announced, not only drawn", async ({ page }) => {
  await page.evaluate(() => window.harness.play("altered"));
  // A statement about whether evidence can be trusted, for somebody who is not looking
  // at the screen.
  await expect(page.locator(".oarlock-verdict")).toHaveAttribute("role", "alert");

  await page.evaluate(() => window.harness.play("valid"));
  // An intact recording is a status, not an alert: interrupting somebody to tell them
  // nothing is wrong trains them to ignore the channel.
  await expect(page.locator(".oarlock-verdict")).toHaveAttribute("role", "status");
});

test("the session id and the verdict are shown as machine values", async ({ page }) => {
  await page.evaluate(() => window.harness.play("altered"));
  const v = await page.evaluate(() => window.harness.verdict());
  expect(v?.meta.join(" ")).toContain("sess_fixture");
  expect(v?.meta.join(" ")).toContain("altered");

  const mono = await page
    .locator(".oarlock-verdict__value")
    .first()
    .evaluate((el) => ({ font: getComputedStyle(el).fontFamily, select: getComputedStyle(el).userSelect }));
  expect(mono.font.toLowerCase()).toContain("mono");
  expect(mono.select).toBe("all");
});

test("every fixture renders a verdict, and only the intact ones read as trusted", async ({
  page,
}) => {
  // Walked from the generated fixtures rather than from a list here, so a new damage mode
  // added on the Go side arrives in this test without anybody remembering to add it.
  const names = await page.evaluate(() => window.harness.recordings());
  expect(names.length).toBeGreaterThan(5);

  for (const name of names) {
    await page.evaluate((n) => window.harness.play(n), name);
    const v = await page.evaluate(() => window.harness.verdict());
    expect(v, `${name} rendered no verdict`).not.toBeNull();
    expect(v!.headline, `${name} has an empty verdict`).not.toBe("");
    if (name.startsWith("valid")) {
      expect(v!.tone, name).toBe("trusted");
    } else {
      expect(v!.tone, `${name} reads as trusted`).not.toBe("trusted");
    }
  }
});

test("the replayed terminal is legible in both themes", async ({ page }) => {
  // The bug this pins: `--term-color-foreground` was mapped to the interface foreground,
  // which in the light theme is dark text — on a terminal ground that is dark in *both*
  // themes. The result was #1b1b1f on #1a1a1e: invisible, and only in replay, so nothing
  // about the live terminal would have shown it.
  for (const scheme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme: scheme });
    await page.evaluate(() => window.harness.play("valid"));
    await expect(page.locator(".oarlock-replay .ap-player")).toBeVisible();

    const { fg, bg } = await page.locator(".ap-player").evaluate((el) => {
      const cs = getComputedStyle(el);
      return {
        fg: cs.getPropertyValue("--term-color-foreground").trim(),
        bg: cs.getPropertyValue("--term-color-background").trim(),
      };
    });
    expect(fg, `${scheme}: no foreground`).not.toBe("");
    expect(bg, `${scheme}: no background`).not.toBe("");

    // Crude but decisive: the two must not be within a hair of each other.
    const lum = (hex: string) => {
      const n = parseInt(hex.replace("#", ""), 16);
      return (((n >> 16) & 255) * 299 + ((n >> 8) & 255) * 587 + (n & 255) * 114) / 1000;
    };
    expect(
      Math.abs(lum(fg) - lum(bg)),
      `${scheme}: ${fg} on ${bg} is not legible`,
    ).toBeGreaterThan(80);
  }
});
