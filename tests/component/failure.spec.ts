// The failure screens, in a browser.
//
// The unit tests cover the vocabulary. These cover what an operator actually sees, and in
// particular the thing the vocabulary cannot guarantee on its own: that the screen on
// screen is the condition the server sent, and not the last thing that happened on the
// way down.

import { test, expect, type Page } from "@playwright/test";

const live = async (page: Page, opts: Record<string, unknown> = {}) => {
  await page.evaluate(
    (o) =>
      window.harness.mount({
        ready: { recording: true, mode: "gateway" },
        ...(o as object),
      } as never),
    opts,
  );
  await expect(page.locator(".oarlock-term .xterm")).toBeVisible();
};

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await page.waitForFunction(() => !!window.harness);
});

test("an ERROR renders its own condition and nothing else", async ({ page }) => {
  await live(page);
  await page.evaluate(() =>
    window.harness.error({ code: "not_authorized", message: "no grant for treadmill-4821" }),
  );

  const f = await page.evaluate(() => window.harness.failure());
  expect(f?.condition).toBe("not_authorized");
  expect(f?.headline).toBe("You don’t have shell access to this device.");
  expect(f?.next).toContain("Ask whoever manages access");
  // The gateway's own message is present but secondary — it is for humans and logs, and
  // the protocol says it is never parsed, so it cannot be the sentence somebody reads to
  // find out what happened.
  await expect(page.locator(".oarlock-fail__detail")).toHaveText("no grant for treadmill-4821");
  await expect(page.locator(".oarlock-fail__headline")).not.toHaveText(
    "no grant for treadmill-4821",
  );
});

test("revoked and authz_unavailable are visibly different screens", async ({ page }) => {
  await live(page);
  await page.evaluate(() => window.harness.error({ code: "revoked" }));
  const revoked = await page.evaluate(() => window.harness.failure());

  await page.evaluate(() => window.harness.dispose());
  await live(page);
  await page.evaluate(() =>
    window.harness.error({ code: "authz_unavailable", retryable: true }),
  );
  const unavailable = await page.evaluate(() => window.harness.failure());

  expect(unavailable?.headline).not.toBe(revoked?.headline);
  expect(unavailable?.fault).toBe("gateway");
  expect(revoked?.fault).toBe("principal");
  // The screen says positively that nothing about their access changed, because silence
  // on the point is what people fill in with the worst reading.
  expect(`${unavailable?.headline} ${unavailable?.next}`).toContain("hasn’t changed");
});

test("the first condition wins, not the last thing that happened", async ({ page }) => {
  await live(page);
  // A dropped session produces a cascade: the real reason, then the consequences. An
  // operator shown "the connection failed" for a session that was revoked has been told
  // the least useful true thing.
  await page.evaluate(() => {
    window.harness.error({ code: "revoked", message: "grant withdrawn" });
    window.harness.closeFromGateway("transport_error");
  });

  const f = await page.evaluate(() => window.harness.failure());
  expect(f?.condition).toBe("revoked");
  await expect(page.locator(".oarlock-fail")).toHaveCount(1);
});

test("a CLOSE reason gets a screen too", async ({ page }) => {
  await live(page);
  // The conditions an operator most needs to read arrive this way: idle_timeout,
  // admin_kill, revoked mid-session. A terminal that simply stops is what this prevents.
  await page.evaluate(() => window.harness.closeFromGateway("idle_timeout"));

  const f = await page.evaluate(() => window.harness.failure());
  expect(f?.condition).toBe("idle_timeout");
  expect(f?.headline).toContain("idle");
  await expect(page.locator(".oarlock-bar__conn")).toHaveText("Ended");
});

test("an administrator's kill does not read as a failure", async ({ page }) => {
  await live(page);
  await page.evaluate(() => window.harness.closeFromGateway("admin_kill"));
  const f = await page.evaluate(() => window.harness.failure());
  expect(f?.condition).toBe("admin_kill");
  expect(f?.fault).toBe("none");
  expect(f?.next).toContain("not by a failure");
});

test("Try again appears only where retrying could work", async ({ page }) => {
  await live(page);
  await page.evaluate(() => window.harness.error({ code: "device_offline" }));
  await expect(page.locator(".oarlock-fail__retry")).toBeVisible();
  await page.locator(".oarlock-fail__retry").click();
  expect(await page.evaluate(() => window.harness.retries)).toBe(1);
  // Pressing it clears the screen, so the operator is not retrying behind a modal.
  await expect(page.locator(".oarlock-fail")).toHaveCount(0);

  await page.evaluate(() => window.harness.dispose());
  await live(page);
  await page.evaluate(() => window.harness.error({ code: "revoked" }));
  await expect(page.locator(".oarlock-fail")).toBeVisible();
  // A retry button on a withdrawn grant invites somebody to keep pressing it at a
  // decision that will not change.
  await expect(page.locator(".oarlock-fail__retry")).toHaveCount(0);
});

test("the reference is shown small and labelled for support", async ({ page }) => {
  await live(page);
  await page.evaluate(() => window.harness.error({ code: "internal", message: "req_01J8Z6QK4M" }));

  const f = await page.evaluate(() => window.harness.failure());
  // An integrator condition: it is not the operator's fault and the screen says so.
  expect(f?.condition).toBe("internal");
  expect(f?.headline).toBe("Something in this application is wrong.");
  // Present for the report, not shouted at the operator: the code is in the metadata,
  // never the headline.
  expect(f?.meta.join(" ")).toContain("Reason");
  expect(f?.meta.join(" ")).toContain("internal");
  expect(f?.headline).not.toContain("internal");

  // Machine values are monospaced, and selectable on their own so somebody can quote
  // just the reference.
  const mono = await page
    .locator(".oarlock-fail__value")
    .first()
    .evaluate((el) => ({
      font: getComputedStyle(el).fontFamily,
      select: getComputedStyle(el).userSelect,
      size: getComputedStyle(el).fontSize,
    }));
  expect(mono.font.toLowerCase()).toContain("mono");
  expect(mono.select).toBe("all");
  expect(parseFloat(mono.size)).toBeLessThan(14);
});

test("an unknown code from a newer gateway still gets a screen", async ({ page }) => {
  await live(page);
  await page.evaluate(() =>
    window.harness.error({ code: "condition_from_2027", message: "who knows" }),
  );

  const f = await page.evaluate(() => window.harness.failure());
  // The protocol's versioning rules allow a gateway to be newer than its client. A blank
  // pane, or the first row of the table, would both be worse than saying so.
  expect(f?.condition).toBe("condition_from_2027");
  expect(f?.headline).toBe("Something in this application is wrong.");
  expect(f?.meta.join(" ")).toContain("condition_from_2027");
});

test("reconnecting is not a failure screen", async ({ page }) => {
  await page.evaluate(() => {
    window.harness.mount({
      ready: { recording: true, mode: "gateway" },
      renewTicket: async () => "resume-1",
    } as never);
  });
  await expect(page.locator(".oarlock-term .xterm")).toBeVisible();
  await page.evaluate(() => window.harness.dropSocket());
  await expect(page.locator(".oarlock-bar__conn")).toHaveText("Reconnecting");
  // A modal here would make the normal case look like a failure. The bar says it, the
  // screen dims, and nothing blocks the terminal the operator is about to get back.
  await expect(page.locator(".oarlock-fail")).toHaveCount(0);
});

test("every operator condition the gateway can emit renders its own screen", async ({ page }) => {
  // Enumerated from the generated table rather than from a list written here — but note
  // what that can and cannot prove. It is self-referential about *membership*: dropping a
  // row removes it from both the list and the screens, so this test cannot notice. What
  // guarantees the table matches the server's set is the Go side's staleness gate
  // (pkg/condition's TestGeneratedTableIsCurrent), and the two together are what make
  // completeness real.
  //
  // What this test does prove is that every row in the table renders *its own* screen:
  // it catches a renderer that falls back to the generic one, and two rows that collide
  // into a single screen an operator cannot tell apart.
  const ids = await page.evaluate(() => window.harness.operatorConditions());
  expect(ids.length).toBeGreaterThan(15);

  const headlines = new Set<string>();
  for (const id of ids) {
    await page.evaluate(() => window.harness.dispose());
    await live(page);
    await page.evaluate((code) => window.harness.error({ code }), id);
    const f = await page.evaluate(() => window.harness.failure());
    expect(f, `${id} rendered no screen`).not.toBeNull();
    expect(f!.condition, id).toBe(id);
    expect(f!.headline, `${id} has an empty headline`).not.toBe("");
    expect(headlines.has(f!.headline), `${id} reuses another condition's screen`).toBe(false);
    headlines.add(f!.headline);
  }
});
