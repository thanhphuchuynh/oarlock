// FR36's ticket-renewal callback.
//
// Tickets are single-use and live 60 s (NFR8), so the ordinary things a browser does —
// a reload, a handshake that loses a race, sitting on the API response for a minute —
// leave it holding a dead credential. Reporting that to the operator as a failure would
// be reporting our own design at them; the component asks the integrator's backend for
// another. That request is also where authorisation gets re-checked, which is why it is
// a callback rather than a stored token.
//
// The reattach *mechanism* — scrollback from the ring — is E3.S3. This is the part that
// stands alone: a refused ticket at open time.

import { test, expect } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await page.waitForFunction(() => !!window.harness);
});

test("a refused ticket is renewed once and the session opens", async ({ page }) => {
  await page.evaluate(() => {
    window.harness.mount({
      ready: null, // the gateway will refuse first, not send READY
      renewTicket: async () => {
        window.harness.renewals.push("asked");
        return "fresh-ticket-123456";
      },
    } as never);
  });
  // The first OPEN carries the stale ticket and is refused, exactly as a gateway would
  // refuse a spent one.
  await page.waitForFunction(() => window.harness.tickets().length === 1);
  await page.evaluate(() =>
    window.harness.error({ code: "ticket_invalid", message: "Refused." }),
  );

  await page.waitForFunction(() => window.harness.tickets().length === 2);
  const tickets = await page.evaluate(() => window.harness.tickets());
  expect(tickets).toEqual(["stub-ticket-abcdef", "fresh-ticket-123456"]);
  expect(await page.evaluate(() => window.harness.renewals)).toEqual(["asked"]);

  // The operator was never shown a failure for something the component could fix.
  expect(await page.evaluate(() => window.harness.errors)).toEqual([]);

  // And the renewed connection is a working session.
  await page.evaluate(() => window.harness.ready({ recording: true, mode: "gateway" }));
  await expect(page.locator(".oarlock-term .xterm")).toBeVisible();
});

test("a second refusal is a real answer, not another renewal", async ({ page }) => {
  await page.evaluate(() => {
    window.harness.mount({
      ready: null,
      renewTicket: async () => {
        window.harness.renewals.push("asked");
        return `fresh-${window.harness.renewals.length}`;
      },
    } as never);
  });
  await page.waitForFunction(() => window.harness.tickets().length === 1);
  await page.evaluate(() => window.harness.error({ code: "ticket_invalid", message: "Refused." }));
  await page.waitForFunction(() => window.harness.tickets().length === 2);
  await page.evaluate(() => window.harness.error({ code: "ticket_invalid", message: "Refused again." }));

  // A renewal loop against a gateway that refuses everything is a denial-of-service we
  // would be running on ourselves.
  await page.waitForTimeout(200);
  expect(await page.evaluate(() => window.harness.renewals)).toEqual(["asked"]);
  expect(await page.evaluate(() => window.harness.errors)).toEqual([
    { code: "ticket_invalid", message: "Refused again." },
  ]);
});

test("a backend that declines to renew is reported, not retried", async ({ page }) => {
  await page.evaluate(() => {
    window.harness.mount({
      ready: null,
      renewTicket: async () => {
        window.harness.renewals.push("asked");
        throw new Error("403 revoked");
      },
    } as never);
  });
  await page.waitForFunction(() => window.harness.tickets().length === 1);
  await page.evaluate(() => window.harness.error({ code: "ticket_invalid", message: "Refused." }));

  // The integrator's backend saying no is a real answer: the operator's authorisation
  // may have been withdrawn since the session opened.
  await page.waitForFunction(() => window.harness.errors.length > 0);
  const errors = await page.evaluate(() => window.harness.errors);
  expect(errors[0]!.code).toBe("ticket_invalid");
  expect(errors[0]!.message).toContain("403 revoked");
  expect(await page.evaluate(() => window.harness.tickets())).toHaveLength(1);
});

test("a refusal after READY is not a ticket problem and is not renewed", async ({ page }) => {
  await page.evaluate(() => {
    window.harness.mount({
      ready: { recording: true, mode: "gateway" },
      renewTicket: async () => {
        window.harness.renewals.push("asked");
        return "should-never-be-used";
      },
    } as never);
  });
  await expect(page.locator(".oarlock-term .xterm")).toBeVisible();

  // Once the session is live, a ticket error means something else entirely, and
  // silently re-dialling would throw away a session the operator is working in.
  await page.evaluate(() => window.harness.error({ code: "ticket_invalid", message: "Odd." }));
  await page.waitForTimeout(150);
  expect(await page.evaluate(() => window.harness.renewals)).toEqual([]);
  expect(await page.evaluate(() => window.harness.errors)).toEqual([
    { code: "ticket_invalid", message: "Odd." },
  ]);
});

test("without a renewal callback the refusal is simply reported", async ({ page }) => {
  await page.evaluate(() => window.harness.mount({ ready: null } as never));
  await page.waitForFunction(() => window.harness.tickets().length === 1);
  await page.evaluate(() => window.harness.error({ code: "ticket_invalid", message: "Refused." }));

  await page.waitForFunction(() => window.harness.errors.length > 0);
  expect(await page.evaluate(() => window.harness.errors)).toEqual([
    { code: "ticket_invalid", message: "Refused." },
  ]);
  expect(await page.evaluate(() => window.harness.tickets())).toHaveLength(1);
});

// ── reconnect ───────────────────────────────────────────────────────────────────
//
// A dropped socket is not an end. The gateway keeps the session attached, holds what
// the device produced in a ring, and replays it on return (FR8) — so the component's
// job is to come back quietly rather than to report a failure for something that is
// about to fix itself.

test("a dropped socket reconnects and replays, without showing a failure", async ({ page }) => {
  await page.evaluate(() => {
    window.harness.mount({
      ready: { recording: true, mode: "gateway" },
      renewTicket: async () => {
        window.harness.renewals.push("asked");
        return `resume-${window.harness.renewals.length}`;
      },
    } as never);
  });
  await expect(page.locator(".oarlock-term .xterm")).toBeVisible();
  await page.evaluate(() => window.harness.write("BEFORE-THE-DROP\r\n"));
  await expect(page.locator(".xterm-rows")).toContainText("BEFORE-THE-DROP");

  await page.evaluate(() => window.harness.dropSocket());

  // The bar says reconnecting; the terminal is dimmed, not dead.
  await expect(page.locator(".oarlock-bar__conn")).toHaveText("Reconnecting");
  await expect(page.locator(".oarlock-term")).toHaveAttribute(
    "data-oarlock-state",
    "reconnecting",
  );
  // No error: a dropped connection is the normal case.
  expect(await page.evaluate(() => window.harness.errors)).toEqual([]);

  // It comes back with a fresh ticket — which is the moment authorisation is
  // re-checked, rather than resuming on the strength of an old decision.
  await page.waitForFunction(() => window.harness.tickets().length === 2, undefined, {
    timeout: 10_000,
  });
  expect(await page.evaluate(() => window.harness.tickets())).toEqual([
    "stub-ticket-abcdef",
    "resume-1",
  ]);

  // The gateway replays the scrollback after READY, and the terminal is live again.
  await page.evaluate(() => {
    window.harness.ready({ recording: true, mode: "gateway", scrollback_len: 17 });
    window.harness.write("BEFORE-THE-DROP\r\nAFTER-THE-DROP\r\n");
  });
  await expect(page.locator(".oarlock-bar__conn")).toHaveText("Live");
  await expect(page.locator(".xterm-rows")).toContainText("AFTER-THE-DROP");
});

test("a gateway CLOSE ends the session and is not reconnected to", async ({ page }) => {
  await page.evaluate(() => {
    window.harness.mount({
      ready: { recording: true, mode: "gateway" },
      renewTicket: async () => {
        window.harness.renewals.push("asked");
        return "should-not-be-used";
      },
    } as never);
  });
  await expect(page.locator(".oarlock-term .xterm")).toBeVisible();

  // "idle_timeout" is a decision, not an accident. Reconnecting through it would put
  // the operator back into a session the gateway deliberately ended.
  await page.evaluate(() => window.harness.closeFromGateway("idle_timeout"));
  await expect(page.locator(".oarlock-bar__conn")).toHaveText("Ended");
  await page.waitForTimeout(300);
  expect(await page.evaluate(() => window.harness.renewals)).toEqual([]);
});

test("a drop before READY is not a reconnect", async ({ page }) => {
  // There is no session to come back to yet: the gateway never paired anything, so a
  // reconnect would be dialling for a session that does not exist.
  await page.evaluate(() => {
    window.harness.mount({
      ready: null,
      renewTicket: async () => {
        window.harness.renewals.push("asked");
        return "unused";
      },
    } as never);
  });
  await page.waitForFunction(() => window.harness.tickets().length === 1);
  await page.evaluate(() => window.harness.dropSocket());

  await page.waitForFunction(() => window.harness.errors.length > 0, undefined, {
    timeout: 5_000,
  });
  expect((await page.evaluate(() => window.harness.errors))[0]!.code).toBe("connection_lost");
  expect(await page.evaluate(() => window.harness.renewals)).toEqual([]);
});

test("reconnecting gives up rather than hammering the gateway", async ({ page }) => {
  await page.evaluate(() => {
    window.harness.mount({
      ready: { recording: true, mode: "gateway" },
      maxReconnects: 2,
      renewTicket: async () => {
        window.harness.renewals.push("asked");
        return `try-${window.harness.renewals.length}`;
      },
    } as never);
  });
  await expect(page.locator(".oarlock-term .xterm")).toBeVisible();

  // Every attempt drops again, as it would against a gateway that is down. Each drop
  // has to wait for the re-dial it caused: dropping the same dead socket in a tight
  // loop is swallowed while a reconnect is already in flight, which made an earlier
  // version of this test measure one attempt and call it four.
  for (let attempt = 1; attempt <= 3; attempt++) {
    await page.evaluate(() => window.harness.dropSocket());
    await page
      .waitForFunction((n) => window.harness.tickets().length >= n, attempt + 1, {
        timeout: 6_000,
      })
      .catch(() => {
        /* the last drop is expected to produce no further dial */
      });
  }
  await page.waitForFunction(() => window.harness.errors.length > 0, undefined, {
    timeout: 15_000,
  });

  // Two attempts, then it says so. A browser that retried forever would keep an
  // operator staring at "Reconnecting" for a session that is never coming back.
  const renewals = await page.evaluate(() => window.harness.renewals);
  expect(renewals.length).toBeLessThanOrEqual(2);
  expect((await page.evaluate(() => window.harness.errors)).at(-1)!.code).toBe("connection_lost");
  await expect(page.locator(".oarlock-bar__conn")).toHaveText("Ended");
});

test("a backend that revokes access while the operator is away says so", async ({ page }) => {
  await page.evaluate(() => {
    window.harness.mount({
      ready: { recording: true, mode: "gateway" },
      renewTicket: async () => {
        throw new Error("403 revoked");
      },
    } as never);
  });
  await expect(page.locator(".oarlock-term .xterm")).toBeVisible();
  await page.evaluate(() => window.harness.dropSocket());

  await page.waitForFunction(() => window.harness.errors.length > 0, undefined, {
    timeout: 10_000,
  });
  const err = (await page.evaluate(() => window.harness.errors)).at(-1)!;
  // "you were revoked" and "the connection dropped" send someone to different places,
  // and re-checking on reconnect is exactly how the first one gets discovered.
  expect(err.code).toBe("not_authorized");
  expect(err.message).toContain("403 revoked");
});

test("keystrokes typed into a dead socket are dropped, not replayed later", async ({ page }) => {
  // A deliberate departure from the journey sketch, which says input queues while
  // reconnecting. A terminal is not a text field: bytes are interpreted in context, so
  // keystrokes replayed eight seconds later can land in a context that has moved on — a
  // pager that exited, a confirmation prompt that is now something else. The screen is
  // dimmed to say "not now"; losing the characters is the safe failure.
  await page.evaluate(() => {
    window.harness.mount({
      ready: { recording: true, mode: "gateway" },
      renewTicket: async () => `resume-${Date.now()}`,
    } as never);
  });
  await expect(page.locator(".oarlock-term .xterm")).toBeVisible();
  await page.evaluate(() => window.harness.dropSocket());
  await expect(page.locator(".oarlock-bar__conn")).toHaveText("Reconnecting");

  await page.locator(".xterm-helper-textarea").focus();
  await page.keyboard.type("rm -rf /tmp/something");

  await page.waitForFunction(() => window.harness.tickets().length === 2, undefined, {
    timeout: 10_000,
  });
  await page.evaluate(() => window.harness.ready({ recording: true, mode: "gateway" }));
  await expect(page.locator(".oarlock-bar__conn")).toHaveText("Live");

  // Nothing typed during the gap reaches the device on the new connection.
  const sent = await page.evaluate(() => window.harness.sent());
  const data = sent.filter((f) => f.type === 0x01).map((f) => f.text).join("");
  expect(data).not.toContain("rm -rf");
});

test("a resize during a reconnect is not lost", async ({ page }) => {
  // Tests the outcome, not the mechanism, and deliberately so.
  //
  // Two things can carry the size across a reconnect: the re-report on READY, and a
  // late ResizeObserver firing after the socket is back. xterm does its own layout work
  // on its own schedule, so which one wins is not controllable from here — removing the
  // READY re-report leaves this test passing, via the observer. That makes it a weaker
  // test than it looks, so it says so: what it pins is that the device ends up with the
  // right dimensions, which is the thing an operator would notice. The re-report exists
  // because the observer path is a race, not because this test demands it.
  await page.evaluate(() => {
    window.harness.mount({
      ready: { recording: true, mode: "gateway" },
      renewTicket: async () => {
        await new Promise((r) => setTimeout(r, 1200));
        return "resume-1";
      },
    } as never);
  });
  await expect(page.locator(".oarlock-term .xterm")).toBeVisible();
  await page.evaluate(() => window.harness.dropSocket());
  await expect(page.locator(".oarlock-bar__conn")).toHaveText("Reconnecting");

  // The operator resizes their window while the socket is down. Without a re-report the
  // device's PTY keeps the old dimensions for the rest of the session, the screen wraps
  // wrongly, and there is nothing to blame it on.
  await page.evaluate(() => {
    const host = document.getElementById("host")!;
    host.style.width = "500px";
    host.style.height = "300px";
  });
  await page.waitForTimeout(500); // the trailing flush fires here, into no socket

  await page.waitForFunction(() => window.harness.tickets().length === 2, undefined, {
    timeout: 10_000,
  });

  await page.evaluate(() => window.harness.ready({ recording: true, mode: "gateway" }));
  await page.waitForFunction(
    () => window.harness.sent().some((f) => f.type === 0x05),
    undefined,
    { timeout: 5_000 },
  );

  const resizes = (await page.evaluate(() => window.harness.sent()))
    .filter((f) => f.type === 0x05)
    .map((f) => JSON.parse(f.text) as { cols: number; rows: number });
  const rows = await page.locator(".xterm-rows").evaluate((el) => el.children.length);
  expect(resizes.at(-1)!.rows).toBe(rows);
});
