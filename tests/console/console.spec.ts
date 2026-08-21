// The console, in a browser, against a **real gateway process**.
//
// Not a stub: the test design is explicit that a protocol stub drifts and then tests the
// stub. So these start `oarlockd` and `oarlock-agent` as processes, open the console in
// Chromium, and drive the journey an operator drives — which is also the only way to find
// out whether the pieces line up outside a harness that arranges them by hand.

import { test, expect, type Page } from "@playwright/test";
import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import net from "node:net";

const repo = resolve(import.meta.dirname, "../..");
const token = "console-token-long-enough-for-checks";

interface Deployment {
  dir: string;
  http: number;
  gateway: ChildProcess;
  agent: ChildProcess;
}

let dep: Deployment | undefined;

async function freePort(): Promise<number> {
  return new Promise((res, rej) => {
    const s = net.createServer();
    s.listen(0, "127.0.0.1", () => {
      const p = (s.address() as net.AddressInfo).port;
      s.close(() => res(p));
    });
    s.on("error", rej);
  });
}

async function waitFor(fn: () => Promise<boolean>, what: string, ms = 30_000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (await fn().catch(() => false)) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`timed out waiting for ${what}`);
}

test.beforeAll(async () => {
  // Built here rather than assumed: a console test against a stale binary is a test of
  // yesterday's gateway.
  const oarlockd = join(tmpdir(), "oarlockd-console-test");
  const agentBin = join(tmpdir(), "oarlock-agent-console-test");
  execFileSync("go", ["build", "-o", oarlockd, "./cmd/oarlockd"], { cwd: repo });
  execFileSync("go", ["build", "-o", agentBin, "./cmd/oarlock-agent"], { cwd: repo });

  const dir = mkdtempSync(join(tmpdir(), "oarlock-console-"));
  const sshPort = await freePort();
  const httpPort = await freePort();

  // A device key. `-generate-key` writes it and prints the public half in the form the
  // registry parses, which is the documented setup step.
  const devPub = execFileSync(agentBin, ["-key", join(dir, "device.key"), "-generate-key"], {
    cwd: dir,
  })
    .toString()
    .trim();

  // An operator key, so the SSH surface is configured even though the console does not
  // use it: the gateway needs an authenticator for both surfaces.
  execFileSync("ssh-keygen", ["-t", "ed25519", "-N", "", "-f", join(dir, "operator_key"),
    "-C", "phuc@example.com"], { stdio: "ignore" });
  writeFileSync(join(dir, "authorized_keys"), readFileSync(join(dir, "operator_key.pub")));

  writeFileSync(join(dir, "devices.yaml"), `devices:
  - id: treadmill-4821
    platform: linux
    keys:
      - "${devPub}"
    profiles: [shell]
`);
  writeFileSync(join(dir, "rules.yaml"), `rules:
  - principals: ["phuc@example.com"]
    devices: ["treadmill-*"]
    actions: ["shell", "exec", "replay", "observe"]
`);
  writeFileSync(join(dir, "oarlock.yaml"), `env: dev
url: ws://127.0.0.1:${httpPort}
listen:
  ssh: "127.0.0.1:${sshPort}"
  http: "127.0.0.1:${httpPort}"
ssh:
  host_key: ./hostkey
  generate_host_key: true
  authorized_keys: ./authorized_keys
devices: ./devices.yaml
authorizer:
  kind: rules
  path: ./rules.yaml
recorder:
  dir: ./recordings
  signing_key: ./recording.key
  generate_signing_key: true
api:
  tokens:
    ${token}: phuc@example.com
`);

  const gateway = spawn(oarlockd, ["-config", "./oarlock.yaml"], { cwd: dir });
  gateway.stderr.on("data", (b: Buffer) => {
    if (process.env["OARLOCK_TEST_VERBOSE"]) process.stdout.write(`[gw] ${b}`);
  });
  await waitFor(async () => {
    const r = await fetch(`http://127.0.0.1:${httpPort}/healthz`).catch(() => null);
    return r?.ok === true;
  }, "the gateway to be healthy");

  const agent = spawn(agentBin, [
    "-gateway", `ws://127.0.0.1:${httpPort}/ws/control`,
    "-device", "treadmill-4821", "-key", "./device.key",
    "-shell", "/bin/sh", "-insecure-skip-pin",
  ], { cwd: dir });
  agent.stderr.on("data", (b: Buffer) => {
    if (process.env["OARLOCK_TEST_VERBOSE"]) process.stdout.write(`[agent] ${b}`);
  });
  await waitFor(async () => {
    const r = await fetch(`http://127.0.0.1:${httpPort}/readyz`).catch(() => null);
    return r?.ok === true;
  }, "the gateway to be ready");
  // The agent's control channel, which the gateway needs before it can invite anything.
  await new Promise((r) => setTimeout(r, 1500));

  dep = { dir, http: httpPort, gateway, agent };
});

// Each test ends whatever it left running.
//
// The deployment is shared, and `sessions_per_device: 1` means a session left live by one
// test refuses the next one with `session_limit` — which is the gateway being right and
// the tests being dependent on each other's leftovers.
test.afterEach(async () => {
  if (!dep) return;
  const res = await fetch(`http://127.0.0.1:${dep.http}/api/v1/sessions?limit=50`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) return;
  const { sessions } = (await res.json()) as { sessions: { id: string; live: boolean }[] };
  await Promise.all(
    sessions
      .filter((s) => s.live)
      .map((s) =>
        fetch(`http://127.0.0.1:${dep!.http}/api/v1/sessions/${s.id}?reason=admin_kill`, {
          method: "DELETE",
          headers: { Authorization: `Bearer ${token}` },
        }),
      ),
  );
});

test.afterAll(() => {
  dep?.agent.kill("SIGTERM");
  dep?.gateway.kill("SIGTERM");
});

async function signIn(page: Page) {
  await page.goto(`http://127.0.0.1:${dep!.http}/ui/`);
  await page.getByPlaceholder("token").fill(token);
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByRole("heading", { name: "Open a shell" })).toBeVisible();
}

test("the console gives an operator a shell on a device", async ({ page }) => {
  await signIn(page);

  await page.getByTestId("device").fill("treadmill-4821");
  await page.getByTestId("reason").fill("ticket AV-9200");
  await page.getByTestId("open").click();

  // The terminal appears, disclosing what it is before the first prompt.
  const term = page.getByTestId("terminal");
  await expect(term).toBeVisible({ timeout: 30_000 });
  await expect(page.locator(".oarlock-bar__device")).toHaveText("treadmill-4821");
  await expect(page.locator(".oarlock-bar__badge--recording")).toHaveText("RECORDED");
  await expect(page.locator(".oarlock-term .xterm")).toBeVisible();

  // A command, on the device, through the gateway.
  await page.locator(".xterm-helper-textarea").focus();
  await page.keyboard.type("printf 'CONSOLE%s\\n' '-OK'");
  await page.keyboard.press("Enter");
  await expect(page.locator(".xterm-rows")).toContainText("CONSOLE-OK", { timeout: 30_000 });
});

test("the session list explains itself", async ({ page }) => {
  await signIn(page);
  // The reason the operator gave is on the row, which is what turns a list into an
  // explanation.
  await expect(page.getByText("ticket AV-9200").first()).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText("Not recorded").first()).toHaveCount(0);
});

test("a device that does not exist fails on its own step", async ({ page }) => {
  await signIn(page);
  await page.getByTestId("device").fill("no-such-device");
  await page.getByTestId("open").click();

  // The failure replaces the step that failed rather than appearing as a banner
  // somewhere else, and it never leaks whether the device exists.
  const waits = page.getByTestId("waits");
  await expect(waits).toBeVisible();
  await expect(waits).toContainText("No such device, or you don't have access to it.", {
    timeout: 20_000,
  });
  // And it never says which: a caller must not be able to enumerate the fleet by trying
  // ids, so the sentence names both possibilities rather than leaving one to be inferred.
  await expect(waits).not.toContainText("does not exist");
  // The steps that succeeded still read as succeeded: the diagnosis is one line, not a
  // reset of the whole panel.
  await expect(waits).toContainText("Authorised as");
});

test("replay shows the integrity verdict above the recording", async ({ page }) => {
  await signIn(page);

  // A session that has ended, so there is something to replay.
  await page.getByTestId("device").fill("treadmill-4821");
  await page.getByTestId("reason").fill("ticket AV-9201");
  await page.getByTestId("open").click();
  await expect(page.locator(".oarlock-term .xterm")).toBeVisible({ timeout: 30_000 });

  // The session this test made, so it replays *that* one. The deployment is shared
  // between tests, and `.first()` picked whichever row happened to be on top — which
  // passed alone and failed in sequence.
  const sessionID = (await page.getByTestId("terminal").locator(".mono").first().textContent())!;
  expect(sessionID).toMatch(/^sess_/);

  await page.locator(".xterm-helper-textarea").focus();
  await page.keyboard.type("echo REPLAY-ME");
  await page.keyboard.press("Enter");
  await expect(page.locator(".xterm-rows")).toContainText("REPLAY-ME", { timeout: 30_000 });
  await page.keyboard.type("exit");
  await page.keyboard.press("Enter");
  await page.getByRole("button", { name: "Leave" }).click();

  const row = page.locator(`tr[data-session="${sessionID}"]`);
  await expect(row).toBeVisible({ timeout: 30_000 });
  await row.getByRole("button", { name: "Replay" }).click({ timeout: 30_000 });
  await expect(page.getByTestId("replay")).toBeVisible();

  // The verdict, above the player, from the gateway's own verifier — a page cannot
  // compute this for itself without also being able to be lied to about it.
  const verdict = page.locator(".oarlock-verdict");
  await expect(verdict).toBeVisible({ timeout: 30_000 });
  await expect(verdict).toHaveAttribute("data-oarlock-tone", "trusted");
  await expect(verdict).toContainText("This recording is intact.");
  await expect(page.locator(".oarlock-replay .ap-player")).toBeVisible();
});
