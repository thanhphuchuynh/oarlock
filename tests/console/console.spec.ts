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
// A second operator, authenticated and granted nothing administrative. The console's
// admin surface has to refuse them, and has to say so rather than showing an empty table.
const visitorToken = "visitor-token-long-enough-for-checks";

interface Deployment {
  dir: string;
  http: number;
  gateway: ChildProcess;
  agent: ChildProcess;
  agentBin: string;
}

let dep: Deployment | undefined;

function startAgent(agentBin: string, dir: string, httpPort: number): ChildProcess {
  const agent = spawn(agentBin, [
    "-gateway", `ws://127.0.0.1:${httpPort}/ws/control`,
    "-device", "treadmill-4821", "-key", "./device.key",
    "-shell", "/bin/sh", "-insecure-skip-pin",
  ], { cwd: dir });
  agent.stderr.on("data", (b: Buffer) => {
    if (process.env["OARLOCK_TEST_VERBOSE"]) process.stdout.write(`[agent] ${b}`);
  });
  return agent;
}

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
    "-C", "admin@mail.com"], { stdio: "ignore" });
  writeFileSync(join(dir, "authorized_keys"), readFileSync(join(dir, "operator_key.pub")));

  writeFileSync(join(dir, "devices.yaml"), `devices:
  - id: treadmill-4821
    platform: linux
    keys:
      - "${devPub}"
    profiles: [shell]
`);
  writeFileSync(join(dir, "rules.yaml"), `rules:
  - principals: ["admin@mail.com"]
    devices: ["treadmill-*"]
    actions: ["shell", "exec", "replay", "observe"]
  - principals: ["admin@mail.com"]
    devices: ["gateway"]
    actions: ["sql:read"]
`);
  writeFileSync(join(dir, "oarlock.yaml"), `env: dev
# Deliberately differs from the browser's 127.0.0.1 origin. The bundled console must
# attach through the origin that served it, while non-browser API clients use this URL.
url: ws://localhost:${httpPort}
listen:
  ssh: "127.0.0.1:${sshPort}"
  http: "127.0.0.1:${httpPort}"
ssh:
  host_key: ./hostkey
  generate_host_key: true
  authorized_keys: ./authorized_keys
store:
  kind: sqlite
  path: ./oarlock.db
devices:
  kind: sqlite
authorizer:
  kind: sqlite
  # The bootstrap. Seeding the first device and the first permission goes through the
  # admin API, and the admin API is authorised by the policy being seeded.
  admins:
    - admin@mail.com
recorder:
  dir: ./recordings
  signing_key: ./recording.key
  generate_signing_key: true
api:
  tokens:
    ${token}: admin@mail.com
    ${visitorToken}: visitor@example.com
  # Twelve browser tests share one gateway and one principal, so they share one rate
  # bucket. The default budget is the right default and the wrong fixture: it made a
  # device-edit assertion fail with "slow down and retry after the reset", which is the
  # limiter working and the test lying about what it tests.
  rate_per_minute: 6000
`);

  const gateway = spawn(oarlockd, ["-config", "./oarlock.yaml"], { cwd: dir });
  gateway.stderr.on("data", (b: Buffer) => {
    if (process.env["OARLOCK_TEST_VERBOSE"]) process.stdout.write(`[gw] ${b}`);
  });
  await waitFor(async () => {
    const r = await fetch(`http://127.0.0.1:${httpPort}/healthz`).catch(() => null);
    return r?.ok === true;
  }, "the gateway to be healthy");

  const seeded = await fetch(`http://127.0.0.1:${httpPort}/api/v1/devices`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      id: "treadmill-4821",
      platform: "linux",
      mode: "persistent",
      keys: [devPub],
      profiles: ["shell"],
    }),
  });
  if (!seeded.ok) throw new Error(`could not seed device: ${await seeded.text()}`);

  // A device that never dials in. Half of what a fleet view has to get right is the row
  // for the machine that is not there, and a deployment with one always-connected device
  // cannot test it.
  const offline = await fetch(`http://127.0.0.1:${httpPort}/api/v1/devices`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      id: "rower-9001", platform: "linux", mode: "persistent",
      keys: [devPub], profiles: ["shell"],
    }),
  });
  if (!offline.ok) throw new Error(`could not seed the offline device: ${await offline.text()}`);

  // A device inside a change-control scope, so the deny path has something to apply to.
  const scoped = await fetch(`http://127.0.0.1:${httpPort}/api/v1/devices`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      id: "treadmill-9999", platform: "linux", mode: "persistent",
      keys: [devPub], profiles: ["shell"], tags: { pci_scope: "true" },
    }),
  });
  if (!scoped.ok) throw new Error(`could not seed the scoped device: ${await scoped.text()}`);

  for (const permission of [
    {
      id: "console-operator", name: "Console operator", principals: ["admin@mail.com"],
      devices: ["treadmill-*"], actions: ["shell", "exec", "replay", "observe"],
      effect: "allow", enabled: true,
    },
    {
      id: "console-sql", name: "Console SQL", principals: ["admin@mail.com"],
      devices: ["gateway"], actions: ["sql:read"], effect: "allow", enabled: true,
    },
    // Written so the console's own administration runs on a real grant rather than on
    // the config break-glass, which is what a deployment past its first hour looks like.
    {
      id: "console-admin", name: "Console administrator", principals: ["admin@mail.com"],
      devices: ["gateway"], actions: ["admin:permissions"], effect: "allow", enabled: true,
    },
    {
      id: "console-fleet", name: "Console fleet admin", principals: ["admin@mail.com"],
      devices: ["*"], actions: ["admin:devices", "admin:kill"], effect: "allow",
      enabled: true,
    },
    {
      id: "visitor-shell", name: "Visitor shell", principals: ["visitor@example.com"],
      devices: ["treadmill-*"], actions: ["shell"], effect: "allow", enabled: true,
    },
    {
      id: "rowers-only", name: "Rowers only", principals: ["rower@example.com"],
      devices: ["rower-*"], actions: ["shell"], effect: "allow", enabled: true,
    },
    {
      id: "deny-pci", name: "PCI change control", principals: ["*"], devices: ["*"],
      tags: { pci_scope: "true" }, actions: ["*"], effect: "deny",
      reason: "PCI-scoped devices need a change ticket", enabled: true,
    },
  ]) {
    const response = await fetch(`http://127.0.0.1:${httpPort}/api/v1/permissions`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(permission),
    });
    if (!response.ok) throw new Error(`could not seed permission: ${await response.text()}`);
  }

  const agent = startAgent(agentBin, dir, httpPort);
  await waitFor(async () => {
    const r = await fetch(`http://127.0.0.1:${httpPort}/readyz`).catch(() => null);
    return r?.ok === true;
  }, "the gateway to be ready");
  // The agent's control channel, which the gateway needs before it can invite anything.
  await new Promise((r) => setTimeout(r, 1500));

  dep = { dir, http: httpPort, gateway, agent, agentBin };
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

async function signIn(page: Page, as = token) {
  await page.goto(`http://127.0.0.1:${dep!.http}/ui/`);
  await page.getByPlaceholder("token").fill(as);
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByTestId("fleet")).toBeVisible();
}

/** Opens one device's row and returns it. Everything about a device lives inside it. */
async function openRow(page: Page, device: string) {
  const row = page.locator(`[data-device="${device}"]`);
  await expect(row).toBeVisible({ timeout: 30_000 });
  if ((await row.locator("button.row-toggle").getAttribute("aria-expanded")) !== "true") {
    await row.locator("button.row-toggle").click();
  }
  return row;
}

test("the console gives an operator a shell on a device", async ({ page }) => {
  await signIn(page);

  const row = await openRow(page, "treadmill-4821");
  await row.getByTestId("reason").fill("ticket AV-9200");
  await row.getByTestId("open").click();

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
  // Its own session rather than the previous test's. The deployment is shared and the
  // tests are not ordered by anything the file guarantees, so a row left behind by a
  // neighbour is a dependency, not a fixture.
  const row = await openRow(page, "treadmill-4821");
  await row.getByTestId("reason").fill("ticket AV-9300");
  await row.getByTestId("open").click();
  await expect(page.locator(".oarlock-term .xterm")).toBeVisible({ timeout: 30_000 });
  await page.getByRole("button", { name: "Leave" }).click();

  await page.getByRole("button", { name: "Sessions", exact: true }).click();
  // The reason the operator gave is on the row, which is what turns a list into an
  // explanation.
  await expect(page.getByText("ticket AV-9300").first()).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText("Not recorded")).toHaveCount(0);
});

// A connected agent is a state of its device, not a second list of the same devices. The
// page it replaced showed treadmill-4821 in a registry table whose STATE column said
// ONLINE and again in a "Live agents" table that existed to say ONLINE.
test("a connected agent is a state of its device, not a separate list", async ({ page }) => {
  await signIn(page);
  await expect(page.getByTestId("fleet-summary")).toContainText("1 online", { timeout: 30_000 });
  await expect(page.getByTestId("fleet-summary")).toContainText("3 devices");

  const row = page.locator('[data-device="treadmill-4821"]');
  await expect(row.locator("button.row-toggle")).toContainText("Online");
  // The control for the channel is in the device's own row, and only while it is up.
  await openRow(page, "treadmill-4821");
  await expect(row.getByRole("button", { name: "Stop agent" })).toBeVisible();

  const absent = page.locator('[data-device="rower-9001"]');
  await expect(absent.locator("button.row-toggle")).toContainText("Offline");
  await openRow(page, "rower-9001");
  await expect(absent.getByRole("button", { name: "Stop agent" })).toHaveCount(0);
});

// The question a flat rule list cannot answer, answered where it is asked — and split in
// two, because reaching a device and administering it are different sentences about a
// person. Listing `admin:devices` under "who can reach it" said something untrue.
test("a device row says who can reach it and who administers it", async ({ page }) => {
  await signIn(page);
  const row = await openRow(page, "treadmill-4821");
  const access = row.getByTestId("device-access");
  await expect(access).toContainText("Who can reach it", { timeout: 30_000 });

  const reach = row.getByTestId("device-access-reach");
  const administer = row.getByTestId("device-access-admin");
  await expect(reach).toContainText("admin@mail.com");
  await expect(reach).toContainText("visitor@example.com");
  // `admin:devices` is not a way to reach a device, so it does not appear under the
  // heading that asks who can.
  await expect(reach).not.toContainText("admin:");
  await expect(administer).toContainText("admin:devices");
  await expect(administer).not.toContainText("shell");

  // Evaluated against this device by the gateway: a rule scoped to the rowers is not
  // listed on a treadmill.
  await expect(access).not.toContainText("rower@example.com");
});

// A denial outranks every allow, so a reader must not have to reach the end of the list
// to find the one line that reverses the rest.
test("a denial is listed first and reads as a denial", async ({ page }) => {
  await signIn(page);
  const scoped = await openRow(page, "treadmill-9999");
  const reach = scoped.getByTestId("device-access-reach");
  await expect(reach).toContainText("Denied", { timeout: 30_000 });
  await expect(reach).toContainText("PCI-scoped devices need a change ticket");

  // First in the list, ahead of the allow that it beats.
  const rows = reach.locator("li");
  await expect(rows.first()).toContainText("Denied");
  await expect(reach).toContainText("Allowed");

  // And it is scoped by tag, so the untagged treadmill next to it is unaffected.
  const plain = await openRow(page, "treadmill-4821");
  await expect(plain.getByTestId("device-access-reach")).not.toContainText("Denied");
});

// Whoever may edit a device is not thereby entitled to know who can reach it. The panel
// says which grant is missing rather than rendering an empty list, which would read as
// "nobody can reach this device".
test("a device row will not invent an access list it cannot read", async ({ page }) => {
  await signIn(page, visitorToken);
  const row = await openRow(page, "treadmill-4821");
  const access = row.getByTestId("device-access");
  await expect(access).toContainText("don\u2019t have access", { timeout: 30_000 });
  await expect(access).toContainText("admin:permissions");
  await expect(access).not.toContainText("Allowed");
});

test("permissions are managed in the admin console", async ({ page }) => {
  await signIn(page);
  await page.getByRole("button", { name: "Permissions", exact: true }).click();
  const permissions = page.getByTestId("permissions");
  await expect(permissions).toContainText("Console operator");

  await permissions.getByRole("button", { name: "Add permission" }).click();
  const dialog = page.getByRole("dialog", { name: "Add permission" });
  await dialog.getByLabel("Permission ID").fill("temporary-observer");
  await dialog.getByLabel("Name").fill("Temporary observer");
  await dialog.getByLabel("Principals").fill("observer@example.com");
  await dialog.getByLabel("Devices").fill("treadmill-*");
  await dialog.getByLabel("Actions").fill("observe");
  await dialog.getByRole("button", { name: "Save permission" }).click();
  await expect(permissions).toContainText("Temporary observer");
});

// The admin surface refuses an operator who has a shell and nothing else — and the
// refusal has to read as "not yours", because an empty table under an "Add permission"
// button says the opposite of what happened.
test("the policy is not readable by an operator who only has a shell", async ({ page }) => {
  await signIn(page, visitorToken);
  await page.getByRole("button", { name: "Permissions", exact: true }).click();
  const refused = page.getByTestId("permissions-refused");
  await expect(refused).toBeVisible();
  await expect(refused).toContainText("don\u2019t have access");
  await expect(refused).toContainText("admin:permissions");
  const permissions = page.getByTestId("permissions");
  await expect(permissions).not.toContainText("Console operator");
  await expect(permissions.getByRole("button", { name: "Add permission" })).toHaveCount(0);
});

test("the console prepares a pinned local SSH command", async ({ page }) => {
  await signIn(page);
  const row = await openRow(page, "treadmill-4821");
  await row.getByRole("button", { name: "SSH client" }).click();
  const dialog = page.getByRole("dialog", { name: "Local SSH client" });
  await expect(dialog).toContainText("SHA256:");
  await expect(dialog.locator("code")).toContainText("treadmill-4821@127.0.0.1");

  const downloadPromise = page.waitForEvent("download");
  await dialog.getByRole("button", { name: "Download host key" }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe("oarlock_known_hosts.txt");
  const path = await download.path();
  expect(path).not.toBeNull();
  expect(readFileSync(path!, "utf8")).toContain("ssh-ed25519");
});

test("the SQL explorer queries curated operational data and refuses writes", async ({ page }) => {
  await signIn(page);
  await page.getByRole("button", { name: "SQL Explorer", exact: true }).click();
  const explorer = page.getByTestId("sql-explorer");
  await expect(explorer).toBeVisible();
  await expect(explorer.getByText("oarlock_devices", { exact: true })).toBeVisible();

  const editor = explorer.getByLabel("SQL query");
  await editor.fill(
    "SELECT id, platform, disabled FROM oarlock_devices WHERE id = 'treadmill-4821'",
  );
  await explorer.getByTestId("run-sql").click();
  await expect(explorer.getByRole("cell", { name: "treadmill-4821" })).toBeVisible();
  // Scoped to one device rather than counting the fleet: a row count that changes when a
  // test registers another device is a test about the wrong thing.
  await expect(explorer.getByText(/1 rows · \d+ ms/)).toBeVisible();

  await editor.fill("DELETE FROM oarlock_devices");
  await explorer.getByTestId("run-sql").click();
  await expect(explorer.getByRole("alert")).toContainText("only SELECT and WITH queries are allowed");
});

test("a device that does not exist fails on its own step", async ({ page }) => {
  await signIn(page);
  // Opening by typed id is the path that survives the restructure precisely so this
  // journey stays reachable: an id with no row cannot be picked from a list.
  await page.getByTestId("open-by-id").click();
  await page.getByTestId("open-by-id-device").fill("no-such-device");
  await page.getByTestId("open-by-id-submit").click();

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
  const row = await openRow(page, "treadmill-4821");
  await row.getByTestId("reason").fill("ticket AV-9201");
  await row.getByTestId("open").click();
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

  await page.getByRole("button", { name: "Sessions", exact: true }).click();
  const finished = page.locator(`tr[data-session="${sessionID}"]`);
  await expect(finished).toBeVisible({ timeout: 30_000 });
  await finished.getByRole("button", { name: "Replay" }).click({ timeout: 30_000 });
  await expect(page.getByTestId("replay")).toBeVisible();

  // The verdict, above the player, from the gateway's own verifier — a page cannot
  // compute this for itself without also being able to be lied to about it.
  const verdict = page.locator(".oarlock-verdict");
  await expect(verdict).toBeVisible({ timeout: 30_000 });
  await expect(verdict).toHaveAttribute("data-oarlock-tone", "trusted");
  await expect(verdict).toContainText("This recording is intact.");
  await expect(page.locator(".oarlock-replay .ap-player")).toBeVisible();
});

test("an administrator can edit, disable, and re-enable a device", async ({ page }) => {
  await signIn(page);

  const row = await openRow(page, "treadmill-4821");
  const summary = row.locator("button.row-toggle");
  await row.getByRole("button", { name: "Edit" }).click();

  const dialog = page.getByRole("dialog", { name: "Edit device" });
  await dialog.getByLabel("Profiles").fill("shell, log");
  await dialog.getByLabel("Tags").fill("fleet=qa");
  await dialog.getByRole("button", { name: "Save changes" }).click();
  await expect(dialog).toBeHidden();
  await expect(summary).toContainText("log shell");

  page.once("dialog", (confirmation) => confirmation.accept());
  const exited = new Promise<void>((resolve) => dep!.agent.once("exit", () => resolve()));
  await row.getByRole("button", { name: "Disable" }).click();
  await expect(summary).toContainText("Disabled");
  await Promise.race([
    exited,
    new Promise<never>((_, reject) => setTimeout(() => reject(new Error("agent did not exit")), 10_000)),
  ]);

  const refused = await fetch(`http://127.0.0.1:${dep!.http}/api/v1/sessions`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ device_id: "treadmill-4821", profile: "shell", reason: "disabled test" }),
  });
  expect(refused.status).toBe(404);

  await openRow(page, "treadmill-4821");
  await row.getByRole("button", { name: "Enable" }).click();
  await expect(summary).toContainText("Offline");
  dep!.agent = startAgent(dep!.agentBin, dep!.dir, dep!.http);
  await waitFor(async () => {
    const response = await fetch(`http://127.0.0.1:${dep!.http}/api/v1/agents`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const body = await response.json() as { agents: Array<{ device_id: string }> };
    return body.agents.some((agent) => agent.device_id === "treadmill-4821");
  }, "the re-enabled agent to reconnect");
  await expect(summary).toContainText("Online", { timeout: 15_000 });
});
