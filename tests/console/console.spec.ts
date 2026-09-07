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

/** Opens one device's own page (`/d/{id}`) and returns its container. Everything about a
 *  device lives inside it — this used to expand an accordion row in place; now it navigates
 *  there instead, which is the whole point of the task that rewrote it. `data-device` is
 *  carried by both the fleet list's link row and the device page's own root, so the same
 *  selector resolves to whichever of the two is currently on screen: the compact link
 *  before this runs, the full page after. That is also what makes a second call for a
 *  device whose page is already open a no-op, the same as re-"opening" an already-expanded
 *  accordion row used to be. */
async function openRow(page: Page, device: string) {
  const row = page.locator(`[data-device="${device}"]`);
  await expect(row).toBeVisible({ timeout: 30_000 });
  if ((await row.getAttribute("data-testid")) !== "device-page") {
    await row.click();
    await expect(row).toBeVisible({ timeout: 30_000 });
    await expect(row).toHaveAttribute("data-testid", "device-page");
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

  // There is no standalone session list to click a tab to: a session's history lives on
  // its device's own page now, at `/d/{id}`. `Leave` navigates back to search (the route
  // was "session" while attached), so getting back to it means going through `openRow`
  // again rather than assuming a still-expanded row, same as it always did.
  const reopened = await openRow(page, "treadmill-4821");
  // The reason the operator gave is on the row, which is what turns a list into an
  // explanation.
  await expect(reopened.getByText("ticket AV-9300")).toBeVisible({ timeout: 30_000 });
  await expect(reopened.getByText("Not recorded")).toHaveCount(0);
});

// A connected agent is a state of its device, not a second list of the same devices. The
// page it replaced showed treadmill-4821 in a registry table whose STATE column said
// ONLINE and again in a "Live agents" table that existed to say ONLINE.
test("a connected agent is a state of its device, not a separate list", async ({ page }) => {
  await signIn(page);
  await expect(page.getByTestId("fleet-summary")).toContainText("1 online", { timeout: 30_000 });
  await expect(page.getByTestId("fleet-summary")).toContainText("3 devices");

  // `row` is the fleet list's own link at this point — the same `data-device` selector
  // that will resolve to the device's own page below, once `openRow` navigates there.
  const row = page.locator('[data-device="treadmill-4821"]');
  await expect(row).toContainText("Online");
  // The control for the channel is on the device's own page now, and only while it is up.
  await openRow(page, "treadmill-4821");
  await expect(row.getByRole("button", { name: "Stop agent" })).toBeVisible();

  // Back to the list for the offline device: the accordion never left the fleet page to
  // check a second row, but a device page is its own route now, so getting to the next
  // device's row means returning to the list first.
  await page.getByRole("button", { name: "Search", exact: true }).click();
  const absent = page.locator('[data-device="rower-9001"]');
  await expect(absent).toContainText("Offline");
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

  // And it is scoped by tag, so the untagged treadmill next to it is unaffected. A device
  // page is its own route now, so reaching a second device means returning to the list —
  // the accordion never had to leave the fleet page to check a neighbouring row.
  await page.getByRole("button", { name: "Search", exact: true }).click();
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

  // The device page's own "recent sessions" list (`Timeline`, shared with the Person page)
  // shows every session in the default 30-day window, each row keyed by id via
  // `data-session` — so this waits for *this* session's own close and recording to
  // finalise before asking for its row, the same way the old aggregate table's poll was
  // waited out. Targeting the row by this session's own id is what the old table's
  // `.first()` had to fake by relying on "newest first" instead.
  await waitFor(async () => {
    const res = await fetch(`http://127.0.0.1:${dep!.http}/api/v1/sessions/${sessionID}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) return false;
    const body = (await res.json()) as { live: boolean; recording_state: string };
    return !body.live && body.recording_state === "recorded";
  }, "the session to close and its recording to finalise");
  // The fleet page polls on its own four-second timer, so confirming the server's state
  // is not the same as the page already showing it — the reload after "Leave" may well
  // have landed before this session closed. A reload here (safe: this is `/ui/`, the one
  // path depth that is not affected by the asset defect noted below) asks fresh rather
  // than waiting out the poll.
  await page.reload();

  // Replay now lives at the session's own route, `/s/{id}`. There is no "Replay" button on
  // the device page any more — the accordion's row is gone, and with it the button that
  // used to sit beside "Attach"/"Watch". Reaching a closed, recorded session's replay is a
  // click on its own row instead, the same way reaching a live one to attach or watch it
  // is: `SessionRoute`'s own cold load already picks the right body — terminal, player, or
  // failure — from what the session actually is, once the click lands there.
  const reopened = await openRow(page, "treadmill-4821");
  const sessionRow = reopened.locator(`[data-session="${sessionID}"]`);
  await expect(sessionRow).toBeVisible({ timeout: 30_000 });
  await sessionRow.click();
  await expect(page.getByTestId("replay")).toBeVisible();
  // The click navigated, so the URL is now this session's own — the point of the route.
  await expect(page).toHaveURL(new RegExp(`/ui/s/${sessionID}$`));

  // The verdict, above the player, from the gateway's own verifier — a page cannot
  // compute this for itself without also being able to be lied to about it.
  const verdict = page.locator(".oarlock-verdict");
  await expect(verdict).toBeVisible({ timeout: 30_000 });
  await expect(verdict).toHaveAttribute("data-oarlock-tone", "trusted");
  await expect(verdict).toContainText("This recording is intact.");
  await expect(page.locator(".oarlock-replay .ap-player")).toBeVisible();

  // A hard reload of this exact URL, not another client-side navigation. Commit 625fbde
  // fixed the defect that used to sit here: the console was built with a relative
  // `base: "./"`, so its `index.html` resolved its asset URLs one directory too deep
  // under any two-segment route and the bundle 404'd before React ever ran. The base is
  // now the absolute `/ui/`, and the click above already left us on the URL to prove it
  // against: reload, and SessionRoute has to re-fetch this now-closed session's cast and
  // verdict from nothing — the ticket the click minted does not survive a real page load.
  await page.reload();
  await expect(page.getByTestId("replay")).toBeVisible({ timeout: 30_000 });
  await expect(verdict).toBeVisible({ timeout: 30_000 });
  await expect(verdict).toHaveAttribute("data-oarlock-tone", "trusted");
  await expect(verdict).toContainText("This recording is intact.");
  await expect(page.locator(".oarlock-replay .ap-player")).toBeVisible();
});

// The increment's entire point: a session's URL survives a real reload, not only a click
// that happened to land there. Opening the session leaves an in-memory bypass ticket
// behind (see `SessionBypass` in App.tsx) that a hard `page.goto` cannot see, so this can
// only pass if SessionRoute's own cold fetch — the same path a pasted link takes — works.
test("a session URL resolves on a cold load", async ({ page }) => {
  await signIn(page);

  const row = await openRow(page, "treadmill-4821");
  await row.getByTestId("reason").fill("ticket AV-9500");
  await row.getByTestId("open").click();
  await expect(page.locator(".oarlock-term .xterm")).toBeVisible({ timeout: 30_000 });

  // This test's own session, not a neighbour's — the deployment is shared, so `.first()`
  // is only unambiguous because it is scoped to the terminal this test just opened.
  const sessionID = (await page.getByTestId("terminal").locator(".mono").first().textContent())!;
  expect(sessionID).toMatch(/^sess_/);

  // A real document load — a fresh navigation, not `navigate()`'s pushState — so nothing
  // survives from the click above but what the URL itself and sessionStorage's token
  // carry.
  await page.goto(`http://127.0.0.1:${dep!.http}/ui/s/${sessionID}`);
  await expect(page.getByTestId("terminal")).toBeVisible({ timeout: 30_000 });
  await expect(page.getByTestId("terminal").locator(".mono").first()).toHaveText(sessionID);
  await expect(page.locator(".oarlock-term .xterm")).toBeVisible();
});

test("the back button returns you to where you were", async ({ page }) => {
  await signIn(page);
  await expect(page.getByTestId("fleet")).toBeVisible();

  await page.getByRole("button", { name: "Permissions", exact: true }).click();
  await expect(page).toHaveURL(/\/ui\/permissions$/);
  await expect(page.getByTestId("permissions")).toBeVisible();
  // Unmounted, not merely hidden — the fleet page is not on this route.
  await expect(page.getByTestId("fleet")).toHaveCount(0);

  await page.goBack();
  await expect(page).toHaveURL(/\/ui\/$/);
  await expect(page.getByTestId("fleet")).toBeVisible();
  await expect(page.getByTestId("permissions")).toHaveCount(0);
});

// The final review's B1: `opening` and `failure` gate every page body, but nothing used
// to clear them when the nav rail navigated away — the URL changed and the clicked tab
// lit up while the dead wait or failure stayed on screen underneath, and the browser's
// own Back button was just as stuck. Reproduced the same way the review did: fail fast on
// a device with no row to click, which leaves `opening` set on a failed step.
test("navigating away from a dead wait actually renders the destination, not just the URL", async ({ page }) => {
  await signIn(page);
  await page.getByTestId("open-by-id").click();
  await page.getByTestId("open-by-id-device").fill("no-such-device");
  await page.getByTestId("open-by-id-submit").click();

  const waits = page.getByTestId("waits");
  await expect(waits).toBeVisible();
  await expect(waits).toContainText("No such device, or you don't have access to it.", {
    timeout: 20_000,
  });

  // The nav rail renders unconditionally — clicking it is the escape gesture this test
  // exists to prove works, not merely that it does not throw.
  await page.getByRole("button", { name: "Permissions", exact: true }).click();
  await expect(page).toHaveURL(/\/ui\/permissions$/);
  // The URL and the active tab agreeing is not enough — the bug produced exactly that
  // while the old screen stayed mounted underneath. This is the assertion that matters:
  // the wait is gone and the destination is actually on screen.
  await expect(waits).toHaveCount(0);
  await expect(page.getByTestId("permissions")).toBeVisible();
});

// The scoped re-review's finding: a version of this fix that only wired the nav rail's
// own click handler left the browser's Back button dead, because Back fires `popstate`
// directly — it is never a click on the rail, so nothing routed through it. A test that
// presses Back only *after* a nav-rail click has already cleared the wedge (as an earlier
// version of this test did) cannot see that gap: Back then has nothing left to resurrect,
// and passes whether or not popstate itself is handled. This one builds history with a
// nav click, returns to Search the same way, and only *then* wedges the screen — so Back is
// the first and only thing that touches the wedge, with no preceding click doing the
// clearing for it.
test("the browser's own Back unwedges a dead wait too, not only the nav rail", async ({ page }) => {
  await signIn(page);
  await expect(page.getByTestId("fleet")).toBeVisible();

  // History now has an entry to go back to, and clicking through it (rather than
  // `page.goBack()` twice) is what proves the wedge below survives entirely on its own,
  // with no earlier click already having cleared it.
  await page.getByRole("button", { name: "Permissions", exact: true }).click();
  await expect(page).toHaveURL(/\/ui\/permissions$/);
  await page.getByRole("button", { name: "Search", exact: true }).click();
  await expect(page).toHaveURL(/\/ui\/$/);

  // Wedge the screen — same repro as above — without navigating anywhere: `openSession`'s
  // failure path never calls `navigate()`, so this leaves `opening` set on the *current*
  // history entry rather than pushing a new one.
  await page.getByTestId("open-by-id").click();
  await page.getByTestId("open-by-id-device").fill("no-such-device");
  await page.getByTestId("open-by-id-submit").click();
  const waits = page.getByTestId("waits");
  await expect(waits).toBeVisible();
  await expect(waits).toContainText("No such device, or you don't have access to it.", {
    timeout: 20_000,
  });

  // No nav-rail click between here and Back — this is the one action under test.
  await page.goBack();
  await expect(page).toHaveURL(/\/ui\/permissions$/);
  // Rendered content, not the URL: the URL changing is exactly what the bug also did.
  await expect(waits).toHaveCount(0);
  await expect(page.getByTestId("permissions")).toBeVisible();
});

test("an unknown path renders the search screen, not an error", async ({ page }) => {
  await signIn(page);
  await page.goto(`http://127.0.0.1:${dep!.http}/ui/nope/whatever`);
  await expect(page.getByTestId("fleet")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId("failure")).toHaveCount(0);
});

// Named for the regression the plan asked to guard: pushState does not fire popstate, so
// the router's state has to live in one external store rather than a per-component copy,
// or only the component that called navigate() would learn the route changed. What this
// test actually exercises is narrower than the name suggests — production has exactly
// one `useRouter()` call site (`App.tsx`), so a `useState` implementation would pass this
// too; there is only one copy of `route` to disagree with itself. What is genuinely
// checked, and worth having: that `navigate()` triggers a re-render at all, and that the
// URL, the active nav class and the mounted page body agree after it — asserted as pairs
// below so a lagging body or a stuck nav class would show up as a mismatch.
test("every subscriber sees the same route after navigating", async ({ page }) => {
  await signIn(page);

  const searchNav = page.getByRole("button", { name: "Search", exact: true });
  const permissionsNav = page.getByRole("button", { name: "Permissions", exact: true });
  const sqlNav = page.getByRole("button", { name: "SQL Explorer", exact: true });

  await expect(searchNav).toHaveClass(/nav-item-active/);
  await expect(page.getByTestId("fleet")).toBeVisible();

  await permissionsNav.click();
  await expect(page).toHaveURL(/\/ui\/permissions$/);
  await expect(permissionsNav).toHaveClass(/nav-item-active/);
  await expect(searchNav).not.toHaveClass(/nav-item-active/);
  await expect(page.getByTestId("permissions")).toBeVisible();
  await expect(page.getByTestId("fleet")).toHaveCount(0);

  await sqlNav.click();
  await expect(page).toHaveURL(/\/ui\/sql$/);
  await expect(sqlNav).toHaveClass(/nav-item-active/);
  await expect(permissionsNav).not.toHaveClass(/nav-item-active/);
  await expect(page.getByTestId("sql-explorer")).toBeVisible();
  await expect(page.getByTestId("permissions")).toHaveCount(0);

  await searchNav.click();
  await expect(page).toHaveURL(/\/ui\/$/);
  await expect(searchNav).toHaveClass(/nav-item-active/);
  await expect(sqlNav).not.toHaveClass(/nav-item-active/);
  await expect(page.getByTestId("fleet")).toBeVisible();
  await expect(page.getByTestId("sql-explorer")).toHaveCount(0);
});

// Task 3's report established that nothing in the suite drives the failed branch of a
// session's own route at all. A cold link is where an operator actually meets it: a
// session id mistyped, or copied off a system that has since forgotten it — never the
// live session or the just-closed recording every other session test opens for itself.
test("a cold link to a session that does not exist renders the failure screen", async ({ page }) => {
  await signIn(page);
  await page.goto(`http://127.0.0.1:${dep!.http}/ui/s/sess_doesnotexist`);
  const failure = page.getByTestId("failure");
  await expect(failure).toBeVisible({ timeout: 15_000 });
  await expect(failure).toContainText("That isn't there, or you don't have access to it.");
  await expect(page.getByTestId("terminal")).toHaveCount(0);
  await expect(page.getByTestId("replay")).toHaveCount(0);
});

// The final review's B2: `/s/{id}`'s cold load called `client.renewAttach(id)`
// unconditionally on a live session, and apisrv.go refuses that to anyone but the
// session's own operator — so a principal who was not the one who opened it saw the same
// "not_found" screen as a link to a session that never existed, even though the same
// session is one click away through the device page's own timeline row, whose click falls
// back to `observe` for exactly this reason. visitor@example.com is seeded above with a
// shell grant on treadmill-* but no observe grant, so the honest answer once the fix stops
// pre-empting the gateway's own check is *that* refusal — not the sentence reserved for
// "there is nothing here".
test("a deep link to a live session you do not own reports why, not that it does not exist", async ({
  page,
  browser,
}) => {
  await signIn(page);
  const row = await openRow(page, "treadmill-4821");
  await row.getByTestId("reason").fill("ticket AV-9700");
  await row.getByTestId("open").click();
  await expect(page.locator(".oarlock-term .xterm")).toBeVisible({ timeout: 30_000 });

  // This test's own session — the deployment is shared, so `.first()` is only
  // unambiguous scoped to the terminal this test just opened.
  const sessionID = (await page.getByTestId("terminal").locator(".mono").first().textContent())!;
  expect(sessionID).toMatch(/^sess_/);

  // A context of its own: sessionStorage is per browser context, and admin@mail.com —
  // not this principal — is the one who opened the session above.
  const visitorContext = await browser.newContext();
  try {
    const visitorPage = await visitorContext.newPage();
    await signIn(visitorPage, visitorToken);
    await visitorPage.goto(`http://127.0.0.1:${dep!.http}/ui/s/${sessionID}`);

    const failure = visitorPage.getByTestId("failure");
    await expect(failure).toBeVisible({ timeout: 15_000 });
    await expect(failure).not.toContainText("That isn't there, or you don't have access to it.");
    await expect(failure).toContainText("not_authorized");
    await expect(failure).toContainText("don’t have access to do that here");
    await expect(visitorPage.getByTestId("terminal")).toHaveCount(0);
  } finally {
    await visitorContext.close();
  }
});

// Task 6's own regression: the product owner clicked Replay on a session and got a
// full-page failure screen naming a refusal the row could have absorbed itself — the
// console offered the action and only refused on click, by replacing the entire page.
// `visitor@example.com` is seeded with a `shell` grant on treadmill-* and nothing else, so
// replaying somebody else's closed, recorded session on that device is refused for real —
// the same "no permission grants replay" the plugin's authoriser actually returns, not one
// this test fabricates. The fix renders that refusal on the row that made the offer: the
// device page stays exactly where it was, and neither the player nor the full-page
// failure screen ever mounts.
test("a refused replay renders on the row, not as a full page", async ({ page, browser }) => {
  await signIn(page);
  const row = await openRow(page, "treadmill-4821");
  await row.getByTestId("reason").fill("ticket AV-9750");
  await row.getByTestId("open").click();
  await expect(page.locator(".oarlock-term .xterm")).toBeVisible({ timeout: 30_000 });

  const sessionID = (await page.getByTestId("terminal").locator(".mono").first().textContent())!;
  expect(sessionID).toMatch(/^sess_/);

  // Closed and recorded, so the row visitor clicks below is unambiguously a replay
  // attempt rather than an attach/observe one.
  await page.locator(".xterm-helper-textarea").focus();
  await page.keyboard.type("exit");
  await page.keyboard.press("Enter");
  await page.getByRole("button", { name: "Leave" }).click();
  await waitFor(async () => {
    const res = await fetch(`http://127.0.0.1:${dep!.http}/api/v1/sessions/${sessionID}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) return false;
    const body = (await res.json()) as { live: boolean; recording_state: string };
    return !body.live && body.recording_state === "recorded";
  }, "the session to close and its recording to finalise");

  // A context of its own: visitor@example.com, not the admin who opened the session above.
  // `listSessions` is unscoped by identity, so visitor's own device page shows this row —
  // the offer is real, and so is the refusal behind it.
  const visitorContext = await browser.newContext();
  try {
    const visitorPage = await visitorContext.newPage();
    await signIn(visitorPage, visitorToken);
    await visitorPage.goto(`http://127.0.0.1:${dep!.http}/ui/d/treadmill-4821`);

    const sessionRow = visitorPage.locator(`[data-session="${sessionID}"]`);
    await expect(sessionRow).toBeVisible({ timeout: 30_000 });
    await sessionRow.click();

    const refusal = visitorPage.getByTestId("session-refused");
    await expect(refusal).toBeVisible({ timeout: 15_000 });
    await expect(refusal).toContainText("You don’t have access to do that here.");
    await expect(refusal).toContainText("no permission grants replay");
    await expect(refusal).toContainText("treadmill-4821");
    await expect(refusal).toContainText("visitor@example.com");

    // In place: the row's own page, not a full-page failure and not the player. (The
    // device page's own default-window effect may have landed a `?since=` on the URL by
    // now, same as it does on every other visit — this only asserts the path stayed put.)
    await expect(visitorPage).toHaveURL(/\/ui\/d\/treadmill-4821(\?|$)/);
    await expect(visitorPage.getByTestId("device-page")).toBeVisible();
    await expect(visitorPage.getByTestId("failure")).toHaveCount(0);
    await expect(visitorPage.getByTestId("replay")).toHaveCount(0);

    // The row itself is still exactly what it was — clickable again, not disabled. The
    // console does not get to decide from the client side that this row is unusable;
    // only the gateway's refusal, rendered here, says so.
    await expect(sessionRow.getByRole("button", { name: `Open session ${sessionID}` })).toBeEnabled();
  } finally {
    await visitorContext.close();
  }
});

test("an administrator can edit, disable, and re-enable a device", async ({ page }) => {
  await signIn(page);

  // Edit, Disable/Enable, Stop agent and Delete moved off the fleet row's accordion and
  // onto the device page itself — the only place any of them renders now — alongside
  // `device-summary`, the paragraph that used to be the accordion's own header line.
  const row = await openRow(page, "treadmill-4821");
  const summary = row.getByTestId("device-summary");
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
  // `DevicePage`'s own wording, unchanged from Task 3: lower-case, and distinct from the
  // fleet list's capitalised "Disabled"/"Online"/"Offline" summary — the two pages use
  // their own vocabularies for the same fact, same as the mockup does.
  await expect(summary).toContainText("disabled");
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
  await expect(summary).toContainText("offline");
  dep!.agent = startAgent(dep!.agentBin, dep!.dir, dep!.http);
  await waitFor(async () => {
    const response = await fetch(`http://127.0.0.1:${dep!.http}/api/v1/agents`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const body = await response.json() as { agents: Array<{ device_id: string }> };
    return body.agents.some((agent) => agent.device_id === "treadmill-4821");
  }, "the re-enabled agent to reconnect");
  await expect(summary).toContainText("connected", { timeout: 15_000 });
});

// The Person page's first question: what did this person do. A cold `page.goto`, not a
// click from somewhere already inside the app — the route's whole point is that a pasted
// link works on its own.
test("a person page reached by URL lists that person's sessions", async ({ page }) => {
  await signIn(page);

  // This test's own session, not a neighbour's — the deployment is shared across the
  // file, so the assertion below is scoped to the row this test made rather than to
  // "the list is non-empty".
  const row = await openRow(page, "treadmill-4821");
  await row.getByTestId("reason").fill("ticket AV-9800");
  await row.getByTestId("open").click();
  await expect(page.locator(".oarlock-term .xterm")).toBeVisible({ timeout: 30_000 });
  const sessionID = (await page.getByTestId("terminal").locator(".mono").first().textContent())!;
  expect(sessionID).toMatch(/^sess_/);

  await page.goto(`http://127.0.0.1:${dep!.http}/ui/p/admin%40mail.com`);
  await expect(page.getByTestId("person-page")).toBeVisible({ timeout: 30_000 });
  const sessions = page.getByTestId("person-sessions");
  await expect(sessions.locator(`[data-session="${sessionID}"]`)).toBeVisible({ timeout: 30_000 });
});

// The Person page's default window lands in the URL rather than staying only in state
// (see the effect in PersonPage.tsx), and every other facet round-trips the same way. A
// link is only a link if it reproduces the view the sender saw — so a `since` supplied in
// the URL has to actually narrow the query, not just decorate it.
test("the facets in the URL narrow the timeline", async ({ page }) => {
  await signIn(page);

  // This test makes its own session rather than relying on one a sibling left behind.
  //
  // Without it the assertion below is order-dependent: a window starting in the future is
  // empty whether or not `since` reaches the query, so with no sessions in the ledger the
  // test passes against a page that ignores the facet entirely. It only fails in sequence,
  // after an earlier test has created something to leak. That is a test which proves the
  // feature works when run one way and nothing at all when run another, and `--grep` runs
  // it the second way.
  const seedRow = await openRow(page, "treadmill-4821");
  await seedRow.getByTestId("reason").fill("ticket AV-9310");
  await seedRow.getByTestId("open").click();
  await expect(page.locator(".oarlock-term .xterm")).toBeVisible({ timeout: 30_000 });
  await page.getByRole("button", { name: "Leave" }).click();

  // The default window shows it, which is what makes the future window's emptiness mean
  // something: the same page, the same principal, one facet apart.
  await page.goto(`http://127.0.0.1:${dep!.http}/ui/p/admin%40mail.com`);
  await expect(page.getByTestId("person-sessions")).toContainText("treadmill-4821", {
    timeout: 30_000,
  });

  const future = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  await page.goto(
    `http://127.0.0.1:${dep!.http}/ui/p/admin%40mail.com?since=${encodeURIComponent(future)}`,
  );
  await expect(page.getByTestId("person-page")).toBeVisible({ timeout: 30_000 });

  // The facet survived rather than being silently replaced by the 30-day default: the
  // effect that lands that default only fires when `since` is absent.
  const url = new URL(page.url());
  expect(url.searchParams.get("since")).toBe(future);

  // A window that starts in the future contains nothing — including every session the
  // tests above and below this one create — so the ready-but-empty state is the only one
  // that can render here. Asserting the literal text (rather than merely that the
  // section exists) is what rules out a page stuck loading or a request that failed.
  const sessions = page.getByTestId("person-sessions");
  await expect(sessions).toContainText("No sessions in this window.", { timeout: 30_000 });
});

// The Person page's second question, for the principal it is actually built for: an
// auditor who very often will not hold `admin:permissions` themselves. Modelled on "a
// device row will not invent an access list it cannot read" (above) — the same design,
// applied to a person instead of a device: the grants section stays on screen and names
// the missing grant, rather than going quiet in a way that would read as "permitted
// nothing".
test("a visitor sees the timeline, and a grants section that says why it is empty", async ({
  page,
}) => {
  await signIn(page, visitorToken);

  // This principal's own session, so the sessions section has something real to show —
  // not merely a section that renders without crashing.
  const row = await openRow(page, "treadmill-4821");
  await row.getByTestId("reason").fill("ticket AV-9900");
  await row.getByTestId("open").click();
  await expect(page.locator(".oarlock-term .xterm")).toBeVisible({ timeout: 30_000 });
  const sessionID = (await page.getByTestId("terminal").locator(".mono").first().textContent())!;
  expect(sessionID).toMatch(/^sess_/);

  await page.goto(`http://127.0.0.1:${dep!.http}/ui/p/visitor%40example.com`);
  await expect(page.getByTestId("person-page")).toBeVisible({ timeout: 30_000 });

  const sessions = page.getByTestId("person-sessions");
  await expect(sessions.locator(`[data-session="${sessionID}"]`)).toBeVisible({ timeout: 30_000 });

  // The grants section itself: present, not hidden — visitor@example.com holds a shell
  // grant and nothing administrative, so this section has to name what is missing rather
  // than disappear or render an empty rule list.
  const access = page.getByTestId("person-access");
  await expect(access).toBeVisible();
  await expect(access).toContainText("don’t have access", { timeout: 30_000 });
  await expect(access).toContainText("admin:permissions");
  await expect(access).not.toContainText("Allowed");
  await expect(access.locator("ul")).toHaveCount(0);
});
