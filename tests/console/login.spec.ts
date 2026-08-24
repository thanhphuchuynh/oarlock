// Signing in to the console through an identity provider, in a real browser.
//
// Not a stub of the flow: an actual OpenID Connect provider on a socket, an actual
// `oarlockd` configured against it, and Chromium following every redirect. The reason to
// go to that trouble is that almost everything which can go wrong here is invisible to a
// unit test — a redirect the browser normalises differently than the server did, a
// handoff consumed twice because something retried, a sign-in screen that flashes before
// the gateway has said which one to show.

import { test, expect } from "@playwright/test";
import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { createServer, type Server } from "node:http";
import { createSign, generateKeyPairSync, randomUUID } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import net from "node:net";

const repo = resolve(import.meta.dirname, "../..");
const clientID = "oarlock-console-test";

function b64url(b: Buffer | string): string {
  return Buffer.from(b).toString("base64url");
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

/**
 * A provider that approves immediately.
 *
 * `/authorize` redirects straight back to the gateway's callback rather than rendering a
 * consent screen: what is under test is the gateway's half of the flow, and a fake login
 * form would only be testing the fake.
 */
class Provider {
  readonly key = generateKeyPairSync("rsa", { modulusLength: 2048 });
  private server?: Server;
  url = "";
  /** Set by the test to make the provider refuse, the way a policy denial arrives. */
  refuse: string | null = null;

  async start(): Promise<void> {
    const port = await freePort();
    this.url = `http://127.0.0.1:${port}`;
    const jwk = this.key.publicKey.export({ format: "jwk" }) as { n: string; e: string };

    this.server = createServer((req, res) => {
      const url = new URL(req.url ?? "/", this.url);
      const json = (body: unknown, status = 200) => {
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify(body));
      };

      switch (url.pathname) {
        case "/.well-known/openid-configuration":
          return json({
            issuer: this.url,
            jwks_uri: `${this.url}/jwks`,
            authorization_endpoint: `${this.url}/authorize`,
            token_endpoint: `${this.url}/token`,
          });

        case "/jwks":
          return json({ keys: [{ kty: "RSA", kid: "k1", use: "sig", alg: "RS256", ...jwk }] });

        case "/authorize": {
          // Straight back to the gateway, carrying the state it gave us. A provider that
          // dropped the state would be a different test.
          const back = new URL(url.searchParams.get("redirect_uri") ?? "");
          if (this.refuse) {
            back.searchParams.set("error", this.refuse);
            back.searchParams.set("error_description", "not in the required group");
          } else {
            back.searchParams.set("code", "code-" + randomUUID());
            back.searchParams.set("state", url.searchParams.get("state") ?? "");
          }
          res.writeHead(303, { location: back.toString() });
          return res.end();
        }

        case "/token": {
          let body = "";
          req.on("data", (c) => (body += c));
          req.on("end", () => {
            const form = new URLSearchParams(body);
            // PKCE is checked, not merely accepted: a verifier that is sent but never
            // verified is a verifier that could be removed without a test noticing.
            if (!form.get("code_verifier")) {
              return json({ error: "invalid_request", error_description: "no code_verifier" }, 400);
            }
            json({
              token_type: "Bearer",
              expires_in: 3600,
              id_token: this.mint(),
            });
          });
          return;
        }

        default:
          res.writeHead(404);
          return res.end();
      }
    });
    await new Promise<void>((r) => this.server!.listen(port, "127.0.0.1", r));
  }

  /** mint signs an id_token for the operator this suite signs in as. */
  mint(email = "amelia@example.com"): string {
    const now = Math.floor(Date.now() / 1000);
    const header = b64url(JSON.stringify({ alg: "RS256", typ: "JWT", kid: "k1" }));
    const payload = b64url(
      JSON.stringify({
        iss: this.url,
        sub: "subject-1",
        aud: clientID,
        exp: now + 3600,
        iat: now,
        email,
        email_verified: true,
        groups: ["oncall"],
      }),
    );
    const signer = createSign("RSA-SHA256");
    signer.update(`${header}.${payload}`);
    return `${header}.${payload}.${b64url(signer.sign(this.key.privateKey))}`;
  }

  async stop(): Promise<void> {
    await new Promise<void>((r) => this.server?.close(() => r()));
  }
}

interface Deployment {
  provider: Provider;
  gateway: ChildProcess;
  http: number;
  dir: string;
}

let dep: Deployment | undefined;

test.beforeAll(async () => {
  const oarlockd = join(tmpdir(), "oarlockd-login-test");
  const agentBin = join(tmpdir(), "oarlock-agent-login-test");
  execFileSync("go", ["build", "-o", oarlockd, "./cmd/oarlockd"], { cwd: repo });
  execFileSync("go", ["build", "-o", agentBin, "./cmd/oarlock-agent"], { cwd: repo });

  const provider = new Provider();
  await provider.start();

  const dir = mkdtempSync(join(tmpdir(), "oarlock-login-"));
  const sshPort = await freePort();
  const httpPort = await freePort();
  const devPub = execFileSync(agentBin, ["-key", join(dir, "device.key"), "-generate-key"], {
    cwd: dir,
  })
    .toString()
    .trim();
  execFileSync("ssh-keygen", ["-t", "ed25519", "-N", "", "-f", join(dir, "operator_key")], {
    stdio: "ignore",
  });

  writeFileSync(
    join(dir, "oarlock.yaml"),
    `env: dev
url: ws://127.0.0.1:${httpPort}
listen:
  ssh: "127.0.0.1:${sshPort}"
  http: "127.0.0.1:${httpPort}"
ssh:
  host_key: ./hostkey
  generate_host_key: true
store:
  kind: sqlite
  path: ./oarlock.db
devices:
  kind: sqlite
auth:
  kind: oidc
  issuer: ${provider.url}
  client_id: ${clientID}
  scopes: [email, groups]
  # Loopback http is the one non-https callback the config gate allows, and a browser
  # treats it as a secure context — so the Secure cookies still come back. That also
  # means this suite cannot catch a Secure-flag mistake, and neither can it catch a
  # SameSite one: a provider and a gateway both on 127.0.0.1 are same-site whatever
  # their ports. Both were checked by injection and both passed, which is how those
  # limits are known rather than assumed.
  redirect_url: http://127.0.0.1:${httpPort}/auth/callback
authorizer:
  kind: sqlite
  admins:
    - amelia@example.com
recorder:
  dir: ./recordings
  signing_key: ./recording.key
  generate_signing_key: true
api:
  rate_per_minute: 6000
`,
  );

  const gateway = spawn(oarlockd, ["-config", "./oarlock.yaml"], { cwd: dir });
  gateway.stderr.on("data", (b: Buffer) => {
    if (process.env["OARLOCK_TEST_VERBOSE"]) process.stdout.write(`[gw] ${b}`);
  });
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const r = await fetch(`http://127.0.0.1:${httpPort}/healthz`).catch(() => null);
    if (r?.ok) break;
    await new Promise((r) => setTimeout(r, 100));
  }

  // Seeded with a provider-minted token, which also proves the API accepts one: there
  // are no static tokens on this gateway at all.
  const bearer = provider.mint();
  const seed = async (path: string, body: unknown) => {
    const res = await fetch(`http://127.0.0.1:${httpPort}${path}`, {
      method: "POST",
      headers: { Authorization: `Bearer ${bearer}`, "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`${path}: ${res.status} ${await res.text()}`);
  };
  await seed("/api/v1/devices", {
    id: "treadmill-4821",
    platform: "linux",
    mode: "persistent",
    keys: [devPub],
    profiles: ["shell"],
  });
  await seed("/api/v1/permissions", {
    id: "oncall",
    name: "On call",
    principals: ["amelia@example.com"],
    devices: ["*"],
    actions: ["shell", "admin:permissions", "admin:devices"],
    effect: "allow",
    enabled: true,
  });

  dep = { provider, gateway, http: httpPort, dir };
});

test.afterAll(async () => {
  dep?.gateway.kill("SIGTERM");
  await dep?.provider.stop();
});

// TestSigningIn: the whole flow, in a browser, with nothing pasted.
test("an operator signs in through the provider and never sees a token", async ({ page }) => {
  const base = `http://127.0.0.1:${dep!.http}`;
  await page.goto(`${base}/ui/`);

  // No paste field. This is the point of the story: the console used to ask for a
  // long-lived shared secret.
  await expect(page.getByTestId("sign-in")).toBeVisible();
  await expect(page.getByPlaceholder("token")).toHaveCount(0);

  await page.getByTestId("sign-in").click();

  // Through the provider and back, landing on the fleet.
  await expect(page.getByTestId("fleet")).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('[data-device="treadmill-4821"]')).toBeVisible();
  // Signed in as the person the provider vouched for, taken from the email claim.
  await expect(page.getByText("amelia@example.com").first()).toBeVisible();

  // The token is the provider's, held in this tab only.
  const stored = await page.evaluate(() => sessionStorage.getItem("oarlock.token"));
  expect(stored?.split(".").length).toBe(3);

  // And the handoff cookie is gone: it was redeemable once, and it has been redeemed.
  const cookies = await page.context().cookies();
  expect(cookies.filter((c) => c.name === "oarlock_handoff")).toHaveLength(0);
});

test("a reload keeps the operator signed in without another round trip", async ({ page }) => {
  const base = `http://127.0.0.1:${dep!.http}`;
  await page.goto(`${base}/ui/`);
  await page.getByTestId("sign-in").click();
  await expect(page.getByTestId("fleet")).toBeVisible({ timeout: 30_000 });

  await page.reload();
  // Straight to the fleet: the token is in sessionStorage, so there is no sign-in screen
  // and no second visit to the provider.
  await expect(page.getByTestId("fleet")).toBeVisible();
  await expect(page.getByTestId("sign-in")).toHaveCount(0);
});

test("signing out returns the operator to the sign-in screen", async ({ page }) => {
  const base = `http://127.0.0.1:${dep!.http}`;
  await page.goto(`${base}/ui/`);
  await page.getByTestId("sign-in").click();
  await expect(page.getByTestId("fleet")).toBeVisible({ timeout: 30_000 });

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByTestId("sign-in")).toBeVisible();
  const stored = await page.evaluate(() => sessionStorage.getItem("oarlock.token"));
  expect(stored).toBeNull();
});

test("a provider refusal is shown, not swallowed", async ({ page }) => {
  const base = `http://127.0.0.1:${dep!.http}`;
  dep!.provider.refuse = "access_denied";
  try {
    await page.goto(`${base}/ui/`);
    await page.getByTestId("sign-in").click();
    // The gateway's own page, because there is no console to render into: an operator
    // who cannot sign in cannot be shown the application.
    await expect(page.getByText(/refused/i)).toBeVisible({ timeout: 30_000 });
    // And it says what the provider said, because "not in the required group" is a
    // policy somebody can act on rather than a bug to report.
    await expect(page.getByText(/not in the required group/)).toBeVisible();
  } finally {
    dep!.provider.refuse = null;
  }
});

test("the console signs in to a shell that works", async ({ page }) => {
  const base = `http://127.0.0.1:${dep!.http}`;
  const agentBin = join(tmpdir(), "oarlock-agent-login-test");
  const agent = spawn(
    agentBin,
    [
      "-gateway",
      `ws://127.0.0.1:${dep!.http}/ws/control`,
      "-device",
      "treadmill-4821",
      "-key",
      "./device.key",
      "-shell",
      "/bin/sh",
      "-insecure-skip-pin",
    ],
    { cwd: dep!.dir },
  );
  try {
    await new Promise((r) => setTimeout(r, 1500));
    await page.goto(`${base}/ui/`);
    await page.getByTestId("sign-in").click();
    await expect(page.getByTestId("fleet")).toBeVisible({ timeout: 30_000 });

    const row = page.locator('[data-device="treadmill-4821"]');
    await row.locator("button.row-toggle").click();
    await row.getByTestId("reason").fill("signed in through the provider");
    await row.getByTestId("open").click();

    await expect(page.locator(".oarlock-term .xterm")).toBeVisible({ timeout: 30_000 });
    await page.locator(".xterm-helper-textarea").focus();
    await page.keyboard.type("printf 'OIDC%s\\n' '-OK'");
    await page.keyboard.press("Enter");
    await expect(page.locator(".xterm-rows")).toContainText("OIDC-OK", { timeout: 30_000 });
  } finally {
    agent.kill("SIGTERM");
  }
});
