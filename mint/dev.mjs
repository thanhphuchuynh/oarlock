#!/usr/bin/env node
/** Run `mint dev` on a Node mint accepts (20.17–24). Node 25+ is refused by the CLI. */
import { spawn } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import { createConnection } from "node:net";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// 3000 by default because the Documents links assume http://localhost:3000/. Override it
// when something else already owns that port — another project's dev server, usually —
// and know that those links will then point at a port nothing is serving.
const PORT = Number(process.env.OARLOCK_DOCS_PORT || 3000);

function portBusy(port) {
  return new Promise((resolve) => {
    const s = createConnection({ port, host: "127.0.0.1" }, () => {
      s.end();
      resolve(true);
    });
    s.on("error", () => resolve(false));
  });
}

function mintNode() {
  const major = Number(process.versions.node.split(".")[0]);
  const minor = Number(process.versions.node.split(".")[1] || 0);
  const ok = (major === 20 && minor >= 17) || (major >= 21 && major <= 24);
  if (ok) return { node: process.execPath, bin: dirname(process.execPath) };

  const nvm = join(homedir(), ".nvm/versions/node");
  if (existsSync(nvm)) {
    const vers = readdirSync(nvm).filter((v) => /^v22\./.test(v)).sort();
    if (vers.length) {
      const bin = join(nvm, vers.at(-1), "bin");
      return { node: join(bin, "node"), bin };
    }
  }
  console.error(
    `mint requires Node >= 20.17 and does not support Node 25+.\n` +
    `This process is Node ${process.version}. Install Node 22 (nvm install 22) and retry.`,
  );
  process.exit(1);
}

if (await portBusy(PORT)) {
  console.error(
    `port ${PORT} is already in use. Landing Documents links assume http://localhost:3000/.\n` +
    `Stop the other process, or set OARLOCK_DOCS_PORT to a free one (those links will then miss).`,
  );
  process.exit(1);
}

const { bin } = mintNode();
const npx = join(bin, "npx");
const child = spawn(npx, ["--yes", "mint", "dev", "--port", String(PORT)], {
  stdio: "inherit",
  cwd: dirname(fileURLToPath(import.meta.url)),
  env: { ...process.env, PATH: `${bin}:${process.env.PATH || ""}` },
});
child.on("exit", (code) => process.exit(code ?? 1));
