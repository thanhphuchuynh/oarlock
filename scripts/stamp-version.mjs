#!/usr/bin/env node
/** Write the product version into the JS packages. Called by `make stamp-version`. */
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const raw = process.argv[2] || "";
const version = raw.replace(/^v/, "");
if (!/^\d+\.\d+\.\d+$/.test(version)) {
  console.error(`stamp-version: ${raw || "(empty)"} is not a product version (v0.1.0)`);
  process.exit(1);
}

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
for (const rel of ["packages/terminal/package.json", "packages/react/package.json"]) {
  const path = join(root, rel);
  const pkg = JSON.parse(readFileSync(path, "utf8"));
  pkg.version = version;
  writeFileSync(path, JSON.stringify(pkg, null, 2) + "\n");
  console.log(`${rel} -> ${version}`);
}
