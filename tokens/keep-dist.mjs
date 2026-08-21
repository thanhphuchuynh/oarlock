// Restores the placeholder that --emptyOutDir deletes.
//
// cmd/oarlockd/app/ui/dist is embedded with `go:embed all:dist`, which fails to *compile*
// when the directory is absent. So the directory has to exist in git, the build empties
// it, and this puts the marker back — otherwise the first `pnpm build:ui` after a clone
// silently removes the thing that lets `go build` work on the next clone.
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const path = resolve(repo, "cmd/oarlockd/app/ui/dist/.gitkeep");

mkdirSync(dirname(path), { recursive: true });
writeFileSync(
  path,
  `The built console lands in this directory: \`pnpm build:ui\`.

This file is committed, and it is not decoration. \`ui.go\` embeds this directory with
\`go:embed all:dist\`, which is a compile-time failure when the directory does not exist —
so without a placeholder, \`go build ./...\` on a fresh clone fails before it can tell you
that the console is optional. Which it is: a gateway built with nothing here works, and
serves /ui with instructions instead of a blank page.

\`pnpm build:ui\` passes --emptyOutDir and deletes this file, so the script recreates it.
`,
);
