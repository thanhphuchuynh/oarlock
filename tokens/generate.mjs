// Generates every palette in the product from tokens/tokens.json.
//
// Two consumers, one source: the component ships CSS custom properties (no framework,
// because it renders inside somebody else's application) and the console uses Tailwind.
// Maintaining both by hand is how "a colour is never written twice" quietly becomes
// false, so both are emitted here and `--check` fails CI when they are stale (R-013).
//
// Run: node tokens/generate.mjs [--check]
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const src = JSON.parse(readFileSync(resolve(root, "tokens/tokens.json"), "utf8"));
const check = process.argv.includes("--check");

const groups = Object.entries(src).filter(([k]) => !k.startsWith("$"));
const flat = groups.flatMap(([group, members]) =>
  Object.entries(members).map(([name, v]) => ({
    group,
    name,
    css: `--oarlock-${group === "text" || group === "surface" ? "" : group + "-"}${name}`,
    light: v.light,
    dark: v.dark,
  })),
);

const banner = (from) =>
  `/* GENERATED FROM ${from} — do not edit. Run \`pnpm tokens\`. */\n`;

// ── the component's custom properties ───────────────────────────────────────────
//
// Every value is defined on the bare root, and dark only *overrides*: the component
// has to render correctly inside a host that has stamped no theme at all, which is the
// majority case. A token whose only definition sits behind a dark selector renders one
// theme's text on the other theme's ground.
const decls = (side, indent) =>
  flat.map((t) => `${indent}${t.css}: ${t[side]};`).join("\n");

const css = `${banner("tokens/tokens.json")}
.oarlock-term {
${decls("light", "  ")}
}

/* The host has asked for dark, or asked for nothing and its OS says dark. Scoped
   under the component root like everything else, so we never touch the host's :root. */
@media (prefers-color-scheme: dark) {
  .oarlock-term:not([data-oarlock-theme="light"]) {
${decls("dark", "    ")}
  }
}

.oarlock-term[data-oarlock-theme="dark"] {
${decls("dark", "  ")}
}
`;

// ── the console's Tailwind theme ────────────────────────────────────────────────
const tw = `${banner("tokens/tokens.json")}
@theme {
${flat.map((t) => `  --color-${t.css.replace("--oarlock-", "")}: var(${t.css});`).join("\n")}
}

/* The console is a normal application, so here the tokens do live on :root. */
:root {
${decls("light", "  ")}
}

@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
${decls("dark", "    ")}
  }
}

:root[data-theme="dark"] {
${decls("dark", "  ")}
}
`;

// ── the terminal's xterm theme, as data ─────────────────────────────────────────
//
// xterm.js takes colours as a JS object, not CSS, so a custom property is no use to it
// and this is the one place the values have to cross into JavaScript.
const xtermSlot = (name) => `"${name.replace(/-([a-z])/g, (_, c) => c.toUpperCase())}"`;
const term = src.terminal;
// selection is spelled selectionBackground by xterm and is emitted explicitly below,
// so it would otherwise appear twice under two names.
const xtermTheme = (side) =>
  Object.entries(term)
    .filter(([name]) => name !== "selection")
    .map(([name, v]) => `    ${xtermSlot(name)}: "${v[side]}"`)
    .join(",\n");

const ts = `${banner("tokens/tokens.json")}
// The palette xterm.js needs as data. Generated, so it cannot drift from the CSS.
export interface XtermPalette {
  readonly background: string;
  readonly foreground: string;
  readonly cursor: string;
  readonly selectionBackground: string;
  readonly [slot: string]: string;
}

export const palette: { readonly light: XtermPalette; readonly dark: XtermPalette } = {
  light: {
    background: "${src.surface["bg-terminal"].light}",
    foreground: "${src.text.fg.dark}",
    selectionBackground: "${term.selection.light}",
${xtermTheme("light")}
  },
  dark: {
    background: "${src.surface["bg-terminal"].dark}",
    foreground: "${src.text.fg.dark}",
    selectionBackground: "${term.selection.dark}",
${xtermTheme("dark")}
  },
};
`;

const outputs = [
  ["packages/terminal/src/tokens.css", css],
  ["packages/terminal/src/palette.ts", ts],
  ["web/src/tokens.css", tw],
];

let stale = [];
for (const [rel, want] of outputs) {
  const path = resolve(root, rel);
  let have = null;
  try {
    have = readFileSync(path, "utf8");
  } catch {
    /* absent counts as stale */
  }
  if (have === want) continue;
  if (check) {
    stale.push(rel);
    continue;
  }
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, want);
  console.log(`wrote ${rel}`);
}

if (stale.length) {
  console.error(
    `Generated token files are stale:\n  ${stale.join("\n  ")}\n\n` +
      `A colour has been written twice, or tokens.json changed without regenerating.\n` +
      `Run \`pnpm tokens\` and commit the result.`,
  );
  process.exit(1);
}
if (check) console.log("token files are current");
