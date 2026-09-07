/* Builds sheets 2 and 3: the document register, and one sheet per specification.
 *
 * Sheet 1 (index.html) has always claimed "Sheet 1 of 3" and linked its Documents band at
 * `../docs/protocol.md`. Served from landing/dist that path is outside the served root, so
 * all fourteen of those links were dead, and the other two sheets did not exist. This
 * renders them from the Markdown that is already the source of truth, so the register
 * cannot describe a document the repository does not have.
 *
 * Markdown is parsed at build time and the output is static HTML. `marked` is a
 * devDependency and nothing it does reaches a reader: these pages ship no JavaScript
 * beyond the eleven lines that light the current clause in the index.
 *
 *   node landing/documents.mjs [--out landing/dist]
 *
 * Run after `vite build --mode landing`, which owns index.html and its assets.
 */

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync, copyFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { marked, Renderer } from "marked";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const outArg = process.argv.indexOf("--out");
const outRoot = resolve(repo, outArg > -1 ? process.argv[outArg + 1] : "landing/dist");
const out = join(outRoot, "documents");

/* The register. Order is the reading order, and the numeral is the document's number on
 * the register — the same idiom as a numbered part on the drawing, and answerable the same
 * way. Glosses say what the document is for; none of them may promise more than it holds.
 */
const REGISTER = [
  { src: "README.md", slug: "overview", name: "Overview",
    group: "The gateway", gloss: "What it is, the quickstart, and the transcript of a real session." },
  { src: "ARCHITECTURE.md", slug: "architecture", name: "Architecture",
    group: "The gateway", gloss: "Every component, the decision records, and the limits each one is under." },
  { src: "docs/protocol.md", slug: "protocol", name: "Protocol",
    group: "The wire", gloss: "Wire version 0. Frames, the handshake, the profiles, and what is unstable." },
  { src: "docs/sdk.md", slug: "sdk", name: "SDK",
    group: "The wire", gloss: "Writing an agent: the control channel, the session leg, and the conformance suite." },
  { src: "docs/plugins.md", slug: "plugins", name: "Plugins",
    group: "The wire", gloss: "The authorizer, dispatcher, registry and recorder seams, and what a backend owes." },
  { src: "docs/threat-model.md", slug: "threat-model", name: "Threat model",
    group: "Security", gloss: "Assets, adversaries, the boundaries, and § 12 — what is not yet defended." },
  { src: "SECURITY.md", slug: "security", name: "Reporting",
    group: "Security", gloss: "How to report a vulnerability, and what to expect after you do." },
  { src: "docs/per-operator-identity.md", slug: "per-operator-identity", name: "Per-operator identity",
    group: "Security", gloss: "Mapping an operator to a device account, and why the gateway does not run as root." },
  { src: "docs/metrics.md", slug: "metrics", name: "Metrics",
    group: "Operating", gloss: "Every series the gateway exports, and the ones worth alerting on." },
  { src: "docs/android.md", slug: "android", name: "Android",
    group: "Operating", gloss: "Running the agent on a headset or a system image, and what the app cannot do." },
  { src: "docs/rust-implementation.md", slug: "rust-implementation", name: "Rust agent",
    group: "Operating", gloss: "Notes for a second implementation of the agent, and where the wire is load-bearing." },
  { src: "docs/diagrams/README.md", slug: "drawings", name: "Drawings",
    group: "Operating", gloss: "The three authored figures, what each is for, and how to regenerate them." },
];

const bySlug = new Map(REGISTER.map((d) => [d.slug, d]));
const byBase = new Map(REGISTER.map((d) => [basename(d.src).toLowerCase(), d]));
byBase.set("readme.md", bySlug.get("overview")); // README at the root, not the drawing index
const number = new Map(REGISTER.map((d, i) => [d.slug, String(i + 1).padStart(2, "0")]));

const unresolved = new Map();

// ── markdown ──────────────────────────────────────────────────────────────────────

const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
  .replace(/"/g, "&quot;");

/* GitHub's heading-slug rule, not one of our own.
 *
 * Every cross-reference in these documents was hand-written against it — ARCHITECTURE.md
 * says `plugins.md#42-storage-immutability-…` for "### 4.2 Storage immutability, …", with
 * the dot dropped rather than turned into a separator. A slug function that is merely
 * self-consistent would renumber every one of those clauses and break all 37 links while
 * looking entirely correct. So: lowercase, drop anything that is not a word character,
 * space or hyphen, then spaces to hyphens — which is what the fragments already assume.
 */
const slugify = (s) =>
  s.toLowerCase().replace(/[^\w\s-]/g, "").trim().replace(/\s/g, "-") || "clause";

let headings = [];
let seen = new Map();

/* A repository path that this register does not publish. There is no remote to link it
 * to, so the honest render is the path itself, set as a path. */
function unpublished(href, label) {
  unresolved.set(href, (unresolved.get(href) ?? 0) + 1);
  return `<code title="repository path, not published here">${label}</code>`;
}

const renderer = {
  heading(token) {
    const html = this.parser.parseInline(token.tokens);
    const text = html.replace(/<[^>]+>/g, "");
    let id = slugify(text);
    if (seen.has(id)) {
      const n = seen.get(id) + 1;
      seen.set(id, n);
      id = `${id}-${n}`;
    } else seen.set(id, 1);
    if (token.depth >= 2 && token.depth <= 3) headings.push({ id, text, depth: token.depth });
    const anchor = token.depth === 1 ? "" :
      `<a class="anchor" href="#${id}" aria-label="Link to this clause">§</a>`;
    return `<h${token.depth} id="${id}">${html}${anchor}</h${token.depth}>\n`;
  },

  code({ text, lang }) {
    const tag = (lang || "").trim().split(/\s+/)[0].toLowerCase();
    // A mermaid fence is diagram source. Rendering it as prose would be a lie about what
    // the reader is looking at, and pulling in a renderer would import a palette this
    // sheet does not have. The authored figures are on the drawings sheet.
    const diagram = tag === "mermaid";
    const label = diagram ? "Diagram source · mermaid" : (tag || "text");
    const note = diagram
      ? `<span>see <a href="drawings.html">the drawings</a></span>`
      : `<span>${text.split("\n").length} lines</span>`;
    return `<figure class="fence wide${diagram ? " fence--diagram" : ""}">` +
      `<figcaption class="fence-head"><span>${esc(label)}</span>${note}</figcaption>` +
      `<pre><code>${esc(text)}</code></pre></figure>\n`;
  },

  link(token) {
    const label = this.parser.parseInline(token.tokens);
    const href = token.href || "";
    if (/^(https?:|mailto:|#)/.test(href)) {
      const ext = /^https?:/.test(href) ? ' rel="noopener noreferrer"' : "";
      return `<a href="${esc(href)}"${ext}${token.title ? ` title="${esc(token.title)}"` : ""}>${label}</a>`;
    }
    // A repository-relative path. Markdown documents on the register become sheets.
    const [path, frag = ""] = href.split("#");
    const clean = path.replace(/^(\.\.?\/)+/, "");
    const hit = bySlug.get(clean.replace(/\.md$/, "")) ??
      (clean.toLowerCase().endsWith(".md") ? byBase.get(basename(clean).toLowerCase()) : null);
    if (hit) return `<a href="${hit.slug}.html${frag ? "#" + slugify(frag) : ""}">${label}</a>`;
    if (/openapi\.ya?ml$/.test(clean)) return `<a href="openapi.yaml">${label}</a>`;
    return unpublished(href, label);
  },

  table(token) {
    return `<div class="wide">${Renderer.prototype.table.call(this, token)}</div>\n`;
  },
};

marked.use({ renderer, gfm: true, breaks: false });

// ── chrome ────────────────────────────────────────────────────────────────────────

const gitMeta = (src) => {
  try {
    const o = execFileSync("git", ["log", "-1", "--format=%cs %h", "--", src],
      { cwd: repo, encoding: "utf8" }).trim();
    return o || "uncommitted";
  } catch {
    return "uncommitted";
  }
};

function chrome({ title, sheet, docNo, nav, body, depthNote, self }) {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${esc(title)} — Oarlock</title>
    <meta name="description" content="${esc(depthNote)}" />
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link
      href="https://fonts.googleapis.com/css2?family=Archivo:wght@400;500;600&family=Bodoni+Moda:opsz,wght@6..96,400;6..96,500&family=JetBrains+Mono:wght@400;500&display=swap"
      rel="stylesheet"
    />
    <link rel="stylesheet" href="documents.css" />
  </head>
  <body>
    <main class="sheet">
      <header class="head">
        <div class="monogram" aria-hidden="true">A<br />O</div>
        <div class="head-mid">
          <h1 class="wordmark">Oarlock<span>gateway-terminated ssh</span></h1>
          <nav class="sheet-nav" aria-label="Sheet">${nav}</nav>
        </div>
        <div class="titleblock">
          <b>${esc(sheet)}</b>
          ${docNo ? `Doc. ${docNo} — ` : ""}File no. OARLOCK-v0
        </div>
      </header>
${body}
      <footer class="foot">
        <span>Oarlock</span>
        <span>Apache 2.0</span>
        <span>Wire version 0 — unstable</span>
        ${self === "index"
          ? `<a href="../index.html" style="margin-left: auto">Sheet 1 — the drawing</a>`
          : `<a href="index.html" style="margin-left: auto">Document register</a>`}
        ${self === "security" ? "" : `<a href="security.html">Report a vulnerability</a>`}
      </footer>
    </main>
  </body>
</html>
`;
}

// ── the specification sheets ──────────────────────────────────────────────────────

mkdirSync(out, { recursive: true });

const rendered = [];
for (const [i, doc] of REGISTER.entries()) {
  const abs = join(repo, doc.src);
  if (!existsSync(abs)) throw new Error(`register names a document that is not here: ${doc.src}`);

  headings = [];
  seen = new Map();
  const md = readFileSync(abs, "utf8");
  const html = marked.parse(md);
  const lines = md.split("\n").length;

  /* The numeral is the clause's number, counted over clauses — not its position in the
   * list of all headings, which is what it was, and which produced an index reading
   * 01, 03, 04, 09, 13 down the rail: four numbers that answer no question a reader has.
   *
   * And where a document numbers its own clauses — every one of protocol's and
   * architecture's do — the column is dropped rather than printed beside them. Two
   * numbering systems in one index means neither of them is the clause number.
   */
  const top = headings.filter((h) => h.depth === 2);
  const selfNumbered = top.length > 0 && top.every((h) => /^\d/.test(h.text.trim()));
  let clause = 0;
  const toc = headings.length
    ? `<nav aria-label="Clauses"><dl><dt>Clauses</dt></dl>` +
      `<ol class="toc${selfNumbered ? " toc--plain" : ""}">` +
      headings.map((h) => {
        const no = h.depth === 2 ? String(++clause).padStart(2, "0") : "";
        return `<li class="depth-${h.depth}" data-clause="${h.id}"><a href="#${h.id}">` +
          `<span class="no">${no}</span><span>${esc(h.text)}</span></a></li>`;
      }).join("") +
      `</ol></nav>`
    : "";

  const prev = REGISTER[i - 1];
  const next = REGISTER[i + 1];
  const nav =
    `<a href="../index.html">Sheet 1 — drawing</a>` +
    `<a href="index.html">Register</a>` +
    (prev ? `<a href="${prev.slug}.html">← ${esc(prev.name)}</a>` : "") +
    (next ? `<a href="${next.slug}.html">${esc(next.name)} →</a>` : "");

  const body =
`      <div class="doc-plate">
        <aside class="rail doc-meta">
          <dl><dt>Document</dt><dd>${esc(doc.name)}</dd></dl>
          <dl><dt>Source</dt><dd><code>${esc(doc.src)}</code></dd></dl>
          <dl><dt>Extent</dt><dd>${lines} lines</dd></dl>
          <dl><dt>Revised</dt><dd>${esc(gitMeta(doc.src))}</dd></dl>
        </aside>
        <article class="prose">
${html}
        </article>
        <aside class="rail doc-index">${toc}</aside>
      </div>
      <script type="module">
        // Sheet 1's one authored interaction, kept: one clause under examination at a
        // time. The register lights the clause the reader is actually in.
        const rows = new Map();
        for (const li of document.querySelectorAll(".toc li")) rows.set(li.dataset.clause, li);
        let lit = null;
        const io = new IntersectionObserver((entries) => {
          for (const e of entries) {
            if (!e.isIntersecting) continue;
            if (lit) rows.get(lit)?.classList.remove("is-lit");
            lit = e.target.id;
            rows.get(lit)?.classList.add("is-lit");
          }
        }, { rootMargin: "-10% 0px -80% 0px" });
        for (const id of rows.keys()) {
          const el = document.getElementById(id);
          if (el) io.observe(el);
        }
      </script>`;

  writeFileSync(join(out, `${doc.slug}.html`),
    chrome({ title: doc.name, sheet: `Sheet 2 of 3`, docNo: number.get(doc.slug), nav, body,
      depthNote: doc.gloss, self: doc.slug }));
  rendered.push({ ...doc, lines, revised: gitMeta(doc.src), clauses: headings.length });
}

// ── the register ──────────────────────────────────────────────────────────────────

const groups = [...new Set(REGISTER.map((d) => d.group))];
const registerBody =
`      <div class="register-lede">
        <p><strong>Sheet 1 is the drawing, this is the register, and sheet 3 is the
        figures.</strong> Every document here is the file in the repository rendered at
        build time, so a claim missing from a page is missing from the specification
        rather than lost on the way to it. Each sheet carries the source path it came
        from and the commit it was last revised in.</p>
      </div>
      <div class="index-band">
${groups.map((g) => `        <section class="index-cell">
          <h2>${esc(g)}</h2>
${rendered.filter((d) => d.group === g).map((d) => `          <a class="entry" href="${d.slug}.html">
            <b>${esc(d.name)}<span class="meta">${number.get(d.slug)} · ${d.lines} ln</span></b>
            <span class="gloss">${esc(d.gloss)}</span>
          </a>`).join("\n")}
        </section>`).join("\n")}
        <section class="index-cell">
          <h2>Machine-readable</h2>
          <a class="entry" href="openapi.yaml">
            <b>OpenAPI<span class="meta">yaml</span></b>
            <span class="gloss">The admin and session API, as the gateway checks it in CI.</span>
          </a>
        </section>
      </div>`;

writeFileSync(join(out, "index.html"), chrome({
  title: "Document register",
  sheet: "Sheet 2 of 3",
  docNo: "",
  nav: `<a href="../index.html">Sheet 1 — drawing</a><a href="index.html" aria-current="true">Register</a><a href="drawings.html">Sheet 3 — figures</a>`,
  body: registerBody,
  depthNote: "Every specification behind the Oarlock gateway: protocol, threat model, plugin seams and the operating notes.",
  self: "index",
}));

// ── assets ────────────────────────────────────────────────────────────────────────

writeFileSync(join(out, "documents.css"),
  readFileSync(join(repo, "landing/sheet.css"), "utf8") + "\n" +
  readFileSync(join(repo, "landing/documents.css"), "utf8"));

copyFileSync(join(repo, "docs/openapi.yaml"), join(out, "openapi.yaml"));

// The three authored figures are generated and gitignored, so on a clean checkout they are
// simply not here. Copy what exists and report what does not, rather than emitting a link
// that 404s for everyone who did not run archify.
const figures = [];
const figDir = join(repo, "docs/diagrams");
for (const f of existsSync(figDir) ? readdirSync(figDir) : []) {
  if (f.endsWith(".html")) {
    copyFileSync(join(figDir, f), join(out, f));
    figures.push(f);
  }
}

// ── verify ────────────────────────────────────────────────────────────────────────

/* Every internal link in the built output, and every fragment it names, resolved against
 * what is actually on disk.
 *
 * This exists because the failure it catches is invisible: sheet 1 shipped for four days
 * with fourteen dead document links, because `../docs/protocol.md` is a perfectly good
 * path from the repository root and a perfectly dead one from the served root. Nothing
 * rendered wrong. The build is the only place that can tell.
 *
 * The copied figures are checked as targets but not crawled as sources: archify authored
 * them, they are self-contained, and re-deriving another tool's link graph here would be
 * asserting something this script does not know.
 */
const pages = new Map(); // path -> {ids, links}
const figureSet = new Set(figures);

function collect(dir, rel = "") {
  for (const f of readdirSync(dir, { withFileTypes: true })) {
    const here = rel ? `${rel}/${f.name}` : f.name;
    if (f.isDirectory()) collect(join(dir, f.name), here);
    else if (f.name.endsWith(".html")) {
      const html = readFileSync(join(dir, f.name), "utf8");
      pages.set(here, {
        ids: new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1])),
        links: figureSet.has(f.name) ? [] :
          [...html.matchAll(/\s(?:href|src)="([^"]+)"/g)].map((m) => m[1]),
      });
    }
  }
}
collect(outRoot);

const dead = [];
for (const [page, { links }] of pages) {
  const base = dirname(page);
  for (const href of links) {
    if (/^(https?:|mailto:|data:|#)/.test(href)) {
      if (href.startsWith("#") && !pages.get(page).ids.has(href.slice(1))) {
        dead.push(`${page} -> ${href} (no such id on this page)`);
      }
      continue;
    }
    const [path, frag] = href.split("#");
    const target = join(base === "." ? "" : base, path).replace(/\/$/, "/index.html");
    const key = target.endsWith("/") ? target + "index.html" : target;
    if (!existsSync(join(outRoot, key))) {
      dead.push(`${page} -> ${href} (missing: ${key})`);
      continue;
    }
    if (frag && pages.has(key) && !pages.get(key).ids.has(frag)) {
      dead.push(`${page} -> ${href} (no such clause in ${key})`);
    }
  }
}

// ── report ────────────────────────────────────────────────────────────────────────

console.log(`documents: ${rendered.length} sheets -> ${out.replace(repo + "/", "")}`);
for (const d of rendered) {
  console.log(`  ${number.get(d.slug)}  ${d.slug.padEnd(22)} ${String(d.lines).padStart(5)} ln  ` +
    `${String(d.clauses).padStart(3)} clauses  ${d.revised}`);
}
console.log(`  figures copied: ${figures.length ? figures.join(", ") : "none (run the archify commands in docs/diagrams/README.md)"}`);
if (unresolved.size) {
  console.log(`  repository paths left as text (no remote to link to):`);
  for (const [href, n] of [...unresolved].sort((a, b) => b[1] - a[1])) {
    console.log(`    ${String(n).padStart(3)}x  ${href}`);
  }
}

const linkCount = [...pages.values()].reduce((n, p) => n + p.links.length, 0);
if (dead.length) {
  console.error(`\n  ${dead.length} dead link(s) of ${linkCount} checked:`);
  for (const d of dead) console.error(`    ${d}`);
  process.exit(1);
}
console.log(`  links: ${linkCount} checked across ${pages.size} pages, all resolve`);
