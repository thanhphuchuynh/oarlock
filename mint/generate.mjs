#!/usr/bin/env node
/**
 * Split canonical Markdown into Mintlify pages. Sources stay at the repo root;
 * this directory is a view, not a second copy of the prose.
 *
 *   node mint/generate.mjs
 *   node mint/generate.mjs --check
 */
import {
  existsSync, mkdirSync, readFileSync, writeFileSync, copyFileSync,
  readdirSync, rmSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  slugify, splitSections, rewriteLinks, firstSentence, buildCatalog, pageMarkdown,
  sanitizeMermaid, escapeMdx,
} from "./lib.mjs";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const mintDir = join(repo, "mint");
const genDir = join(mintDir, "generated");
const figOut = join(mintDir, "figures");
const check = process.argv.includes("--check");

export const REGISTER = [
  {
    src: "README.md", slug: "overview", group: "Get started",
    skipHeadings: [
      "Quickstart",
      "Integrating it into something you already have",
      "Where this came from, and what it is not",
      "Documentation",
      "Building it",
      "Status",
      "Licence",
    ],
  },
  {
    src: "ARCHITECTURE.md", slug: "architecture", group: "Gateway",
    skipHeadings: ["12. Repository layout", "14. Milestones"],
  },
  { src: "docs/protocol.md", slug: "protocol", group: "Wire" },
  {
    src: "docs/sdk.md", slug: "sdk", group: "Wire",
    skipHeadings: ["4. Server SDKs", "10. A whole integration, end to end"],
  },
  {
    src: "docs/plugins.md", slug: "plugins", group: "Wire",
    skipHeadings: ["10.1 `AuditSink` — the event set"],
  },
  {
    src: "docs/threat-model.md", slug: "threat-model", group: "Security",
    skipHeadings: ["13. Reporting a vulnerability"],
  },
  {
    src: "SECURITY.md", slug: "security", group: "Security",
    skipHeadings: ["Safe harbour", "Supported versions", "Regulatory note"],
  },
  {
    src: "docs/metrics.md", slug: "metrics", group: "Operate",
    skipHeadings: ["What is *not* here, and why", "What this deliberately does not use"],
  },
  { src: "docs/android.md", slug: "android", group: "Operate" },
];

function injectHeadingIds(body) {
  return body.replace(/^(#{2,6})\s+(.*)$/gm, (_, hashes, text) => {
    const id = slugify(text);
    return `<a id="${id}"></a>\n${hashes} ${text}`;
  });
}

function loadDocs() {
  return REGISTER.map((doc) => {
    const abs = join(repo, doc.src);
    if (!existsSync(abs)) throw new Error(`register names a document that is not here: ${doc.src}`);
    const md = readFileSync(abs, "utf8");
    const sections = splitSections(md, { skipHeadings: doc.skipHeadings || [] });
    return { ...doc, abs, md, sections };
  });
}

function writePages(docs, catalog) {
  rmSync(genDir, { recursive: true, force: true });
  mkdirSync(genDir, { recursive: true });
  const written = [];
  const problems = [];

  for (const doc of docs) {
    const dir = join(genDir, doc.slug);
    mkdirSync(dir, { recursive: true });
    for (const sec of doc.sections) {
      let body = rewriteLinks(sec.body, catalog);
      body = sanitizeMermaid(body);
      body = injectHeadingIds(body);
      body = escapeMdx(body);
      const nonHeading = body.split("\n").filter((l) => l.trim() && !/^#{1,6}\s/.test(l) && !/^<a id=/.test(l));
      if (nonHeading.length < 2 && sec.body.trim().split("\n").filter(Boolean).length >= 2) {
        problems.push(`${doc.slug}/${sec.slug}: fewer than two body lines after wrap`);
      }
      const desc = firstSentence(sec.body.replace(/^#{1,6}.*$/gm, ""));
      const rel = `generated/${doc.slug}/${sec.slug}`;
      writeFileSync(join(dir, `${sec.slug}.mdx`), pageMarkdown({
        title: sec.heading,
        description: desc,
        body,
      }));
      written.push(rel);
    }
  }
  return { written, problems };
}

function copyFigures() {
  mkdirSync(figOut, { recursive: true });
  const figDir = join(repo, "docs/diagrams");
  const files = [];
  for (const f of existsSync(figDir) ? readdirSync(figDir) : []) {
    if (!f.endsWith(".html")) continue;
    copyFileSync(join(figDir, f), join(figOut, f));
    files.push(f);
  }
  const story = join(mintDir, "animation/story.html");
  if (existsSync(story)) copyFileSync(story, join(figOut, "story.html"));
  return files;
}

function pagesFor(docs, slug) {
  const doc = docs.find((d) => d.slug === slug);
  return doc ? doc.sections.map((s) => `generated/${slug}/${s.slug}`) : [];
}

function writeNav(docs) {
  const nav = {
    groups: [
      { group: "Get started", pages: ["index", "use-cases", "quickstart", "diagrams", ...pagesFor(docs, "overview")] },
      { group: "Gateway", pages: pagesFor(docs, "architecture") },
      {
        group: "Wire",
        pages: [
          { group: "Protocol", pages: pagesFor(docs, "protocol") },
          { group: "SDK", pages: pagesFor(docs, "sdk") },
          { group: "Plugins", pages: pagesFor(docs, "plugins") },
        ],
      },
      { group: "Security", pages: [...pagesFor(docs, "threat-model"), ...pagesFor(docs, "security")] },
      { group: "Operate", pages: [...pagesFor(docs, "metrics"), ...pagesFor(docs, "android")] },
      { group: "API", openapi: "openapi.yaml" },
    ],
  };
  mkdirSync(genDir, { recursive: true });
  writeFileSync(join(mintDir, "docs.json"), JSON.stringify({
    $schema: "https://mintlify.com/docs.json",
    theme: "mint",
    name: "Oarlock",
    colors: { primary: "#b3231c", dark: "#b3231c", light: "#e0706a" },
    appearance: { default: "dark", strict: false },
    navbar: {
      links: [{ label: "Report a vulnerability", href: "/generated/security/reporting-a-vulnerability" }],
    },
    footer: { title: "Apache 2.0 · Wire version 0 — unstable" },
    navigation: nav,
    openapi: "openapi.yaml",
    api: { mdx: { server: "http://127.0.0.1:8443" } },
  }, null, 2) + "\n");
  return nav;
}

function flattenPages(pages) {
  const out = [];
  for (const p of pages || []) {
    if (typeof p === "string") out.push(p);
    else if (p && p.pages) out.push(...flattenPages(p.pages));
  }
  return out;
}

function checkLinks(docs, catalog, nav) {
  const dead = [];
  const files = new Set(nav.groups.flatMap((g) => flattenPages(g.pages)));
  for (const rel of files) {
    const abs = join(mintDir, rel + ".md");
    const mdx = join(mintDir, rel + ".mdx");
    if (!existsSync(abs) && !existsSync(mdx)) dead.push(`nav names missing page: ${rel}`);
  }
  for (const doc of docs) {
    for (const sec of doc.sections) {
      const rel = `generated/${doc.slug}/${sec.slug}`;
      if (!files.has(rel)) dead.push(`generated page not in nav: ${rel}`);
      const text = readFileSync(join(genDir, doc.slug, `${sec.slug}.mdx`), "utf8");
      for (const m of text.matchAll(/\]\((\/generated\/[^)#]+)(#[^)]+)?\)/g)) {
        const page = m[1].replace(/^\//, "");
        const frag = m[2] ? m[2].slice(1) : "";
        const target = [join(mintDir, page + ".mdx"), join(mintDir, page + ".md")].find(existsSync);
        if (!target) {
          dead.push(`${rel} -> ${m[1]} missing`);
          continue;
        }
        if (frag) {
          const t = readFileSync(target, "utf8");
          if (!t.includes(`id="${frag}"`) && !t.includes(`slug: ${JSON.stringify(frag)}`)) {
            dead.push(`${rel} -> ${m[1]}#${frag} (no id)`);
          }
        }
      }
    }
  }
  return dead;
}

function main() {
  const docs = loadDocs();
  const catalog = buildCatalog(docs);
  const figures = copyFigures();
  copyFileSync(join(repo, "docs/openapi.yaml"), join(mintDir, "openapi.yaml"));
  const { written, problems } = writePages(docs, catalog);
  const nav = writeNav(docs);
  const dead = checkLinks(docs, catalog, nav);
  const errors = [...problems, ...dead];

  console.log(`mint: ${written.length} pages -> mint/generated`);
  for (const doc of docs) {
    console.log(`  ${doc.slug.padEnd(24)} ${String(doc.sections.length).padStart(3)} pages  ${doc.src}`);
  }
  console.log(`  figures: ${figures.length ? figures.join(", ") : "none"}`);

  if (errors.length) {
    console.error(`\n${errors.length} problem(s):`);
    for (const e of errors) console.error(`  ${e}`);
    process.exit(1);
  }
  if (check) console.log("check: navigation and rewritten links resolve");
}

main();
