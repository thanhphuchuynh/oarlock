import { test } from "node:test";
import assert from "node:assert/strict";
import { slugify, splitSections, rewriteLinks, firstSentence, buildCatalog, sanitizeMermaid } from "./lib.mjs";

test("GitHub slug: architecture reachability heading", () => {
  assert.equal(slugify("3. Reachability modes"), "3-reachability-modes");
});

test("GitHub slug: threat model section 12", () => {
  assert.equal(slugify("12. What is actually built"), "12-what-is-actually-built");
});

test("GitHub slug: authorizer heading with em dash and backticks", () => {
  assert.equal(
    slugify("3. `Authorizer` — may they, on this device, right now"),
    "3-authorizer--may-they-on-this-device-right-now",
  );
});

test("splitSections yields one page per ## and skips named headings", () => {
  const md = [
    "# Title",
    "",
    "Preamble stays on the first page.",
    "",
    "## Alpha",
    "",
    "alpha body",
    "",
    "## Quickstart",
    "",
    "do not emit",
    "",
    "## Beta",
    "",
    "beta body",
    "",
  ].join("\n");
  const pages = splitSections(md, { skipHeadings: ["Quickstart"] });
  assert.deepEqual(pages.map((p) => p.slug), ["alpha", "beta"]);
  assert.match(pages[0].body, /Preamble stays on the first page/);
  assert.match(pages[0].body, /alpha body/);
  assert.equal(pages[0].heading, "Alpha");
  assert.doesNotMatch(pages[0].body, /^## Alpha/m);
});

test("rewriteLinks maps a spec file fragment onto the split page", () => {
  const catalog = buildCatalog([
    {
      src: "ARCHITECTURE.md",
      slug: "architecture",
      sections: [
        {
          heading: "3. Reachability modes",
          slug: "3-reachability-modes",
          ids: ["3-reachability-modes", "31-persistent--the-agent-holds-a-connection-open"],
        },
      ],
    },
    {
      src: "docs/threat-model.md",
      slug: "threat-model",
      sections: [{ heading: "12. What is actually built", slug: "12-what-is-actually-built", ids: ["12-what-is-actually-built"] }],
    },
  ]);
  const out = rewriteLinks(
    "see [reach](ARCHITECTURE.md#3-reachability-modes) and [§12](docs/threat-model.md#12-what-is-actually-built)",
    catalog,
  );
  assert.match(out, /\]\(\/generated\/architecture\/3-reachability-modes\)/);
  assert.match(out, /\]\(\/generated\/threat-model\/12-what-is-actually-built\)/);
});

test("rewriteLinks leaves unpublished repo paths as code", () => {
  const catalog = buildCatalog([]);
  const out = rewriteLinks("see [term](packages/terminal) and [lic](LICENSE)", catalog);
  assert.equal(out, "see `packages/terminal` and `LICENSE`");
});

test("firstSentence takes the first sentence and truncates", () => {
  assert.equal(firstSentence("Hello world. More."), "Hello world.");
  assert.equal(firstSentence("x".repeat(200)).length, 160);
});

test("firstSentence skips a leading table, which is what broke 6. Error codes", () => {
  const md = [
    "| code | meaning | retryable |",
    "|---|---|---|",
    "| `ticket_invalid` | unknown, expired, or already redeemed | no |",
    "",
    "Every code above is a closed set member.",
  ].join("\n");
  assert.equal(firstSentence(md), "Every code above is a closed set member.");
});

test("firstSentence skips blockquotes, lists and rules", () => {
  assert.equal(firstSentence("> Companion documents: x\n\nThe scope is the gateway."),
    "The scope is the gateway.");
  assert.equal(firstSentence("- one\n- two\n\nLists are not descriptions."),
    "Lists are not descriptions.");
});

test("firstSentence returns nothing when a section is only a table", () => {
  assert.equal(firstSentence("| a | b |\n|---|---|\n| 1 | 2 |"), "");
});

test("firstSentence truncates on a word boundary, not mid-word", () => {
  const long = ("alpha bravo charlie delta echo foxtrot golf hotel ").repeat(6);
  const out = firstSentence(long);
  assert.ok(out.length <= 160);
  assert.ok(!/\s$/.test(out));
  assert.ok(long.startsWith(out), "truncation must stay a prefix of the source");
});

test("firstSentence ignores a mermaid fence so a chart is not the description", () => {
  const md = "```mermaid\nsequenceDiagram\n    A->>B: hi\n```\n\nThe operator waits on the doorbell.";
  assert.equal(firstSentence(md), "The operator waits on the doorbell.");
});

test("sanitizeMermaid strips braces and HTML so Mintlify can render sequence diagrams", () => {
  const out = sanitizeMermaid("```mermaid\nA->>B: DIAL{ticket}<br/>done…\n```");
  assert.match(out, /DIAL\(ticket\)/);
  assert.doesNotMatch(out, /<br/);
  assert.match(out, /done\.\.\./);
});

test("ARCHITECTURE.md splits into fourteen ## pages", async () => {
  const { readFileSync } = await import("node:fs");
  const { resolve, dirname } = await import("node:path");
  const { fileURLToPath } = await import("node:url");
  const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const pages = splitSections(readFileSync(resolve(repo, "ARCHITECTURE.md"), "utf8"));
  assert.equal(pages.length, 14);
  assert.equal(pages[2].slug, "3-reachability-modes");
});
