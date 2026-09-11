/** GitHub heading-slug rule. Same function the drawing-sheet generator used. */
export function slugify(s) {
  return s.toLowerCase().replace(/[^\w\s-]/g, "").trim().replace(/\s/g, "-") || "clause";
}

export function firstSentence(text) {
  const src = String(text || "")
    .replace(/```[\s\S]*?```/g, "\n")
    .replace(/<[^>]+>/g, " ");

  // Only prose makes a description. A section that opens with a table used to be
  // flattened into one — "6. Error codes" read `| code | meaning | retryable |
  // |---|---|---| | ticket_invalid | unknown, expired…`, cut off mid-word, because a
  // table row contains no sentence-ending punctuation to stop at. Skip the block forms
  // that are not sentences and take the first paragraph that is.
  const prose = [];
  for (const raw of src.split("\n")) {
    const line = raw.trim();
    if (!line) {
      if (prose.length) break;   // one paragraph is a description; two is an article
      continue;
    }
    if (/^\|/.test(line)) continue;                  // table row or separator
    if (/^[>#]/.test(line)) continue;                // blockquote, heading
    if (/^([-*+]\s|\d+[.)]\s)/.test(line)) continue;  // list item
    if (/^([-*_]\s*){3,}$/.test(line)) continue;      // horizontal rule
    prose.push(line);
  }

  const t = prose
    .join(" ")
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, "$1")       // a link reads as its text
    .replace(/\*\*/g, "")                             // bold markers are not prose
    .replace(/`/g, "")                                // nor are code ticks
    .replace(/\s+/g, " ")
    .trim();
  if (!t) return "";
  const m = t.match(/^[^.!?]+[.!?]/);
  const s = (m ? m[0] : t).trim();
  if (s.length <= 160) return s;
  // Cut on a word boundary when there is one; "…this dev" was the old giveaway.
  const cut = s.slice(0, 160);
  const sp = cut.lastIndexOf(" ");
  return sp > 100 ? cut.slice(0, sp) : cut;
}

export function splitSections(md, { skipHeadings = [] } = {}) {
  const skip = new Set(skipHeadings.map((h) => h.toLowerCase()));
  const lines = md.split("\n");
  const sections = [];
  let current = null;
  const preamble = [];

  for (const line of lines) {
    const m = /^##\s+(.*)$/.exec(line);
    if (m) {
      if (current) sections.push(current);
      current = { heading: m[1].trim(), slug: slugify(m[1]), lines: [] };
      continue;
    }
    if (current) current.lines.push(line);
    else if (!/^#\s/.test(line)) preamble.push(line);
  }
  if (current) sections.push(current);

  const pre = preamble.join("\n").trim();
  const kept = sections.filter((s) => !skip.has(s.heading.toLowerCase()) && !skip.has(s.slug));
  if (pre && kept[0]) {
    kept[0] = { ...kept[0], lines: [pre, "", ...kept[0].lines] };
  }
  return kept.map((s) => {
    const body = s.lines.join("\n").replace(/^\n+/, "").replace(/\n+$/, "") + "\n";
    const ids = [s.slug];
    for (const line of s.lines) {
      const hm = /^(#{2,6})\s+(.*)$/.exec(line);
      if (hm) ids.push(slugify(hm[2]));
    }
    return { heading: s.heading, slug: s.slug, body, ids };
  });
}

export function buildCatalog(docs) {
  const bySrc = new Map();
  const byBase = new Map();
  const bySlug = new Map();
  const idToPath = new Map();

  for (const doc of docs) {
    const rec = {
      src: doc.src,
      slug: doc.slug,
      sections: doc.sections,
      first: doc.sections[0] ? `/generated/${doc.slug}/${doc.sections[0].slug}` : `/generated/${doc.slug}`,
    };
    bySrc.set(doc.src.replace(/\\/g, "/"), rec);
    bySlug.set(doc.slug, rec);
    byBase.set(doc.src.split("/").pop().toLowerCase(), rec);
    for (const sec of doc.sections) {
      const page = `/generated/${doc.slug}/${sec.slug}`;
      for (const id of sec.ids || [sec.slug]) {
        const isPage = id === sec.slug;
        idToPath.set(`${doc.slug}#${id}`, isPage ? page : `${page}#${id}`);
      }
    }
  }
  byBase.set("readme.md", bySlug.get("overview"));
  return { bySrc, byBase, bySlug, idToPath };
}

function resolvePath(href) {
  const [path, frag = ""] = href.split("#");
  const clean = path.replace(/^(\.\.?\/)+/, "");
  return { clean, frag: frag ? slugify(frag) : "" };
}

export function rewriteLinks(md, catalog) {
  return md.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (all, label, href) => {
    if (/^(https?:|mailto:|#|\/)/.test(href)) return all;
    const { clean, frag } = resolvePath(href);
    if (/openapi\.ya?ml$/i.test(clean)) return `[${label}](/api-reference)`;

    const rec = catalog.bySlug.get(clean.replace(/\.md$/, "")) ||
      (clean.toLowerCase().endsWith(".md") ? catalog.byBase.get(clean.split("/").pop().toLowerCase()) : null) ||
      catalog.bySrc.get(clean);
    if (!rec) return `\`${clean || href}\``;
    if (!frag) return `[${label}](${rec.first})`;
    const dest = catalog.idToPath.get(`${rec.slug}#${frag}`);
    return `[${label}](${dest || rec.first})`;
  });
}

export function yamlQuote(s) {
  return JSON.stringify(String(s));
}

/** Mintlify's mermaid parser chokes on HTML, unicode, and braces in labels. */
export function sanitizeMermaid(md) {
  return md.replace(/```mermaid\r?\n([\s\S]*?)```/g, (_, body) => {
    const clean = body
      .replace(/<br\s*\/?>/gi, " ")
      .replace(/[…]/g, "...")
      .replace(/[≤]/g, "<=")
      .replace(/[≥]/g, ">=")
      .replace(/[–—]/g, "-")
      .replace(/[→]/g, "->")
      .replace(/[←]/g, "<-")
      .replace(/\{/g, "(")
      .replace(/\}/g, ")");
    return "```mermaid\n" + clean + "```";
  });
}

/** Escape JSX-significant braces outside fenced code so generated pages can be MDX. */
export function escapeMdx(md) {
  return md.replace(/(```[\s\S]*?```)|([^`]+)/g, (all, fence, rest) => {
    if (fence) return fence;
    return rest.replace(/\{/g, "\\{").replace(/\}/g, "\\}");
  });
}

export function pageMarkdown({ title, description, body }) {
  // A section that is only a table has no sentence to describe it. Repeating the title
  // as the description puts the same words twice on the page and reads as a mistake, so
  // the field is omitted instead.
  const desc = description ? `description: ${yamlQuote(description)}\n` : "";
  return `---\ntitle: ${yamlQuote(title)}\n${desc}mode: wide\n---\n\n${body}`;
}
