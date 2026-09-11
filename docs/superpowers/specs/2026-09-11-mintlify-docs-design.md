# Mintlify docs site

**Date:** 2026-09-11  
**Status:** draft — awaiting review  
**Replaces:** `landing/documents.mjs` drawing-sheet HTML (sheets 2 and 3)

## 1. Goal

Give an evaluating engineer a docs site they can search and skim: sidebar, short pages, a real quickstart, an OpenAPI playground. The landing sheet stays the persuasion surface. It must not be the place someone reads protocol §4.

Canonical prose stays in the files GitHub already shows (`README.md`, `ARCHITECTURE.md`, `docs/*.md`, `SECURITY.md`). Mintlify does not become a second source of truth.

Local preview only. No Mintlify cloud, no custom domain, no GitHub Action deploy.

## 2. Constraints

- Do not rewrite ARCHITECTURE, protocol, plugins, or the threat model. Split and wrap; do not paraphrase.
- Do not invent customers, logos, benchmarks, or a public URL.
- Voice stays the existing one: cost before benefit, no superlative where a number would do.
- Carmine `#b3231c` is the primary colour. Docs default to dark mode; the theme toggle stays so light is still available.
- `docs/superpowers/` and other planning files are not in the site.
- The Mintlify CLI (`mint`) requires Node ≥ 20.17 and **does not support Node 25+**. This machine has been seen on Node 26. The Makefile/`pnpm docs` path must run `mint` under Node 22 if `node -v` is 25+, or fail with that reason. Do not pretend it works on 26.

## 3. Layout

```
mint/
  docs.json                 # committed: name, theme, colours, appearance, navigation
  index.mdx                 # committed: hand-authored home
  quickstart.mdx            # committed: the README transcript as Steps
  generate.mjs              # committed: splits sources → generated/
  generated/                # gitignored: one MDX per ## section
  openapi.yaml              # gitignored copy of docs/openapi.yaml, or generated/
  logo/                     # optional committed SVG wordmark, not a customer mark
```

`landing/documents.mjs`, `landing/documents.css`, and `landing/dist/documents/` go away once the generator and `mint dev` work. `pnpm build:landing` builds only Sheet 1.

## 4. Generator

`node mint/generate.mjs` (also `--check`, which writes to a temp dir and diffs, or hashes sources against a committed manifest — same idea as `TestSharedVectorsAreCurrent`).

For each registered source:

1. Parse GitHub-style heading slugs (the same function `landing/documents.mjs` already uses, so existing fragments keep working).
2. Split on `##` headings. The title `#` line becomes the page group title, not a page of its own unless there is prose before the first `##`.
3. Write `mint/generated/<slug>/<section-slug>.mdx` with frontmatter:

   ```yaml
   ---
   title: "<heading text>"
   description: "<first sentence of the section, truncated>"
   ---
   ```

4. Rewrite in-body links:
   - `ARCHITECTURE.md#3-reachability-modes` → `/generated/architecture/3-reachability-modes` (or whatever path `docs.json` names).
   - `docs/protocol.md` → the protocol group index (first section, or a generated `_index`).
   - `openapi.yaml` → the API tab.
   - Repository paths with no page (`packages/terminal`, `LICENSE`) stay as code, not links — same as today.
5. Copy `docs/openapi.yaml` to `mint/openapi.yaml`.
6. Copy the three figure HTML files from `docs/diagrams/` into `mint/generated/figures/` so Drawings can iframe or link them locally.

**Split map (deterministic, listed here so `docs.json` and the generator cannot disagree):**

| source | pages (one per `##`) |
|---|---|
| README.md | overview of remaining sections except Quickstart (Quickstart is the hand-authored page) |
| ARCHITECTURE.md | 1 Scope … 14 Milestones (14 pages) |
| docs/protocol.md | 1–7 |
| docs/sdk.md | each `##` |
| docs/plugins.md | 1 How wired, then one page per interface (2–11) |
| docs/threat-model.md | each `##` including §12 |
| SECURITY.md | each `##` |
| docs/per-operator-identity.md | each `##` |
| docs/metrics.md | each `##` |
| docs/android.md | each `##` |
| docs/rust-implementation.md | each `##` |
| docs/diagrams/README.md | as Drawings, plus links to the three figures |

A `##` with no body still becomes a page (so the sidebar matches the spec). Empty pages are a generator bug; `--check` fails if a page is fewer than two non-heading lines unless the source section is actually that short.

## 5. Navigation (`docs.json`)

```
Get started
  index
  quickstart
  generated/overview/*          # README without Quickstart
Gateway
  generated/architecture/*
Wire
  generated/protocol/*
  generated/sdk/*
  generated/plugins/*
Security
  generated/threat-model/*
  generated/security/*          # SECURITY.md
  generated/per-operator-identity/*
Operate
  generated/metrics/*
  generated/android/*
  generated/rust-implementation/*
  generated/drawings
API
  openapi.yaml                  # Mintlify OpenAPI playground
```

`docs.json` lists these paths explicitly. The generator’s `--check` fails if it would write a file that is not in the navigation, or if navigation names a generated file that was not written. Adding a `##` to ARCHITECTURE.md is therefore a two-file change: the Markdown, then `docs.json` (or a one-line update the generator can print).

Tabs are not required. One sidebar is enough.

Navbar: Overview (landing is not here), GitHub omitted until there is a public repo. Footer: Apache 2.0, wire v0 — unstable, Report a vulnerability → `/generated/security/…` reporting page.

## 6. Hand-authored pages

**`index.mdx`**

- Title: Oarlock
- First paragraph: the cost sentence (gateway reads every keystroke).
- Cards: Quickstart, Threat model §12, Protocol, Architecture.
- Callout: protocol is v0, no releases.
- What is not built: multi-replica, generated SDKs. Do not list SSH-CA or passthrough as missing.

**`quickstart.mdx`**

- The six steps from README § Quickstart as `<Steps>`. Commands are the real flags.
- Warning callout on `-insecure-skip-pin` and pinning.
- Closing: the ssh transcript with `this session is recorded`.
- Link to examples/ files, not a paste of full yaml beyond `devices.yaml`.

No other hand-authored pages in this spec. Spec prose stays generated.

## 7. Theme

```json
{
  "theme": "mint",
  "name": "Oarlock",
  "colors": { "primary": "#b3231c", "light": "#b3231c" },
  "appearance": { "default": "light", "strict": true }
}
```

No dark toggle. Favicon can be a simple OL monogram SVG if one is added; otherwise Mintlify default until then. Do not load Bodoni on this site — readability is the point.

## 8. Landing

In `landing/index.html`:

- Documents / Figures / Profiles / footer links that currently go to `./documents/…` go to `http://localhost:3000/…` with the matching generated path (threat model §12, plugins authorizer, protocol sections for shell/exec/file/tcp — **not** all four to DIAL).
- Title block: drop “Sheet 1 of 3”. “File no. OARLOCK-v0” can stay.
- Secondary button “Read the threat model” may keep `#security` on the sheet *or* jump to Mintlify §12; prefer Mintlify §12 because that is the status table.

`package.json`:

- `docs` → `node mint/generate.mjs && mint dev --port 3000 --strict-port` (exact CLI flags as supported by the installed `mint`).
- `docs:gen` → `node mint/generate.mjs`
- `docs:check` → `node mint/generate.mjs --check`
- Remove `documents` as a landing-sheet generator. `build:landing` no longer calls `landing/documents.mjs`.

Makefile: `make documents` / landing-preview stop depending on the old sheets. `make landing` stays Sheet 1.

CI frontend job: replace `pnpm build:landing`’s document-sheet link check with `pnpm docs:check`. Do not run `mint dev` in CI. Optionally `mint broken-links` if it can run headless after generate and does not need Node 26.

## 9. Testing

- `pnpm docs:check` fails if generated output would drift from navigation or if a rewritten link has no target.
- A unit test or node assert: GitHub slug function matches a fixture of real ARCHITECTURE fragments already used on the landing (`#3-reachability-modes`, threat-model `#12-what-is-actually-built`).
- Manual: `pnpm docs`, open `/`, `/quickstart`, one architecture page, threat-model §12, OpenAPI tab, and follow four landing Documents links.

## 10. Out of scope

- Mintlify cloud, custom domain, search analytics.
- Rewriting spec prose into Cards throughout.
- Landing P1s (CTA, carmine-as-accent, mobile transcript) except the Documents hrefs required by this spec.
- Moving README or ARCHITECTURE out of the repo root.
- Dark mode.
- i18n.

## 11. Risks

- **Node 26 vs `mint`.** Must be handled in the run script, not discovered when someone types `pnpm docs`.
- **OpenAPI playground** talks to `{host}` in the spec; local demo is `http://127.0.0.1:8443`. Set `api.mdx.server` / OpenAPI overlay to that for local, and hide the playground if the spec’s `{host}` variable makes it lie.
- **Figure HTML** is large Archify output. Linking the files is enough; do not inline them in MDX.
- **Cross-doc fragments.** A split page’s heading ids must remain GitHub slugs so `#12-what-is-actually-built` still lands.

## 12. Done when

1. `pnpm docs` shows a sidebar that matches §5.
2. Quickstart on the site is the real command sequence, not only a transcript.
3. Landing Documents links open the Mintlify pages (with `mint dev` running).
4. `pnpm build:landing` no longer emits `landing/dist/documents`.
5. Editing a sentence in `docs/threat-model.md` and re-running generate shows that sentence in Mintlify. No hand copy.
