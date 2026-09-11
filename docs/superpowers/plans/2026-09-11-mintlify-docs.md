# Mintlify Docs Implementation Plan

> **For agentic workers:** Inline execution. Spec: `docs/superpowers/specs/2026-09-11-mintlify-docs-design.md`.

**Goal:** Replace drawing-sheet HTML with a Mintlify site generated from the existing Markdown.

**Architecture:** `mint/generate.mjs` splits canonical Markdown on `##` into `mint/generated/`. Hand-authored `index.mdx` and `quickstart.mdx`. `pnpm docs` generates then runs `mint dev` on :3000 under Node 22 if needed.

**Tech Stack:** Node, Mintlify CLI (`mint`), existing Markdown sources.

**Spec:** `docs/superpowers/specs/2026-09-11-mintlify-docs-design.md`

## Global Constraints

- Canonical sources stay at README.md, ARCHITECTURE.md, docs/*.md, SECURITY.md
- Carmine `#b3231c`, light only
- Node 25+ must not run `mint`; fail or use Node 22
- Do not paraphrase spec prose
- No Mintlify cloud

### Task 1: Generator (slug, split, rewrite) with tests
### Task 2: mint/ site files (docs.json, index, quickstart)
### Task 3: Landing links, package.json, Makefile, CI, gitignore
### Task 4: Verify generate + mint preview
