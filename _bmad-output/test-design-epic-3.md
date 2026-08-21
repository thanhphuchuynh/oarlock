# Test Design: Epic 3 — The browser, and the second pair of eyes

**Author:** Tphuc
**Date:** 2026-08-21
**Mode:** epic-level (Phase 4) · **Design level:** full
**Inputs:** `epics-oarlock-2026-08-20.md`, `prd-oarlock-2026-08-20.md`,
`ux-design-specification.md`, `ARCHITECTURE.md`, `docs/threat-model.md`,
`docs/protocol.md`

---

## Executive Summary

**Scope:** full test design for Epic 3 (M2 — the browser leg and read-only observation)

**Risk Summary:**

- Total risks identified: **16**
- High-priority risks (≥6): **7**
- Critical categories: **SEC** (5 of the 7), then **DATA**

**Coverage Summary:** estimates, and they carry more uncertainty than the numbers
suggest — this repository has **no front-end toolchain at all** today, so the first
figure includes standing one up.

- P0 scenarios: **19** (~5–7 days, including harness setup)
- P1 scenarios: **23** (~4–6 days)
- P2/P3 scenarios: **17** (~3–4 days)
- **Total effort:** ~12–17 days

**The finding worth reading first.** The highest-scoring risk is not a browser
problem: it is that **an integrator can compose the mode disclosure away** (R-001,
score 9). Every other control in this epic protects the operator from the device or
the network. This one protects the operator from the integrator, and it is the only
risk here that the gateway cannot mitigate on its own.

**The second is a concrete bug, not a category.** The 256 KiB scrollback ring cuts at
an arbitrary byte, which can be the middle of an escape sequence. Replaying that into
xterm.js leaves its parser in a state no subsequent output repairs — the exact failure
the shell profile refuses to cause everywhere else, reintroduced by the reattach path
(R-002, score 6).

---

## Risk Assessment

### High-Priority Risks (Score ≥6)

| Risk ID | Category | Description | Probability | Impact | Score | Mitigation | Owner | Timeline |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R-001 | SEC | An integrator composes the disclosure away — uses `<StatusBar>` alone, or passes the opt-out prop — and ships a terminal that never says the session is unrecorded or passthrough | 3 | 3 | **9** | `<Terminal>` **refuses to render** an unrecorded session unless a gate was acknowledged or an explicitly named prop was set; the prop's name states the consequence; a component test asserts the refusal | E3.S2 | before M2 exit |
| R-002 | DATA | Scrollback replay cuts an escape sequence in half at the ring boundary, leaving xterm.js's parser broken for the rest of the session | 3 | 2 | **6** | The ring trims to the last **complete** sequence before replaying, and the trimmed prefix is announced rather than silently dropped; property test over a corpus of sequences cut at every offset | E3.S3 | before M2 exit |
| R-003 | SEC | Device- or gateway-supplied text (`frame.Error.Message`, close reasons, device ids) is rendered as HTML in a failure screen → injection from a compromised device | 2 | 3 | **6** | All server-supplied strings render as text nodes, never `innerHTML`/`dangerouslySetInnerHTML`; a lint rule forbids the latter in the console; a test feeds `<img onerror>` through an ERROR frame | E3.S4 | before M2 exit |
| R-004 | SEC | The `observe` action is enforced only in the UI, so a crafted attach request watches a session the caller was never granted | 2 | 3 | **6** | Enforcement is server-side in `Authorizer`; the UI is presentation only. A test attaches with a principal holding `shell` but not `observe` and asserts refusal at the API | E3.S5 | before M2 exit |
| R-005 | SEC | An attach ticket leaks through the browser: a query string, `document.referrer`, history, an error report, a screenshot of devtools | 2 | 3 | **6** | Ticket only ever in the `OPEN` frame body; a test asserts it appears in no URL, no `history`, no logged event; renewal fetches a fresh one rather than reusing | E3.S1 | before M2 exit |
| R-006 | DATA | The integrity verdict renders as passing when verification did not actually run — an error path that falls through to "OK" | 2 | 3 | **6** | The player refuses to render without an explicit verdict object; "unknown" is a distinct, visible state, never a default; a test injects a verification error and asserts playback is gated | E3.S6 | before M2 exit |
| R-007 | SEC | Replay is reachable with `shell` alone, because `replay` was checked in the console but not on the endpoint | 2 | 3 | **6** | `replay` checked server-side on both the manifest and the stream; a test grants `shell` only and asserts 403 on the recording endpoint | E3.S6 | before M2 exit |

### Medium-Priority Risks (Score 3-4)

| Risk ID | Category | Description | Probability | Impact | Score | Mitigation | Owner |
| --- | --- | --- | --- | --- | --- | --- | --- |
| R-008 | TECH | The browser keeps its own session state machine and it disagrees with the server's | 2 | 2 | 4 | Server state is the only truth (UX spec § Component Strategy); the UI holds no mirror. Test: force a server-side close and assert the UI follows without a local transition | E3.S1 |
| R-009 | PERF | Replaying 256 KiB of scrollback janks the terminal, or unbounded xterm scrollback grows memory across a long session | 2 | 2 | 4 | Bounded xterm `scrollback`; replay written in chunks with yields; measure paint time on a 256 KiB replay | E3.S3 |
| R-010 | BUS | Reattach reads as a failure, so the operator opens a second session, hits the one-per-device cap, and concludes the product is broken | 2 | 2 | 4 | Reconnecting is an ambient state, not an error screen; input queues rather than erroring. Test: kill the socket mid-command and assert no error surface appears | E3.S3 |
| R-011 | OPS | The component's CSS collides with a host application despite scoping | 2 | 2 | 4 | Every selector under one root class, every property `--oarlock-*`, no bare element selectors; test mounts the component inside a page with an aggressive global reset | E3.S2 |
| R-012 | SEC | OSC 52 clipboard writes or title reporting are re-enabled by a default change, letting a compromised device write to the operator's clipboard | 1 | 3 | 3 | Off by default, opt-in per instance; a test asserts a device emitting OSC 52 does not alter the clipboard | E3.S2 |
| R-013 | OPS | The two styling systems drift because nothing enforces "a colour is never written twice" | 3 | 1 | 3 | Tokens generated from one source into both the component's CSS properties and the Tailwind theme; CI fails if the generated files are stale | E3.S2 |
| R-014 | BUS | The observed operator's indicator is present but so quiet that it is never noticed — the risk the chosen design knowingly accepts | 2 | 2 | 4 | Contrast and placement checked against the accepted trade-off; `aria-live` announcement covers the non-visual case; usability check with one real operator | E3.S5 |

### Low-Priority Risks (Score 1-2)

| Risk ID | Category | Description | Probability | Impact | Score | Action |
| --- | --- | --- | --- | --- | --- | --- |
| R-015 | BUS | The two named waits collapse into a single spinner during implementation, throwing away the diagnosis the gateway already has | 2 | 1 | 2 | Covered by a P1 test asserting two distinct labelled steps |
| R-016 | OPS | Failure screens drift out of step with the eleven server conditions as conditions are added | 1 | 2 | 2 | A test enumerates the server's condition set and asserts a screen exists for each; monitor |

### Risk Category Legend

- **TECH**: Technical/Architecture (flaws, integration, scalability)
- **SEC**: Security (access controls, auth, data exposure)
- **PERF**: Performance (SLA violations, degradation, resource limits)
- **DATA**: Data Integrity (loss, corruption, inconsistency)
- **BUS**: Business Impact (UX harm, logic errors, revenue)
- **OPS**: Operations (deployment, config, monitoring)

---

## Test Coverage Plan

### P0 (Critical) — run on every commit

**Criteria**: blocks the core journey + high risk (≥6) + no workaround

| Requirement | Test Level | Risk Link | Test Count | Owner | Notes |
| --- | --- | --- | --- | --- | --- |
| FR12 — an unrecorded session cannot be rendered without an acknowledged gate | Component | R-001 | 4 | dev | Includes the composed-around case: `<StatusBar>` alone plus a bare `<Terminal>` |
| FR12 — the status bar is present, unscrollable, undismissable | Component | R-001 | 3 | dev | Asserts no dismissal affordance exists in the DOM at all |
| FR8 — replayed scrollback never cuts an escape sequence | Unit | R-002 | 3 | dev | Property test: a sequence corpus truncated at **every** byte offset |
| FR7 — server-supplied strings are never interpreted as HTML | Component | R-003 | 3 | dev | `<img src=x onerror=…>` through an `ERROR` frame and a close reason |
| FR13 — `observe` is enforced server-side | API | R-004 | 2 | dev | `shell` without `observe` is refused at the attach endpoint |
| NFR8 — the attach ticket never reaches a URL, history or a logged event | E2E | R-005 | 2 | dev | Asserts across navigation and a forced error report |
| FR26 — playback is gated on an explicit integrity verdict | Component | R-006 | 2 | dev | Verification error and verification absent are both distinct visible states |
| FR30 — `replay` is enforced separately from `shell` | API | R-007 | 2 | dev | Manifest **and** stream endpoints |

**Total P0**: 21 tests, ~5–7 days *including* standing up the front-end harness

### P1 (High) — run on PR to main

**Criteria**: important feature, medium risk (3–5), a difficult workaround exists

| Requirement | Test Level | Risk Link | Test Count | Owner | Notes |
| --- | --- | --- | --- | --- | --- |
| FR7 — J2 end to end: click → two named waits → prompt | E2E | R-015 | 3 | dev | Two distinct labelled steps, each with its own state |
| FR8 — reattach is undramatic | E2E | R-010 | 3 | dev | Socket killed mid-command; no error surface; scrollback replays; the command's result still arrives |
| FR7 — each of the eleven server conditions renders its own screen | Component | R-016 | 11 | dev | Table-driven from the server's condition set, so a new condition fails the build |
| FR8 — the UI holds no state machine of its own | E2E | R-008 | 2 | dev | Server-side close with no client transition; UI must follow |
| FR13 — the observed operator's indicator, and the observer's disabled input | Component | R-014 | 3 | dev | Input **disabled**, not ignored; watcher named; `aria-live` announced |
| FR36 — the component survives a hostile host stylesheet | Component | R-011 | 2 | dev | Mounted under an aggressive global reset and a CSS framework |

**Total P1**: 24 tests, ~4–6 days

### P2 (Medium) — nightly

| Requirement | Test Level | Risk Link | Test Count | Owner | Notes |
| --- | --- | --- | --- | --- | --- |
| PERF — 256 KiB scrollback replay paint budget | E2E | R-009 | 2 | dev | Measured, with a recorded baseline rather than a hard threshold at first |
| PERF — sustained flood for 10 minutes, memory bounded | E2E | R-009 | 1 | dev | Asserts xterm scrollback is capped |
| SEC — OSC 52 and title reporting stay off | Component | R-012 | 2 | dev | Clipboard unchanged after a device emits the sequence |
| OPS — generated token files are not stale | Unit | R-013 | 1 | dev | CI check, cheap and catches the drift early |
| A11y — status bar announced; gate traps focus; `Escape` cancels | Component | — | 5 | dev | The two accessibility requirements that are security requirements |
| A11y — WCAG AA contrast for chrome and the ANSI palette | Unit | — | 2 | dev | The ANSI palette is where default terminal themes usually fail |

**Total P2**: 13 tests, ~2–3 days

### P3 (Low) — on demand

| Requirement | Test Level | Risk Link | Test Count | Owner | Notes |
| --- | --- | --- | --- | --- | --- |
| Responsive layouts at three widths | Component | — | 3 | dev | Status bar must keep the recording state when it condenses |
| Empty states name what would fill them | Component | — | 2 | dev | |
| Time renders relative at rest, absolute on hover and in copy | Unit | — | 2 | dev | |

**Total P3**: 7 tests, ~1 day

---

## Execution Order

### Smoke tests (<5 min)

1. The component mounts and connects against a stub gateway
2. An unrecorded session refuses to render without an acknowledged gate (R-001)
3. J2 reaches a prompt

### P0 tests (<10 min)

4. Disclosure suite (R-001) — component
5. Escape-sequence boundary property test (R-002) — unit, fast
6. HTML-injection suite (R-003) — component
7. `observe` and `replay` enforcement (R-004, R-007) — API, reuses the Go harness
8. Ticket-leak suite (R-005) — E2E
9. Integrity-verdict gating (R-006) — component

### P1 tests (<30 min)

10. J2 and reattach end to end
11. The eleven condition→screen cases
12. Observer states
13. Hostile-stylesheet mounts

### P2/P3 tests (<60 min)

14. Performance measurements, accessibility, responsive, token freshness

---

## Resource Estimates

### Test development effort

| Band | Tests | Estimate | Confidence |
| --- | --- | --- | --- |
| Harness setup (Playwright + component runner + stub gateway) | — | 2–3 days | low — nothing exists yet |
| P0 | 21 | 3–4 days | medium |
| P1 | 24 | 4–6 days | medium |
| P2 | 13 | 2–3 days | medium |
| P3 | 7 | ~1 day | high |
| **Total** | **65** | **12–17 days** | **low–medium** |

These are estimates from a repository with **zero** front-end tests. Treat the harness
figure as the least reliable number here; everything else depends on it.

### Prerequisites

- **A front-end toolchain.** None exists: no `package.json`, no bundler, no test
  runner. This is the single largest prerequisite and it is not in any story.
- **A stub gateway for component tests.** The Go side already has `memory` transport
  and a real `/ws/session`; the browser tests need either a real gateway process or a
  small WebSocket stub. Prefer the real gateway — the Go e2e harness already stands one
  up, and a stub that drifts from the protocol tests the stub.
- **`POST /api/v1/sessions`** must exist (E3.S1) before any E2E test can open a session.
- **An `observe` action** in `ARCHITECTURE.md` § 7 — already added.
- **A recording with a known-bad integrity verdict** as a fixture. `internal/record`
  already produces truncated and altered cases; export them as fixtures rather than
  re-deriving them in TypeScript.

---

## Quality Gate Criteria

### Pass/fail thresholds

- **P0 pass rate**: 100%, no exceptions
- **P1 pass rate**: ≥95%, waivers recorded with a reason
- **P2/P3 pass rate**: ≥90%, informational
- **High-risk mitigations**: 100% complete or an approved, written waiver

### Coverage targets

- **Critical paths** (J2, reattach, replay): ≥80%
- **Security scenarios** (SEC category): **100%** — five of the seven high risks are SEC
- **Business logic**: ≥70%
- **Edge cases**: ≥50%

### Non-negotiable requirements

- [ ] R-001 mitigated: an unrecorded session cannot be rendered without an
      acknowledged gate, and the test covers the composed-around case
- [ ] R-002 mitigated: replayed scrollback never contains a partial escape sequence
- [ ] R-003 mitigated: no `innerHTML`/`dangerouslySetInnerHTML` anywhere in the
      console, enforced by lint
- [ ] R-004 and R-007 mitigated: `observe` and `replay` enforced **server-side**, with
      tests that bypass the UI entirely
- [ ] All eleven server conditions have a screen, asserted from the server's own set

---

## Mitigation Plans

### R-001: An integrator composes the disclosure away (Score: 9)

**Mitigation Strategy:** `<Terminal>` refuses to render a session whose `recording`
is false unless either the gate was acknowledged or an explicitly named prop was set —
something like `acknowledgeUnrecordedWithoutPrompt`, whose name states the consequence
so that using it is a decision rather than a convenience. `<StatusBar>` and
`<PreflightGate>` remain separately exported for layout, but composing with them does
not disable the refusal.

This is the only risk in the epic the gateway cannot mitigate alone, and it is the
reason the requirement belongs in the *component* rather than in documentation. It is
also **UX spec open question 1**, so the decision must be made before E3.S2 starts.

**Owner:** E3.S2 · **Timeline:** before M2 exit · **Status:** Planned

### R-002: Scrollback replay cuts an escape sequence (Score: 6)

**Mitigation Strategy:** the ring trims to the last **complete** escape sequence
before replaying, and reports how many bytes it dropped so the operator sees a gap
marker rather than a silently mangled screen. Tested as a property: a corpus of real
sequences truncated at every byte offset, asserting the trimmed output parses cleanly.

Note the shape of this bug — it is the same failure the `shell` profile refuses to
cause (a dropped chunk mid-sequence), reintroduced by a different path. Worth stating
in the code, because someone optimising the ring will otherwise re-add it.

**Owner:** E3.S3 · **Timeline:** before M2 exit · **Status:** Planned

### R-006: A passing verdict for a verification that never ran (Score: 6)

**Mitigation Strategy:** the player takes a verdict as a required prop with no default.
"Unknown" is a distinct visible state, so an error path cannot fall through to
something that looks like success. A recording that does not verify is not played
inline at all — the operator has to choose to view it, with the verdict stated.

**Owner:** E3.S6 · **Timeline:** before M2 exit · **Status:** Planned

---

## Assumptions and Dependencies

### Assumptions

- The reference console and the embeddable component share a test harness. If they
  diverge, the estimates roughly double.
- E2E tests run against a **real gateway process**, not a protocol stub. The Go e2e
  harness already builds one, and a stub that drifts from the protocol tests the stub.
- Playwright for both E2E and component tests, so there is one runner and one set of
  fixtures rather than two.

### Dependencies

- **E3.S1 blocks every E2E test** — `POST /api/v1/sessions` and `/ws/attach` have to
  exist before a browser can open a session.
- **UX spec open question 1 blocks R-001's mitigation.** The test cannot be written
  until it is decided whether the component refuses or merely warns.
- **UX spec open question 2** (may an observed operator *refuse* observation?) changes
  E3.S5's test set materially. Deciding it late means rewriting those tests.
- Integrity fixtures come from `internal/record`; exporting them is a small Go task
  that has to happen first.

### Risks to plan

- **The harness estimate is the weak number.** Standing up a front-end toolchain in a
  repository that has none has historically been where this kind of estimate goes
  wrong, and nothing here makes that less true.
- **Component-level terminal testing is awkward.** xterm.js needs a real DOM and a
  real canvas; jsdom is not enough. This pushes work that looks like unit testing into
  the slower component tier, which the estimates assume but which could still surprise.
- **R-014 is a knowingly accepted risk, not a solved one.** The chosen observer design
  trades noticeability for honesty. If a usability check shows operators genuinely miss
  it, the answer is a design change, not another test.

---

## Follow-on Workflows (Manual)

- `atdd` — generate failing acceptance tests for the P0 set before implementation
- `automate` — expand coverage after E3 lands
- `ci` — add the front-end job to the existing pipeline
- `trace` — requirements-to-tests matrix once the tests exist
- `nfr-assess` — before M2 exit, against the PERF and SEC risks here

---

## Appendix

### Related documents

- `ux-design-specification.md` — the four decisions and the four open questions
- `ARCHITECTURE.md` § 11 — the eleven condition→screen mappings the UI renders
- `docs/threat-model.md` § 6 — hostile-device risks, including OSC 52
- `epics-oarlock-2026-08-20.md` — Epic 3 stories, including E3.S7 added by the UX pass
