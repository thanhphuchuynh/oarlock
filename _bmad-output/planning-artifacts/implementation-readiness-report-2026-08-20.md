---
title: Implementation Readiness Assessment — oarlock
workflow: 3-solutioning/check-implementation-readiness
stepsCompleted: [1, 2, 3, 4, 5, 6]
project_name: oarlock
date: 2026-08-20
verdict: 'Revision 2 — GO for M0 and M1 (Epics 1, 2, 9). Epic 3 blocked on UX. Epics 4–7 need story detail.'
blocking_items: 7
blocking_items_cleared: 7
revision: 2
revision_date: 2026-08-20
---

# Implementation Readiness Assessment Report

**Date:** 2026-08-20
**Project:** oarlock

## 1. Document discovery

| document | location | state |
|---|---|---|
| PRD | `_bmad-output/planning-artifacts/prd-oarlock-2026-08-20.md` | present, 43 FR / 28 NFR |
| Architecture | **`ARCHITECTURE.md` + `docs/*.md` at the repo root** | present, 20 ADRs — *not* in `planning-artifacts` |
| Epics & Stories | `_bmad-output/planning-artifacts/epics-oarlock-2026-08-20.md` | present, 8 epics / 41 stories |
| UX design specification | — | **absent** |
| Adversarial spec review | `adversarial-review-spec-2026-08-20.md` | 20 findings, 5 resolved |
| Research (technical, domain) | two documents | 10 design implications |

**D-1.** The architecture is the repository's own documentation set, not a
`planning-artifacts` document. That is the right home for an open-source project — the
architecture *is* the product's docs — but it means BMAD's later workflows will not find it
by convention, and `create-story` will need the path passed explicitly.

**D-2.** There is **no UX specification**, and the PRD contains two journeys (J2, J5) and
five functional requirements (FR7, FR8, FR13, FR30, FR36) that are user-interface work.
See § 4.

## 2. PRD analysis

**Strengths.** Requirements are actor-scoped and testable. Success criteria are measurable
and several are falsifiable by a specific test rather than by opinion (SC5's "zero sessions
closed during a 60 s dependency outage" is the strongest of them). Out-of-scope is stated
positively — including the two exclusions most likely to be assumed present, redaction and
command filtering. The domain section carries a genuine regulatory conflict rather than a
compliance checklist.

**Weaknesses.**

**P-1 — `record_input` per tenant requires a tenancy model that does not exist.** FR27 and
NFR28 say the setting is scoped "per tenant or region". Nothing in the architecture has a
tenant: `Device` carries `ID`, `Mode`, `PublicKeys`, `AllowPassthrough`, `Tags` and
`Profiles`. Either the requirement means "per device tag" and should say so, or a tenancy
concept has to be introduced — which touches `DeviceRegistry`, `Authorizer` and the session
schema. **Blocking for Epic 4.**

**P-2 — FR13 needs an authorisation action the architecture does not define.** The
read-only observer needs `observe`; ARCHITECTURE § 7 enumerates `shell`, `exec`,
`file:read`, `file:write`, `tcp`, `passthrough`, `replay`. An action list that the PRD
silently extends is exactly the drift the ADRs exist to prevent. **Blocking for Epic 3.**

**P-3 — E1.S6 resolves a default from a field that does not exist.** The story resolves the
reachability default from "the device's declared platform"; `Device` has no platform field.
Small, and it is in the first epic. **Blocking for Epic 1** — a one-line addition to the
struct and the registry file format, but it must be decided before the story is picked up.

**P-4 — NFR5 is a guess that admits it.** "At least 5 000 idle `persistent` agents on
2 vCPU / 2 GiB — to be established by a load test, not assumed." Honest, and not a
requirement: nothing can pass or fail it today. E6.S6 exists to measure it, which is the
right structure, but until then NFR5 should be labelled a *hypothesis*, not an NFR, so that
nobody treats it as a commitment.

**P-5 — SC6 measures the wrong thing.** "A from-scratch integration in under an hour"
depends on the integrator, not the product. It needs a proxy that is actually measurable —
lines of integrator code, or number of concepts in the quickstart.

## 3. Epic coverage validation

Mechanical trace of every requirement against the epic set:

| check | result |
|---|---|
| FRs declared in the PRD | 43 |
| FRs absent from the traceability table | **none** |
| NFRs absent from the traceability table | none — 4 apparent misses (NFR3, 23, 26, 27) are range notation (`NFR2–NFR4`), not gaps |
| FRs appearing *only* in the table, never in a story body | **FR16, FR17, FR19, FR41, FR42** |
| Journeys referenced by an epic | J2–J7. **J1 is not referenced by any epic.** |
| Success criteria referenced by an epic | SC4, SC5, SC6, SC9. **SC1, SC2, SC3, SC7, SC8 are not.** |

**C-1 — Five requirements are traced but not written down where the work happens.** FR16,
FR17, FR19 land in E4.S5, FR41 in E6.S3, FR42 in E6.S1/S2 — the stories describe the right
behaviour but never cite the requirement. A developer picking up E4.S5 has no way to know it
satisfies three FRs, and a reviewer has no way to check it did. Every story needs its
requirement ids inline, not only in a table at the bottom of the document.

**C-2 — J1, the primary journey, has no epic.** The whole product exists so that an operator
in an incident can `ssh` to a frozen treadmill, and no epic claims that journey. It is
implicitly E1.S5 plus E2, which is precisely the problem: the one path that must work
end-to-end is the one nothing owns.

**C-3 — SC2 has no verification story at all.** "Nothing new listens on the device" is a
load-bearing claim — OL-001, the assumption the entire architecture derives from — and no
story port-scans a device. It needs to be a test in E1, and it needs to run against a real
device, not a mock.

**C-4 — SC1, SC3, SC7 and SC8 are covered in substance but unowned.** SC1 by E1.S5, SC3 by
E2.S1/S2, SC7 by E5.S6, SC8 by E6.S6. Each needs an explicit acceptance criterion naming the
criterion it discharges, or nobody will notice when it silently stops being true.

**C-5 — FR2 straddles two milestones and the epics hide it.** `dispatch` mode is FR2, listed
against E1.S3 "(partial)", with the doorbell actually arriving in Epic 4 / M3. But § 4.1 of
the technical research concluded `dispatch` is the **required** mode for Android, the primary
target platform. So the plan builds and tests the mode the primary platform fights, for three
milestones, before building the one it needs. **This is the most consequential sequencing
finding in this report.** Either `dispatch` moves forward into M0/M1, or the plan should say
plainly that Android is not exercised until M3.

## 4. UX alignment

**U-1 — There is no UX specification, and there is UI in scope.** FR7, FR8, FR13, FR30 and
FR36 are interface work; J2 and J5 are interface journeys; ARCHITECTURE § 11 defines six
failure screens by their *content* but nothing defines the terminal page, the session list,
the replay view, or the observer's consent affordance. Epic 3 is six stories that assume a
design that does not exist.

**U-2 — Two UI decisions have security consequences and no owner.** How the mode-and-recording
banner is presented in the browser (FR12, where it cannot be an SSH banner), and how the first
operator is notified they are being observed (FR13). Both are UX decisions that discharge
security requirements, which means they should not be improvised during implementation.

**Recommendation:** run `create-ux-design` before Epic 3 is planned. It is not needed for
Epics 1 or 2.

## 5. Epic quality review

**Q-1 — Depth is uneven by design, and the document says so.** Epics 1–2 carry full
acceptance criteria; 3–8 are story definitions. That is a defensible choice and it is
disclosed. It also means **only Epics 1 and 2 are plannable today**, and the report's verdict
reflects that rather than pretending otherwise.

**Q-2 — Epic 2 is oversized.** Six stories covering the recorder, the hash chain, the spool,
the ledger, the banner and the API. E2.S2 (hash chain and signed manifest) is a
cryptographic-integrity story sharing an epic with CRUD. Split the integrity work out — it
has different reviewers and a different failure mode.

**Q-3 — No story carries a test strategy beyond Epics 1–2.** The threat model asks for
fuzzing, the PRD asks for fault injection, and E1/E2 name specific tests. Epics 3–8 name
none. `test-design` should run over the epic set before M3.

**Q-4 — Dependencies are implicit in milestone ordering only.** E1.S6 needs the registry
platform field (P-3); E3.S5 needs an `observe` action (P-2); E4.S9 needs a tenancy model
(P-1); E6.S2 needs the ring's home decided (NFR18). None of these are drawn as dependencies,
so each will be discovered by whoever picks the story up.

**Q-5 — E8 is correctly marked continuous and starting now.** The CRA reporting obligation
begins **11 September 2026**, three weeks from this assessment. E8.S1 (`SECURITY.md`,
coordinated disclosure) is a half-day of work that is currently scheduled behind everything.
It should be done this week, independent of M0.

## 6. Final assessment

### Verdict: **CONDITIONAL**

| scope | verdict | condition |
|---|---|---|
| **Epic 1 (M0)** | **READY** | after P-3: add a platform field to `Device` and the registry format |
| **Epic 2 (M1)** | **READY with changes** | after Q-2 (split the integrity story) and a decision on C-5 (whether `dispatch` moves forward) |
| **Epic 3 (M2)** | **NOT READY** | needs a UX specification (U-1) and the `observe` action defined (P-2) |
| **Epic 4 (M3)** | **NOT READY** | needs the tenancy question answered (P-1) |
| **Epics 5–7** | **NOT READY** | story-level detail and test design required (Q-1, Q-3) |
| **Epic 8** | **READY, and late** | E8.S1 should not wait for M0 (Q-5) |

### The seven blocking items, in the order they should be cleared

1. **E8.S1 now** — `SECURITY.md` and a disclosure policy, ahead of the 11 September CRA date.
   Half a day, no dependencies, and the only item here with an external deadline.
2. **Decide C-5** — does `dispatch` move into M0/M1, or is Android explicitly unexercised
   until M3? This changes the first two epics and it is the highest-consequence open question
   in the plan.
3. **P-3** — add `Platform` to `Device`; unblocks E1.S6.
4. **P-1** — decide whether "per tenant" means a tenancy model or a device tag; unblocks E4.S9
   and touches three interfaces if it means the former.
5. **P-2** — define the `observe` action in ARCHITECTURE § 7; unblocks E3.S5.
6. **C-1 and C-2** — put requirement ids inline in every story, and give J1 an owning epic
   with an end-to-end acceptance test.
7. **C-3** — add a story that verifies SC2 against a real device. The claim the architecture
   rests on is currently unverified by anything.

### What is genuinely good here

The requirement set traces cleanly — zero FRs are unmapped, which is unusual at this stage.
The failure-mode thinking is thorough: the three-outcome authorisation contract, the recorder
spool and the "zero sessions closed during a 60 s outage" criterion together mean the most
likely production incident has a designed answer and a test. The research fed real changes
rather than decoration — the recording format, the multiplexer, the transport interface and
the Android default all moved because of it.

**What would most improve this plan:** decide C-5. Everything else on the blocking list is an
hour's work or a paragraph. C-5 is a question about whether the first three milestones are
building toward the platform the product is actually for.


---

# Revision 2 — blockers cleared

**Decision taken:** `dispatch` moves into M0 (item 2, the one with real consequences).
All seven blocking items are now closed. Recorded here rather than in a separate document so
the assessment and its resolution stay together.

| # | item | resolution |
|---|---|---|
| 1 | `SECURITY.md` ahead of the 11 Sept CRA date | **Done.** `SECURITY.md` written: coordinated disclosure via GitHub private vulnerability reporting (works today, needs no address), response targets, scope with explicit out-of-scope, safe harbour, supported-versions table, supply-chain commitments, and a note that the policy does **not** discharge a manufacturer's own CRA obligations. The email contact is a marked placeholder that must be set before any release. |
| 2 | **C-5 — `dispatch` in M0 or Android unexercised until M3** | **Decided: `dispatch` moves into M0.** New story E1.S4 carries tickets, the `Dispatcher` interface and the `exec` + `webhook` adapters — no infrastructure, testable on a laptop. The MQTT adapter stays at M3 as E4.S11: the mode was urgent, the broker was not. ADR-021 records the reasoning. |
| 3 | P-3 — `Device.Platform` | **Done.** Added to the struct and registry file format in `docs/plugins.md` § 6, with the resolution rule (`android` → `dispatch`; `linux`/`container` → `persistent`; explicit `Mode` wins) and the requirement to log the resolved value at registration. E1.S7 unblocked. |
| 4 | P-1 — what "per tenant" means | **Decided: no tenancy entity.** ARCHITECTURE § 8.2 resolves `record_input` from a selector policy matching **operator attributes and device tags** — because employment law attaches to the operator and PCI scope attaches to the device. This reuses the selector mechanism the `rules` authorizer already has. A new decision falls out of it: **conflicts refuse the session** with `policy_conflict` (FR44, ADR-022) rather than silently choosing a regime to violate. |
| 5 | P-2 — the `observe` action | **Done.** Added to ARCHITECTURE § 7 and to `Action` in `docs/plugins.md`, with the reasoning: watching a colleague work is a different capability from working, it carries a consent dimension `shell` does not, the observed operator is told, and an observer sends no input. ADR-023. |
| 6 | C-1, C-2 — inline requirement ids, and an owner for J1 | **Done.** Every story now carries its `FR`/`NFR` ids inline. J1 has an owning story, **E1.S8**, with one automated test walking the whole journey over both reachability modes — and it blocks a release. |
| 7 | C-3 — verify SC2 against a real device | **Done.** **E1.S9**: port scan against a pre-agent baseline on real Android and Linux hardware, plus an assertion that the agent holds no host key material. It also captures the two numbers currently guessed — doze wake latency and whether an OEM power manager kills a device-owner foreground service — feeding `answer_deadline` and NFR1. Exit criterion for M0 alongside E1.S8. |

**Also cleared while in there:** Q-2 (recording integrity split into **Epic 9**, running in
parallel with Epic 2 in M1, because it has different reviewers and a different failure mode
from session CRUD); P-4 (NFR5 relabelled a **hypothesis**, with E6.S6 owning the measurement
that turns it into a requirement); P-5 (SC6 now measures integrator lines of code and concept
count, which the product controls, rather than an hour on the clock, which it does not);
C-4 (SC1, SC3, SC7, SC8 given owning stories); Q-4 (a **Dependencies** table added to the
epics document, with each item marked done, open, or blocked).

## Coverage after revision 2

| check | result |
|---|---|
| FRs declared | 44 (FR44 added by item 4) |
| FRs absent from traceability | none |
| NFRs absent from traceability | none |
| Requirements traced but absent from a story body | **none** — was FR16, FR17, FR19, FR41, FR42, NFR23, NFR24 |
| Journeys without an owning story | **none** — was J1 |
| Success criteria without an owning story | **none** — was SC1, SC2, SC3, SC7, SC8 |
| Epics / stories | 9 / 59 |

## Revised verdict

| scope | verdict |
|---|---|
| **Epic 1 (M0)** | **GO.** Nine stories, full acceptance criteria, both reachability modes, two exit criteria that are tests rather than opinions. |
| **Epic 2 (M1)** | **GO.** Five stories; integrity moved out to Epic 9. |
| **Epic 9 (M1)** | **GO.** Four stories, ships with the first recorder. |
| **Epic 3 (M2)** | **BLOCKED** — on a UX specification, not on anything cleared here. |
| **Epics 4–7** | **NOT READY** — story detail and `test-design` required before each. |
| **Epic 8** | **IN PROGRESS** — E8.S1 done; S2–S4 remain. |

## What is still open, and deliberately not closed

1. ~~**No UX specification.**~~ ✅ **Closed 2026-08-21.**
   `ux-design-specification.md` exists, and both security-bearing UI decisions are made:
   the disclosure is a permanent status bar **plus** a blocking acknowledgement when the
   session is unrecorded or passthrough, and observation is a persistent named indicator
   rather than a toast. Epic 3 is unblocked. The spec names four questions it
   deliberately left open, so story planning starts from a known edge rather than
   discovering one.
2. ~~**No test strategy for Epics 3–8.**~~ 🟡 **Partly closed 2026-08-21.**
   `test-design-epic-3.md` and `test-design-epic-4.md` exist: 31 risks scored, 8 of them
   ≥6, with coverage plans, gate criteria and mitigation owners. Epics 5–8 are **not**
   done, and deliberately — their stories are one-line definitions, and a risk-and-
   coverage plan built on those would be inventing detail that Epic 3 and 4 will
   invalidate. Run `test-design` per epic as each one's stories gain detail, which is
   how the workflow is meant to be used.

   Two findings from the pass are worth surfacing here rather than leaving in the plans:
   **Epic 3's top risk is not a browser problem** — an integrator can compose the mode
   disclosure away (score 9), and it is the only risk in that epic the gateway cannot
   mitigate alone. **Epic 4's top risk is a contract a third-party backend author can
   get wrong**, turning an outage into `revoked` in the audit trail; its mitigation is
   the `plugintest` conformance suite, which is promised in the docs and not yet written,
   so it is a prerequisite rather than a deliverable.
3. **The scrollback ring's home under node-to-node forwarding** (NFR18) states the requirement
   without deciding the design. Open until E6.S2.
4. **The recording signing key's handling** — separate from the SSH host key, but where it
   lives and how it rotates is undecided. Open until E9.S2.
5. **E1.S9 needs real hardware.** The only hardware dependency in M0, and the only way to
   replace two guesses with measurements.
6. **NFR5 remains a hypothesis** until E6.S6 measures it.

None of these blocks M0. Items 1 and 2 block their own epics and nothing earlier.
