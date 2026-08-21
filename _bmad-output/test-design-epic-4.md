# Test Design: Epic 4 — Identity, authorisation, revocation

**Author:** Tphuc
**Date:** 2026-08-21
**Mode:** epic-level (Phase 4) · **Design level:** full
**Inputs:** `epics-oarlock-2026-08-20.md`, `prd-oarlock-2026-08-20.md`,
`ARCHITECTURE.md` §§ 7–7.1 and 8.2, `docs/plugins.md` § 3, `docs/sdk.md` § 3,
`docs/threat-model.md` § 5, `adversarial-review-spec-2026-08-20.md`

---

## Executive Summary

**Scope:** full test design for Epic 4 (M3 — identity, authorisation, revocation)

**Risk Summary:**

- Total risks identified: **15**
- High-priority risks (≥6): **8**
- Critical categories: **SEC** (6 of the 8), then **OPS**

**Coverage Summary:** estimates.

- P0 scenarios: **26** (~5–7 days)
- P1 scenarios: **18** (~3–4 days)
- P2/P3 scenarios: **11** (~2 days)
- **Total effort:** ~10–13 days

**Why this epic carries the project's highest stakes.** Everything before it decides
*how* a shell is delivered. This epic decides *whether* — and three of its
requirements were blocking findings in the adversarial review, which means their
designs are new and untested rather than inherited. The single highest risk is not an
implementation bug but a **contract a third-party backend author can get wrong in a
way that writes a lie into the audit trail** (R-001).

**The test that matters most is a fault-injection test, not a unit test.** SC5 — "a
60-second failure of any single dependency closes zero live sessions" — is what
separates this design from the naive fail-closed one it replaced, and it cannot be
demonstrated by anything except breaking a dependency on purpose and watching sessions
survive.

---

## Risk Assessment

### High-Priority Risks (Score ≥6)

| Risk ID | Category | Description | Probability | Impact | Score | Mitigation | Owner | Timeline |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R-001 | SEC | A backend author returns `Decision{Allow:false}` when their service is *down*, so an outage is recorded as `revoked` — a lie in the audit trail, and one that also closes every live session | 3 | 2 | **6** | The three-outcome contract is asserted by `plugintest`: a conformance suite every backend runs, with a case that fails a backend which conflates the two. Documented in `docs/plugins.md` § 3 | E4.S4 | before M3 exit |
| R-002 | SEC | A service acts for a human it should not: a forged or replayed `On-Behalf-Of` assertion, or a `may_act_for` allow-list that is not actually consulted | 2 | 3 | **6** | Signature and audience verified; `exp` under 60 s for service-signed assertions; allow-list checked on every call. Tests: expired assertion, wrong audience, subject outside the list, replay of a used assertion | E4.S6 | before M3 exit |
| R-003 | SEC | Revocation never reaches a live session: the `Watch` stream drops silently, or the re-check goroutine dies, and the grant is withdrawn while the shell continues | 2 | 3 | **6** | `Watch` reconnects with backoff and its liveness is observable; the re-check interval is the guarantee and `Watch` is only the optimisation. Test: kill the stream, withdraw a grant, assert closure within `recheck_interval` | E4.S3, E4.S5 | before M3 exit |
| R-004 | SEC | A rotated device key is never retired, so a key stolen months ago still authenticates | 3 | 2 | **6** | Rotation is publish-then-retire with both steps tested, and a retired key is refused. Test: three keys, retire the middle one, assert only the remaining two verify | E4.S7 | before M3 exit |
| R-005 | SEC | The shared SSH host key leaks — committed to config, logged at startup, or copied between replicas insecurely | 2 | 3 | **6** | The private half is never logged and never rendered; a test greps startup output for key material; the documented distribution path is a secret store, not a config file | E4.S8 | before M3 exit |
| R-006 | SEC | A `record_input` policy conflict silently picks a regime instead of refusing, so a session runs that violates one of two mutually exclusive obligations | 2 | 3 | **6** | A conflict with a non-overridable rule refuses the session with `policy_conflict` and names **both** rules in the audit event. Test: PCI-scoped device plus an EU-staff operator; assert refusal, not a choice | E4.S9 | before M3 exit |
| R-007 | OPS | The grace window is misconfigured — long enough that revocation feels broken, or zero in a deployment that did not mean strict fail-closed | 2 | 3 | **6** | `authz.grace` is bounded and its effect is asserted at both ends: 0 closes immediately, N survives N failures and no more. The boot gate already refuses a negative value | E4.S4 | before M3 exit |
| R-008 | SEC | An OIDC token is accepted past its expiry, or cached beyond it, so a session outlives the credential that opened it | 2 | 3 | **6** | `Principal.Expiry` is enforced as a ceiling on the session, independent of the re-check interval. Test: a token expiring in 5 s opens a session that closes at expiry | E4.S1 | before M3 exit |

### Medium-Priority Risks (Score 3-4)

| Risk ID | Category | Description | Probability | Impact | Score | Mitigation | Owner |
| --- | --- | --- | --- | --- | --- | --- | --- |
| R-009 | DATA | The audit sink drops events under load and says nothing, so the trail has holes exactly when the most is happening | 2 | 2 | 4 | Bounded queue with a **counted** drop and a metric; `Emit` cannot fail by contract, but it can report. Test: flood the sink and assert the drop count is non-zero and visible | E4.S10 |
| R-010 | SEC | An unattended service session is not tagged, so robot and human activity sum into one number in a "who touched this device" query | 2 | 2 | 4 | `unattended` set at creation and asserted in the ledger; a query test proves the two can be separated | E4.S6 |
| R-011 | OPS | The webhook authorizer's cache TTL exceeds the re-check interval, so a revocation is invisible for longer than the interval promises | 2 | 2 | 4 | Cache TTL must be **shorter** than `recheck_interval`; a boot check or a test asserts the relationship rather than trusting configuration | E4.S3 |
| R-012 | SEC | An MQTT invitation is delivered to the wrong device through a topic mismatch, handing a ticket to a device that was never invited | 1 | 3 | 3 | Topic derived from the device id with no interpolation of caller input; the ticket is scoped to one device, so a mis-delivered ticket is refused at redemption. Test both halves | E4.S11 |
| R-013 | OPS | `Watch` reconnect storms against the authorisation backend after it recovers | 2 | 1 | 2 | Jittered backoff, reusing `internal/backoff`; test that N watchers do not reconnect in lockstep | E4.S3 |

### Low-Priority Risks (Score 1-2)

| Risk ID | Category | Description | Probability | Impact | Score | Action |
| --- | --- | --- | --- | --- | --- | --- |
| R-014 | OPS | `authorized_keys` remains in use in production despite the boot warning | 2 | 1 | 2 | Warning already exists; monitor. The real fix is `sshca` being easy enough to prefer |
| R-015 | TECH | Two authorisation paths — SSH and API — drift, so a grant enforced on one is not on the other | 1 | 2 | 2 | One `Authorizer` call site per action; a test asserts both surfaces refuse the same principal |

### Risk Category Legend

- **TECH**: Technical/Architecture · **SEC**: Security · **PERF**: Performance
- **DATA**: Data Integrity · **BUS**: Business Impact · **OPS**: Operations

---

## Test Coverage Plan

### P0 (Critical) — run on every commit

| Requirement | Test Level | Risk Link | Test Count | Owner | Notes |
| --- | --- | --- | --- | --- | --- |
| **SC5** — a 60 s failure of the authz backend closes **zero** live sessions | Integration | R-001, R-007 | 3 | dev | Fault injection. The test that distinguishes this design from the one it replaced |
| FR18 — deny closes as `revoked`; **error** refuses new sessions and grants live ones a grace window, closing as `authz_unavailable` | Integration | R-001 | 5 | dev | Both close reasons asserted in the ledger, because the audit trail is the deliverable |
| FR18 — `authz.grace: 0` restores strict fail-closed | Integration | R-007 | 2 | dev | Both ends of the range, or the parameter is untested |
| `plugintest` conformance — a backend that returns `Allow:false` on error **fails the suite** | Unit | R-001 | 3 | dev | The suite is the mitigation; a suite that passes a wrong backend is worthless |
| FR20 — a bare `On-Behalf-Of` header is refused | API | R-002 | 2 | dev | |
| FR20 — assertion: expired, wrong audience, subject outside `may_act_for`, replayed | API | R-002 | 5 | dev | Four distinct refusals, each with its own code |
| FR16/FR17 — a withdrawn grant closes a live session within `recheck_interval` even with `Watch` dead | Integration | R-003 | 3 | dev | Kill the stream first; the interval is the guarantee |
| FR17 — `Watch` closes a live session in under a second | Integration | R-003 | 2 | dev | |
| FR22 — a retired device key no longer authenticates; the remaining keys still do | Integration | R-004 | 3 | dev | Publish-then-retire, both steps |
| FR27/FR44 — a `record_input` conflict refuses with `policy_conflict` and names both rules | Integration | R-006 | 3 | dev | PCI device + EU operator. Must refuse, not choose |
| FR15 — `Principal.Expiry` caps the session | Integration | R-008 | 2 | dev | Session closes at expiry, not at the next re-check |

**Total P0**: 36 tests, ~5–7 days

### P1 (High) — run on PR to main

| Requirement | Test Level | Risk Link | Test Count | Owner | Notes |
| --- | --- | --- | --- | --- | --- |
| FR15 — OIDC device-code flow over keyboard-interactive | Integration | R-008 | 3 | dev | Needs an OIDC test double |
| FR15 — SSH-CA: a valid short-lived cert is accepted, an expired one is not, a wrong-CA one is not | Integration | — | 4 | dev | Promoted to the recommended default, so it needs the strongest coverage of the three backends |
| FR23 — every replica presents the same host key; the private half is never logged | Integration | R-005 | 3 | dev | Grep startup output for key material |
| FR21 — unattended sessions are tagged and separable in a query | API | R-010 | 2 | dev | |
| FR31 — the audit event set, and a counted drop under flood | Integration | R-009 | 3 | dev | |
| FR2 — the MQTT adapter delivers to the right topic; a mis-delivered ticket is refused | Integration | R-012 | 3 | dev | Both halves: routing and scope |
| FR19 — `admin_kill` from the API on a live session | E2E | — | 1 | dev | Already covered by J7; keep it here as the regression anchor |

**Total P1**: 19 tests, ~3–4 days

### P2 (Medium) — nightly

| Requirement | Test Level | Risk Link | Test Count | Owner | Notes |
| --- | --- | --- | --- | --- | --- |
| Webhook cache TTL is shorter than `recheck_interval` | Unit | R-011 | 2 | dev | Assert the relationship, not the values |
| `Watch` reconnects with jitter; N watchers do not lockstep | Unit | R-013 | 2 | dev | |
| Both surfaces (SSH and API) refuse the same principal | Integration | R-015 | 2 | dev | |
| Authorisation decision latency under 200 concurrent sessions | Integration | — | 2 | dev | The re-check load is `sessions × 2/min`; measure before it surprises someone |

**Total P2**: 8 tests, ~1–2 days

### P3 (Low) — on demand

| Requirement | Test Level | Risk Link | Test Count | Owner | Notes |
| --- | --- | --- | --- | --- | --- |
| `authorized_keys` boot warning fires above the threshold | Unit | R-014 | 1 | dev | |
| Every action string is enforced somewhere | Unit | — | 2 | dev | Enumerates the action set and asserts a call site per action |

**Total P3**: 3 tests, ~0.5 days

---

## Execution Order

### Smoke tests (<5 min)

1. A grant allows; its withdrawal closes the session
2. A bare `On-Behalf-Of` is refused
3. An authz error does not close a live session

### P0 tests (<10 min)

4. The three-outcome contract, both close reasons (R-001)
5. `plugintest` conformance, including the negative case
6. Delegated-authority refusals (R-002)
7. Revocation with and without `Watch` (R-003)
8. Key rotation (R-004)
9. Policy conflict (R-006)
10. Expiry ceiling (R-008)

### P1 tests (<30 min)

11. OIDC and SSH-CA backends
12. Host key across replicas
13. Audit events and drops
14. MQTT delivery

### P2/P3 tests (<60 min)

15. Cache/interval relationship, jitter, cross-surface parity, decision latency

---

## Resource Estimates

### Test development effort

| Band | Tests | Estimate | Confidence |
| --- | --- | --- | --- |
| Test doubles (OIDC provider, MQTT broker, SSH CA, webhook authorizer with SSE) | — | 2–3 days | medium |
| P0 | 36 | 4–5 days | medium — the Go harness already exists |
| P1 | 19 | 3–4 days | medium |
| P2 | 8 | 1–2 days | high |
| P3 | 3 | ~0.5 days | high |
| **Total** | **66** | **10–13 days** | **medium** |

Confidence is higher than Epic 3's because the harness exists: `internal/e2e` already
stands up a whole gateway, and the fault-injection pattern is already proven by
`TestBackendOutageClosesZeroSessions`.

### Prerequisites

- **A `plugintest` conformance package.** Promised in `docs/plugins.md` § 11.1 and not
  yet written. It is R-001's entire mitigation, so it is a prerequisite rather than a
  deliverable of the last story.
- **Test doubles**: an OIDC provider, an MQTT broker, an SSH CA, and a webhook
  authorizer that can be made to fail on command. The last one already exists in
  spirit — `internal/record`'s `flakyStore` is the pattern to copy.
- **A tenancy-free policy selector model** — decided in ARCHITECTURE § 8.2; no
  further design needed.
- **A second gateway replica in the harness** for R-005's host-key test. `internal/e2e`
  builds one today.

---

## Quality Gate Criteria

### Pass/fail thresholds

- **P0 pass rate**: 100%, no exceptions
- **P1 pass rate**: ≥95%
- **P2/P3 pass rate**: ≥90%
- **High-risk mitigations**: 100% complete or an approved written waiver

### Coverage targets

- **Critical paths** (J6, J7): ≥80%
- **Security scenarios**: **100%** — six of eight high risks are SEC, and this epic is
  the one where a gap is not a bug but an access-control failure
- **Business logic**: ≥70%
- **Edge cases**: ≥50%

### Non-negotiable requirements

- [ ] **SC5 demonstrated by fault injection**: a 60 s outage of the authz backend, the
      recorder backend and the doorbell each close zero live sessions
- [ ] `authz_unavailable` and `revoked` are never interchangeable, asserted in the ledger
- [ ] `plugintest` fails a backend that returns `Allow:false` on error
- [ ] A bare `On-Behalf-Of` is refused; all four assertion failures have distinct codes
- [ ] A retired device key does not authenticate
- [ ] A `record_input` conflict refuses rather than choosing

---

## Mitigation Plans

### R-001: A backend conflates "denied" with "could not decide" (Score: 6)

**Mitigation Strategy:** the conformance suite, not documentation. `plugintest` runs a
backend through a case where its dependency is down and asserts it returns an `error`
rather than `Allow:false`. A backend that conflates them fails the suite.

The reason this is the top risk despite a modest score is the shape of the failure: it
is silent, it writes `revoked` into an audit trail for an outage, and it converts a
dependency's bad minute into a fleet-wide session kill — the precise failure the
three-outcome contract was introduced to prevent. And it is entirely in the hands of
somebody who does not work on Oarlock.

**Owner:** E4.S4 · **Timeline:** before M3 exit · **Status:** Planned

### R-003: Revocation that never arrives (Score: 6)

**Mitigation Strategy:** the re-check interval is the guarantee; `Watch` is the
optimisation. So the test that matters kills the stream *first* and then withdraws the
grant, asserting closure within `recheck_interval`. A test that only exercises the
happy path through `Watch` would pass on a build where the interval loop is broken —
which is the build where revocation quietly stops working.

**Owner:** E4.S3, E4.S5 · **Timeline:** before M3 exit · **Status:** Planned

### R-006: A policy conflict resolved instead of refused (Score: 6)

**Mitigation Strategy:** the test constructs the actual regulatory collision — a
PCI-scoped device and an operator whose jurisdiction forbids keystroke capture — and
asserts the session is **refused** with `policy_conflict`, with both rules named in the
audit event. Any test that asserts a *choice* is asserting the bug.

**Owner:** E4.S9 · **Timeline:** before M3 exit · **Status:** Planned

---

## Assumptions and Dependencies

### Assumptions

- Test doubles are in-process Go, following the `flakyStore` pattern, rather than
  containers. Faster, and it keeps fault injection precise.
- `internal/e2e` is extended rather than duplicated. It already builds a whole gateway.
- Fault-injection tests use short deadlines scaled from the shipped ratios rather than
  real 60-second waits, as `TestBackendOutageClosesZeroSessions` already does.

### Dependencies

- **`plugintest` blocks R-001.** It is the mitigation, so it comes first.
- **E4.S9 depends on the policy selector model**, which ARCHITECTURE § 8.2 settles.
- **R-005 depends on a two-replica harness**, which does not exist yet — `internal/e2e`
  builds one gateway.
- **E4.S11 (MQTT) depends on a broker double.** The `exec` and `webhook` dispatchers
  need none, so this is the only new infrastructure in the epic.

### Risks to plan

- **Three of this epic's requirements are new designs from the review, not inherited
  ones** — the three-outcome contract, signed delegation, and conflict refusal. New
  designs are where tests find design problems rather than implementation ones, and
  finding one mid-epic will cost more than the estimate allows.
- **Scaled fault-injection timings can hide a real timing bug.** A 60-second deadline
  tested at 2 seconds proves the mechanism, not the constant. At least one test should
  run at the real value, nightly.
- **Six of eight high risks are SEC**, and a 100% target on security scenarios means
  the P0 band has no slack. If the estimate slips, the slip has to come out of P2.

---

## Follow-on Workflows (Manual)

- `atdd` — failing acceptance tests for the P0 set, especially SC5
- `nfr-assess` — before M3 exit, against the SEC and OPS risks here
- `trace` — requirements-to-tests matrix; this epic has the densest requirement set
- `automate` — after E4 lands

---

## Appendix

### Related documents

- `ARCHITECTURE.md` § 7.1 — denied and could-not-ask are different facts
- `ARCHITECTURE.md` § 8.2 — `record_input` as a selector policy, and conflict refusal
- `docs/sdk.md` § 3 — delegated authority, and why a bare header is refused
- `docs/plugins.md` § 3 and § 11.1 — the `Authorizer` contract and `plugintest`
- `adversarial-review-spec-2026-08-20.md` — findings 1 and 3, whose fixes this epic implements
