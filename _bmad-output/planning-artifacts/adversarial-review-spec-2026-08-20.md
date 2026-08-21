---
title: Adversarial Review — Oarlock specification
task: _bmad/core/tasks/review-adversarial-general.xml
project: oarlock
date: 2026-08-20
reviewer: cynical review pass (in-process, not a cold subagent — see caveat)
content_reviewed:
  - README.md
  - ARCHITECTURE.md
  - docs/protocol.md
  - docs/plugins.md
  - docs/sdk.md
  - docs/threat-model.md
findings: 20
blocking: 5
blocking_resolved: 5
resolved_date: 2026-08-20
---

# Adversarial Review — Oarlock specification

**Caveat on this review's weight.** The task file asks for this to run in a separate process
with no context except the content. It ran in-process, with the author's context, so it is
biased toward the spec's own framing. Findings below are real; the ones it *failed* to find
are the risk. A cold read by someone who has not seen these documents is still owed.

Content type: six design documents, 2,196 lines, no implementation.

---

## Blocking — a design decision is wrong, not merely thin

> **All five were amended in the specification on 2026-08-20**, before PRD work began.
> Each carries its resolution and the ADR that records it. Findings 6–20 are carried into
> planning unresolved — except 7, fixed in passing because it was a wrong path, not a
> decision.

**1. Fail-closed authorisation turns a permissions-API blip into a fleet-wide session kill.**
`Authorizer` is re-checked every 30 s, the plugin cache TTL defaults to 5 s, and an error
denies. So every live session makes a live call to the authz backend twice a minute, and
the *first* failed call closes the session with `revoked`. A thirty-second outage of the
permissions service terminates every shell in the fleet simultaneously — during exactly the
kind of incident when operators need shells. The spec never distinguishes **denied** from
**could not ask**, which are different facts with different correct responses. A grace
window ("keep existing sessions for N failed re-checks, refuse new ones") is missing, and
`revoked` is the wrong close reason for an infrastructure failure.

**Resolved** — `ARCHITECTURE.md` § 7.1 now has three outcomes, not two. An authorisation
*error* refuses new sessions immediately and gives live ones `authz.grace` (default 3)
re-checks before closing them as `authz_unavailable` rather than `revoked`. `authz.grace: 0`
restores strict fail-closed for anyone who wants it. ADR-016.

**2. Recorder failure being fatal has the same shape, and the spec argues for it proudly.**
`recorder_failed` closes live sessions. With the S3/GCS recorder that means a transient
5xx from object storage kills work in progress. The reasoning ("an unrecorded session that
looks recorded is worse than none") is sound; the implementation of that reasoning has no
tolerance band. What is missing is a bounded local spool with a defined ceiling — buffer to
disk, keep the session, close only when the spool is full or the flush deadline passes.
As written, the audit guarantee is purchased with an availability outage triggerable by a
third party.

**Resolved** — `ARCHITECTURE.md` § 8.1 puts a bounded spool between the pump and the
`Recorder`: `recorder.spool_bytes` 64 MiB, `recorder.flush_deadline` 60 s. Only exhaustion
closes the session, and the partial recording survives on disk for recovery. ADR-017.

**3. `On-Behalf-Of` is an unauthenticated privilege escalation.**
`docs/sdk.md` §3 has a service present `Authorization: Bearer svc_…` and then *assert*
`On-Behalf-Of: phuc@example.com` in a plain header. Nothing binds that assertion to
anything. Any holder of any service token can claim to act for any human — including one
with broader grants than the caller. The correct shape is a signed actor claim (an OIDC
token with an `act` claim, or a short-lived assertion the human's own session produced),
plus a per-service allow-list of subjects it may act for. The document spends a paragraph
explaining why attribution matters and then makes attribution self-asserted.

**Resolved** — `docs/sdk.md` § 3 replaces the bare header with `On-Behalf-Of-Token`,
verified by a new `Authenticator.AuthDelegated`. Two accepted shapes: the subject's own IdP
token (preferred), or a service-signed assertion under 60 s constrained by a `may_act_for`
allow-list. The weaker shape is documented as weaker. ADR-018.

**4. Idle timeout measured on operator input alone kills the sessions that matter most.**
`ARCHITECTURE.md` §9.3 defines `limits.idle` as "no operator input for 5 min". An operator
who starts a twenty-minute firmware flash and watches it has their session killed at minute
five, mid-flash, on a device in a customer's home. Output activity must count toward
liveness, or the timer specifically punishes long privileged operations. As specified this
is not a tuning choice, it is a defect with a plausible path to bricking hardware.

**Resolved** — `ARCHITECTURE.md` § 9.3: `limits.idle` (5 min) now measures bytes in
*either* direction, and a new `limits.idle_input` (60 min) catches a `tail -f` nobody is
reading without killing work in progress. ADR-019.

**5. `limits.frame` and `limits.rate` are two orders of magnitude apart.**
1 MiB frame ceiling, 25 ms coalescing window, 256 KiB/s per-session cap. At the cap a 25 ms
window holds roughly 6.5 KiB, so a legitimate frame can never approach 1 MiB. Either the
rate cap does not apply where the reader assumes, or the frame ceiling is arbitrary. One of
the three numbers is wrong and the spec gives no way to tell which.

**Resolved** — `ARCHITECTURE.md` § 9.3 chooses all three as one set and shows the
arithmetic: `limits.batch` 64 KiB bounds one coalesced `DATA` frame, `limits.rate` is
256 KiB/s sustained with a 1 MiB burst bucket, and `limits.frame` 1 MiB becomes an explicit
safety net that `DATA` never approaches. ADR-020.

## Serious — a real gap that will be discovered in implementation

**6. Multi-attach is offered by the API and specified nowhere.**
`POST /sessions/{id}/attach` says "for a reconnecting browser, **or a second viewer**".
Nothing in any document describes two attached operators: who holds input, whether the
second is read-only, whether the first is told they are observed, or how `Authorizer`
scopes an observer. Watching someone else's shell is a distinct capability with its own
consent and audit questions, and there is no `read_only` flag, no `observe` action, and no
event for it. Either delete the phrase or specify the feature.

**7. `POST /sessions/{id}/exec` is nested under a session it does not use.**
It is described as a one-shot — run an allow-listed command, get stdout and an exit code —
and the text calls it the endpoint most integrations should start with. A one-shot has no
session to be nested under. The path should be `POST /devices/{id}/exec`, and as written
the API contradicts its own resource model.

**Resolved in passing** — moved to `POST /api/v1/devices/{id}/exec`.

**8. Nothing specifies the gateway's own SSH host key across replicas.**
Multi-node is designed in §10, and the SSH front door is the primary CLI surface. If
replicas do not share a host key, every operator gets a host-key-mismatch warning on
reconnect and will be trained to ignore it — which is the exact failure the warning exists
to prevent. Shared key material across replicas, rotation, and how operators pin it are
all unaddressed. This is security-relevant and it is not in the threat model.

**9. Device key rotation is out of scope by accident.**
Enrollment is explicitly not Oarlock's job, which is defensible. But `AgentAuthenticator`
*is* Oarlock, and rotating a device key, revoking a compromised one, and handling a
factory-reset device that returns with a new key under the same id are all Oarlock's
problem. `PublicKeys` is a list, which hints at rotation, and no document describes it.

**10. `file` and `tcp` sessions are unrecorded without being flagged as such.**
The spec establishes a principle — an unrecorded session must be a queryable fact, not an
absence — and then exempts two profiles from recording by table entry alone. Passthrough
gets `recording_state: not_recorded`, three guard rails and a banner; a `file` read of
`/data/secrets.json` gets none of that. At minimum these need the same session-row marking,
and the spec should say what *is* recorded for them (path, byte count, nothing).

**11. The scrollback ring has no defined home under node-to-node forwarding.**
§10 forwards an operator on replica B to the agent on replica A. The 256 KiB ring, the
coalescer and the recorder all live somewhere in that path and the document does not say
where. If the ring is on B, a reattach that lands on C replays nothing; if on A, the
forwarding hop is inside the recorded stream. This is the kind of ambiguity that becomes
two incompatible implementations.

**12. `Idempotency-Key` outlives the ticket it caches.**
Keys are honoured for 24 h; attach tickets expire in 60 s. A retry at minute two returns
`201` with a dead ticket and no indication that it is dead. The cached response must either
re-mint the ticket or the error must say "session exists, request a new attach".

**13. The doorbell answer deadline argues against itself.**
§3.2 says to "budget 30 s before giving up, because a sleeping radio is slow, not broken",
which is the correct instinct and the wrong number — Android doze plus push delivery is
routinely minutes, not seconds. Compounding it, the ticket TTL is 60 s, so there is no room
for the agent to fail once and retry with a fresh ticket inside the same operator wait.
The two timers were chosen independently and do not compose.

## Thin — under-specified rather than wrong

**14. "Output-only recording still shows every command" is false often enough to matter.**
`ARCHITECTURE.md` §8 uses this to justify `record_input: false`. It holds for a line-mode
shell echoing commands. It fails for anything in raw mode — `vi`, `less`, a TUI — and for
any client that sends input without echo. The default is still defensible; the justification
overstates its own coverage and should say what the recording *loses*.

**15. Observability is a `/metrics` endpoint and no specification.**
For a service whose failure mode is "operators cannot get in during an incident", there is
no golden-signal list, no SLO for session-open latency, no defined metric names, and no
alerting guidance. `/metrics` is explicitly excluded from the compatibility promise, which
means dashboards break between minors.

**16. Rate limits and pagination are named without being specified.**
"Cursor-paginated" and "rate limits and headers" appear as prose. No header names, no
default page size, no limit values, no `429` semantics or `Retry-After`. SDK authors will
guess differently.

**17. API stability is promised on top of an admittedly unstable substrate.**
`/api/v1` is additive-only forever; the wire protocol is `v0` and "will change". `READY`
fields (`mode`, `recording`) surface directly in API responses. Nothing describes how a
protocol change is prevented from becoming an API change.

**18. No conformance suite for third-party agents.**
The wire protocol is public and third-party agents are an explicit goal. `plugintest`
covers plugins; nothing covers agents. Without an agent conformance suite, the Android
agent and the reference agent will diverge, and the divergence will be found by an operator
at 2 a.m.

**19. No CLI.**
An OSS SSH gateway with no `oarlockctl` means every operational action — list sessions,
kill one, pull a recording — is a `curl` with a hand-made token. The SDK section covers
integrators and skips operators.

**20. M0 has no test strategy.**
The milestone list describes features and never mentions how any of it is verified. The
threat model asks for fuzzing of `pkg/frame` and the `file` profile; the milestones do not
schedule it, so it will not happen.

---

## Verdict

The spec is coherent and unusually explicit about its own costs. Its weakness is a pattern,
not a list: **three separate places choose "fail closed" without a tolerance band**
(findings 1, 2, and the recorder's interaction with 11), which converts other people's
transient failures into Oarlock outages during incidents. That pattern plus finding 3 —
self-asserted attribution in the one place the design claims attribution as its reason to
exist — are what a cold reviewer would lead with.

Findings 1–5 should change the documents before any code is written. Findings 6–13 should
be resolved during PRD and epic breakdown. Findings 14–20 are backlog.
