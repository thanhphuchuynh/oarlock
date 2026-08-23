---
stepsCompleted: [1, 2, 3, 4]
inputDocuments:
  - _bmad-output/planning-artifacts/prd-oarlock-2026-08-20.md
  - _bmad-output/planning-artifacts/implementation-readiness-report-2026-08-20.md
  - ARCHITECTURE.md
  - docs/protocol.md
  - docs/plugins.md
  - docs/sdk.md
  - docs/threat-model.md
workflowType: 'create-epics-and-stories'
project_name: oarlock
epics: 9
stories: 59
revision: 2
revision_note: 'Revised against the readiness report: dispatch moved into M0, requirement ids inline, J1 and SC2 given owning stories, recording integrity split into its own epic, dependencies made explicit'
---

# Epics & Stories - oarlock

**Author:** Tphuc
**Date:** 2026-08-20 · revision 2

**Depth note.** Epics 1, 2 and 9 carry full acceptance criteria — they are M0 and M1 and get
picked up next. Epics 3–8 carry story definitions with requirement ids and the criteria that
constrain design; each needs a pass through `create-story` before a developer takes it.
Writing 46 fully specified stories now would invent detail M0 is about to invalidate.

**Every story names its requirements inline.** A developer picking up a story should not have
to consult a table at the bottom of the document to know what it discharges.

---

## Epic 1 — Reach a device, both ways, and pair a session (M0)

**Goal:** the two hard mechanisms — finding each other, and moving bytes — proven over
**both** reachability modes before anything is built on them.
**Journey:** J1 (owned, see E1.S8) · **Success criteria:** SC1, SC2, SC8 (partial)
**Progress:** S1 ✅ · S2 ✅ · S3 ✅ · S4 ✅ · S5 ✅ · S6 ✅ · S7 ✅ · S8 ✅ —
remaining: **S9** (hardware, needs a device on a bench). `internal/e2e` is the
product's smoke test: J1 over **both** reachability modes, with its own CI job.

### E1.S1 — Frame codec behind a transport interface · `NFR19, NFR11` — ✅ **done**

*As an implementer, I need the wire codec and a transport abstraction, so adopting
WebTransport later deletes code instead of adding a second protocol.*

- `pkg/frame` encodes and decodes every frame type in `docs/protocol.md`, mux and non-mux.
- A `Transport` interface exposes connect / send-message / receive-message / close.
  WebSocket is the only implementation, and **no WebSocket type appears in any signature
  above it** — asserted by a test that compiles the gateway against a stub transport.
- Unknown session-scoped frame types are ignored with a counter; unknown connection-scoped
  types close the connection.
- Text WebSocket frames are a protocol error.
- A frame over `limits.frame` is rejected by the transport without allocating on the sender's
  behalf.
- `go test -fuzz` targets for the decoder run in CI.
- **Rejects:** any path where an attacker-supplied length or count drives an allocation.

### E1.S2 — Agent handshake and device registry · `FR5, FR22 (partial), NFR9, NFR10` — ✅ **done**

*As a gateway, I need to know a connecting agent is the device it claims to be.*

- `HELLO` / `CHALLENGE` / `AUTH` / `WELCOME` per protocol § 3.1: Ed25519, both nonces
  contributed, `device_id` and `gateway_id` inside the signed blob.
- 5 s budget from socket open; over budget closes the connection.
- `PublicKeys` is read as a **list** from a file-backed `DeviceRegistry`, so E4.S7 can rotate
  without a schema change.
- Agent pins the gateway certificate by default; unpinned logs a warning at startup.
- `caps` recorded; a profile the agent did not advertise is refused at open with
  `profile_unsupported`, not after a round trip.
- **Rejects:** any long-lived bearer token stored on the device.

### E1.S3 — `persistent` mode: the control channel · `FR1, FR4, NFR16, NFR20` — ✅ **done**

*As an agent on a Linux host, I hold one channel open so the gateway can reach me.*

**Decision taken (ADR-024): Oarlock does not multiplex.** The conflict this story
previously carried — NFR20 wanted `smux`, and `smux` wants a byte stream, which
reintroduces the length field `pkg/frame` exists to avoid — is resolved by removing
multiplexing rather than choosing a multiplexer. The control channel carries no
session traffic at all.

- One outbound connection per agent, `PING` every 30 s, three missed `PONG`s closes.
- The channel carries **only** connection-scoped frames: `HELLO`, `CHALLENGE`,
  `AUTH`, `WELCOME`, `PING`, `PONG`, `DIAL`, `CANCEL`, `GOAWAY`. A session frame
  arriving here closes the channel — `frame.Expect` already returns `ErrWrongChan`
  for it, and a test asserts the channel handler acts on that.
- Hub maps `device_id → control channel`, with pending invitations per device.
- `DIAL` carries an `Invitation`; the agent dials a fresh session connection and
  presents the ticket. `CANCEL` withdraws an invitation so a slow device does not
  wake up and dial for a session nobody is waiting on.
- Reconnect backoff jittered: base 1 s, ×1.6, cap 60 s, ±25 %.
- `WELCOME.resume` carries one invitation per session the gateway still holds, and
  the agent dials back for each — which is how a shell survives a lost radio.
- **No stream ids anywhere.** A test asserts `frame.HeaderLen == 1`.

### E1.S4 — `dispatch` mode: tickets and the doorbell · `FR2, FR5, NFR8` — ✅ **done**

*As an agent on Android, I am woken by a doorbell and dial one connection per session.*

**Moved into M0 from M3.** Android buckets apps into standby tiers, can flag persistent
connections as excessive, and forbids a `dataSync` foreground service from starting at
`BOOT_COMPLETED` — exactly when a rebooted device must become reachable. Building
`persistent` first and reaching the doorbell three milestones later would test the mode the
primary platform resists and ship the one it needs last.

- **Both modes end here.** After ADR-024 a session is always its own connection opened
  with a ticket; `dispatch` differs from `persistent` only in how the `Invitation` was
  delivered. This story owns the ticket, the `Dispatcher` interface and the two
  infrastructure-free adapters; E1.S3 owns the `DIAL` delivery path. One `Invitation`
  type, one handler.
- Ticket: 32 bytes from `crypto/rand`, base64url, single use, TTL 60 s, scoped to one device,
  profile and principal.
- **Redemption is an atomic compare-and-delete** — a concurrency test races two redeemers and
  asserts exactly one wins.
- Ticket travels in the `OPEN` frame body. A test asserts no ticket appears in any URL, log
  line or `Sec-WebSocket-Protocol` value.
- `Dispatcher` interface plus the **`exec`** and **`webhook`** adapters — no infrastructure,
  so the mode is testable on a laptop. **MQTT stays in E4.**
- `Invitation` names the specific node to dial, not a load balancer.
- **`Wake` failure is distinguished from device-offline**: a broken doorbell reports
  `doorbell_failed`, never `device_offline` (FR5). A test asserts the two produce different
  API responses and different operator-facing text.
- An agent retrying a dial **fetches a fresh ticket**; a test asserts a resent ticket is
  refused exactly as a replay would be.
- `answer_deadline` is configurable and defaults to 30 s, with the doze caveat documented:
  this number is a guess until measured on real hardware (E1.S9 note).

### E1.S5 — Byte pump, coalescing, per-profile flow control · `NFR2, NFR3, NFR4` — ✅ **done**

*As an operator, output arrives promptly and my full-screen program never corrupts.*

- Device→operator `DATA` coalesced into ≤ 25 ms batches, capped at `limits.batch` 64 KiB.
- Operator input forwarded immediately, never batched.
- `shell` applies backpressure at a high-water mark, resumes at a low one, and **never emits
  `THROTTLE`** — a `THROTTLE` on a shell stream fails the suite.
- `log` and `exec` coalesce and drop, announcing bytes dropped.
- `limits.rate` as a token bucket: 256 KiB/s sustained, 1 MiB burst.
- A test runs `vi`, floods concurrently, and asserts the terminal is not corrupted.
  ✅ **Landed in E1.S6** as `TestFloodOfEscapeSequencesIsLossless`: 2000 lines of
  cursor-home, erase and colour sequences through a real PTY and an 8 KiB buffer,
  asserting every sequence arrives intact. A literal `vi` would add an
  environment dependency without adding a property.
  Previously deferred from E1.S5, which is where a PTY did not yet exist. E1.S5 covers the same
  property without one: a megabyte of escape sequences through a deliberately small
  buffer, asserted byte-exact, plus a test that fails if `THROTTLE` is ever emitted
  on a shell stream.

### E1.S6 — PTY on the agent, SSH front door · `FR6, FR9, FR10 (shell), FR15 (keys), NFR6` — ✅ **done**

*As an operator, `ssh dev-1@localhost -p 2222` gives me a working shell.*

- `gliderlabs/ssh` front door; **`x/crypto` ≥ 0.17.0 with strict kex, version asserted in
  CI** — Terrapin (CVE-2023-48795) is a live class against custom SSH servers.
- SSH user parsed as the **device id**; the operator comes from their key.
- Agent `forkpty`s the platform shell behind a `Shell` hook; `TERM` from `OPEN_STREAM`.
- `RESIZE` reaches the PTY, coalesced to one per 100 ms; `EXIT` carries the exit code.
- `authorized_keys` authenticator, in-memory session store.

### E1.S7 — Reachability default from platform · `FR3` — ✅ **done** (landed with E1.S2, since the field belongs to the registry's data model)

*As a gateway operator, Android devices use `dispatch` and Linux hosts use `persistent`
without my configuring each one.*

- **`Device.Platform`** added to the struct and the registry file format —
  `android | linux | container | other`.
- Unset `Mode` resolves: `android` → `dispatch`; `linux`, `container` → `persistent`.
  An explicit `Mode` always wins.
- The resolved value is logged at registration, so a surprising default is visible once.
- **Depends on:** the `Platform` field landing in `docs/plugins.md` § 6 (done).

### E1.S8 — J1 end to end, as one owned test · `FR6, FR12, SC1` — ✅ **done**

*As an operator in an incident, I ssh to a frozen device, fix it, and leave a trail.*

The primary journey gets an owning story and a single test that walks it, because the one
path that must always work should not be the emergent sum of five other stories.

- Automated: authenticate → banner naming device, mode and recording state → prompt → run a
  command → read output → exit → session row exists, attributed, with the reason string.
- **Runs against both reachability modes** in CI.
- Asserts SC1: an unmodified `ssh` client with no `~/.ssh/config` entry, no wrapper, no
  plugin.
- Failure of this test blocks a release. It is the product's smoke test.

### E1.S9 — Verify nothing listens on the device · `SC2, OL-001`

*As a reviewer, I want the assumption the whole architecture rests on to be tested rather
than asserted.*

The readiness report found this claim unverified by anything. It is OL-001, the assumption
every other decision derives from.

- A port scan of a device running the agent in mode C shows **no new listening socket**,
  compared against a pre-agent baseline.
- The agent process holds **no host key material** — asserted on the filesystem and in the
  keystore.
- Runs against **real hardware**, not a mock: an Android device and a Linux host.
- Also captures, on the same real hardware, the two numbers currently guessed: doze wake
  latency for the doorbell, and whether an OEM power manager kills a device-owner foreground
  service. Feeds `answer_deadline` (E1.S4) and NFR1.
- **Exit criterion for M0** alongside E1.S8.

---

## Epic 2 — Record a session and account for it (M1)

**Progress:** S1 ✅ · S2 ✅ · S3 ✅* · S4 ✅ · S5 ✅** — Epic 2 is complete for M1.

**\*\*`POST /api/v1/sessions` is deliberately not in S5.** Its success response is an
attach ticket for `/ws/attach`, and until that endpoint exists the endpoint would hand
callers a credential for a connection they cannot make. It lands with **E3.S1**, where
the 201 becomes usable. What S5 does deliver: the read and administrative surface
(`GET`, `GET /{id}`, `DELETE /{id}`), the RFC 9457 error envelope with a correlation
id on every failure, cursor pagination with documented headers, per-principal rate
limiting with an honest `Retry-After`, the **live-session registry** that makes
`admin_kill` possible at all (and which E4.S5 and E6.S3 both need), and the
`internal/safety` boot gate.

**The boot gate has no caller yet.** `internal/safety` is a tested library; the daemon
that calls it at startup is `cmd/oarlockd`, which arrives with M6. Wiring it into a
main that does not exist would have been a no-op dressed as a control.

**S4 changed the design, not just the tests.** The criterion asked for a test that a
truncation attack cannot suppress the disclosure. Writing it made clear that a single
early message *can* be suppressed if strict key exchange ever fails to negotiate — so
the disclosure is now **said twice**, once before the prompt and once at close, where
no prefix attack reaches. The closing copy also carries the session id, which is what
somebody needs in order to find the recording. Strict kex is asserted by reading the
server's KEXINIT off the wire, not inferred from `go.mod`.

**\*One part of S3 is deliberately not built: NFR14's detach.** The criterion says a
dropped operator connection must not close a session. Over SSH there is nothing to
reattach *to* — a second `ssh` invocation is a new session — so a detached SSH session
would be a shell nobody can reach, holding the device's only slot until the idle timer
fires. That is worse than closing it. The ledger has the states for it; the mechanism
(ring buffer, `detached`, reattach) belongs to **E3.S3**, where a browser can actually
come back. Building half of it here would have meant a feature that only makes things
worse.

**Seam change while building S2:** storage is pluggable as a **blob `Store`**, not as
an event writer. The spool has to sit below the asciicast encoder — above it, a retry
would re-encode and recompute the hash chain, so a retry could change a recording's
identity. Recorded in `docs/plugins.md` § 4.


**Goal:** a session you can replay and account for. Integrity is Epic 9, running in parallel.
**Requirements:** FR24, FR28, FR29, FR32, FR14, FR12, FR10 (`exec` recording), NFR12,
NFR14, NFR15, NFR21 · **Journey:** J5 (partial, replay in E3.S6)

### E2.S1 — asciicast v3 streaming writer · `FR24, NFR15, NFR21` — ✅ **done**

- asciicast **v3** — relative event deltas, grouped header. Relative deltas let a spooling
  recorder resume mid-session without rewriting, which v2's absolute timestamps do not.
- Streamed and flushed continuously; a file truncated at any line boundary plays up to that
  point — asserted by a kill-mid-session test.
- Output always recorded; input only when the policy resolves true (E4.S9).
- `RESIZE` recorded, so replay reflows.
- Sidecar at close: exit code, close reason, principal, device, byte counts, duration.

### E2.S2 — Recorder spool and honest degradation · `FR29, NFR13, SC5` — ✅ **done**

- Bounded spool per session: `recorder.spool_bytes` 64 MiB, `recorder.flush_deadline` 60 s.
- A backend failing inside those bounds is invisible to the operator; one `recorder.degraded`
  audit event.
- On exhaustion: session closed `recorder_failed`, spool written to `recorder.spool_dir`.
- **Fault injection: backend returns 503 for 60 s → zero sessions closed.**
- Failure at open refuses the session. There is no silent unrecorded session.

### E2.S3 — Session ledger, close reasons, limits · `FR14, FR28, NFR14` — ✅ **mostly done**

- `SessionStore` with SQLite. `Create` enforces `sessions_per_device` and
  `sessions_per_principal` **atomically** via a unique index — a race test asserts the second
  opener gets `session_limit`, not a corrupted state.
- Every close reason in ARCHITECTURE § 6 reachable and tested, including `authz_unavailable`,
  `recorder_failed` and `policy_conflict`.
- A dropped operator connection does **not** close a session.
- `limits.idle` counts bytes either direction; `limits.idle_input` counts operator input only.
  Tested with a 20-minute simulated flash (must survive) and an unwatched `tail -f` (must be
  closed by `idle_input`).
- `recording_state` written for every session, including `not_recorded` for `file`, `tcp`,
  passthrough and `Recorder: none`.

### E2.S4 — Session banner and mode disclosure · `FR12, NFR7` — ✅ **done**

- Before the first prompt: device id, mode, recording state.
- **Not carried by an unauthenticated early channel message that prefix truncation could
  remove.** A test simulates a Terrapin-style truncation and asserts the banner cannot be
  suppressed.

### E2.S5 — Sessions API and the safe-defaults gate · `FR32, NFR12` — ✅ **done**, minus `POST`

- `POST /api/v1/sessions`, `GET`, `GET /{id}`, `DELETE /{id}`; cursor pagination with a
  documented header set, `429` and `Retry-After` semantics.
- RFC 9457 problem+json, shared error vocabulary, correlation `instance` on every error.
- A boot-time gate asserts shipped defaults are the safe ones and refuses to start
  `Authenticator: static` outside dev.

---

## Epic 9 — Recording integrity (M1, parallel with Epic 2)

**Progress:** S1 ✅ · S2 ✅ · S3 🟡 (`Verify` and the five verdicts exist and J1
checks them; `oarlockctl verify` is E6.S4 and the replay UI is E3.S6) · S4 ✅ —
**Epic 9 is complete for M1.** The chain and the signed manifest shipped *with* the
first recorder, as intended.

**S4 turned out to be more than documentation.** The criterion asked for a config
check that warns when a recorder writes to a mutable bucket. A config field would have
been a guarantee an operator types in and nobody verifies, so the check lives on the
**store** — an optional `ImmutabilityReporter` interface — and whatever it reports is
**written into the signed manifest**. A chain proves the bytes have not changed; this
records what stood between them and a change, which is the question an auditor asks
two years later and cannot otherwise answer. `unknown` is treated as mutable, because
silence is not a guarantee.

**Split out of Epic 2 per the readiness report:** cryptographic integrity has different
reviewers and a different failure mode from session CRUD. It ships **with** the first recorder
because a hash chain cannot be added to recordings that already exist.
**Requirements:** FR25, FR26 · **Success criterion:** SC3 · driven by PCI's "tamper-proof log"

### E9.S1 — Hash chain over the event stream · `FR25` — ✅ **done**

- Each event appends `H(prev ‖ event_bytes)`; the chain head is maintained as the recording
  is written, not computed afterwards.
- Truncation is detectable and **distinguishable from alteration**.
- Chain survives a spool-and-resume cycle (E2.S2) without a gap.

### E9.S2 — Signed manifest at close · `FR25` — ✅ **done**

- At close, a manifest signed over the chain head, session metadata and byte counts.
- Key handling documented; signing key separable from the gateway's SSH host key.
- A manifest is written even when the session ended badly.

### E9.S3 — Verification, surfaced not buried · `FR26, SC3` — 🟡 **partly done**: `Verify` and the five verdicts exist and J1 checks them; `oarlockctl verify` is E6.S4 and the replay UI is E3.S6.

- `oarlockctl verify <session>` recomputes the chain and checks the signature.
- **Replay surfaces a failed verification in the UI and in the API response**, not only in a
  log. An integrity guarantee nobody sees is decoration.
- Adversarial tests: altered byte, removed event, reordered events, truncated file, valid
  chain with a wrong signature — each produces a distinct, correct verdict.

### E9.S4 — WORM guidance for object stores · `FR25` — ✅ **done**

- S3 and GCS recorder documentation covers object lock / retention configuration.
- A configuration check warns when a recorder writes to a mutable bucket.

---

## Epic 3 — The browser, and the second pair of eyes (M2)

**Unblocked 2026-08-21:** `ux-design-specification.md` is written. The four decisions
that gate the stories: component **plus** a reference console; plain CSS for the
component and Tailwind + shadcn/ui for the console; disclosure as a permanent status
bar with a blocking gate only when unrecorded or passthrough; observation as a
persistent named indicator.

**Two stories gain scope from it.** E3.S2 now includes `<StatusBar>` and
`<PreflightGate>` as **separately exported, default-on** components — an integrator has
to take a deliberate step to ship without the disclosure. E3.S5 gains the observed
operator's named indicator and the observer's own disabled-input `READ-ONLY` state.

**One story is added:** **E3.S7 — progress as two named waits.** The architecture has
two distinct waits (waking the agent, opening the tunnel) and either can be the one
that stalls; a single spinner throws away information the gateway already has. The UX
spec calls this the product's defining interaction.
**Requirements:** FR7, FR8, FR13, FR30, FR36 · **Journeys:** J2, J5

- **E3.S1** `/ws/attach`, ticket in the `OPEN` frame, single use, renewal callback · `FR7, NFR8`
- **E3.S2** xterm.js terminal; OSC 52 clipboard writes and title reporting off by default · `FR36`
- **E3.S3** Reattach with scrollback from the ring; a fresh ticket means authorisation is
  re-checked for free · `FR8`
- **E3.S4** The failure screens, each rendered from exactly one server condition — including
  `authz_unavailable`, which must not read as "you were revoked" · `FR7, SC4`
- **E3.S5** **Read-only observer**: output only, no input, first operator notified, attachment
  audited. Uses the `observe` action now defined in ARCHITECTURE § 7 · `FR13`
- **E3.S6** Replay: asciinema player, `replay` enforced separately from `shell`, **integrity
  verdict above the player and read before playback** — a recording that does not verify must
  not be watched as though it does, and `truncated` reads differently from `altered` · `FR30, SC3`
- **E3.S7** Progress as two named waits, each with its own state and its own failure
  sentence in place. No spinner: nothing here has a knowable fraction, and an operator
  who thinks the UI has hung opens a second session · `FR7, SC8`

## Epic 4 — Identity, authorisation, revocation (M3)

**Requirements:** FR15–FR23, FR27, FR31, FR44, FR2 (MQTT adapter) · **Journeys:** J6, J7 ·
**SC4, SC5**

- **E4.S1** OIDC authenticator: device-code over keyboard-interactive for CLI, code flow for
  browser · `FR15`
- **E4.S2** SSH-CA authenticator, promoted to recommended default; `authorized_keys` warns at
  boot that it does not scale · `FR15`
- **E4.S3** Webhook authorizer with TTL cache and SSE `Watch` · `FR17` — ✅ **done**
- **E4.S4** **The three-outcome contract**: deny closes `revoked`; error refuses new sessions
  and grants live ones `authz.grace` re-checks before `authz_unavailable`. Fault injection
  proves zero sessions closed in a 60 s outage · `FR18, NFR13, SC5`
- **E4.S5** Mid-session re-check loop, sub-second `Watch` closure, `admin_kill` · `FR16, FR17, FR19, SC4`
- **E4.S6** **Delegated authority**: `AuthDelegated`, subject-token and service-signed
  assertion shapes, `may_act_for` allow-list, bare `On-Behalf-Of` refused, unattended sessions
  tagged · `FR20, FR21` — ✅ **done**
- **E4.S7** Device key rotation and revocation; a reset device returning with a new key under
  an existing id is refused until re-registered · `FR22` — ✅ **done**
- **E4.S8** Shared SSH host key across replicas, with a documented rotation procedure · `FR23` — ✅ **done**
- **E4.S9** `record_input` selector policy over operator attributes and device tags, and
  `policy_conflict` refusal · `FR27, FR44` — ✅ **done**
- **E4.S10** `AuditSink` event set and anomaly counters · `FR31` — ✅ **done**
- **E4.S11** MQTT dispatcher adapter — the mode shipped in E1.S4; this is the broker · `FR2` — ✅ **done**
- **E4.S12** **Authorisation on the admin surface** · `FR17, FR19` — ✅ **done**. *Added
  2026-08-23, found by review rather than planning.* The device and permission CRUD
  endpoints, agent stop and session kill authenticated the caller and then discarded the
  principal. Under `authorizer.kind: sqlite` — where the store that answers authorisation
  questions is the store the admin API writes to — that made every other action in the set
  advisory: a token refused `sql:read` could `POST` itself a wildcard allow and ask again.
  Confirmed by walking that path before fixing it. Three new actions (`admin:devices`,
  `admin:permissions`, `admin:kill`), device-scoped against the **stored** record so a
  tag-scoped deny reaches the admin surface; reading the policy is gated with the writes;
  ending your own session needs nothing. `authorizer.admins` is the break-glass for the
  empty-store bootstrap and grants `admin:*` only, so deny-beats-allow survives for every
  session action. Every request emits `admin.change`, refusals included, and a policy write
  records what it granted rather than just its id.

  **The plan missed this**, and the reason is worth keeping: every story in this epic asked
  "may this operator do this to this device" and none asked "may this operator change the
  answer". A closed action set is only closed if the thing that edits it is inside it.

## Epic 5 — The rest of the protocol, and passthrough (M4)

**Requirements:** FR10 (full), FR11, FR33, FR39 · **SC7**

- **E5.S1** `exec` profile: allow-listed argv, no shell interpretation, `DATA_ERR` → SSH
  extended data, exit code. `POST /api/v1/devices/{id}/exec` · `FR10, FR33`
- **E5.S2** `file` profile confined to a root, symlinks resolved and re-checked, fuzzed · `FR10, NFR11`
- **E5.S3** `tcp` profile, loopback-only allow-list, empty by default · `FR10`
- **E5.S4** sftp subsystem and `direct-tcpip` on the gateway · `FR10`
- **E5.S5** Mode A passthrough on `tcp`: both guard rails, the banner, `not_recorded`.
  Backpressure only — dropping bytes breaks the SSH MAC · `FR11, NFR4`
- **E5.S6** **Agent conformance suite**: an executable spec a third-party agent runs, covering
  the handshake, every frame type, flow control and the failure paths · `FR39, SC7`

## Epic 6 — More than one replica, and operating it (M5)

**Requirements:** FR40–FR43, NFR5, NFR17, NFR18

- **E6.S1** Redis `Ownership`, leases at 3× the renew interval · `FR42, NFR17`
- **E6.S2** Cross-replica invitations: replica B asks replica A (which holds the device's
  control channel) to send a `DIAL` naming **B**. One small JSON hop on the control plane;
  **no session bytes cross a replica boundary**, and the ring, coalescer and recorder live
  on the node the agent dialled. ADR-025 turned this from a forwarding proxy into a
  message · `FR42, NFR18`
- **E6.S3** Drain on SIGTERM: no new sessions, operators told, recordings finalised, leases
  released, `GOAWAY` with per-agent jitter · `FR41, NFR16`
- **E6.S4** `oarlockctl`: list, inspect, kill, fetch, verify · `FR40`
- **E6.S5** Documented stable metrics — golden signals plus per-plugin latency and error rate
  — with a starter dashboard and alert set · `FR43`
- **E6.S6** Load test establishing the real idle-agent ceiling; the measured number replaces
  NFR5's hypothesis · `NFR5, NFR1, SC8`

## Epic 7 — The integration surface (M6)

**Requirements:** FR32, FR34–FR38 · **Journeys:** J3, J4 · **SC6**

- **E7.S1** OpenAPI 3.1 generated from handlers in CI; drift fails the build. Also fixes the
  public API surface — `pkg/frame`, `pkg/plugin`, `/api/v1`, the SDKs, and nothing else · `FR32, NFR22, NFR24`
- **E7.S2** Idempotency keys, including the expired-cached-ticket case · `FR34`
- **E7.S3** Long-poll `?wait=` state awaiting · `FR35`
- **E7.S4** Go SDK, hand-written: retry-on-retryable only, automatic idempotency keys,
  `instance` on every error · `FR32, SC6`
- **E7.S5** TypeScript and Python SDKs generated under a thin ergonomic layer, on semver with
  a six-month window for the previous major; gateway supports one wire version back · `FR32, NFR23`
- **E7.S6** `@oarlock/terminal` and `@oarlock/react` · `FR36, SC6`
- **E7.S7** Agent library and Kotlin/Android binding, run from a foreground service, with the
  `BOOT_COMPLETED` restriction documented and worked around · `FR37, J4`
- **E7.S8** Signed webhooks, at-least-once, stable delivery id, dead-letter list · `FR38`

## Epic 8 — Supply chain and compliance (continuous, started)

**Requirements:** NFR25–NFR28 · **SC9** · CRA reporting obligations from 11 Sept 2026

- **E8.S1** ✅ **Done** — `SECURITY.md`: coordinated disclosure via GitHub private reporting,
  response targets, scope, safe harbour, supported versions, CRA note · `NFR25`
- **E8.S2** SBOM per release and signed artefacts with verifiable provenance · `NFR26`
- **E8.S3** Documented support and security-update window; changelog marking security fixes · `NFR27`
- **E8.S4** `docs/compliance.md`: what each setting captures, DPIA inputs, works-council
  obligations, PCI mapping to Requirements 8/10/12, and the explicit statement that redaction
  is out of scope and recordings are secret-bearing · `NFR28`

---

## Dependencies

Made explicit because the readiness report found each of these waiting to be discovered by
whoever picked the story up.

| story | needs | state |
|---|---|---|
| E1.S7 | `Device.Platform` in the registry struct and file format | ✅ added to `docs/plugins.md` § 6 |
| E1.S4 | ticket semantics and `Dispatcher` in the spec | ✅ already specified |
| E1.S9 | real Android hardware and a Linux host in CI or on a bench | ⚠️ **needs a device** — the only hardware dependency in M0 |
| — | **spec and implementation bugs found by building** | ✅ (1) `ERROR` was session-scoped, so a failing control-channel handshake could not tell the agent *why* — now universal. (1b) **`PING`/`PONG` had the same bug**, found one layer up: the protocol says they work on both connection kinds, but their `0x1x` numbering made the pump reject them on a session connection. `ERROR`, `PING` and `PONG` are now the complete exempt set. (2) The signing input was plain concatenation, ambiguous for variable-length fields — now length-prefixed and domain-separated. (3) **Control-channel writes were unbounded**, so a peer that stopped *reading* blocked the ping loop and the liveness check never fired — every write is now bounded by `WriteTimeout`, and a timeout closes the channel. (4) The memory transport's `Close` unblocked only the peer's reader, not the local one, unlike a real WebSocket — which is what hid (3). |
| E2.S1 | asciicast v3 decision | ✅ NFR21 |
| E2.S3 | `policy_conflict` close reason | ✅ added to ARCHITECTURE § 6 |
| E3.S5 | `observe` action defined | ✅ added to ARCHITECTURE § 7 |
| E3.* | a UX specification | ✅ `ux-design-specification.md`, 2026-08-21 |
| E3.S2 | one token source emitting both the component's CSS properties and the Tailwind theme | ⚠️ open — the rule is "a colour is never written twice"; the mechanism is an implementation choice |
| E3.S5 | whether an observed operator may *refuse* observation, not just be told | ⚠️ **open product decision** — FR13 requires telling; refusing is a different feature with a different UI |
| E4.S9 | policy selector model, no tenancy entity | ✅ ARCHITECTURE § 8.2 |
| E1.S3 | whether Oarlock multiplexes at all | ✅ **decided: it does not** (ADR-024). Raised while building E1.S1, resolved before E1.S3 started. `pkg/frame` now has a one-byte header and no stream id. |
| E6.S2 | the ring's home under forwarding decided | ✅ **resolved by ADR-025.** The invitation names a node, so the ring lives on the node the agent dialled. No forwarding path to design. |
| E9.* | signing key handling separate from the SSH host key | ⚠️ open — decide in E9.S2 |
| Epic 3 | per-story test strategy | ✅ `test-design-epic-3.md`, 2026-08-21 — 16 risks, 7 high, 65 scenarios |
| Epic 4 | per-story test strategy | ✅ `test-design-epic-4.md`, 2026-08-21 — 15 risks, 8 high, 66 scenarios |
| Epic 4 | **`plugintest` conformance package** | ⚠️ **prerequisite, not written.** It is the whole mitigation for Epic 4's top risk (a backend conflating "denied" with "could not decide"), so it comes before E4.S4, not after |
| Epic 3 | a front-end toolchain | ⚠️ **none exists** — no `package.json`, no runner. The largest prerequisite in Epic 3 and it is in no story |
| Epics 5–8 | per-story test strategy | ⏳ run `test-design` per epic as its stories gain detail |

## Requirement traceability

| requirement | epic.story |
|---|---|
| FR1, FR4 | E1.S3 |
| FR2 | **E1.S4** (mode, `exec`/`webhook` adapters), E4.S11 (MQTT) |
| FR3 | E1.S7 |
| FR5 | E1.S2, E1.S4 |
| FR6 | E1.S6, E1.S8 |
| FR7 | E3.S1, E3.S4 |
| FR8 | E3.S3 |
| FR9 | E1.S6 |
| FR10 | E1.S6 (`shell`), E5.S1–S4 |
| FR11 | E5.S5 |
| FR12 | E2.S4, E1.S8 |
| FR13 | E3.S5 |
| FR14 | E2.S3 |
| FR15 | E1.S6, E4.S1, E4.S2 |
| FR16, FR17, FR19 | E4.S5 (FR17 also E4.S3) |
| FR18 | E4.S4 |
| FR20, FR21 | E4.S6 |
| FR22 | E1.S2 (key list), E4.S7 |
| FR23 | E4.S8 |
| FR24 | E2.S1 |
| FR25 | E9.S1, E9.S2, E9.S4 |
| FR26 | E9.S3 |
| FR27, FR44 | E4.S9 |
| FR28 | E2.S3 |
| FR29 | E2.S2 |
| FR30 | E3.S6 |
| FR31 | E4.S10 |
| FR32 | E2.S5, E7.S1, E7.S4 |
| FR33 | E5.S1 |
| FR34 | E7.S2 |
| FR35 | E7.S3 |
| FR36 | E3.S2, E7.S6 |
| FR37 | E7.S7 |
| FR38 | E7.S8 |
| FR39 | E5.S6 |
| FR40 | E6.S4 |
| FR41 | E6.S3 |
| FR42 | E6.S1, E6.S2 |
| FR43 | E6.S5 |
| NFR1 | E1.S9, E6.S6 |
| NFR2, NFR3, NFR4 | E1.S5, E5.S5 |
| NFR5 | E6.S6 |
| NFR6 | E1.S6 |
| NFR7 | E2.S4 |
| NFR8 | E1.S4, E3.S1 |
| NFR9, NFR10 | E1.S2, E7.S7 |
| NFR11 | E1.S1, E5.S2 |
| NFR12 | E2.S5 |
| NFR13 | E2.S2, E4.S4 |
| NFR14 | E2.S3 |
| NFR15 | E2.S1 |
| NFR16 | E1.S3, E6.S3 |
| NFR17, NFR18 | E6.S1, E6.S2 |
| NFR19, NFR20 | E1.S1, E1.S3 |
| NFR21 | E2.S1 |
| NFR22 | E7.S1 |
| NFR23, NFR24 | E7.S1, E7.S5 |
| NFR25 | **E8.S1 — done** |
| NFR26, NFR27 | E8.S2, E8.S3 |
| NFR28 | E8.S4 |

### Journeys and success criteria — every one owned

| | owning story |
|---|---|
| J1 operator, terminal, incident | **E1.S8** |
| J2 operator, browser | E3.S1–S4 |
| J3 integrator | E7.S4, E7.S6 |
| J4 device app developer | E7.S7 |
| J5 auditor | E9.S3, E3.S6 |
| J6 on-call during an authz outage | E4.S4 |
| J7 operator who should no longer have access | E4.S5 |
| SC1 own ssh client, no new tooling | **E1.S8** |
| SC2 nothing new listens on the device | **E1.S9** |
| SC3 every session replayable, integrity verifies | **E9.S3** |
| SC4 revocation fast and honest | E4.S5, E3.S4 |
| SC5 a dependency's bad minute is not an outage | E2.S2, E4.S4 |
| SC6 integration is one call and one component | E7.S4, E7.S6 |
| SC7 third-party agent from the docs alone | E5.S6 |
| SC8 session setup fast enough not to be noticed | **E6.S6**, baseline in E1.S9 |
| SC9 embeddable in an EU-sold product | E8.S1–S3 |
