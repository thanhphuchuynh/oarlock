---
stepsCompleted: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
inputDocuments:
  - README.md
  - ARCHITECTURE.md
  - docs/protocol.md
  - docs/plugins.md
  - docs/sdk.md
  - docs/threat-model.md
  - _bmad-output/planning-artifacts/adversarial-review-spec-2026-08-20.md
  - _bmad-output/planning-artifacts/research-technical-oarlock-2026-08-20.md
  - _bmad-output/planning-artifacts/research-domain-oarlock-2026-08-20.md
workflowType: 'prd'
project_name: oarlock
---

# Product Requirements Document - oarlock

**Author:** Tphuc
**Date:** 2026-08-20

---

## Product Scope

**What Oarlock is.** An open-source SSH gateway that gives an operator a real shell on a
device that cannot be dialled — behind NAT, on a cellular APN, on a customer's LAN — without
a listener, a host key or an open port on that device. The gateway is the SSH server, so it
sits in the plaintext, records the session, and can withdraw access mid-session.

**Primary target platform:** Android appliances in kiosk mode, device-owner, mains-powered,
in customers' homes and gyms. Linux hosts and containers are supported and are the easy case.

### In scope

- Reaching a device by held connection (`persistent`) or by doorbell plus on-demand dial
  (`dispatch`).
- Gateway-terminated SSH (mode C) for CLI and browser operators, on one session.
- Opt-in, per-device, never-silent passthrough (mode A) for sessions that must be opaque.
- Session recording with integrity protection, and replay authorised separately.
- Pluggable authentication, authorisation with mid-session revocation, recording,
  session storage, doorbell, device registry and audit.
- A control API, server SDKs, a terminal embed, an agent library and outbound webhooks.
- A CLI for operators.

### Out of scope, stated so silence is not read as a promise

- **Device management** — enrollment, inventory, OTA, telemetry, configuration.
- **Identity** — no user database; bring an IdP or a file.
- **An L3 overlay** — a session is a pipe to one process, not a network.
- **Command filtering inside a shell.** An interactive shell is Turing-complete; filtering it
  is theatre. Control is *who gets a shell, on which device, for how long, and recorded*.
- **Redaction of recordings.** A recording that captured a secret stays a secret-bearing
  artefact. Pattern-matching a byte stream containing escape sequences is not something this
  project will claim to do.
- **Protecting a session from the gateway operator.** In mode C that is not on offer.
- **Recording at the device.** Technically possible — Tailscale does it — and rejected here
  on trust grounds, because the device is the least trustworthy component in the system.

## Success Criteria

| # | criterion | measure |
|---|---|---|
| SC1 | An operator uses their own SSH client with no new tooling | `ssh <device>@gateway` reaches a PTY; no wrapper, no plugin, no `~/.ssh/config` entry required |
| SC2 | Nothing new listens on the device | A port scan of a device in any mode but A shows no new listener; the agent holds no host key |
| SC3 | Every mode-C session is replayable | 100 % of closed mode-C sessions have a recording whose integrity verifies; unrecorded sessions are queryable, never merely absent |
| SC4 | Revocation is fast and honest | Withdrawn access closes a live session in under 1 s with `Watch`, under `recheck_interval` without; an authz outage never reports `revoked` |
| SC5 | A dependency's bad minute does not become an outage | A 60 s failure of the authz backend, the recorder backend or the doorbell closes **zero** live sessions |
| SC6 | Integration is one call and one component | A working shell button costs the integrator **≤ 25 lines** and requires understanding **≤ 4 concepts** (session, ticket, attach, webhook). Measured on the code, not on the integrator. |
| SC7 | A third-party agent can be written from the documents alone | An independent implementer passes the agent conformance suite using `docs/protocol.md` and `pkg/frame` only |
| SC8 | Session setup is fast enough not to be noticed | p50 under 1 s in `persistent`; p95 under 10 s in `dispatch` on a warm radio |
| SC9 | The project is embeddable in an EU-sold product | `SECURITY.md`, coordinated disclosure, SBOM per release, signed releases, documented support window |

## User Journeys

**J1 — Operator, terminal, incident.** A treadmill in a gym is frozen. The operator types
`ssh treadmill-4821@gw.example.org`, authenticates with the SSH certificate their login
issued, sees a banner naming the device and stating the session is recorded, gets a prompt,
reads `logcat`, restarts a service, exits. The session appears in the console attributed to
them with the ticket number they gave as a reason, and the recording is attached to it.

**J2 — Operator, browser, no terminal.** A support agent clicks **Shell** in the admin
console. Two progress lines — waking the agent, opening the tunnel — then a terminal. Their
wifi drops; the terminal says reconnecting, comes back, and replays what they missed. The
long command they started never died.

**J3 — Integrator.** A backend developer adds the shell button: one `POST /api/v1/sessions`
with the operator's own token forwarded, one `<Terminal />`, two webhook handlers. They never
learn what a PTY is.

**J4 — Device app developer.** An Android engineer embeds the agent library in an existing
APK, supplies a `Shell` hook naming the platform's shell and a hardware-backed key signer,
and runs it from a foreground service. They never ship a second binary, because the platform
forbids it.

**J5 — Auditor.** A compliance reviewer asks who opened a shell on a device in March, what
they did, and whether the recording has been altered. They get a filtered list, a replay,
and an integrity verification — without being able to open a session themselves.

**J6 — On-call, during the outage that matters.** The permissions service is down. New
sessions are refused with a message naming the reason; **sessions already open keep working**
for the grace window so the person fixing it can keep working. Nothing in the audit trail
claims anyone was revoked.

**J7 — Operator who should no longer have access.** Someone is removed from the on-call
group mid-session. Within a second their shell closes with `revoked`, the recording is
finalised, and the event is emitted.

## Domain-Specific Requirements

Two regimes pull in opposite directions on the same setting, and the product must let a
deployer satisfy either without editing code.

- **PCI DSS 4.0.1** (mandatory since March 2025) expects privileged session recording that
  captures administrator keystrokes in a **tamper-proof log**, replayable with time, date,
  commands and responses, mapping to Requirements 8, 10 and 12.
- **GDPR and EU employment law** treat continuous keystroke logging as effectively
  prohibited, require a **DPIA before deployment** of systematic monitoring, and give
  **works councils co-determination rights** in DE, NL, AT, SE, FR and PL. Deploying without
  consultation is a separate violation from any GDPR breach.
- **EU Cyber Resilience Act**: incident and vulnerability reporting obligations begin
  **11 September 2026**; full applicability 11 December 2027. Scope explicitly includes
  *remote data processing components essential to a product's core function* — which is what
  Oarlock is inside a connected exercise machine.

**Consequence:** `record_input` is resolved by a selector policy over operator attributes and
device tags rather than being a global default (FR27); a conflict between a non-overridable
rule and a scope requirement **refuses the session** rather than picking a regime to violate
(FR44); recordings need integrity protection to be worth anything to an auditor (FR25, FR26);
and the project needs coordinated-disclosure machinery before anyone embeds it in a product
sold in the EU (NFR25–NFR27, delivered in `SECURITY.md`).

## Innovation & Novel Patterns

**The doorbell.** Every reference implementation of this pattern — ngrok, Cloudflare Tunnel,
frp — holds one outbound connection per agent, permanently, so an unannounced inbound request
can be answered. Oarlock separates *reachability* from *transport*: a doorbell the fleet
already has wakes the device, and the tunnel is dialled per session. Because shells are rare
and short, this is strictly smaller than the reference implementations — and on Android it is
the only approach the platform cooperates with.

**Gateway-terminated SSH with pluggable authorisation and mid-session revocation.** Teleport
does the termination; what is not otherwise available permissively licensed is the
combination of that with a device that runs no listener, an authorisation interface anyone
can implement, and revocation that reaches a session already in progress.

**A trust argument, not a technical one, for where recording happens.** Recording at the
endpoint is possible and shipping in Tailscale. Oarlock records at the gateway because a
recorder inside the blast radius of the thing being recorded is not evidence.

## Functional Requirements

This list is binding. A capability not named here does not exist unless it is explicitly
added.

### Reaching a device

- FR1: An **agent** can hold one outbound connection open and receive multiple sessions
  multiplexed on it (`persistent`).
- FR2: An **agent** can be woken by a doorbell and dial one connection per session with a
  single-use ticket (`dispatch`).
- FR3: A **gateway operator** can set the reachability mode **per device** via
  `Device.Mode`, and when unset it resolves from `Device.Platform` — `dispatch` for Android,
  `persistent` for Linux and containers. The resolved value is logged at registration.
- FR4: An **agent** can reconnect after a network loss and reattach an existing live session
  rather than losing the operator's shell.
- FR5: A **gateway** can report the difference between *device not connected*, *device did
  not answer* and *the doorbell itself failed*, and never conflate the third with the first.

### Opening and running a session

- FR6: An **operator** can open a session with their own `ssh` client and no local
  configuration.
- FR7: An **operator** can open the same session in a browser terminal.
- FR8: An **operator** can reattach after losing their connection and receive the scrollback
  they missed.
- FR9: An **operator** can resize, signal, and receive the exit code of what they ran.
- FR10: A **gateway** can run a session under one of the profiles `shell`, `exec`, `log`,
  `file`, `tcp`, `sshpass`, and refuse a profile the agent did not advertise.
- FR11: A **gateway operator** can enable mode A passthrough per device, and it is refused
  unless both the device flag and the gateway policy allow it.
- FR12: An **operator** is told, before the first prompt, which mode they are in and whether
  the session is recorded.
- FR13: A **second operator** can attach to a live session **read-only**, with the first
  operator notified and the attachment audited. Input remains with the first attachment.
  (Resolves review finding 6 — this was implied by the API and unspecified.)
- FR14: A **gateway** can enforce one live session per device and a per-principal ceiling,
  atomically.

### Authentication, authorisation, revocation

- FR15: An **operator** can authenticate by SSH certificate, SSH public key, OIDC, or a
  configured static token, chosen by the deployer.
- FR16: A **gateway** re-checks authorisation for every live session on an interval, and
  closes sessions whose grant was withdrawn.
- FR17: An **authorisation backend** can stream revocations for sub-second closure.
- FR18: A **gateway** distinguishes a denial from an inability to decide: denial closes,
  an error refuses new sessions and grants live ones a grace window, closing them as
  `authz_unavailable`.
- FR19: An **administrator** can kill any live session immediately.
- FR20: A **service** can open a session on behalf of a human only by presenting a **signed
  assertion**; a bare identifier is refused.
- FR21: A **gateway operator** can permit unattended service sessions explicitly, and those
  sessions are tagged so they never sum with human ones.
- FR22: A **gateway operator** can rotate or revoke a device's identity key, and a
  factory-reset device returning under the same id with a new key is refused until
  re-registered. (Resolves finding 9.)
- FR23: All **gateway replicas** present the same SSH host key, so operators never see a
  mismatch warning they will learn to ignore. (Resolves finding 8.)

### Recording, integrity, audit

- FR24: A **gateway** streams a recording for every mode-C session, playable if truncated at
  any point.
- FR25: A **recording** carries a **hash chain** over its event stream and a **signed
  manifest** at close covering the chain head, session metadata and byte counts.
- FR26: An **auditor** can verify a recording's integrity at replay, and a failed
  verification is surfaced, not logged quietly.
- FR27: A **gateway operator** can set `record_input` from a **selector policy** matching
  operator attributes *and* device tags — because employment law attaches to the operator and
  PCI scope attaches to the device — with the compliance consequence documented where it is
  configured. No tenancy entity is introduced; selectors match attributes that already exist.
- FR44: A **gateway** refuses a session with `policy_conflict` when two `record_input` rules
  disagree and one is marked non-overridable, naming both rules in the audit event, rather
  than silently choosing which regime to violate.
- FR28: A **session that is not recorded** — passthrough, `file`, `tcp`, or `Recorder: none`
  — is written to the session log with an explicit `recording_state`, queryable as a fact.
  (Resolves finding 10.)
- FR29: A **recorder backend failure** is absorbed by a bounded spool; only exhaustion closes
  the session, and the partial recording survives on disk.
- FR30: An **auditor** can be granted `replay` without being granted `shell`.
- FR31: An **audit sink** receives authentication, authorisation allow and deny, session open
  and close with reason, revocation, passthrough use, replay access, unattended-session use,
  and limit hits — including counters usable as an anomaly surface.

### Integration

- FR32: A **backend** can open a session, list, inspect and kill sessions, and fetch a
  recording, over a versioned HTTP API with a generated OpenAPI document.
- FR33: A **backend** can run one allow-listed command on a device and get stdout, stderr and
  an exit code, with no terminal and no attach.
- FR34: A **backend** can retry any `POST` safely with an idempotency key, and a retry whose
  cached ticket has expired is told so rather than handed a dead ticket. (Resolves finding 12.)
- FR35: A **backend** can await a session state change without polling.
- FR36: A **web app** can embed the terminal, supply a ticket-renewal callback, and receive
  the failure states as typed events.
- FR37: A **device app** can embed the agent as a library, supplying the shell, the exec
  allow-list, the file root, the TCP allow-list and a key signer.
- FR38: A **consumer** can receive signed, at-least-once webhooks with a stable delivery id
  and read a dead-letter list.
- FR39: An **independent implementer** can pass an **agent conformance suite** using only the
  protocol document and the frame codec. (Resolves finding 18.)

### Operations

- FR40: An **operator** can list, inspect, kill and fetch recordings from a **CLI**, without
  hand-made tokens and `curl`. (Resolves finding 19.)
- FR41: A **gateway operator** can drain a replica: no new sessions, attached operators told,
  recordings finalised, agents told when to reconnect with jitter.
- FR42: A **gateway operator** can run more than one replica, with device ownership tracked
  and an operator's session forwarded to the replica holding the agent.
- FR43: A **gateway operator** can see documented, stable metrics for the golden signals and
  every plugin's latency and error rate. (Resolves finding 15.)

## Non-Functional Requirements

### Performance

- NFR1: Session open p50 < 1 s (`persistent`), p95 < 10 s (`dispatch`, warm radio).
- NFR2: Added keystroke latency attributable to the gateway < 5 ms at p95; operator input is
  never batched.
- NFR3: Output coalesced into ≤ 25 ms batches; `limits.batch` 64 KiB, `limits.rate` 256 KiB/s
  sustained with a 1 MiB burst, `limits.frame` 1 MiB as a safety net — chosen as one set.
- NFR4: `shell` and `sshpass` never drop a byte; they apply backpressure. `log` and `exec` may
  drop and must announce it.
- NFR5: *(**Hypothesis, not yet a requirement.**)* One replica is expected to hold on the
  order of 5 000 idle `persistent` agents on 2 vCPU / 2 GiB. Nothing can pass or fail this
  today. E6.S6 measures it, and the measured figure replaces this line and becomes the NFR.

### Security

- NFR6: `golang.org/x/crypto` pinned ≥ 0.17.0 with strict key exchange enabled, enforced in
  CI, because Terrapin (CVE-2023-48795) is a live attack class against custom SSH servers.
- NFR7: No security-relevant statement — including the mode and recording banner — depends on
  an unauthenticated early channel message that prefix truncation could remove.
- NFR8: Tickets are single-use, 60 s, scoped to one device, profile and principal, redeemed by
  atomic compare-and-delete, and never carried in a URL.
- NFR9: Device private keys never leave the device, and use hardware-backed storage where the
  platform offers it.
- NFR10: The agent pins the gateway certificate by default.
- NFR11: `pkg/frame` and the `file` profile's path handling are fuzzed in CI from the first
  commit. (Resolves finding 20.)
- NFR12: Default configuration is safe: `allow_unrecorded` false, `AllowPassthrough` false,
  `record_input` false, `tcp` and `file` allow-lists empty.

### Reliability and availability

- NFR13: A 60 s failure of any single plugin backend closes zero live sessions.
- NFR14: An operator's dropped connection never closes a session.
- NFR15: A gateway restart leaves every recording playable up to the moment of the restart.
- NFR16: Agent reconnection is jittered, and a drain tells each agent when to return.

### Scalability

- NFR17: Adding a replica requires configuration, not a redesign. An `Ownership` map plus a
  control-plane hop carrying an invitation is sufficient; **no session bytes cross a replica
  boundary** (ADR-025), so there is no forwarding proxy to build.
- NFR18: The scrollback ring, coalescer and recorder have one defined home per session:
  **the node the operator is attached to**, because that is the node the agent dialled.
  ADR-025 makes this true by construction — an invitation names a specific node — rather
  than by convention. (Resolves finding 11.)

### Compatibility and maintainability

- NFR19: The transport is behind an interface. WebSocket is the only implementation; adopting
  WebTransport later must delete code, not add a second protocol.
- NFR20: **Oarlock does not multiplex.** A connection carries one session or the control
  channel, never several sessions (ADR-024). This supersedes the earlier requirement to
  adopt `smux`: every such library wants a byte stream, and turning messages back into
  bytes reintroduces the length field that lets a peer drive an allocation. Not
  multiplexing costs one TLS handshake per session and removes the stream id, the credit
  protocol and the head-of-line class entirely.
- NFR21: Recording format is **asciicast v3** — relative event deltas let a spooling recorder
  resume mid-session without rewriting, which v2's absolute timestamps do not.
- NFR22: `/api/v1` changes additively only; the `v0` wire protocol may change freely, and the
  boundary that decouples them is explicit. (Resolves finding 17.)
- NFR23: The gateway supports one wire version back, and the previous API major for six
  months. Agents are the slow half of any fleet.
- NFR24: Only `pkg/frame`, `pkg/plugin`, `/api/v1` and the published SDKs are public API.

### Compliance and supply chain

- NFR25: `SECURITY.md` with a coordinated disclosure policy and a real contact exists before
  the first release, per CRA reporting obligations effective 11 September 2026.
- NFR26: Every release publishes an SBOM and is signed with verifiable provenance.
- NFR27: A support and security-update window is documented.
- NFR28: A compliance appendix maps settings to what they capture, provides DPIA inputs, notes
  works-council obligations, and maps to PCI Requirements 8, 10 and 12.

## Project Scoping & Phased Development

Revised against the review and the research. The order changed in one important way: **the
recording hash chain moved into the first recording milestone**, because it cannot be
retrofitted onto recordings that already exist.

| phase | contents | exit |
|---|---|---|
| **M0 — spike** | **Both reachability modes** — `persistent` with smux, and `dispatch` with tickets plus the `exec` and `webhook` dispatchers. Mode C, `shell`, `authorized_keys`, in-memory store, transport interface, fuzz harness, no-listener verification. No recording. | J1 works end to end over **either** mode; fuzzers green; SC2 verified against real hardware |
| **M1 — recordable** | asciicast v3 recorder, spool, SQLite store, close reasons, limits, per-profile flow control, `/api/v1` sessions — **and, in parallel, the hash chain and signed manifest (Epic 9)**, which ship with the first recorder because they cannot be added to recordings that already exist | A session is replayable and its integrity verifies |
| **M2 — browser** | `/ws/attach`, xterm.js, reattach with scrollback, the failure screens, read-only observer, player | J2 and J5 work end to end |
| **M3 — pluggable** | OIDC and SSH-CA authenticators, webhook authorizer with `Watch` and the grace window, the **MQTT** dispatcher adapter, S3/GCS recorder, Postgres, device key rotation, `record_input` policy resolution | J6 and J7 verified by fault injection |
| **M4 — protocol rest** | `exec`, `file`, `tcp`, sftp subsystem, `direct-tcpip`, mode A passthrough, agent conformance suite | A third-party agent passes the suite |
| **M5 — more than one** | Redis ownership, node-to-node forwarding, shared host key, drain, load test | NFR5 and NFR17 measured |
| **M6 — integration** | OpenAPI in CI, Go and TS SDKs, `@oarlock/terminal`, webhooks with dead-letter, agent library and Kotlin binding, CLI | J3 and J4 in under an hour |
| **Continuous** | `SECURITY.md`, SBOM, signed releases, compliance appendix | NFR25–NFR28 |

**Why `dispatch` is in M0 rather than M3.** The primary target platform requires it: Android
buckets apps into standby tiers, can flag persistent connections as excessive, and forbids a
`dataSync` foreground service from starting at `BOOT_COMPLETED` — precisely when a rebooted
device must become reachable. Scheduling the doorbell at M3 would have meant three milestones
of building and testing the mode Android resists, and shipping the one it needs last. The
`Dispatcher` interface plus the `exec` and `webhook` adapters move with it; the MQTT adapter
stays at M3, because the mode was urgent and the broker was not.

**Deliberately deferred:** WebTransport (behind NFR19's interface until browser support and
need justify it), redaction (out of scope), and anything that looks like device management.

**Still open, and not deferred by choice:** there is no UX specification, and Epic 3 is
interface work. `create-ux-design` must run before Epic 3 is planned — including the two UI
decisions that discharge security requirements: how the mode-and-recording banner appears in
a browser, where it cannot be an SSH banner, and how an observed operator is notified.
