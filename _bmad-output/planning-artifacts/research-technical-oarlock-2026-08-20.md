---
stepsCompleted: [1, 2, 3, 4, 5, 6]
inputDocuments:
  - README.md
  - ARCHITECTURE.md
  - docs/protocol.md
  - docs/plugins.md
  - docs/sdk.md
  - docs/threat-model.md
  - _bmad-output/planning-artifacts/adversarial-review-spec-2026-08-20.md
workflowType: 'research'
lastStep: 6
research_type: 'technical'
research_topic: 'Oarlock — an open-source SSH gateway that terminates SSH centrally to reach NAT-bound Android devices, with session recording and pluggable authorisation'
research_goals: 'Validate the technical choices in the specification against current public sources; find what is coming that changes them; surface anything that should alter the design before implementation begins'
user_name: 'Tphuc'
date: '2026-08-20'
web_research_enabled: true
source_verification: true
findings_that_change_the_design: 6
---

# Research Report: technical

**Date:** 2026-08-20
**Author:** Tphuc
**Research Type:** technical

---

## Executive Summary

Six findings change the specification. Two are corrections — the document states things
that are no longer true — and four are decisions the design has not yet made.

| # | finding | effect |
|---|---|---|
| **T1** | Tailscale SSH records **at the destination node**, not at a proxy | The claim that recording is impossible under end-to-end encryption is false as an absolute. It survives for Oarlock only on a trust argument, which the spec never makes. |
| **T2** | Teleport's OSS core went **AGPLv3** in Dec 2023, and Community Edition went to a **commercial** licence at v16 | `README.md`'s prior-art table is factually wrong. |
| **T3** | **asciicast v3** shipped with asciinema 3.0; the CLI is a Rust rewrite | The spec targets v2. v3's relative-delta events are better suited to streaming, and it is not backward compatible. |
| **T4** | **yamux** and **smux** are mature Go multiplexers with flow control | `0x19 WINDOW` is a hand-rolled version of a solved problem. smux's session-wide receive buffer solves memory bounding better than per-stream windows do. |
| **T5** | Android background limits keep tightening; persistent connections are flagged as excessive | `persistent` is the wrong **default** on the primary target platform. |
| **T6** | **WebTransport reached Baseline in March 2026**; WebSocket-over-HTTP/3 has no browser support | WebSocket is right for now, and the transport must be abstracted because the successor is real and its native streams would delete T4's problem entirely. |

The spec's core shape — outbound dial, gateway-terminated SSH, framed device leg — is
well supported by current practice. What the research undermines is not the architecture
but three of its justifications and one of its defaults.

## Table of Contents

1. [Technology Stack Analysis](#1-technology-stack-analysis)
2. [Integration Patterns](#2-integration-patterns)
3. [Architectural Patterns](#3-architectural-patterns)
4. [Implementation Research](#4-implementation-research)
5. [Synthesis and Design Implications](#5-synthesis-and-design-implications)
6. [Sources](#6-sources)

---

## 1. Technology Stack Analysis

### 1.1 The SSH server library

`gliderlabs/ssh` wraps `golang.org/x/crypto/ssh` with a `net/http`-shaped API and is
**still maintained** — 0.3.8-2 entered Debian unstable on 28 May 2026, and it is packaged
across Debian and Ubuntu. Confidence: high.

A stronger signal than the package feeds: **Tailscale vendors it** as
`tailscale.com/tempfork/gliderlabs/ssh`. A company shipping gateway-terminated SSH at scale
forked it rather than replacing it, which is the endorsement that matters — and the fact
that they *forked* rather than depended is itself information about how much local
modification this use case needs.

### 1.2 Terrapin, and a specific warning for custom SSH servers

CVE-2023-48795 (Terrapin) is a prefix-truncation attack on the SSH binary packet protocol:
an attacker who can modify traffic manipulates handshake sequence numbers to **delete
messages sent immediately after the channel is established**, silently downgrading
negotiated features. It affects `golang.org/x/crypto` before **0.17.0**, mitigated there by
strict key exchange.

The advisory carries a warning aimed directly at what Oarlock is:

> If you are using a custom SSH service and do not resort to the authentication protocol,
> you should check that dropping the first few messages of a connection does not yield
> security risks.

Oarlock's gateway is exactly a custom SSH service, and its own banner — the one that tells
an operator which mode they are in and whether the session is recorded — is a message sent
immediately after the channel is established. **A truncation attack that silently removes
the "this session is NOT recorded" banner is a real attack on this design**, and no
document mentions it. Requirements: pin `x/crypto` ≥ 0.17.0 with strict kex on and CI
enforcement, and never carry security-relevant state in an early channel message that the
protocol does not authenticate.

### 1.3 Recording format: v2 or v3

asciinema **3.0** introduced **asciicast v3**, alongside a CLI rewritten in Rust and
real-time streaming. v3 replaces v2's absolute timestamps with **event deltas** and
regroups the header; it is **not backward compatible** with v1/v2, though the v2→v3 gap is
much smaller than v1→v2. `asciinema-player` is at 3.10.0 and reads both. Confidence: high
on the facts, medium on exact release dating (a third-party summary dates 3.0 to
September 2025).

Relative deltas matter more here than they look. Under v2 a streaming writer must know the
session start time and every event carries an offset from it; under v3 each event is
relative to its predecessor, which means **a stream can be resumed or spliced without
rewriting anything** — precisely the property a spooling recorder (ARCHITECTURE § 8.1)
needs when it reconnects to a backend mid-session.

### 1.4 Multiplexing

`hashicorp/yamux` and `xtaci/smux` both provide stream multiplexing over a reliable
connection with flow control:

| | yamux | smux |
|---|---|---|
| header | 12 bytes | 8 bytes |
| flow control | per-stream windows, backpressure | per-stream sliding window (v2+), **plus a session-wide receive buffer shared across streams** |
| extras | keepalives, server-side push | token-bucket receive, built-in fair queueing |
| lineage | SPDY-inspired, powers HashiCorp's own tooling | built for kcp-go |

smux's **session-wide shared receive buffer** is the interesting one. Oarlock's spec bounds
memory per stream (`limits.window` 256 KiB each); smux bounds it per *session*, which is
what an operator actually needs to reason about — "this connection cannot cost more than
N bytes" rather than "N bytes times however many streams happen to be open". Its fair
queueing also solves a problem the spec does not address: with several sessions on one
device's connection, one noisy stream starving the others.

## 2. Integration Patterns

### 2.1 Transport: WebSocket now, and the successor is no longer hypothetical

**WebTransport reached Baseline in March 2026** — Chrome, Firefox, Safari and Edge all
support it unflagged, at roughly 75 % of browsers in the field. Go is the strongest
server-side ecosystem via `quic-go` and `webtransport-go`. Meanwhile **WebSocket over
HTTP/3 (RFC 9220) has no production browser implementation**: Chrome is at "intent to
prototype", Firefox has announced nothing.

The current consensus is to ship WebTransport as an enhancement with a WebSocket fallback,
because WebSocket is at 99 %+ support with mature tooling.

For Oarlock the interesting part is not the latency: it is that **WebTransport gives native
QUIC streams with their own flow control**. On that transport the entire `0x19 WINDOW`
mechanism, the mux header, and the head-of-line-blocking argument that justifies them
simply do not exist — one session is one stream, and the transport handles it. The design
consequence is not "adopt WebTransport now" but **abstract the transport behind an
interface so that adopting it later deletes code instead of adding a second protocol.**

### 2.2 Delegated authority

The industry direction confirms the amendment already made for finding 3: short-lived,
centrally issued, time-bound credentials, with static long-lived keys retired
progressively. Nothing found suggests a bare identity header is acceptable anywhere.

## 3. Architectural Patterns

### 3.1 The finding that most challenges the specification

**Tailscale SSH session recording records at the destination node.** When a session starts,
the SSH server *on the target machine* captures terminal output in asciinema format and
streams it to a dedicated recorder node in the tailnet. The recorder is a `tsnet` binary
the customer deploys; it writes to a filesystem or to S3-compatible storage; multiple
recorders can be configured for fallback, selected by lowest IP address. Recordings are
end-to-end encrypted like all other tailnet traffic.

This directly contradicts a load-bearing claim in Oarlock's documents — that end-to-end
encryption makes recording impossible, and therefore that mode A forfeits the recording.
**It does not, if the endpoint records.** There is a fourth shape the spec never considered:

> **Shape D — SSH terminates on the device, and the device records.**
> End-to-end encrypted, and recorded. What ngrok cannot do and Tailscale does.

Why it still loses for Oarlock — an argument the spec must now make explicitly rather than
assume:

1. **The trust model is inverted.** Tailscale's destination node is a server the customer
   owns and administers. Oarlock's device is an appliance in a customer's gym, physically
   accessible to the public, sometimes rooted. **A recorder that runs on the recorded
   machine is trustworthy only if the machine is** — and an attacker with a shell can
   simply not record, or record a fiction. Gateway-side recording is trustworthy precisely
   because it is outside the blast radius of the thing being recorded.
2. **It needs a listener and a host key on the device**, which is OL-001, the assumption
   everything else follows from.
3. **The device pays the cost.** Streaming a recording out of a cellular appliance doubles
   its egress and adds a second outbound connection to supervise, on the platform whose
   background limits are getting stricter (§4.1).

Shape D is nonetheless **the right answer for a different product** — one whose targets are
customer-administered servers. Worth stating, because "we considered recording at the
endpoint and rejected it for this trust model" is a much stronger position than "recording
requires terminating SSH", which is now demonstrably false.

### 3.2 Prior art, corrected

`README.md` lists Teleport as "AGPL-3.0 (CE)". Both halves are out of date:

- The OSS core relicensed **Apache 2.0 → AGPLv3 on 1 December 2023**.
- **Community Edition adopted a commercial licence starting at version 16**, restricting
  commercial use by companies while remaining free for individuals and hobby use.

So the accurate statement is stronger than the one in the document: Teleport is not merely
copyleft, it is **no longer usable as a company's free foundation at all**. That materially
improves Oarlock's build-vs-adopt argument and it should be quoted correctly.

OpenZiti remains Apache 2.0 with no evidence of a change. No current information was found
on ShellHub's licence or its recording tier, so the README's claim there is **unverified**
and should be marked as such until checked at adoption.

## 4. Implementation Research

### 4.1 Android is hostile to `persistent`, and getting more so

Current Android behaviour, from developer documentation and practitioner sources:

- Apps are bucketed **active / working set / frequent / restricted**; an app opened rarely
  can be moved to restricted, which throttles background work, network access and alarms.
- A foreground service is **"a privilege, not a loophole"** — and specific types including
  `dataSync` **cannot be launched from `BOOT_COMPLETED`**.
- Since Android 12, apps cannot start a foreground service while in the background at all,
  outside narrow exemptions.
- Devices in 2026 apply dynamic power budgeting, and **apps that maintain persistent
  connections may be flagged as "excessive"**.
- OEM power managers add their own, undocumented layer on top.

Oarlock's fleet is kiosk-mode, mains-powered, device-owner appliances, which is the most
favourable case — but the spec's default is still wrong for it. `persistent` mode asks an
Android app to hold a socket open forever and to re-establish it at boot, and the platform
is actively engineered against both. Concretely: **the agent cannot reliably start its
foreground service from `BOOT_COMPLETED`**, which is exactly when a device that just
rebooted needs to become reachable.

`dispatch` mode sidesteps all of it, because a doorbell delivered through FCM or an
existing MQTT service is the mechanism the platform *wants* you to use. The spec already
supports both; it picked the wrong one as default for its primary platform, and it picked
it for a good reason that does not apply on Android — zero external dependencies.

### 4.2 Credential practice validates the amendment

Short-lived certificates valid for roughly one work session are the stated best practice;
the CA public key on the server replaces per-user `authorized_keys`; automated issuance,
renewal and expiry are described as essential at scale. This supports promoting `sshca`
from "the recommendation at any real size" to **the default**, with `authorized_keys`
demoted to a documented convenience that warns at boot.

## 5. Synthesis and Design Implications

Ordered by how much they cost to act on later rather than now.

| # | change | where | cost if deferred |
|---|---|---|---|
| **1** | Abstract the transport behind an interface; keep WebSocket as the only implementation | `docs/protocol.md` § 1, `pkg/frame` | High. Retrofitting WebTransport onto a WebSocket-shaped codec means a second protocol instead of a second transport. |
| **2** | Adopt smux or yamux instead of hand-rolled `WINDOW`; prefer smux for its session-wide buffer | `docs/protocol.md` § 4.15 | High. A hand-rolled multiplexer is a bug farm, and replacing it after agents ship is a wire-breaking change. |
| **3** | Make `dispatch` the default for Android device profiles; keep `persistent` the default for Linux and containers | `ARCHITECTURE.md` § 3 | Medium. Changes a default, not a mechanism — but it changes which path gets tested first, and the untested one is the one that fails in the field. |
| **4** | Target asciicast **v3**, and say why | `ARCHITECTURE.md` § 8 | Medium. Recordings are durable artefacts; a format migration means a converter and two readers forever. |
| **5** | Replace "recording requires terminating SSH" with the trust argument, and document shape D as considered and rejected | `ARCHITECTURE.md` § 4.3, § 8 | Low to fix, high to leave. The current claim is false, and a reviewer who knows Tailscale will find it immediately and distrust the rest. |
| **6** | Correct the Teleport licence facts; mark the ShellHub claim unverified | `README.md` | Low. But a wrong licence claim in a build-vs-adopt table is the kind of error that ends a technical argument badly. |
| **7** | Pin `x/crypto` ≥ 0.17.0, strict kex on, CI check; treat the mode banner as security-relevant and never rely on an unauthenticated early message | `docs/threat-model.md` | High. This is a live CVE class against exactly this component, with a published warning for custom SSH services. |

**What the research did not find:** no evidence that anything in the market has made the
core bet obsolete. Nothing found does gateway-terminated SSH to a PTY inside an app on a
device that runs no listener, with pluggable authorisation and central recording. Tailscale
is the closest and it requires an SSH server on the target and a tailnet. The gap Oarlock
aims at is still open.

**What remains unverified and should not be repeated as fact:** ShellHub's licence and
whether its session recording is a paid tier; the exact release date of asciinema 3.0;
whether any OEM Android power manager will kill a device-owner foreground service in
practice — which is a question for a device, not a search engine, and belongs in M0.

## 6. Sources

- [gliderlabs/ssh — GitHub](https://github.com/gliderlabs/ssh) · [pkg.go.dev](https://pkg.go.dev/github.com/gliderlabs/ssh) · [Debian package tracker, 0.3.8-2, May 2026](https://tracker.debian.org/pkg/golang-github-gliderlabs-ssh) · [Tailscale's tempfork](https://pkg.go.dev/tailscale.com/tempfork/gliderlabs/ssh)
- [Tailscale SSH session recording — docs](https://tailscale.com/kb/1246/tailscale-ssh-session-recording) · [multiple recorder nodes](https://tailscale.com/docs/reference/multiple-recorder-nodes) · [session recording to S3](https://tailscale.com/docs/features/tailscale-ssh/how-to/session-recording-s3) · [beta announcement](https://tailscale.com/blog/session-recording-beta)
- [asciicast v3 specification](https://docs.asciinema.org/manual/asciicast/v3/) · [asciinema 3.0 announcement](https://blog.asciinema.org/post/three-point-o/) · [asciinema-player 3.10.0](https://github.com/asciinema/asciinema-player/releases/tag/v3.10.0) · [third-party summary of 3.0](https://www.x-cmd.com/blog/250920/)
- [hashicorp/yamux](https://github.com/hashicorp/yamux) · [yamux spec](https://github.com/hashicorp/yamux/blob/master/spec.md) · [xtaci/smux](https://github.com/xtaci/smux)
- [WebTransport vs WebSockets — WebSocket.org](https://websocket.org/comparisons/webtransport/) · [Future of WebSockets: HTTP/3, WebTransport](https://websocket.org/guides/future-of-websockets/) · [WebTransport now in all browsers](https://anhtu.dev/webtransport-next-gen-realtime-protocol-2026-2228)
- [Teleport OSS relicensing to AGPLv3](https://goteleport.com/blog/teleport-oss-switches-to-agpl-v3/) · [Teleport CE commercial licence from v16](https://goteleport.com/blog/teleport-community-license/) · [discussion #39158](https://github.com/gravitational/teleport/discussions/39158)
- [CVE-2023-48795 — Terrapin, Snyk advisory for x/crypto/ssh](https://security.snyk.io/vuln/SNYK-GOLANG-GOLANGORGXCRYPTOSSH-6130669) · [oss-sec disclosure](https://seclists.org/oss-sec/2023/q4/300) · [Terrapin attack — Wikipedia](https://en.wikipedia.org/wiki/Terrapin_attack) · [golang-announce](https://groups.google.com/g/golang-announce/c/qN_GDasRQSA)
- [Android background execution limits](https://developer.android.com/about/versions/oreo/background) · [restrictions on starting a foreground service from the background](https://developer.android.com/develop/background-work/services/fgs/restrictions-bg-start) · [Beyond Doze: reliable background execution, including OEM realities](https://proandroiddev.com/beyond-doze-building-reliable-background-execution-on-modern-android-including-oem-realities-5fa0a6e05672) · [App background activity 2026](https://alexrooter.com/os-background-limits/)
- [Cloudflare — short-lived certificates bring Zero Trust to infrastructure](https://blog.cloudflare.com/intro-access-for-infrastructure-ssh/) · [HashiCorp — why we need short-lived credentials](https://www.hashicorp.com/en/blog/why-we-need-short-lived-credentials-and-how-to-adopt-them) · [Teleport — SSH certificate-based authentication](https://goteleport.com/blog/how-to-configure-ssh-certificate-based-authentication/) · [smallstep step-ca](https://smallstep.com/docs/step-ca/)
