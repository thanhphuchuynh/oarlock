# Threat model

Oarlock hands a shell on a remote device to a human over the internet. That is a
high-value capability, so this document says plainly what it protects, what it does not,
and which risks it accepts on purpose.

Originally written against the design in [ARCHITECTURE.md](../ARCHITECTURE.md), and since
revised against the code. **§12 says which of the mitigations below are actually built**,
and it is the section to read first if you are deciding whether to trust any of this.

---

## 1. What is worth stealing

| asset | why an attacker wants it |
|---|---|
| **A shell on a device** | Root-adjacent code execution on hardware in a customer's home or gym. The whole point. |
| **A shell on *every* device** | Fleet-wide execution. The difference between an incident and a company-ending one. |
| **Session recordings** | Durable, greppable, and nobody is watching them being read. They contain command history, file contents, tokens pasted into a prompt — and if `record_input` is on, typed passwords. |
| **Operator credentials** | Reusable, and usually good for more than Oarlock. |
| **Device identity keys** | Impersonate a device, receive sessions meant for it, feed an operator fabricated output. |
| **Tickets in flight** | Single-use and short-lived, but a redeemed one is a session. |
| **The device registry** | A map of the fleet: ids, tags, which devices allow unrecorded sessions. |

## 2. Trust boundaries

```
 operator ──┬── SSH / TLS ──▶ ┃ oarlockd ┃ ──── TLS ────▶ agent ──▶ PTY
 browser ──┘                  ┃          ┃
                              ┃  FULLY   ┃
                              ┃ TRUSTED  ┃
                              ┗━━━━━━━━━━┛
                                   │
                    ┌──────────────┼───────────────┐
                    ▼              ▼               ▼
              Authenticator   Recorder        Dispatcher
              Authorizer      SessionStore    Ownership
              (trusted, in-process, but network-adjacent)
```

| actor | trusted with |
|---|---|
| **Operator** | Nothing until authenticated, then exactly the actions `Authorizer` allows on the devices it names. |
| **Agent** | Its own device only. It cannot open a session, cannot address another device, and cannot enumerate anything. It is a target, not a participant. |
| **Gateway** | Everything. See §4. |
| **Plugins** | Whatever they need. They are compiled in and run in-process; a hostile plugin is a hostile gateway. |
| **Recording store** | Confidentiality and integrity of every past session. Frequently under-protected relative to what it holds. |
| **Doorbell** (`dispatch`) | Availability of session setup, and it sees ticket material in transit. |

## 3. Adversaries

**In scope.** A network attacker between any two components. An authenticated operator
exceeding their grant, or keeping access after it is withdrawn. A compromised device
attacking the gateway or the operator's terminal. A departed employee. A stolen device in
someone's hands. An attacker who reads logs — application, ingress, or LB.

**Out of scope, and named so nobody assumes otherwise.** A compromised gateway (§4). A
malicious plugin. Anyone with root on the machine `oarlockd` runs on. Physical attacks on a
device beyond what its own platform resists. The confidentiality of a session from the
gateway operator — in mode C that is not a property Oarlock offers, by construction.

## 4. Gateway compromise is total

**The gateway reads every keystroke and every byte of output, and can inject its own.**
Not a bug, not a mitigation gap — it is the direct cost of the decision that makes
recording and mid-session revocation possible. An attacker with code execution in
`oarlockd` can read live sessions, replay recordings, mint tickets, forge authorisation
decisions, and open a shell on any device in the fleet.

Anyone considering Oarlock should read that paragraph and decide whether they are
comfortable, before reading anything else. If the answer is no, mode A passthrough (§8) is
the shape that removes it — at the cost of the recording, and only for CLI operators.

What follows from accepting it:

- The gateway is the most sensitive service in the deployment. Treat it like a KMS, not
  like an API pod: minimal image, no shell in the container, read-only root filesystem,
  its own node pool if you have one, its own build and review path.
- Nothing else should share its process. No sidecar with a debug endpoint, no
  `pprof` on a listening port in production, no log agent that can read its memory.
- Every deploy is a supply-chain event. Pin dependencies, review upgrades, and sign the
  image.
- Access to the host is access to the fleet. Audit it separately and more loudly than the
  sessions themselves.

## 5. Operator authentication and authorisation

| threat | mitigation | residual |
|---|---|---|
| Stolen operator SSH key | `sshca` backend issues short-lived certificates, so a stolen key expires on its own. `authorized_keys` does not — it is the default for convenience and the wrong choice past a handful of people. | A key stolen inside its validity window works. Certificate TTL is the only lever; keep it hours, not weeks. |
| Access kept after revocation | Re-check every 30 s, plus `Authorizer.Watch` for sub-second kills, plus `admin_kill`. No credential on the device to un-deploy. | Up to `recheck_interval` of extra access when `Watch` is unavailable or broken. Shorten the interval if that matters. |
| Privilege escalation between actions | `exec` does not imply `shell`; `passthrough` and `replay` imply nothing. Grants are per action, per device, and — for `tcp`, `file:read`, `file:write` and `exec` — per **target**: a port, a path glob, an argv. | `shell` is still all-or-nothing on a device, because a shell has no target to narrow. Oarlock does not restrict *what you type* — see §7. A backend that ignores the target grants every target, and forgetting to read it is not a compile error. |
| Session fixation / ticket theft on the browser leg | Tickets are single-use, 60 s, scoped to one device, one profile, one principal, and carried in a frame body rather than a URL. | An attacker who can read the ticket *and* wins the race against the legitimate browser gets one session. TLS is the control. |
| Brute force on the SSH front door | A 15 s pre-authentication budget closes a connection that never authenticates; a ceiling on concurrent connections bounds how many can be held at once; and a per-client connection rate limit (default 30/min, keyed by IPv4 address or IPv6 /64) bounds how fast one source may try. Failures do not distinguish "no such device" from "not authorized", so a valid key cannot enumerate the fleet by trying usernames. | **The rate limit counts connections, not attempts.** `MaxAuthTries` is the x/crypto default of six, so the real budget is six times the configured number — and a distributed attempt from many sources is not slowed at all. **There is no per-*user* limit**, so an attacker who spreads across sources gets an unthrottled guess rate against a single account. **A deployment behind a TCP load balancer without PROXY protocol sees one client for the whole world** and must disable the limit rather than inherit it. An enumeration oracle may still exist in the timing of the error paths — untested. |
| A service acting as a human it should not | `AuthDelegated` requires a signed assertion: the subject's own token, or a service-signed assertion constrained by a `may_act_for` allow-list with a sub-60 s lifetime. A bare `On-Behalf-Of` identifier is refused. | With the service-signed fallback, a compromised service can act for anyone on its allow-list. Narrow the list; prefer forwarding the subject's token. |
| Authorisation backend outage used as a lever | An error is not a denial: new sessions are refused, live ones get a grace window and then close as `authz_unavailable`, never `revoked`. | An attacker who can take down the authz backend can still stop *new* sessions — a denial of service, deliberately chosen over admitting sessions on stale decisions. |
| A malicious or careless operator | Every session recorded and attributed; `AuditSink` gets open, close, deny and revocation events. | Detection, not prevention. An operator with `shell` on a device owns that device. That is what a shell is. |

## 6. The device leg

| threat | mitigation | residual |
|---|---|---|
| Device key extracted from a stolen device | Ed25519 key generated on-device, never transmitted. On Android, the reference agent should use the hardware keystore where available. | A rooted device without hardware key storage gives up its key. Then that *one* device can be impersonated — and nothing else, because keys are per device. |
| Impersonating another device | Keys are per device and the signed blob binds `device_id` and `gateway_id`. | Only as strong as the registry's key provisioning, which Oarlock does not own. |
| Ticket replay (`dispatch`) | Atomic compare-and-delete; second redemption fails. An agent that retries must fetch a fresh ticket. | A ticket intercepted and redeemed *before* the real agent wins. The real agent then fails, loudly — which is the detection signal, so alert on it. |
| MITM relaying a valid handshake | The agent pins the gateway certificate (`--pin-sha256`) by default. | `v0` has no channel binding; a TLS-terminating middlebox the agent was configured to trust can relay. `v1` should mix in RFC 5705 exported keying material. **Known gap.** |
| A compromised device attacking the gateway | Frame size cap, strict parsing, per-connection rate limits, no dynamic allocation from attacker-controlled lengths (the WebSocket message boundary is the frame boundary). | Parser bugs. This is the largest untrusted-input surface in the project and deserves fuzzing from the first commit, not after the first report. |
| A compromised device attacking the *operator's terminal* | Output is raw bytes and always was — a hostile device can emit any escape sequence. The web terminal disables OSC 52 (clipboard write) and window-title reporting by default. | A local `ssh` client's terminal is outside Oarlock's control. A hostile device can garble it and, with an unlucky terminal emulator, do worse. This is true of `ssh` generally; it is not made worse here. |
| Prefix truncation deleting the mode disclosure | Strict key exchange removes the primitive; `x/crypto` implements it from v0.17.0 and the version is asserted in CI, and a test reads the server's KEXINIT off the wire to confirm `kex-strict-s-v00@openssh.com` is advertised. Structurally, the disclosure is also **repeated at session close**, where no prefix attack can reach, and the one message inside the vulnerable window carries no security-relevant claim. | An attacker who can modify traffic can still make the *opening* line disappear on a peer that somehow negotiated without strict kex; the closing line is what makes that survivable. |
| Escape sequences poisoning logs and audit | Non-printable bytes are escaped before anything reaches a log line or an audit event. | Whatever consumes your logs may still render them naively. |
| `tcp` profile used for lateral movement | Two independent gates. The gateway refuses any destination that is not the device's own loopback and checks `tcp` against a per-port grant; the device refuses any port not on the allow-list it holds. Both apply, and neither is permitted to stand in for the other — the gateway's compromise is total (§4), so the device's own list is what holds when the gateway is lying. | An allow-list that includes a proxy port turns the device into a pivot into the network it sits on. Do not allow-list broadly, and never `0.0.0.0`. Changing the device-side list is still a fleet push rather than a policy edit, so the fast lever is the gateway-side grant. |
| `file` profile path traversal | Confined to a configured root, symlinks resolved and re-checked. | Classic bug class. Test it adversarially. |
| `exec` profile becoming a shell | Allow-listed argv, no shell interpretation, no user-supplied arguments unless the entry declares them. | An allow-listed entry that takes a filename takes whatever a shell would have. Keep entries argument-free where possible. |

## 7. What Oarlock deliberately does not do

**It does not restrict what an operator types.** No command filtering, no `sudo`
interception, no per-command approval. An interactive shell is a Turing-complete
capability: filtering it is theatre, because `sh -c` and a base64 blob defeat any
allow-list, and each new bypass is discovered in production. The controls are *who gets a
shell at all*, *on which device*, *for how long*, and *that it is recorded*.

If you need per-command control, do not grant `shell`. Grant `exec` with an allow-list, and
put the review in front of what goes on the list.

**It does not protect a session from the gateway.** §4.

**It does not authenticate the operator to the device.** The agent trusts the gateway
completely and cannot verify a principal. `principal` in a `DIAL` invitation is for the agent's
log, never for a decision.

## 8. Mode A passthrough, specifically

Passthrough removes the gateway from the plaintext and adds its own set of problems, all
of which are the reason it is opt-in and off by default.

| threat | note |
|---|---|
| **No recording, ever** | Ciphertext. There is nothing to record. The session row says `not_recorded` so this is a queryable fact rather than a missing file, and the operator is shown a banner before the first prompt. |
| **A listener on the device** | "Bound to loopback" reads as private and is not, on Android: apps share a network namespace, so any other app holding `INTERNET` can reach `127.0.0.1:2222`. On a locked kiosk that is low probability; it is still a new local attack surface on hardware the public stands on. |
| **A second PKI** | Every device needs a host key and every client must trust it, which at fleet scale means an SSH CA: a signing service, short-lived host certificates, re-signing sweeps, and a revocation story that amounts to keeping the TTL short. OpenSSH certificates are their own format, not X.509, so an existing device PKI (an MQTT mTLS one, say) contributes nothing. |
| **Operator authorisation on the device** | `authorized_keys` on the device means revoking someone is a push to the fleet, and a device offline for a week still honours a departed employee's key. One shared key instead means any bypass of the gateway is a fleet-wide shell from a single credential. Neither is good, and the device has no notion of tenant or role to check against. |
| **Free port forwarding** | `direct-tcpip` arrives with the protocol. On the device's own network. Disable it in the device `sshd` config unless it is wanted. |
| **Coarse failure diagnosis** | A blind relay cannot tell "device refused" from "auth failed" from "shell died". The six failure states in ARCHITECTURE § 11 collapse to "connection closed". An operational cost, not a security one — but it is the cost paid on every incident. |
| **No mid-session revocation** | The gateway can kill the pipe, which is real. It cannot re-check a grant against a session it cannot read, so `revoked` becomes "the tunnel was cut" with no record of what was happening. |

**Mode A does not buy a more capable shell.** Both modes run as the agent's uid;
`sshd`-on-device and `forkpty`-in-agent have identical privilege. "Real SSH" does not mean
"real Linux box".

## 9. Recordings are as sensitive as the sessions

A recording is a durable copy of a privileged session, read when nobody is watching. It is
routinely the least-protected asset in a deployment like this, so:

- **`replay` is its own action.** Being able to open a shell is not being able to read what
  someone else did in one.
- **Encrypt at rest**, and prefer a store that can enforce object-level access rather than
  one bucket everyone can list.
- **Set a retention period and mean it.** Recordings you have no plan for are liability
  with storage costs.
- **`record_input` is off by default** because keystroke capture records what is typed into
  a password prompt — echo is suppressed on the device, so the gateway sees the characters
  regardless of what the screen showed. Turning it on makes recordings a credential store.
- **Audit reads.** `AuditSink` gets a `replay` event with principal, session and time. An
  unusual pattern of recording access is a signal worth having.
- **Consider who else is in the recording.** Sessions capture file contents, customer data,
  and in some jurisdictions the operator's own keystrokes are personal data with its own
  legal weight. That is a question for whoever owns privacy at your organisation, and it is
  better asked before the first recording than after a request to produce them.

## 10. Denial of service

| threat | mitigation |
|---|---|
| A device flooding output | 25 ms coalescing, `limits.batch` (64 KiB per frame), `limits.rate` (256 KiB/s sustained, 1 MiB burst), and `shell` backpressures rather than buffering. Memory is bounded by the ring buffer and socket buffers. |
| Recorder backend failure killing every session | A bounded spool (`recorder.spool_bytes`, `recorder.flush_deadline`) absorbs a failing backend; only exhaustion closes the session, and the partial recording survives on disk. |
| Authz backend failure killing every session | `authz.grace` re-checks before closing, and the close reason says `authz_unavailable` rather than `revoked`. |
| One session stalling another on the same connection | **Not possible:** a connection carries one session (ADR-024), so socket backpressure slows exactly the session that is not keeping up. This is what removing multiplexing bought — there is no head-of-line class to defend against. |
| An operator opening many sessions | `sessions_per_principal`, enforced atomically in `SessionStore`. |
| Many sessions per device | `sessions_per_device` (default 1), enforced by a unique index, not a check-then-act. |
| Unauthenticated connection flood on `/ws/control` or `/ws/session` | 5 s handshake budget; a per-client connection rate limit (default 120/min, shared across all three `/ws/*` doors, keyed by IPv4 address or IPv6 /64) applied before the upgrade; and the handshake does no allocation on behalf of an unauthenticated peer beyond a fixed-size buffer. Neither door can be *guessed* at — Ed25519 challenge-response and a 32-byte random ticket — so the limit bounds work rather than attempts. |
| Idle sessions accumulating | `limits.idle` (5 min) and `limits.max_duration` (4 h). |
| A malformed length forcing an allocation | There is no length field. The WebSocket message boundary is the frame boundary, and messages over `limits.frame` are rejected by the transport. |
| Thundering-herd reconnect after a restart (`persistent`) | Jittered backoff in the agent, and `GOAWAY` carries a per-agent `reconnect_after_ms` during a drain. |
| A plugin hanging | Every plugin call has a context deadline. `AuditSink.Emit` cannot fail or block by contract, so audit can never become the lever. |
| The doorbell being down (`dispatch`) | Sessions cannot open. Reported as `doorbell_failed`, not `device_offline`, so on-call looks at the broker rather than at hardware. |

## 11. Hardening checklist

For anyone actually deploying this:

- [ ] `Authenticator: sshca` or `oidc`. Not `authorized_keys`, past a handful of operators.
- [ ] `recheck_interval` at or below 30 s, and `Authorizer.Watch` implemented.
- [ ] `allow_unrecorded: false` unless there is a written reason.
- [ ] `AllowPassthrough: false` on every device that does not specifically need it.
- [ ] `record_input: false` unless recordings are handled as a credential store.
- [ ] Recordings encrypted at rest, `replay` granted separately, retention set, reads audited.
- [ ] `tcp` and `file` allow-lists empty unless used; never a proxy port, never `0.0.0.0`.
- [ ] Agent pins the gateway certificate.
- [ ] Device keys in hardware-backed storage where the platform offers it.
- [ ] Gateway on its own node pool, read-only root filesystem, no shell in the image, no
      `pprof` listener in production.
- [ ] Audit shipped off the gateway host, and host access audited separately.
- [ ] Fuzzing in CI for `pkg/frame` and the `file` profile path handling.

## 12. What is actually built

The first version of this document ended with "nothing is written yet". That stopped being
true, and a threat model that understates what exists is worse than one that overstates it:
a reader who cannot tell which rows are real cannot tell which rows are **not**.

So this section is the status of everything above. It is a self-review — code read by
somebody who also wrote some of it, not an independent audit — and the statuses mean:

- **tested** — implemented, and there is a test that fails when the guarantee is removed.
- **built** — implemented and read, with no test pinning the specific property.
- **not built** — described above, absent from the code. These are the ones that matter.

| § | mitigation | status | where |
|---|---|---|---|
| 5 | Operator authentication by key or OIDC | tested | `internal/auth/authorizedkeys`, `internal/auth/oidc` |
| 5 | JWT algorithm allow-list bound to the key kind, and a `kid`-flood limiter | tested | `internal/auth/oidc/verify.go`, `jwks.go` |
| 5 | `sshca` short-lived certificates | **not built** | — the row above names a backend that does not exist |
| 5 | Per-action, per-device authorisation | tested | `internal/authz`, `pkg/plugin/authz.go` |
| 5 | Per-target authorisation for `tcp`, `file:*`, `exec` | tested | `plugin.Target`; `rules` and `sqlite` backends |
| 5 | Re-check every 30 s, `Watch` as the optimisation | tested | `internal/authz/supervisor.go` |
| 5 | Re-checks replay the target the session opened with | tested | `internal/authz/target_test.go` |
| 5 | An outage is refused as `authz_unavailable`, never `revoked` | tested | `internal/authz`, and `plugintest` fails a backend that gets it wrong |
| 5 | Tickets single-use, 60 s, scoped, compare-and-delete | tested | `internal/ticket` |
| 5 | Pre-authentication budget and connection ceiling on the SSH door | tested | `internal/sshsrv/preauth.go` |
| 5 | Per-client connection rate limit on the SSH door | tested | `internal/sshsrv/ratelimit.go` — keyed by IPv4 address or IPv6 /64 |
| 5 | Per-IP rate limit on the HTTP/API surface | tested | `internal/apisrv` — and keyed correctly for IPv6, which it was not |
| 6 | Connection rate limit on the WebSocket legs | tested | `internal/ratelimit` — one budget across `/ws/control`, `/ws/session` and `/ws/attach`, refused before the upgrade |
| 5 | Delegated authority needs a signed assertion | built | `internal/auth/delegated` |
| 5 | Audit of open, close, deny and revocation | built | `plugin.AuditSink` |
| 6 | Ed25519 challenge-response, key generated on-device | tested | `internal/handshake` |
| 6 | Signing input length-prefixed and domain-separated | tested | `handshake.SigningInput` |
| 6 | Gateway certificate pinning, additive, over the SPKI | built | `pkg/transport/websocket` |
| 6 | Channel binding on the agent handshake | **not built** | see gap 1 below |
| 6 | No allocation from an attacker-controlled length | tested, fuzzed in CI | `pkg/frame` — there is no length field to lie about |
| 6 | Terrapin: strict key exchange | tested | the `x/crypto` floor is asserted in CI |
| 6 | `tcp` confined to device loopback, per-port allow-list on the device | tested | `internal/sshsrv/tcpip.go`, `agent/tcp.go` |
| 6 | `file` confined by `os.Root`, no TOCTOU window | tested, fuzzed in CI | `agent/file.go` |
| 6 | `exec` allow-listed argv, no shell interpretation | built | `agent/exec.go` |
| 6 | Escape sequences escaped before reaching a log or an audit event | **unverified** | claimed above; not checked during this review |
| 9 | `replay` is its own action | built | the action set is closed and checked |
| 9 | Recordings signed and hash-chained | built | `internal/record` |
| 10 | Frame and batch ceilings, coalescing, backpressure | tested | `internal/pump`, `pkg/frame` |
| 10 | `sessions_per_device` by unique index, not check-then-act | tested | `internal/sessions` |
| 10 | Forwarded connections capped apart, never claiming the device slot | tested | `sessions.HoldsDevice` |
| 10 | Handshake budget on the WebSocket legs | built | `internal/handshake` (5 s) |
| 11 | The boot gate refuses dangerous configurations rather than warning | tested | `internal/safety` |

### Gaps, recorded here rather than discovered later

1. **No channel binding in the `v0` agent handshake** (§6). Certificate pinning is the
   stopgap; RFC 5705 exported keying material is the fix, and it belongs in `v1`.
2. **`authorized_keys` as the default authenticator** is the wrong default for anything
   past a lab, and it is the default because it needs no dependencies. The README and this
   document both say so; a warning at boot would say it louder.
3. **`sshca` does not exist.** §5 offers it as the answer to a stolen key, and there is no
   such backend. Until there is, the answer to a stolen key is OIDC or a short grant.
4. **The device writes half the policy for `tcp`, `file` and `exec`.** The gateway can now
   narrow to a port, a path or an argv, but the device's own allow-list is what holds when
   the gateway is lying — and changing that list is a fleet push, not a policy edit. Both
   gates are deliberate (§6); the asymmetry in how fast each can be changed is the part
   worth knowing before an incident.
5. **A backend that ignores `Target` grants every target**, and forgetting to read it is
   not a compile error. The widening direction is the quiet one. Review backends for it.
6. **The SSH rate limit counts connections, not authentication attempts**, at six tries
   each, and does nothing about an attempt spread across many sources. It makes a single
   source useless, which is all a per-client limit can honestly claim.
7. **Two rate limits in this codebase key IPv6 differently.** `internal/ratelimit` groups
   an IPv6 client by its /64, because a per-address counter is defeated by rotating the
   low half; `internal/apisrv` keys per address, and a test there asserts that on the
   reasoning that a shared bucket lets one caller spend a bystander's. Both arguments are
   real, and they point opposite ways on the door where the limit exists to bound *token
   guessing*. The API surface is the one that is guessable, so it is the one where the
   weaker key matters most. Unresolved.
8. **All three rate limits are per node and in memory.** A gateway behind a load balancer
   with N replicas gives an attacker N times the budget, and a restart clears every
   counter. Shared state would fix it and would put a dependency in the path of accepting
   a connection, which is its own risk. Not attempted.
9. **None of this has been reviewed by anyone who did not write it.** The statuses above
   say what the code does, not that the code is right.

## 13. Reporting a vulnerability

Once this project is real, this section needs a security contact and a disclosure policy,
and `SECURITY.md` needs to exist. Until then there is no code to report against.
