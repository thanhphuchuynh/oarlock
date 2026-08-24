# Oarlock

**An SSH gateway for machines you cannot dial.**

Oarlock gives you a real `ssh` prompt on a device sitting behind NAT, on a cellular
APN, or on a customer's LAN — without putting a listener, a host key, or an open port
on that device. The gateway is the SSH server. The device only ever dials out.

Because the gateway is the SSH endpoint, it sits in the plaintext: every session can be
recorded to [asciicast v3](https://docs.asciinema.org/manual/asciicast/v3/) and replayed
later, and authorisation is checked centrally and **can be revoked mid-session**.

> **Name is a placeholder.** `oarlock` / `oarlockd` / `oarlock-agent` appear throughout;
> they are one `sed` away from anything else. Decide before the first tag, not after.

---

## The shape

```
        ┌──────────────┐                                        ┌──────────────┐
 CLI ──▶│  ssh client  │──── SSH ────┐                          │              │
        └──────────────┘             │      ┌───────────┐       │   agent      │
                                     ├─────▶│  oarlockd │──WS──▶│   PTY        │
        ┌──────────────┐             │      │  records  │ frames│  no listener │
 UI  ──▶│   browser    │──── WSS ────┘      └───────────┘       │  no host key │
        └──────────────┘                          ▲             └──────┬───────┘
                                                  │                    │
                                            plaintext lives         dials out
                                            here, on purpose        :443 only
```

Two operator front doors, one device leg. An operator with a terminal types
`ssh treadmill-4821@gw.example.org` and uses their own client, their own key, their own
muscle memory. An operator in a browser gets xterm.js over a WebSocket. Both land on the
same session, the same recorder, the same authorisation check.

The device leg is always outbound and always framed. **Nothing new listens on the
internet, and nothing at all listens on the device.**

## Two ways to reach a device

Oarlock ships both, because the right answer depends on how many devices you have and
whether you already run a message bus.

| | `persistent` (default) | `dispatch` |
|---|---|---|
| How the agent is reached | it holds one outbound WSS open, and the gateway rings it through that | the gateway rings a doorbell (MQTT, webhook, exec); the agent dials out per session |
| External dependencies | **none** — two binaries and you are done | whatever the doorbell is |
| Cost at rest | one idle socket per device, on the gateway | nothing |
| Session setup latency | one round trip | doorbell delivery + TLS handshake |
| Best for | tens to low thousands of devices; anyone evaluating Oarlock | large fleets that already have an always-on control channel |

Both converge on the same pairing and pumping code the moment a session opens — the mode
only decides how the two ends find each other. A session is always its own connection:
Oarlock does not multiplex, because a connection is either one session or the control
channel, never several at once.

**A held control channel is used whatever the mode says.** The mode describes how to reach
a device that is *not* connected, and a device holding a channel right now is reachable
through it — so a `dispatch` device whose agent happens to be holding one needs no doorbell
at all. `android` resolves to dispatch because the platform *resists* a held connection, not
because it forbids one, and an agent running on a desk holds one perfectly well. See
[ARCHITECTURE.md § Reachability](ARCHITECTURE.md#3-reachability-modes).

## Two ways to terminate SSH

**Mode C — gateway-terminated (default).** The gateway speaks SSH to the operator and
framed WebSocket to the agent, which runs a PTY. The gateway sees plaintext, so it can
record, rate-limit, and inject a policy banner. This is what Teleport does, and it is the
only shape that gives you a browser terminal *and* a real `ssh` client *and* a recording.

**Mode A — passthrough (opt-in, per device).** The gateway becomes a blind pipe and raw
SSH is tunneled to a `sshd` the device already runs. End-to-end encrypted; the gateway
cannot read a byte. You get `scp`, `sftp` and `ssh -L` free — and you get **no recording**,
no per-command audit, and a much coarser failure story, because it is all ciphertext.

Passthrough is off by default and refused unless a device is explicitly flagged for it and
the policy sets `allow_unrecorded: true`. Sessions that run this way are written to the
session log with `recording_state: not_recorded`, so an unrecorded session is a fact you
can query for, never an absence you have to notice.

## What is actually pluggable

Every integration point is a Go interface with a working default, so `go run` needs no
external service — and nothing forces the defaults on you at scale.

| Interface | Default | Also shipped |
|---|---|---|
| `Authenticator` | `authorized_keys` file | **OIDC** (bearer JWT + SSH device code), SSH certificate CA, static token |
| `Authorizer` | allow-listed `principal → device` rules in YAML | SQLite permissions with an admin UI, HTTP webhook (with revocation stream) |
| `Recorder` | asciicast v3 on local disk | S3 / GCS streaming, `none` |
| `SessionStore` | in-memory | SQLite, Postgres |
| `Dispatcher` | n/a (`persistent` mode) | MQTT, HTTP webhook, `exec` |
| `AgentAuthenticator` | Ed25519 device key, challenge–response | mTLS, one-time ticket |
| `AuditSink` | JSON lines on stderr | HTTP, syslog |
| `Ownership` | in-memory (single node) | Redis (multi-node) |

Full signatures and a worked example in [docs/plugins.md](docs/plugins.md).

## Revoking an operator

This is the feature that justifies terminating SSH at the gateway, so it gets more than a
`return false` at connect time:

1. **At session open**, `Authorizer.Authorize(principal, device, action)` must say yes.
2. **Every `recheck_interval` (default 30 s)** while the session is live, the same call is
   made again. A `no` closes the session with reason `revoked`.
3. **`Authorizer.Watch()`** streams revocations as they happen, so a webhook backend can
   kill a live shell in under a second instead of waiting for the next re-check.
4. **`DELETE /api/sessions/{id}`** kills one session immediately (`admin_kill`). Your own
   session needs no grant; somebody else's needs `admin:kill` on its device.

The same `Authorizer` gates the admin surface, which is the part that is easy to forget:
`admin:devices`, `admin:permissions` and `admin:kill` are actions like any other, because a
token that proves who you are must not thereby let you rewrite the policy that decides what
you may do. `authorizer.admins` in the config file is the break-glass for an empty policy
store, and it grants those three and nothing else — see
[docs/plugins.md § 3.1.1](docs/plugins.md).

There is no key on the device to un-deploy and no offline device that keeps honouring a
departed employee's credential — because the device never held one.

## Integrating it into something you already have

Most people will not run Oarlock as a product — they will add a shell to an admin console
or a device backend they already own. Four surfaces, covered in [docs/sdk.md](docs/sdk.md):

| surface | what you write |
|---|---|
| **Control API** (`/api/v1`) | one HTTP call: `POST /sessions` returns a session and a single-use attach ticket |
| **`@oarlock/terminal`** | a `<Terminal />` in your own page; reconnect, scrollback and the six failure states are handled |
| **Agent library** (Go, Kotlin) | the device side goes *inside* your existing app — on Android it has to |
| **Webhooks** | `session.closed`, `recording.available`, `authz.denied` |

Sessions are opened **on behalf of a human**, never by a service account of its own:
`Authorizer` sees the person, the recording attributes the person, and the calling service
is recorded separately. An audit trail whose every entry says `svc-crm` is one nobody can
use. The claim is a **signed assertion**, not a header — a bare `On-Behalf-Of: someone` is
refused, because it would let any service token act as any human.

If your backend is already Go, the gateway can be a library on your own mux instead of a
deployment — with the caveat that it then reads every keystroke inside your application
process.

## Quickstart

This runs. The flags below are the real ones.

```bash
go build -o oarlockd ./cmd/oarlockd
go build -o oarlock-agent ./cmd/oarlock-agent
mkdir demo && cd demo
```

**1. A device key, and an operator key.**

```bash
../oarlock-agent -key ./device.key -generate-key
#   writes device.key, and prints the public half for devices.yaml
ssh-keygen -t ed25519 -N "" -f ./operator_key -C phuc@example.com
cat operator_key.pub > authorized_keys
```

**2. Three config files.** Copy `examples/oarlock.yaml`, `examples/rules.yaml`, and a
device registry naming the device and the public half of its key:

```yaml
# devices.yaml
devices:
  - id: treadmill-4821
    platform: linux
    keys:
      - "<what -generate-key printed>"
    retired_keys: []  # move old keys here after rotation
    profiles: [shell]
```

For a real deployment, generate `ssh.host_key` once and distribute the same private key to
every gateway replica through your secret store. Use `ssh.generate_host_key` only for this
local demo.

Input capture is controlled separately from output recording. `policy.record_input`
matches operator attributes/groups and device tags; if two matching rules disagree, the
gateway refuses the session with `policy_conflict` instead of guessing which obligation to
violate.

**3. Check, then start.**

```bash
../oarlockd -config ./oarlock.yaml -check   # config + the boot gate, without starting
../oarlockd -config ./oarlock.yaml
```

`-check` is worth using in CI. It validates the file — unknown keys are refused, not
ignored — and runs the boot gate, which reports **every** unsafe setting at once rather
than one per boot. In `env: dev` it warns; anything that is not `dev` or `test` gets the
strict checks, including an unset value.

**4. The agent, on the device.**

```bash
../oarlock-agent -gateway ws://127.0.0.1:8443/ws/control \
                 -device treadmill-4821 -key ./device.key \
                 -shell /bin/sh -insecure-skip-pin
```

`-insecure-skip-pin` is required to leave the gateway unpinned, and the agent refuses to
start without one or the other. Wire version `v0` has no channel binding, so pinning is
what stands between the handshake and a TLS-terminating middlebox relaying it — an agent
that connects unpinned because nobody passed a flag is an agent nobody decided about.

**5. A shell.**

```bash
ssh -p 2222 -i ./operator_key treadmill-4821@127.0.0.1
#   oarlock: waking treadmill-4821…
#   oarlock: treadmill-4821 · gateway-terminated · this session is recorded
#   sh-3.2$
```

**6. What happened.**

```bash
curl -s -H "Authorization: Bearer dev-token-long-enough-for-the-check" \
     http://127.0.0.1:8443/api/v1/sessions | jq '.sessions[0]'

curl -s http://127.0.0.1:8443/readyz     # ok live=0 watch=unsupported

asciinema play recordings/*/sess_*.cast
```

The `.cast` file is asciicast v3 with a hash-chain header, and the `.json` beside it is
the signed manifest. `internal/record` verifies the pair and tells you *how* they disagree
— truncated, altered, or signed by another key — because those send you to three different
places.

**7. The console.** Open <http://127.0.0.1:8443/ui/> and paste the same token. It lists
sessions with the reason each operator gave, opens a shell in the browser, watches
somebody else's read-only, and replays a recording with its integrity verdict above the
player.

Building it is a separate step, because it needs a different toolchain:

```bash
pnpm install && pnpm build:ui   # builds into the binary's embedded assets
go build -o oarlockd ./cmd/oarlockd
```

A gateway built without it still works — ssh, `/api` and `/ws/attach` do not depend on
the console — and `/ui` then says how to build it rather than serving a blank page.

## Where this came from, and what it is not

Reaching a machine behind NAT is a solved category — ngrok, Cloudflare Tunnel, frp,
remote.it, ShellHub. Oarlock borrows the dial-out, the held connection, the
name→connection map and the stream-per-session without change. What it does **not** borrow
is the assumption underneath the last step: that the target already runs a service worth
forwarding to. Oarlock's device leg terminates in a PTY inside the agent process, which is
why it works on Android and other places where you cannot install and supervise a `sshd`.

Existing tools worth choosing over Oarlock:

- **[Teleport](https://goteleport.com)** — if your targets are Linux hosts with system
  users. Far more mature, and its proxy does exactly what Oarlock's gateway does. Note the
  licensing: the OSS core moved from Apache 2.0 to **AGPLv3** in December 2023, and
  **Community Edition adopted a commercial licence at v16** that restricts company use while
  staying free for individuals. It also brings its own identity and cluster backend.
- **[Tailscale SSH](https://tailscale.com/kb/1246/tailscale-ssh-session-recording)** — if
  your targets are machines you administer. It records **at the destination node** and
  streams to a recorder in your tailnet, which means it gets end-to-end encryption *and* a
  recording. Oarlock cannot copy that: its devices are appliances in customers' gyms, and a
  recorder running on the recorded machine is only as trustworthy as the machine.
- **[ShellHub](https://shellhub.io)** — the closest neighbour, built for NAT-bound IoT,
  agent dials out over WebSocket. Its agent targets Linux with real system users. *Its
  licence and whether session recording is a paid tier are unverified as of August 2026 —
  check before relying on either.*
- **[chisel](https://github.com/jpillora/chisel) / frp / rathole** — if you want only the
  tunnel and will build tickets, RBAC, recording and session bookkeeping yourself.
- **[OpenZiti](https://openziti.io) / NetBird / Headscale** — if you want an L3 overlay.
  They solve connectivity, not sessions, and they put the fleet on one network.

Oarlock is worth it when you need all three of: a real `ssh` client, a browser terminal,
and a recording of both — on devices that cannot run a listener.

## Documentation

| | |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | components, planes, reachability modes, session lifecycle, multi-node |
| [docs/protocol.md](docs/protocol.md) | frame format, handshakes, every frame type, error codes, versioning |
| [docs/sdk.md](docs/sdk.md) | control API, server SDKs, terminal embed, agent library, webhooks |
| [docs/plugins.md](docs/plugins.md) | every interface, its contract, and how to write one |
| [docs/threat-model.md](docs/threat-model.md) | assets, adversaries, trust boundaries, residual risk |
| [`packages/terminal`](packages/terminal) | the embeddable browser terminal, and the disclosure rules it enforces |

## Building it

Two toolchains, because the gateway is Go and the terminal is a browser component.

```sh
# the gateway, the agent, the plugins
go test -race ./...

# the browser component
pnpm install
pnpm test               # tokens are current, typecheck, then Playwright
```

`pnpm test` runs one runner over two tiers. `unit` is pure logic in Node — the wire
codec, the disclosure policy — and `component` mounts the real component in real
Chromium, because xterm.js draws to a canvas and measures a DOM. jsdom cannot tell you
whether a terminal rendered, and a test that cannot tell is worse than no test.

Two generated things are committed, and CI fails when either goes stale:

- **`tokens/tokens.json` is the only place a colour is written.** `pnpm tokens`
  regenerates the component's custom properties, the console's Tailwind theme, and the
  palette xterm needs as data. Two hand-maintained palettes drift.
- **`tests/fixtures/recordings/verdicts.json` is real recordings, really damaged.** The
  browser's replay tests read recordings this repository produced and then truncated,
  edited and re-keyed in the ways `internal/record` distinguishes — with the verdict
  *computed* by the verifier rather than written by hand, so the component is tested
  against what a truncation is rather than against somebody's belief about one.
  Regenerate with `go test ./internal/record/ -run TestRecordingFixtures -update-fixtures`.
- **`tests/fixtures/frames.json` is the wire, generated from Go.** The TypeScript codec
  reads the same bytes the Go tests assert, because a second implementation of a wire
  format is where a protocol forks quietly — both suites pass and the two disagree in
  production. Regenerate with `go test ./pkg/frame/ -run TestSharedVectors -update`.

## Status

Runnable, and not finished.

`oarlockd` and `oarlock-agent` build and work: the Quickstart above is a transcript, not a
plan. What works, with tests: the wire codec, both reachability modes, the SSH surface
against a real PTY, session recording with a hash chain and a signed manifest, reattach
with scrollback, read-only observation, the control API, the browser attach endpoint, the
authorisation contract with its grace window, and the embeddable terminal component.

Since then: the admin console at `/ui`, the webhook authorizer with its revocation
stream, the MQTT dispatcher, delegated authority, device key rotation and retirement, the
`record_input` policy, the SQLite device registry and authorizer with an admin UI, and the
authorisation gate on that admin surface.

Missing: the SSH-CA authenticator, and the browser half of the OIDC login — the API and
the SSH surfaces authenticate against a provider, but the console still takes a pasted
`id_token` rather than redirecting you to sign in. Epics 5 to 8 (the rest of the profiles, passthrough, multi-replica operation, the generated
SDKs and the supply-chain work) are planned and unbuilt. No releases and no API stability:
the protocol in `docs/protocol.md` is `v0` and will change without ceremony until it is
tagged.

## Licence

[Apache-2.0](LICENSE).
