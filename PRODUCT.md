# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Existing: TypeScript, React 19, Tailwind v4, Vite. The console builds from the repository
root via `vite build --mode console` into `cmd/oarlockd/app/ui/dist`, which the Go binary
embeds with `go:embed`. Two workspace packages ship separately: `packages/terminal` (a
framework-free xterm.js component) and `packages/react` (its React wrapper).

The landing page is a new surface with no scaffold of its own. It inherits this stack
rather than introducing a second one.

## Users

**Primary: the operator.** A support or platform engineer who needs a shell on one specific
machine, right now, and cannot reach it — the machine is behind NAT, on a cellular APN, or
on a customer's LAN. They arrive in one of two ways and both land on the same session:

- **A terminal.** `ssh treadmill-4821@gw.example.org` with their own client, their own key,
  their own muscle memory. They are addressing a fleet of thousands with one credential, so
  the addressable thing in the connection string is the *device*, not the operator.
- **A browser.** The admin console at `/ui`: fleet, live sessions, permissions, recordings,
  and an xterm.js terminal.

**Secondary: whoever owns access.** They do not open sessions. They read recordings, edit
permissions, and answer for who could reach what. The console's permissions and session
history are written for them, not for the operator.

**Evaluating, not yet using:** an engineer deciding whether to run this at all. They need
the security model to survive their own scepticism before they will install anything.

## Product Purpose

Give an operator a real `ssh` prompt on a device that cannot accept an inbound connection,
without putting a listener, a host key, or an open port on that device.

The device only ever dials out, to :443. Nothing new listens on the internet, and nothing at
all listens on the device.

Success is that reaching a machine in somebody's home is boring: it works from the tools the
operator already has, it is recorded, and access can be withdrawn while the session is open.

## Positioning

**The gateway is the SSH server, not a relay.** It terminates the operator's SSH connection
and speaks its own framed protocol to the device. That single decision is the mechanism a
neighbouring product cannot truthfully copy without accepting the same cost, because
everything else follows from it:

- The gateway sits in the plaintext, so **every session can be recorded** to asciicast v3
  and replayed later.
- Authorisation is checked centrally and **can be revoked mid-session** — not at the next
  login, during this one.
- Failures are diagnosable. A blind relay collapses "device refused", "auth failed" and
  "shell died" into "connection closed".

The cost is stated rather than hidden: the gateway reads every keystroke and every byte of
output. Anyone evaluating this is told so before anything else, and a passthrough mode
exists for those who cannot accept it.

## Operating Context

- **Devices are consumer hardware in other people's buildings** — the worked example
  throughout is `treadmill-4821`, a machine in a customer's home or a gym. They are Android,
  frequently on cellular, frequently asleep, and never physically reachable.
- **Two reachability modes.** `persistent`: the agent holds one outbound WSS open and the
  gateway rings it. `dispatch`: a doorbell (MQTT, webhook, exec) wakes the agent, which then
  dials out per session. Both converge on the same pairing and pumping code.
- **A session is its own connection.** Oarlock does not multiplex: a connection is one
  session or the control channel, never several at once.
- **The operator is usually mid-incident.** The console is opened because something is
  wrong, often on a phone, often by someone who did not write it.

## Capabilities and Constraints

**Working, with tests:** the wire codec; both reachability modes; the SSH front door against
a real PTY; session recording with a hash chain and a signed manifest; reattach with
scrollback; read-only observation; the control API; the browser attach endpoint; the
authorisation contract with its grace window; the admin console; the embeddable terminal
component; and four profiles — `shell`, `exec` (one allow-listed command), `file` (read and
write under a confined root), and `tcp` (`ssh -L` to the device's own loopback).

**Authorisation** is per action, per device, and per target: a grant can name the port, the
path or the argv.

**Not built, and must not be claimed:** the SSH-CA authenticator; mode A passthrough (it is
expressible in policy and nothing serves it); multi-replica operation; the generated SDKs.

**Constraints that bind design work:**

- **The design tokens are generated.** `tokens/tokens.json` is the source; `web/src/tokens.css`
  and the terminal component's palette are generated from it, and CI fails on a stale copy
  (`pnpm tokens:check`). Never edit the generated file.
- **The terminal palette is functional, not decorative.** xterm.js reads the same tokens, and
  sixteen ANSI colours must stay distinguishable against the terminal background.
- **The console is embedded in the Go binary**, so its build output has a fixed home and
  cannot depend on a CDN.
- **No releases and no API stability.** The protocol is `v0`.

## Brand Commitments

- **Name: Oarlock**; binaries are `oarlockd` and `oarlock-agent`. Confirmed this session,
  replacing the README's note that the name was a placeholder. *A rowing term* — an oarlock
  is the fixed pivot an oar turns against. The metaphor is therefore available and accurate:
  the gateway is the fixed point; the device does the moving.
- **Voice, evidenced throughout the existing documentation:** plain, specific, and willing to
  state costs. It explains *why* rather than *what*, names what is missing before a reader
  finds it, and does not use a superlative where a number would do. The landing page and the
  console inherit this voice; a marketing register would read as a different product.
- **Licence:** Apache 2.0.

## Evidence on Hand

Real, in the repository, and usable as page content:

- `README.md` — the shape diagram, the two-modes table, and a **quickstart that is a
  transcript, not a plan**, ending in a real `sh-3.2$` prompt.
- `docs/threat-model.md` — including § 4 "Gateway compromise is total" and § 12, an honest
  table of what is built, tested, or only described.
- `docs/diagrams/` — three rendered diagrams: trust boundaries, port forwarding, the
  authentication flow.
- `docs/protocol.md`, `docs/plugins.md`, `docs/sdk.md`, `docs/android.md`.
- The console itself, and `packages/terminal`.

**Absent, and not to be invented:** customers, testimonials, logos, benchmarks, uptime
figures, pricing, funding, team photos, adoption numbers, and any deployment claim. There
are no releases and no public repository yet, so "used by" and "trusted by" have no
referent.

## Product Principles

1. **State the cost before the benefit.** The gateway reads the plaintext. Every surface that
   describes what this makes possible says what it costs first.
2. **The operator already has tools.** Do not replace `ssh`; meet it. The browser is the
   second door, not the front one.
3. **Nothing is claimed that a test does not back.** § 12 of the threat model is the standard
   — built, tested, or not built, said plainly.
4. **The device is a target, not a participant.** It holds no bearer token, opens nothing,
   and can address nothing but itself.
5. **A failure must be diagnosable.** Distinct causes get distinct names, in the UI and on the
   wire.

## Accessibility & Inclusion

No formal standard has been established for this project. Two product-specific needs are
real regardless:

- **The console is used during incidents**, sometimes one-handed on a phone, sometimes by
  someone unfamiliar with it. Density must not cost legibility.
- **State is currently carried by colour** (recorded, unrecorded, observed, reconnecting,
  ended, refused). It needs a second channel — shape, label, or position — so the six states
  survive a colour-vision difference and a bad screen in a plant room.
