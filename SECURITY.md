# Security policy

Oarlock hands a shell on a remote device to a human over the internet. A vulnerability here
is not an inconvenience, so this policy is deliberate about what we promise and when.

## Reporting a vulnerability

**Email <nguoigiaumat100@gmail.com>.** That is the channel, and until there is a
public repository it is the only one.

It reaches one person rather than a rota, which is worth knowing before you wait on a reply:
the acknowledgement target below assumes that person is not on leave. **If you have heard
nothing in five working days, send it again** rather than conclude it was received and
ignored — a single-person channel fails silently, and this is the failure it has.

Please **do not** make a security report public before there has been a chance to fix it —
not in an issue, a pull request, a discussion, a blog post, or a talk. On a project like this
one, a public report hands a working technique to everyone reading it before anybody running
it can patch.

Include, as far as you have it: what you did, what happened, what you expected, the version
or commit, and whether you believe it is remotely exploitable. A rough report is worth far
more than no report — do not sit on something because it is not written up.

**On GitHub private vulnerability reporting:** it is the better mechanism — a private thread,
and an advisory that publishes with the fix — and it is not offered here because there is no
public repository to offer it on. It will be named as the preferred route when there is one.
Pointing a reporter at a *Security* tab that does not exist is how a report gets abandoned
halfway, so this policy would rather say the plain thing and be usable.

## What we will do

| stage | target |
|---|---|
| Acknowledge your report | 3 working days |
| Initial assessment — severity, whether we can reproduce it | 10 working days |
| Fix or documented mitigation for critical and high severity | 30 days from confirmation |
| Public advisory | with the fix, or at 90 days, whichever is first |

We will tell you what we found, credit you in the advisory unless you would rather we did
not, and tell you if we disagree that it is a vulnerability — with reasons, not silence.

If a report is critical and we cannot fix it in 30 days, we will say so publicly with a
mitigation rather than let the deadline pass quietly.

## Scope

**In scope**

- The gateway (`oarlockd`) — SSH front door, the WebSocket surfaces, the control API.
- The agent and the agent library, including the reference Android binding.
- `pkg/frame`, `pkg/plugin`, and the published SDKs.
- The wire protocol itself: a design flaw is in scope, not only an implementation bug.
- Default configuration that is unsafe in a way the documentation does not warn about.

**Out of scope**

- Third-party plugins and forks we do not publish.
- Anything requiring a compromised gateway host. [The threat model](docs/threat-model.md#4-gateway-compromise-is-total)
  states plainly that the gateway is fully trusted; an attack that starts with code execution
  inside `oarlockd` is not a new finding.
- Missing hardening that the documentation already names as a known gap
  ([threat model § 12](docs/threat-model.md#12-what-is-actually-built)) — though a *working exploit* of
  one of those gaps is very much in scope and welcome.
- Denial of service through resource exhaustion that the documented limits are designed to
  bound, unless you can show the limits do not hold.

## Safe harbour

We will not pursue or support legal action against research that is a good-faith effort to
follow this policy: testing against your own deployment, avoiding privacy violations and
service degradation, and giving us a reasonable window before disclosure. If you are unsure
whether something is in bounds, ask by email first.

Do not test against somebody else's gateway or somebody else's devices. On this project that
means real hardware in real homes and gyms.

## Supported versions

| version | supported |
|---|---|
| `main` | yes — pre-release, no stability promise |
| tagged releases | **none yet** |

There has been no release. Once there is one, this table names the versions receiving
security fixes and for how long, and that window is a commitment rather than an intention.

## Supply chain

Per release, once releases exist:

- an **SBOM** (CycloneDX or SPDX) published as a release asset;
- **signed artefacts** with verifiable provenance;
- a changelog that marks security fixes as security fixes, so an operator scanning it can
  tell what they must take.

Dependencies are pinned. `golang.org/x/crypto` is held at **≥ 0.17.0 with strict key
exchange enabled and asserted in CI** — Terrapin (CVE-2023-48795) is a live attack class
against custom SSH servers, which is exactly what the gateway is.

## Regulatory note

The EU **Cyber Resilience Act** places incident and vulnerability reporting obligations on
manufacturers of products with digital elements from **11 September 2026**, and covers remote
data processing components essential to a product's core function. An Oarlock agent embedded
in a connected device sold in the EU is such a component.

**This policy does not discharge your obligations.** If you ship Oarlock inside a product,
you are the manufacturer, and the reporting duties are yours. What this project undertakes is
to make them possible to meet: a real disclosure channel, an SBOM, signed releases, published
advisories, and a documented support window.
