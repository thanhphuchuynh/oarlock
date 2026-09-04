# Scope — per-operator Unix identity

**Status: scoped, not built. Nothing here is implemented.**

The ask: two operators open a shell on the same device and land as different Unix users.
Today they cannot — the identity is chosen by *profile*, and every operator granted
`shell` gets the same one.

This document exists because the feature is small to build and easy to build wrongly. The
mechanism is roughly forty lines. The decision underneath it is the interesting part, and
it is not mine to make.

---

## 1. What exists today

The agent can already drop a session to a Unix identity. `agent/shell.go`:

```go
// Identity picks the OS identity for one session, by profile. Nil — or a nil
// return — inherits the agent's own identity.
Identity func(profile string) *Identity
```

Configured on the device, in the agent's own file:

```yaml
sessions:
  user: oarlock
  groups: [1007, 3003]
  per_profile:
    shell: oncall
    exec:  fieldservice
```

Checked at boot by `canDropTo` (`cmd/oarlock-agent/main.go`), so a user the agent cannot
drop to fails at startup rather than thirty seconds after an operator asks for a shell.

**The principal already reaches the device.** `frame.Invitation.Principal` is delivered
with every invitation and is already carried into `ShellRequest`, `ExecRequest`,
`DialRequest`, `FileRequest` and the log profile's request. No wire change is needed.

---

## 2. The invariant this feature changes

`pkg/frame/payload.go`, on `Invitation`:

> Principal is passed so the agent can log who is on it. It is not an authorisation
> input — the agent trusts the gateway completely and cannot check anything itself.
> **Do not gate on it.**

The same sentence appears on five more structs. This is a deliberate, repeated rule, and
per-operator identity is precisely the thing it forbids: it makes the principal select
what a session can touch.

Read carefully, the rule is not "the principal is untrusted" — the gateway is fully
trusted (threat model § 2). It is a division of powers, stated in `agent/shell.go`:

> The gateway can say who may open a shell; only the agent can say what that shell can
> touch.

Any design here has to say which side of that line it lands on, out loud, rather than
inheriting the ambiguity.

---

## 3. Three designs

### A. The gateway names the identity

`Invitation` grows `run_as: "oncall"`. The agent obeys.

**Reject.** A compromised or merely buggy gateway now selects the Unix identity on every
device in the fleet. It converts the gateway from "can open sessions the policy allows"
into "can be root anywhere", and it deletes the division of powers rather than adjusting
it. It is also the easiest design to build, which is why it is worth naming and refusing
in writing.

### B. The device maps principal → identity  *(recommended)*

The agent's config gains a mapping it owns:

```yaml
sessions:
  user: oarlock              # the default, unchanged
  per_profile:
    exec: fieldservice
  per_principal:             # new
    admin@mail.com: oncall
    contractor@partner.example.com: nobody
```

The hook widens from `Identity(profile)` to `Identity(profile, principal)`.

The principal becomes an *input to a device-local lookup*, not an authorisation decision.
The device's config remains the complete enumeration of every identity that device will
ever hand out; the gateway can only select among entries the device already wrote down.
The division of powers survives in substance: the gateway still cannot name an identity,
only a principal.

**What it costs, stated plainly.** Today a compromised gateway gets exactly one identity
per profile — whatever `sessions.user` says. Under B it gets to choose among the
configured set. The blast radius grows from one identity to N. That is a real weakening
and it belongs in the threat model, not in a footnote.

### C. Do nothing; express it with profiles

Grant different *profiles* to different people in the authorizer, and map profiles to
users on the device. `oncall` gets the `shell` profile, field service gets `exec`.

This already works and costs nothing. It is the right answer when the tiers are few and
correspond to kinds of work. It is the wrong answer when the tiers correspond to
*people* — you end up minting a profile per person, and profiles are a wire-visible,
policy-visible concept that was not meant to carry identity.

**Recommendation: B, with C documented as the answer for most deployments.**

---

## 4. The sharp edge

**Only `shell` and `exec` fork a process. `file`, `tcp` and `log` run inside the agent.**

Verified: `Credential` is set in `agent/shell.go` and `agent/exec.go` and nowhere else;
`agent/file.go`, `agent/tcp.go` and `agent/log.go` contain no `exec.Command` at all.

So an operator mapped to a restricted user gets a restricted *shell* — and then reads any
file the agent can reach through `file:read`, opens any allow-listed loopback port through
`tcp`, and tails any published source through `log`, all as the agent's own identity.

This is the failure mode that makes the feature dangerous to ship quietly: it looks like
containment and is not. An operator confined to `nobody` in a shell who can `file:read`
`/data/secrets` as root has been given a false sense of a boundary, which is worse than no
boundary at all, because somebody will grant on the strength of it.

Two honest resolutions, and the choice is a product decision:

1. **Scope the feature to `shell` and `exec`, and refuse to start** when a principal has a
   per-principal identity *and* holds a grant for `file`, `tcp` or `log` on that device.
   The agent cannot see grants, so this check belongs on the gateway's boot gate or in the
   authorizer — which means the feature is not purely device-side after all.
2. **Give the in-process profiles a real identity** by moving each behind a forked helper.
   Larger, and it changes `file`'s `os.Root` confinement story, which is currently one of
   the better-tested things in the codebase.

Shipping (1) without the check is the outcome to avoid.

---

## 5. Also in scope

- **Audit.** The session row records the principal. It must also record the *effective*
  uid/user, or the trail says "admin opened a shell" without saying "as root". One column,
  one field in the audit event, one column in the console's session detail.
- **The operator should be told.** The gateway's banner already says the session is
  recorded. Adding the user it is running as is cheap and prevents the "I thought I was
  root" class of confusion. It also has to survive `safeText`.
- **Boot validation.** `canDropTo` already checks configured users at startup; it grows to
  cover the per-principal set. A mapping to a user that does not exist must fail at boot.
- **The unmapped principal.** Falls through to `per_profile`, then `user`, then inherit.
  Refusing an unmapped principal is safer but breaks every existing operator the moment
  the map is added, so it should be opt-in — `sessions.require_mapping: true`.
- **Mode A passthrough is out of scope** and needs nothing: `sshpass` hands the connection
  to the device's own `sshd`, which does its own user authentication. It is already
  per-user by construction.
- **Principal matching is exact, not patterned.** The config-declared administrators list
  refuses patterns at boot for the same reason: a wildcard in an identity mapping is a
  wildcard granting a Unix user, and a typo in a glob is not a thing you want between an
  operator and root.

---

## 6. Work breakdown

Assuming design B, scoped to `shell` and `exec`:

| # | work | size |
|---|---|---|
| 1 | `Identity(profile, principal)` — widen the hook, update both call sites | small |
| 2 | `sessions.per_principal` in the agent config, exact ids only | small |
| 3 | `canDropTo` over the per-principal set; boot fails on an unknown user | small |
| 4 | Record the effective identity: session row, audit event, console detail | medium |
| 5 | Name the identity in the operator's banner | small |
| 6 | The § 4 guard — refuse the combination that is a false boundary | **medium, and it crosses into the gateway** |
| 7 | Threat model rows: the widened blast radius, and the in-process profiles | small |
| 8 | Tests: mapping resolution, fallback order, boot refusal, and a negative control that the gateway cannot name an identity directly | medium |

Items 1–3 and 5 are perhaps a day. Item 6 is the one that decides whether this is a
day or a week, because it is the item that keeps the feature honest.

---

## 7. What a human has to decide

1. **Design B or C?** If the tiers are kinds of work rather than people, C already ships.
2. **Is the widened blast radius acceptable?** A compromised gateway choosing among N
   device-configured identities instead of one.
3. **Which resolution for § 4** — scope to the forking profiles plus a guard, or fork the
   in-process ones too?
4. **Does an unmapped principal fall back or get refused?** Fallback is compatible;
   refusal is safe. Default fallback, make refusal a setting.

Until 1 and 3 are answered, nothing here should be built.
