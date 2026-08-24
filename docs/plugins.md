# Plugins

Every integration point in Oarlock is a Go interface in `pkg/plugin` with a working
default. Two rules shape all of them:

1. **`go run` needs nothing.** Clone, build, run — no database, no broker, no identity
   provider. Every default is in-process or a file on disk.
2. **Scale must not need a fork.** Nothing that talks to the outside world is reached
   except through one of these interfaces, so replacing it is a config line and an import,
   never a patch.

---

## 1. How a plugin is wired

**Not** via Go's `plugin` package. It requires an exact toolchain and dependency-version
match between host and plugin, does not work on every platform Oarlock targets, and cannot
be unloaded. The cure is worse than the disease.

Instead: a registry, populated by `init()`, selected by name in config.

```go
// plugins/oidc/oidc.go
package oidc

import "github.com/oarlock/oarlock/pkg/plugin"

func init() {
    plugin.RegisterAuthenticator("oidc", New)
}

func New(cfg plugin.Config) (plugin.Authenticator, error) { /* … */ }
```

```yaml
# oarlock.yaml
authenticator:
  kind: oidc
  issuer: https://id.example.com
  audience: oarlock
```

Built-ins under `plugins/` are imported by `cmd/oarlockd`. **For something out of tree,
you write your own `main`** — twelve lines, and it is the supported path, not a workaround:

```go
package main

import (
    "github.com/oarlock/oarlock/cmd/oarlockd/app"
    _ "example.com/our-stack/oarlock-dispatcher"
    _ "example.com/our-stack/oarlock-casdoor"   // yours
)

func main() { app.Main() }
```

You get a single static binary with your integrations in it, your own release cadence, and
no ABI to keep in step. `pkg/plugin` is versioned as public API; the rest of the tree is
not.

### 1.1 Rules every plugin obeys

- **Take a `context.Context` and honour it.** The gateway sets deadlines and cancels; a
  plugin that ignores cancellation holds a session open after the operator has gone.
- **Be safe for concurrent use.** One instance serves every session.
- **Do not block the pump.** Anything on the per-frame path must return in microseconds.
  `Recorder` writes are the only per-byte call, and they are expected to buffer internally
  and flush on their own schedule.
- **Fail closed, but distinguish a denial from an outage.** Returning
  `Decision{Allow:false}` is a decision, and it closes the session as `revoked`. Returning
  an `error` means *you could not decide*: new sessions are refused immediately, live ones
  get `authz.grace` re-checks before closing as `authz_unavailable`. Never return
  `Allow:false` to signal that your backend is down — that writes a lie into the audit
  trail. `Recorder` errors are absorbed by the spool until it is exhausted. An `AuditSink`
  error is logged and swallowed, because audit must never be the thing that breaks a shell —
  that turns the audit trail into a denial-of-service lever.
- **Expose metrics through the passed registry.** Every plugin gets a
  `prometheus.Registerer`; a plugin whose latency you cannot see is a plugin you cannot
  operate.

## 2. `Authenticator` — who is this operator

```go
type Authenticator interface {
    // AuthPublicKey is called during SSH publickey auth. Returning a nil error
    // accepts the key and binds the connection to the returned principal.
    AuthPublicKey(ctx context.Context, user string, key ssh.PublicKey) (*Principal, error)

    // AuthDelegated verifies that `service` may act for the subject named in a signed
    // assertion, and returns the SUBJECT's principal. The assertion is a token the
    // subject's own login produced — never a bare identifier in a header. Returning
    // ErrUnsupported disables delegated access, which refuses every On-Behalf-Of call.
    AuthDelegated(ctx context.Context, service *Principal, assertion string) (*Principal, error)

    // AuthInteractive backs keyboard-interactive: an OIDC device-code flow, a TOTP
    // prompt, anything conversational. Nil means "not supported by this backend".
    AuthInteractive(ctx context.Context, user string, c Challenger) (*Principal, error)

    // AuthHTTP authenticates the browser and API surface: a session cookie, a bearer
    // token, an OIDC id_token.
    AuthHTTP(ctx context.Context, r *http.Request) (*Principal, error)
}

type Principal struct {
    ID     string            // stable, unique, and what gets recorded — never the SSH user
    Email  string
    Groups []string
    Attrs  map[string]string // opaque, passed to Authorizer
    Expiry time.Time         // zero means "no expiry known"; drives the re-check floor
}
```

The SSH *user* is the **device id**, not the operator: `ssh treadmill-4821@gw`. The
operator's identity comes from their key or their token. This is the one piece of SSH
convention Oarlock breaks, and it earns it — an operator connects to a fleet of thousands
of devices with one set of credentials, so the addressable thing in the connection string
has to be the device.

`Expiry` is worth setting. It puts a ceiling on how long a session can outlive the
credential that opened it, independent of the re-check interval.

| built-in | notes |
|---|---|
| `authorized_keys` (default) | one file, `oarlock` extension comments carry the principal id. Fine for a handful of operators; revocation means editing a file on every replica. |
| `oidc` | device-code flow over keyboard-interactive for CLI, standard code flow for the browser. The one most people should use. |
| `sshca` | trust one CA, accept short-lived user certificates, read the principal from the cert. No per-operator state on the gateway at all, and expiry is enforced by the protocol. |
| `static` | tokens in config. For tests and CI. Refuses to start if `env != dev`. |

**`sshca` is the recommendation at any real size.** One key to trust, certificates that
expire on their own, and revocation becomes "stop issuing" rather than a push to every
replica. It is the one idea worth importing from the mode-A world without importing mode A.

### 2.1 Gateway SSH host key

`ssh.host_key` is the gateway's SSH identity, not an operator credential and not a
recording-signing key. Every replica behind the same operator-facing name must load the
same private host key, or operators will see a host-key-mismatch warning whenever a load
balancer moves them. That trains people to ignore the one SSH warning that matters.

Generate it once, put the private key in a secret store, and mount the same bytes at
`ssh.host_key` on every replica:

```bash
ssh-keygen -t ed25519 -N "" -f oarlock_host_ed25519 -C oarlock-gateway
ssh-keygen -y -f oarlock_host_ed25519 > oarlock_host_ed25519.pub
```

`ssh.generate_host_key: true` is for development only. The boot gate refuses a generated
host key in production, and startup logs only the path, never the private key material.

Rotation is an operator trust event, so do it like an SSH host-key rotation rather than a
silent deploy:

1. Generate the replacement key and publish its public half through the same channel your
   operators use for known-hosts material.
2. Deploy the replacement private key to every replica while the old key is still the one
   operators know.
3. Drain replicas and restart them as one change window, so all replicas present the same
   new key.
4. Remove the old public key from managed `known_hosts` after the window.

Do not reuse the recording signing key here. The SSH host key is presented to every SSH
client; the recording key attests to archived bytes. Rotating one must not force rotating
the other.

### 2.1 The `oidc` backend

The one that makes production possible. Both surfaces, one identity:

| surface | mechanism |
|---|---|
| API and browser | a bearer JWT, verified offline against the provider's published keys |
| SSH | the device authorization grant (RFC 8628) over keyboard-interactive |

```yaml
auth:
  kind: oidc
  issuer: https://accounts.example.com
  client_id: oarlock-gateway
  scopes: [email, groups]
  subject_claim: email      # what becomes the principal id
  groups_claim: groups
```

**SSH with no key and no password.** The gateway prints a URL and a short code; the
operator approves in a browser that already holds their session and whatever second factor
the provider enforces. The gateway never sees a password and cannot weaken the MFA, and no
key material lands on a laptop. Offered only when the backend implements the optional
`plugin.InteractiveAuthenticator`, so a key-only deployment does not advertise a method it
cannot answer.

**The principal id is a policy decision, not a default.** `subject_claim` defaults to
`email` because the authorisation language is globs over principal ids and people write
`*@oncall.example.com`, not a list of opaque uuids. The cost is that email is mutable at
the provider — so a token whose `email_verified` is false is refused outright, since an
unverified email is a name its owner chose rather than an identity anyone vouches for. Set
`subject_claim: sub` where immutability matters more than legibility; `sub` and `iss` are
kept in `Principal.Attrs` either way.

**Only asymmetric algorithms, ever.** `RS256/384/512` and `ES256/384/512`. There is no
shared secret between a gateway and a provider that could make an HMAC meaningful, so
accepting `HS*` would only ever be the algorithm-confusion attack succeeding — and the
verification routine is chosen from the *key's* type, never from the token header, so a
header claiming one thing over a key of another gets nowhere.

**Key rotation and key revocation are different problems**, and both are handled:

- A token naming a key we have not got triggers one refetch, rate-limited to once every
  thirty seconds so a flood of invented `kid`s cannot become a flood of requests aimed at
  the provider. A rotation is therefore picked up within seconds.
- The cached set is refetched once it is older than `jwks_refresh` (default five minutes),
  whether or not anything is missing. **This is the bound on how long a key the provider
  has withdrawn keeps verifying tokens** — without it a retired key works for as long as
  the process lives. If the provider is unreachable the stale set is served rather than
  refusing every login, and that is logged loudly, because a key retired during the outage
  keeps working until it ends.

**Opaque access tokens are refused.** Send the `id_token`. Verifying an opaque token means
calling `userinfo`, which turns every API request into a second round trip and makes the
provider's availability a dependency of every list of sessions.

**The browser login** is mounted at `/auth/*` when `auth.redirect_url` is set:

```yaml
auth:
  kind: oidc
  issuer: https://accounts.example.com
  client_id: oarlock-gateway
  redirect_url: https://gw.example.com/auth/callback   # registered with the provider
```

Authorization code with PKCE (S256 only — `plain` makes the challenge equal the verifier,
which protects against nobody who can read the request). `state` and PKCE are both present
and do different jobs: PKCE stops a stolen code being spent, `state` stops an attacker
starting a flow and having somebody else's browser finish it.

`redirect_url` is required rather than derived from the request's `Host`. A provider
matches it byte for byte, and deriving it from a header would let a proxy — or anyone who
can set one — choose where an authorization code is delivered. It must be `https` outside
loopback.

**No session cookie.** The obvious design is a cookie the API accepts, and that is also how
an API acquires a CSRF surface. Instead the callback sets a one-hop cookie, the console
exchanges it once at `/auth/token` for the provider's own `id_token`, and the cookie is
cleared in the same response. From then on the console sends a bearer header like any other
client and the API has no cookie path at all. The token is the provider's, not one this
gateway minted: a self-signed token would be a second credential system to rotate, revoke
and get wrong.

**`return_to` accepts only a path on this origin**, matched against an allow-list of
characters rather than parsed. `url.Parse` reports no host for `/\evil.example.com`, and a
browser normalises that backslash to a slash — so a parser-based check hands you an open
redirect on the one endpoint every operator visits.

**Static tokens alongside OIDC are refused at boot.** A long-lived shared secret next to a
real identity provider is just the easier way in. A key file alongside is *allowed* — for a
break-glass account, or automation that cannot do a browser flow — but it warns, because
revoking that operator then means editing a file on every replica as well.

## 3. `Authorizer` — may they, on this device, right now

```go
type Authorizer interface {
    Authorize(ctx context.Context, p *Principal, dev *Device, a Action) (Decision, error)

    // Watch streams revocations as they happen. Returning ErrUnsupported is fine —
    // the gateway falls back to polling Authorize on recheck_interval.
    Watch(ctx context.Context) (<-chan RevocationEvent, error)
}

type Action string // shell, exec, file:read, file:write, tcp, passthrough, replay, observe

type Decision struct {
    Allow  bool
    Reason string        // shown to the operator on a deny; make it actionable
    Limits *Limits       // optional per-grant override, only ever more restrictive
    TTL    time.Duration // re-check sooner than the default for this grant
}

type RevocationEvent struct {
    PrincipalID string // "" means every principal
    DeviceID    string // "" means every device
    Reason      string
}
```

This is the interface that justifies the whole architecture, so it gets called more than
once per session:

**`plugintest` enforces this table**, and its most important case is the last column: a
backend that answers `Allow: false` when its own dependency is down fails the suite. See
§ 11.1.

| when | on a deny | on an *error* |
|---|---|---|
| at open | `403`, no session row, `not_authorized` | `503`, no session row, `authz_unavailable` |
| every `recheck_interval` (default 30 s) | closed, `revoked` | grace window, then `authz_unavailable` |
| on a `RevocationEvent` | closed, `revoked`, typically <1 s | n/a — a dropped stream is not a denial |
| `DELETE /api/sessions/{id}` | closed, `admin_kill` | n/a |

**`Limits` may only tighten.** A grant that widened a limit would let an authorisation
backend raise the ceilings the gateway operator set, which inverts who is in charge. The
gateway takes the minimum of the two, always.

`Watch` reconnects with backoff if the stream drops, and **a broken `Watch` is not a
security failure** — the re-check interval is the guarantee and `Watch` is the
optimisation. Design your backend so that being disconnected for a minute costs you a
minute of staleness, not a missed revocation.

Two things follow, and `plugintest` checks both. **Close the channel when the context
ends**, or the gateway leaks a watcher goroutine per reconnect. And **never close it to
mean "everything is revoked"** — the gateway treats a close as "reconnect", because a
stream that dies must not be able to kill a fleet. Say that with a `RevocationEvent`
naming neither a principal nor a device, which is the explicit way to state it.

| built-in | notes |
|---|---|
| `rules` (default) | `principal → device selector → actions` in YAML, reloaded on file change. Selectors match on device id, tags, or glob; a `deny: true` rule beats every allow. **Never returns an error** — its source of truth is a file already in memory, so there is no outage in which it starts denying people, and a file that fails to reload leaves the previous rules in place. |
| `sqlite` | Durable permissions in the operational database, managed through `/api/v1/permissions` and the admin UI. Supports principal/device globs, exact device tags, actions, deny precedence and grant limits. A database failure is reported as `authz_unavailable`, never as a denial. |
| `webhook` | `POST` per decision with a short cache TTL, plus an SSE endpoint for `Watch`. The escape hatch for anything: Casdoor, OPA, a permission table in your own database. |

### 3.1 SQLite permissions

```yaml
store:
  kind: sqlite
  path: ./oarlock.db

authorizer:
  kind: sqlite
  recheck_interval: 30s
```

The backend creates `oarlock_permissions` on first boot. Permission selectors and actions
are stored as JSON columns so one permission is replaced atomically; public policy data is
also available in the curated SQL Explorer snapshot. Private operator and device keys are
not stored in this table.

**`Watch` is unsupported here**, so revocation lands on the re-check interval rather than
within the second. ADR-029 makes the interval the guarantee and `Watch` the optimisation,
so this is a supported configuration — but a permission disabled in the admin UI does not
close a live session immediately. Kill the session if you need it gone now.

### 3.1.1 Administering the policy

The admin API is authorised by the policy it edits, which needs saying out loud because the
first version of it was not. Three actions govern the surface:

| action | checked against | governs |
|---|---|---|
| `admin:devices` | the device being changed, as **stored** | `POST`/`PUT`/`DELETE /api/v1/devices` |
| `admin:permissions` | the synthetic `gateway` device | all of `/api/v1/permissions`, reads included |
| `admin:kill` | the session's or agent's device | `DELETE /api/v1/sessions/{id}` for somebody else's session, `DELETE /api/v1/agents/{id}` |

```yaml
# A fleet lead who runs the treadmills and cannot touch policy.
- principals: ["lead@example.com"]
  devices: ["treadmill-*"]
  actions: ["admin:devices", "admin:kill"]

# Access management, which is a different job.
- principals: ["security@example.com"]
  devices: ["gateway"]
  actions: ["admin:permissions"]
```

`GET /api/v1/devices/{id}/access` answers the other direction — which rules are written
about one device, denials first. It exists because a flat rule list cannot answer "who can
reach this thing": that needs glob-and-tag matching, and the one place it must not be
re-implemented is a browser one hop from the backend that owns it. `plugin.Permission`'s
`AppliesTo`, `MatchesPrincipal` and `Grants` are the shared predicates, so the admin view
and the decision cannot disagree about what a rule means.

Notes worth having before you write these:

- **Reading the policy needs `admin:permissions`.** A list of who may reach what is a map
  of whom to phish, so `GET` is gated with the writes.
- **`admin:devices` is checked against the stored record**, so a `tags:` deny reaches the
  admin surface. On *create* there is no stored record yet, so a caller who may create
  devices can create one whose tags a deny would have matched. Scope create-capable grants
  accordingly.
- **Ending your own session needs nothing.** `admin:kill` is about ending somebody else's.
- **Neither implies the other, and neither implies a session.** `admin:devices` on `*` does
  not get you a shell.

### 3.1.2 `authorizer.admins`: the break-glass

```yaml
authorizer:
  kind: sqlite
  admins:
    - root@example.com
```

An empty policy store has nobody who may write the first rule, and deleting the last
`admin:permissions` grant locks the room. This field names principals — exact ids, patterns
are refused at boot — who are allowed the administrative actions regardless of what the
backend answers, so whoever owns the config file can always get back in. It is logged at
boot and on every use.

**It grants `admin:*` and nothing else.** A config administrator may repair the policy; to
open a shell, watch a session or query the database they must write themselves a grant,
which is a visible row and an audit line rather than a line in a file nobody re-reads.

**It does outrank a deny on the administrative actions.** That is deliberate: anyone who
can edit this file can also edit the rules file, repoint the database or restart with a
different backend, so a deny row cannot meaningfully constrain them, and pretending
otherwise would only cost the recovery the field exists for. It does not reach a session
action, so `deny`-beats-`allow` holds for everything an operator does on a device.

Every administrative request emits `admin.change`, refusals included, and a policy write
records what the rule granted — principals, devices, actions, effect — rather than just its
id, because the row it names may since have been edited away.

### 3.2 The `rules` file

```yaml
rules:
  # Everyone on call gets a shell on the treadmills.
  - principals: ["*@oncall.example.com"]
    devices: ["treadmill-*"]
    actions: ["shell", "exec"]

  # A contractor, on a leash: fifteen minutes, and re-checked every ten seconds.
  - principals: ["contractor@partner.example.com"]
    devices: ["treadmill-4821"]
    actions: ["shell"]
    max_duration: 15m
    idle: 2m
    ttl: 10s

  # Auditors read recordings and watch live sessions. They never get a keyboard.
  - principals: ["auditor@example.com"]
    actions: ["replay", "observe"]

  # A carve-out. A matching deny beats every allow, wherever it appears in the file,
  # so this cannot be defeated by rule ordering somebody else controls.
  - principals: ["*"]
    tags: {scope: "pci"}
    actions: ["*"]
    deny: true
    reason: "PCI-scoped devices need a change ticket"
```

- **`actions` is never defaulted.** An empty list is refused at load: it is far more
  likely to be an unfinished rule than an intent to grant the fleet. Write
  `actions: ["*"]` if you mean every action.
- **Every listed tag must match.** A rule scoped to PCI *and* the EU does not grant on a
  device that is only one of them.
- **`max_duration`, `idle` and `ttl` only tighten**, like every per-grant limit: the
  gateway takes the minimum of its own ceiling and the grant's.
- **A file that fails to load changes nothing.** A syntax error, or a deleted file, leaves
  the rules already in memory in place and logs loudly. Dropping to no rules would deny
  everybody instantly because of a typo — and it would look exactly like a mass revocation
  to every operator it hit.
- **Unknown keys are refused.** A typo in a key name must not silently mean "default".

### 3.3 The `webhook` authorizer

Use `webhook` when the source of truth lives somewhere else: OPA, Casdoor, an internal
permission table, or a service that already understands on-call state.

```yaml
authorizer:
  kind: webhook
  url: https://permissions.example.com/oarlock/authorize
  watch_url: https://permissions.example.com/oarlock/revocations
  token: ${OARLOCK_AUTHZ_TOKEN}
  timeout: 2s
  cache_ttl: 5s
  recheck_interval: 30s
```

`cache_ttl` must be shorter than `recheck_interval`. The re-check interval is the promise
that a withdrawn grant goes stale for no longer than that window; a cache that outlived it
would make the promise untrue, so the boot check refuses it.

The decision endpoint receives:

```json
{
  "principal": {
    "id": "phuc@example.com",
    "email": "phuc@example.com",
    "groups": ["on-call"],
    "attrs": {"jurisdiction": "EU"}
  },
  "device": {
    "id": "treadmill-4821",
    "platform": "android",
    "mode": "",
    "resolved_mode": "dispatch",
    "tags": {"scope": "pci"},
    "profiles": ["shell"]
  },
  "action": "shell"
}
```

Return `2xx` with a decision:

```json
{
  "allow": true,
  "limits": {"max_duration": "15m", "idle": "2m", "rate": 262144},
  "ttl": "5s"
}
```

A denial is still a decision: return `2xx` with `"allow": false` and an actionable
`reason`, or return `403` with the same JSON body. Other non-2xx responses, malformed JSON
and transport errors are **unavailable**, not denied; the gateway reports
`authz_unavailable` and applies the grace-window contract from § 3.

`watch_url` is optional. When set, it is a server-sent event stream whose `data:` payload is
a JSON `RevocationEvent`:

```text
data: {"principal_id":"phuc@example.com","device_id":"treadmill-4821","reason":"left on-call"}
```

An empty `principal_id` or `device_id` means every principal or every device. Closing the
stream is not a revocation; the gateway reconnects and the re-check interval remains the
guarantee.

## 4. `Recorder` — the artefact

**A backend implements `Store`, not `RecordingWriter`.** The first cut made the whole
recorder pluggable — a backend received `Output`/`Input`/`Resize` and encoded asciicast
itself — and building the spool showed that to be the wrong seam, for three reasons:

1. The spool must buffer exactly the bytes destined for storage, so it has to sit *below*
   the encoder. Above it, a retry would mean re-encoding, and the hash chain would have to
   be recomputed — so a retry could change a recording's identity.
2. A spooled fragment dumped to disk is then a valid *slice* of a .cast file, recoverable by
   appending it at a known byte offset. Buffered events are not.
3. It is far less for a third-party backend to implement, and it removes the possibility of
   a backend encoding asciicast subtly wrongly — which would produce recordings that verify
   but do not play.

So the encoder, the chain and the manifest are Oarlock's, and a backend answers one
question: where do these bytes go.

```go
// Store is the pluggable seam.
type Store interface {
    Create(ctx context.Context, m *SessionMeta) (io.WriteCloser, error)
    PutManifest(ctx context.Context, sessionID string, b []byte) error
    Get(ctx context.Context, sessionID string) (io.ReadCloser, error)
    GetManifest(ctx context.Context, sessionID string) ([]byte, error)
    // URL returns a time-limited direct link if the backend can issue one,
    // so replay does not stream through the gateway. ErrUnsupported otherwise.
    URL(ctx context.Context, sessionID string, ttl time.Duration) (string, error)
}

// Recorder is the gateway-facing interface, which Oarlock implements over a Store.
type Recorder interface {
    // Open is called before the operator sees a prompt. An error here fails the session.
    Open(ctx context.Context, m *SessionMeta) (RecordingWriter, error)
    Get(ctx context.Context, sessionID string) (io.ReadCloser, error)
    URL(ctx context.Context, sessionID string, ttl time.Duration) (string, error)
}

// The gateway puts a bounded spool in front of these calls (ARCHITECTURE § 8.1), so a
// backend failing for thirty seconds is invisible to the operator. Return errors honestly
// and let the spool absorb them — retrying internally forever hides the failure from the
// mechanism built to handle it.
type RecordingWriter interface {
    // Output is on the per-byte path. Buffer; do not do I/O per call.
    Output(at time.Duration, b []byte) error
    Input(at time.Duration, b []byte) error   // only if record_input is on
    Resize(at time.Duration, cols, rows int) error
    // Close writes the sidecar. It runs even when the session died badly.
    Close(ctx context.Context, r Result) error
}
```

Output is [asciicast v2](https://docs.asciinema.org/manual/asciicast/v2/): a JSON header
line, then one `[time, "o", data]` line per chunk. **Stream it, do not buffer it.** A
gateway killed mid-session must still leave a playable file, and an asciicast truncated at
any line boundary plays perfectly up to that point.

`Close` writes a sidecar with the exit code, `close_reason`, principal, device, byte
counts and duration — so a recording is self-describing even if it is copied away from the
store that indexed it.

| built-in | notes |
|---|---|
| `file` (default) | `./recordings/YYYY-MM-DD/{session_id}.cast` + `.json`. `fsync` on close, and the manifest is written to a temp file then renamed, so a reader never sees half of one. |
| `s3`, `gcs` | multipart streaming upload, part per ~5 MiB, finalised on close. `URL` issues a signed link. See § 4.2 before pointing one at a bucket. |
| `none` | records nothing, and **logs a warning at every session open**. Chosen unrecorded is a legitimate configuration; quietly unrecorded is not. |

### 4.2 Storage immutability, and why the chain is not enough

The hash chain and the signed manifest make tampering **detectable**. Only storage
makes it **impossible**, and the two are not substitutes: detection tells you
afterwards, and afterwards is when somebody is already asking why the recording
disagrees with the incident report.

A store reports what it can enforce, through an optional interface:

```go
type ImmutabilityReporter interface {
    Immutability(ctx context.Context) (Immutability, error)
}
```

| mode | what it means | what it survives |
|---|---|---|
| `unknown` | the store does not implement the interface | nothing — **silence is not a guarantee**, so this is treated as mutable |
| `mutable` | anything with write access can alter or delete a recording | nothing |
| `declared` | an operator says the storage is protected and the gateway cannot verify it | whatever the operator actually did |
| `governance` | an object lock that sufficiently privileged users can lift | an accident, and a compromised writer |
| `compliance` | a lock nobody can lift until retention expires, including the account owner | a compromised administrator |

**Whatever it reports is written into the manifest and signed.** That is the point:
the chain proves the bytes have not changed, and this records what stood between them
and a change. An auditor reading a recording two years from now should not have to
guess whether the bucket had object lock enabled in 2026 — and because the field is
inside the signed bytes, the claim cannot be upgraded after the fact.

#### Configuring it

**S3.** Object Lock must be enabled **at bucket creation** — it cannot be turned on
afterwards, which is the single most common way this gets missed. Then set a default
retention:

```
aws s3api create-bucket --bucket oarlock-recordings --object-lock-enabled-for-bucket
aws s3api put-object-lock-configuration --bucket oarlock-recordings   --object-lock-configuration '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Days":365}}}'
```

`COMPLIANCE` cannot be shortened or lifted by anyone, including the root account.
`GOVERNANCE` can be lifted with `s3:BypassGovernanceRetention`, which is the right
choice only if you have a real need to delete recordings early — and if you do, the
people holding that permission are now part of your audit story.

**GCS.** A bucket-level retention policy, then **lock it** — an unlocked policy can be
shortened or removed, which makes it a preference rather than a control:

```
gcloud storage buckets update gs://oarlock-recordings --retention-period=365d
gcloud storage buckets update gs://oarlock-recordings --lock-retention-period
```

Locking is irreversible. That is the feature.

**Both.** Retention interacts with the spool
([ARCHITECTURE § 8.1](../ARCHITECTURE.md#81-what-happens-when-the-recorder-fails)): a
dumped fragment recovered later has to be written as a *new* object, because the
original is immutable by design. Name it after the fragment's offset and keep it
beside the original rather than trying to append.

**The keys.** Immutable storage does not help if the signing key lives in the same
account: whoever can rewrite the manifest can re-sign it. Keep the recording signing
key somewhere the recording store cannot reach — a KMS, an HSM, a different account.
`Signer` is a `crypto.Signer`, so that costs configuration and not code.

### 4.3 `record_input` is off by default

Keystroke capture records whatever an operator types into a `sudo` or `mysql -p` prompt.
Echo is suppressed on the *device*, so the gateway sees the characters regardless of what
the screen shows. Turn it on and your recordings are a credential store that must be
encrypted, access-controlled and retention-bounded like one.

Output-only recording still shows every command, because the shell echoes it. You lose
keystroke timing and typo history; you gain not having built a secrets file by accident.

`record_input` is resolved per session from `policy.record_input`, matching both the
operator and the device:

```yaml
policy:
  record_input:
    default: false
    rules:
      - name: pci capture
        when:
          device_tags: {pci_scope: "true"}
        value: true
      - authority: employment-law
        when:
          principal_groups: ["eu-*"]
        value: false
```

Selectors can match `principals`, `principal_groups`, `principal_attrs`, `devices`, and
`device_tags`. Principal and device entries are globs; attribute and tag selectors are
exact key/value matches. A conflict between matching rules refuses the open as
`policy_conflict` and names both rules. That is deliberate: silently choosing either value
would silently violate one of the regimes the rules were written to satisfy.

## 5. `AuditSink` — what happened

```go
type AuditSink interface {
    Emit(ctx context.Context, e AuditEvent)
}
```

`Emit` cannot fail by contract. Audit must never become the thing that breaks a shell, so
the built-in sink is an async bounded queue. When the queue is full, events are dropped and
the drop counter is incremented and logged; silent audit loss is the failure this avoids.

The default sink writes JSON lines to stderr:

```yaml
audit:
  kind: stderr   # stderr | none
  buffer: 1024
```

Current event kinds include `session.opened`, `session.closed`, `session.rejected`,
`api.error`, and `observe.issued`. A `policy_conflict` API error carries the conflict text
that names both matching rules.

## 6. `SessionStore` — the ledger

```go
type SessionStore interface {
    Create(ctx context.Context, s *Session) error   // enforces the concurrency caps
    Update(ctx context.Context, id string, f func(*Session) error) error
    Close(ctx context.Context, id string, reason CloseReason, res Result) error
    Get(ctx context.Context, id string) (*Session, error)
    List(ctx context.Context, q Query) ([]*Session, string, error) // cursor-paginated
}
```

`Create` is where `sessions_per_device` and `sessions_per_principal` are enforced, and it
must be **atomic** — a unique index or a transaction, not a read-then-write. Two operators
opening a shell on the same device in the same second is exactly the race this exists to
lose gracefully, and "we checked and it was fine" is not an enforcement mechanism.

| built-in | notes |
|---|---|
| `memory` (default) | single node; sessions are lost on restart, which is honest rather than surprising. |
| `sqlite` | one file, survives restarts, plenty for one gateway. |
| `postgres` | multi-node, partial unique index for the per-device cap. |

## 7. `DeviceRegistry` — what the gateway knows about a device

```go
type DeviceRegistry interface {
    Get(ctx context.Context, id string) (*Device, error)
    List(ctx context.Context, q DeviceQuery) ([]*Device, string, error)
}

type Device struct {
    ID               string
    Platform         Platform             // android | linux | container | other
    Disabled         bool                 // revoke access without deleting history
    Mode             Mode                 // persistent | dispatch | "" = resolve from Platform
    Keys             []ed25519.PublicKey  // control-channel identity; a list, so keys rotate
    RetiredKeys      []ed25519.PublicKey  // old identities that must no longer authenticate
    AllowPassthrough bool                 // mode A, per device, default false
    Tags             map[string]string    // what Authorizer and policy selectors match on
    Profiles         []string             // what this device may be asked to do
}
```

**`Keys` are Ed25519, not SSH keys.** A device's identity key signs a challenge on
the control channel; it is not an SSH key and never appears in an SSH handshake.
Typing it as `ssh.PublicKey` would pull an SSH library into the device-identity
layer for nothing. The registry file still accepts the `ssh-ed25519 AAAA…` form
because that is what `ssh-keygen -t ed25519` produces, and requiring a bespoke
encoding for no reason is how a config file becomes something only a script can
write.

Rotation is publish-then-retire:

```yaml
devices:
  - id: treadmill-4821
    platform: linux
    keys:
      - "<old public key>"
      - "<new public key>"

# after the device has rolled:
devices:
  - id: treadmill-4821
    platform: linux
    keys:
      - "<new public key>"
    retired_keys:
      - "<old public key>"
```

A key cannot appear in both lists. A retired key that signs a control-channel handshake is
rejected with the same `auth_failed` response as any other authentication failure; the
specific reason is logged server-side, not sent to the unauthenticated peer.

The registry contract starts read-only: Oarlock can read from whatever already owns the
fleet. A backend may also implement `DeviceRegistryAdmin` to create, update and delete
devices through the admin API/UI. The default `file` backend remains a YAML list, which is
enough for a lab and intentionally not rewritten by the gateway; the built-in `sqlite`
backend stores editable devices in the operational DB with `oarlock_` table prefixes.

Disabling a device is an operational revocation: the gateway stops its connected agent,
rejects new control-channel handshakes, and refuses new SSH or browser sessions. The registry
row and all existing session history remain available. Re-enabling allows the device to
authenticate and reconnect again.

```yaml
store:
  kind: sqlite
  path: ./oarlock.db

devices:
  kind: sqlite
```

**`Platform` exists to pick the reachability default**, and it earns its place because the
right default differs by platform rather than by deployment: `android` resolves to
`dispatch`, because the platform resists held connections; `linux` and `container` resolve to
`persistent`, because nothing there objects and it needs no doorbell. An explicit `Mode`
always wins. The resolved value is logged at registration, so a surprising default is visible
once rather than never.

**`Tags` do double duty** — `Authorizer` selectors and `record_input` policy selectors both
match on them ([ARCHITECTURE § 8.2](../ARCHITECTURE.md#82-record_input-is-a-policy-not-a-preference)).
That is deliberate: compliance scope and jurisdiction get expressed through a mechanism that
already exists, and no tenancy concept has to be invented to carry them.

## 8. `AgentAuthenticator` — is this really that device

```go
type AgentAuthenticator interface {
    // Persistent mode: verify the challenge-response from protocol §3.1.
    VerifyDeviceKey(ctx context.Context, deviceID string, nonces Nonces, sig []byte) error
    // Dispatch mode: redeem a one-time ticket, atomically.
    RedeemTicket(ctx context.Context, ticket string) (*TicketClaims, error)
}
```

`RedeemTicket` **must be atomic** — a compare-and-delete, not a read then a delete. A
ticket that can be redeemed twice is a ticket an attacker can race the real agent for.

| built-in | notes |
|---|---|
| `devicekey` (default) | Ed25519, keys from `DeviceRegistry`. |
| `mtls` | client certificates; moves the whole problem into the TLS layer and skips the in-band handshake. If you already run a device PKI — an MQTT mTLS one, say — this reuses it. |

## 9. `Dispatcher` — the doorbell (`dispatch` mode only)

```go
type Dispatcher interface {
    // Wake must be fast and must distinguish "device is not reachable" from
    // "I could not deliver". The gateway shows the operator different things.
    Wake(ctx context.Context, dev *Device, inv frame.Invitation) error
}

type Invitation struct {
    Ticket    string
    SessionID string
    URL       string        // which gateway to dial — the node, not the LB
    Profile   string
    ExpiresAt time.Time
}
```

`URL` names the specific node. That is what makes `dispatch` mode scale without the
node-to-node forwarding `persistent` mode needs: the agent connects to the right replica
the first time.

**Distinguishing the two failures matters more than it sounds.** "Device is offline" sends
someone to look at hardware in a gym. "I couldn't deliver the wake-up" sends someone to
look at the broker. Returning the wrong one wastes an on-call hour.

| built-in | notes |
|---|---|
| `mqtt` | publish to a per-device topic, QoS 1. |
| `webhook` | `POST` to your own push service. |
| `exec` | run a command with the invitation on stdin. For testing, and for the one place a shell script is genuinely the right integration. |

Configured examples:

```yaml
dispatcher:
  kind: mqtt
  url: mqtts://broker.example.org:8883
  topic: oarlock/devices/{device_id}/wake
  client_id: oarlock-gateway-a
  username: oarlock
  password: ${OARLOCK_MQTT_PASSWORD}
  qos: 1
  timeout: 10s
```

```yaml
dispatcher:
  kind: webhook
  url: https://push.example.org/oarlock/wake
  secret: shared-webhook-secret
  timeout: 10s
```

```yaml
dispatcher:
  kind: exec
  command: ["/usr/local/bin/oarlock-doorbell"]
  timeout: 10s
```

The MQTT topic must contain `{device_id}`. Oarlock only substitutes the registry device
id; the ticket stays in the JSON payload and never appears in the topic, command line or
URL.

## 10. `Ownership` — which gateway holds this device

```go
type Ownership interface {
    Claim(ctx context.Context, deviceID, nodeID string, ttl time.Duration) (bool, error)
    Renew(ctx context.Context, deviceID, nodeID string, ttl time.Duration) error
    Release(ctx context.Context, deviceID, nodeID string) error
    Lookup(ctx context.Context, deviceID string) (nodeID string, err error)
}
```

Only used with more than one replica. `Lookup` is what lets replica B forward an
operator's session to replica A, which holds the agent's socket. Leases expire so that a
node dying does not strand its devices; TTL defaults to 3× the renew interval.

| built-in | notes |
|---|---|
| `memory` (default) | single node. `Lookup` always returns self. |
| `redis` | `SET NX PX` claim, `EXPIRE` renew. |

## 10.1 `AuditSink` — the event set

```go
type AuditSink interface {
    Emit(ctx context.Context, e Event) // must not block, must not error
}
```

Structured events for everything that matters: authn, authz allow and deny, session open,
close with reason, revocation, passthrough use, replay access, config reload, limit hit.

`Emit` returns nothing, and that is the contract. **Audit must never be able to break a
shell** — a sink that can fail a session is a denial-of-service lever pointed at your own
operators. Buffer, drop on overflow, and count the drops.

| built-in | notes |
|---|---|
| `stderr` (default) | JSON lines. Whatever collects your logs collects your audit. |
| `http` | batched `POST`, at-least-once, bounded queue. |
| `syslog` | RFC 5424. |

## 11. Writing one — a worked example

An `Authorizer` backed by an internal permissions API, with revocation over SSE:

```go
package ourauthz

import (
    "context"
    "net/http"
    "time"

    "github.com/oarlock/oarlock/pkg/plugin"
)

func init() { plugin.RegisterAuthorizer("ourstack", New) }

type authz struct {
    api   *http.Client
    base  string
    cache *plugin.TTLCache[plugin.Decision] // provided; 5 s default, metrics included
}

func New(cfg plugin.Config) (plugin.Authorizer, error) {
    base, err := cfg.RequireString("base_url")
    if err != nil {
        return nil, err // config errors must fail at boot, never at first session
    }
    return &authz{
        api:   cfg.HTTPClient(),           // timeouts, tracing and metrics pre-wired
        base:  base,
        cache: plugin.NewTTLCache[plugin.Decision](cfg.Duration("cache_ttl", 5*time.Second)),
    }, nil
}

func (a *authz) Authorize(ctx context.Context, p *plugin.Principal,
    dev *plugin.Device, act plugin.Action) (plugin.Decision, error) {

    key := p.ID + "|" + dev.ID + "|" + string(act)
    if d, ok := a.cache.Get(key); ok {
        return d, nil
    }
    d, err := a.ask(ctx, p, dev, act)
    if err != nil {
        // An error is not a denial. The gateway refuses NEW sessions immediately and gives
        // live ones authz.grace re-checks before closing them as authz_unavailable.
        // Returning Decision{Allow:false} here would write "revoked" into the audit trail
        // for what is actually an outage.
        return plugin.Decision{}, err
    }
    a.cache.Put(key, d)
    return d, nil
}

func (a *authz) Watch(ctx context.Context) (<-chan plugin.RevocationEvent, error) {
    ch := make(chan plugin.RevocationEvent, 64)
    go a.streamSSE(ctx, ch) // reconnects with backoff; closes ch when ctx is done
    return ch, nil
}
```

Then build your own gateway:

```go
package main

import (
    "github.com/oarlock/oarlock/cmd/oarlockd/app"
    _ "example.com/our-stack/ourauthz"
)

func main() { app.Main() }
```

```yaml
authorizer:
  kind: ourstack
  base_url: https://api.internal/permissions
  cache_ttl: 5s
recheck_interval: 30s
```

### 11.1 The test kit

`pkg/plugin/plugintest` is a conformance suite. Call it from your own tests:

```go
func TestConformance(t *testing.T) {
    plugintest.Authorizer(t, plugintest.AuthorizerHarness{
        New:     func(t *testing.T) plugin.Authorizer { return newMyAuthz(t) },
        Allowed: func() (*plugin.Principal, *plugin.Device, plugin.Action) { … },
        Denied:  func() (*plugin.Principal, *plugin.Device, plugin.Action) { … },

        // Make your dependency unavailable. This is the case the suite exists for.
        BreakDependency: func(t *testing.T) (restore func()) { … },
    })
}
```

It checks what is easy to get wrong and hard to notice: that you distinguish "no" from
"I could not decide", that a denial carries a reason an operator can act on, that
cancellation is honoured, that concurrent calls agree, that a per-grant limit only
tightens, and that a dropped `Watch` stream closes its channel rather than leaking a
goroutine per reconnect.

**The suite fails a backend that returns `Allow: false` when its dependency is down.**
That is its reason for existing. A backend that conflates the two writes `revoked` into
an audit trail for an outage, tells an operator their access was withdrawn when nothing
about it changed, and converts one service's bad minute into a fleet-wide session kill —
during the incident that put those operators on those devices. Documenting the contract
was the first attempt at preventing this; the suite is the second.

**Nothing in it skips quietly.** A conformance suite whose most important case can be
omitted by leaving a field nil reports success for a backend it never tested, so the cases
that carry a contract *fail* when their harness is incomplete. Opting out takes a field
whose name says what it costs — `NoDependencyToBreak` for an authorizer that genuinely
has nothing that can be unavailable, `NoTransportToBreak` for an in-process dispatcher —
and even then the suite checks the part of the claim that is checkable.

Suites available now: `Authorizer`, `Authenticator`, `Dispatcher`. The shipped backends
run through them (`plugins/authz/rules`, `plugins/authz/webhook`,
`plugins/dispatch/exec`, `plugins/dispatch/webhook`, `plugins/dispatch/mqtt`,
`internal/auth/authorizedkeys`, `internal/auth/statictoken`), which is not ceremony:
a suite the first-party implementations do not pass is one nobody should trust.

**The suite tests itself.** `plugintest`'s own tests run each suite against backends that
are wrong in each specific way — denies on error, allows on error, errors instead of
denying, denies with no reason, ignores cancellation, disagrees under concurrency, hangs
on `Watch`, leaks a `Watch` goroutine, blames the device for its own outage, leaks a
ticket into an error message — and assert that the suite *fails* them. A conformance suite
that passes a wrong backend is worthless, and the only way to know it does not is to try.
