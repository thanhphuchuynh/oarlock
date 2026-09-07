# S3 Object Lock Recorder Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make "can your administrator delete the evidence?" answerable with *no*.

**Architecture:** A new `record.Store` backend writing recordings to S3 with Object Lock, plus an honest `ImmutabilityReporter` that asks the bucket rather than trusting the config. The interface already anticipates this — `ModeCompliance` and the store kind `"s3"` are both already named in `internal/record/store.go`.

**Tech Stack:** Go 1.25, `github.com/minio/minio-go/v7`.

---

## Why this is the highest-value gap

Today the gateway says this at every startup:

    recording store cannot enforce immutability — the hash chain makes tampering
    detectable, not impossible

The signed, hash-chained, offline-verifiable recording is the product's differentiator.
`internal/record/store.go` already defines the vocabulary for the fix:

- `ModeCompliance` — *"a lock nobody can lift until retention expires, including the account
  owner. The only mode that survives a compromised administrator."*
- `ModeGovernance` — *"an object lock that sufficiently privileged users can lift."*
- `Kind` — *"names the store, e.g. `file`, `s3`."*

Nothing implements any of it. The only backend is `file`, which reports `ModeMutable`.

## The dependency, and why

`Store.Create` returns an `io.WriteCloser` and the spool writes to it **incrementally**
(`internal/record/spool.go` — `sink io.WriteCloser`, `s.flushed += int64(n)`). So the
backend receives a stream of unknown final length, which on S3 means multipart upload:
`CreateMultipartUpload` → `UploadPart` × N → `CompleteMultipartUpload`, and
`AbortMultipartUpload` on any failure or an abandoned session.

Hand-rolling that plus SigV4 plus presigned URLs is a large security-adjacent surface where
a mistake is silent. `minio-go/v7` covers all three, is one module, and is S3-compatible —
so a deployment can point it at AWS S3, MinIO on-prem, Ceph or Backblaze without a second
backend.

**This is a departure** for a project that hand-encodes Prometheus text format rather than
take `client_golang`. Recorded here so nobody has to reconstruct the reasoning: the
Prometheus encoder is ~200 lines of deterministic formatting with a test that reads the
output. Multipart S3 with request signing is neither deterministic to eyeball nor safe to
get subtly wrong, and an aborted-upload bug leaks storage and money silently.

---

## The rule this whole feature turns on

**The store reports what the bucket says, never what the config says.**

A backend that returned `ModeCompliance` because its YAML said `mode: compliance` would be
the same class of lie as a console that decides for itself what a principal may do. The
operator would get a green light and no lock.

So `Immutability(ctx)` **asks S3** — `GetObjectLockConfig` on the bucket — and reports what
comes back. A bucket with no lock configuration reports `ModeMutable` even if the config
asked for compliance, and the boot gate refuses that combination rather than starting.

The codebase already holds this line in three places, which is why the feature fits without
argument:

- `store.go`'s comment on the optional interface — *"the answer for such a backend is
  ModeUnknown, which is treated as mutable. Silence is not a guarantee."*
- `safety.Settings.RecordingStoreProtected`'s comment — *"as **reported by the store**
  rather than declared in configuration. A guarantee an operator types into a config file
  is a guarantee nobody checked."*
- `Mode.Protected()`, which deliberately excludes `ModeUnknown`.

**And one place where it is already broken.** `cmd/oarlockd/app/app.go:263` reads:

```go
recProtected = imm.Mode != "mutable"
```

`Mode.Protected()` exists and is not called. The string comparison counts **`ModeUnknown`
as protected** — and `ModeUnknown` is exactly what `immutabilityOf` returns when a store's
`Immutability` call fails (`store.go:120`, `"could not read: " + err.Error()`). Today
`FileStore` can only answer `declared` or `mutable`, so nothing reaches it. The moment a
backend exists that can fail to answer — a bucket that is unreachable at boot — an
unverified store reports as protected and **the boot gate goes quiet**. Fix it in Task 2
with a test that pins `ModeUnknown` to unprotected.

---

## Global Constraints

*The task-brief generator extracts per-task text only and will not carry this section. Whoever dispatches a task must restate it.*

- **One new dependency, `github.com/minio/minio-go/v7`, and nothing else.** Run
  `go mod tidy` and report every transitive module it brings.
- **Green from the committed state:** `go build ./... && go test ./...` with nothing
  uncommitted.
- **`docs/openapi.yaml` is generated** — regenerate if any API surface changes. A drift
  test fails otherwise.
- **No credentials in the repo, in a test fixture, or in a log line.** The fake S3 in the
  tests takes whatever it is given; real credentials come from the environment or the
  config file, and the config file is already gitignored for `demo/`.
- **A recording that cannot be written must close the session**, not be dropped. That is
  existing behaviour via the spool and its `FlushDeadline`; do not weaken it.

---

## File Structure

| file | responsibility |
|---|---|
| `internal/record/s3store/s3store.go` | the backend: `Create`, `PutManifest`, `Get`, `GetManifest`, `URL`, `Immutability` |
| `internal/record/s3store/s3store_test.go` | tests against a fake S3 served by `httptest` |
| `internal/config/config.go` | the `recorder.s3` block |
| `internal/safety/` | the boot gate: config asking for compliance against a bucket without a lock |
| `cmd/oarlockd/app/app.go` | wire it when configured |
| `docs/plugins.md` § 4.2 | document the modes and what each buys |

---

### Task 1: The backend, against a fake S3

**Files:**
- Create: `internal/record/s3store/s3store.go`, `internal/record/s3store/s3store_test.go`
- Modify: `go.mod`, `go.sum`

**Interfaces:**
- Consumes: `record.Store`, `record.ImmutabilityReporter`, `record.Immutability`,
  `record.Mode*`, `record.ErrNotFound`, `plugin.SessionMeta`, `plugin.ErrUnsupported`.
- Produces: `s3store.Open(cfg Config) (*Store, error)`. Task 2 wires it.

**Read first:** `internal/record/store.go` in full — the `Store` interface, the `Mode`
constants and their comments, and `FileStore` as the reference implementation of the same
five methods.

- [ ] **Step 1: The test's fake S3 comes first**

The one test that matters asserts **the object-lock headers are actually sent**. Without it
this feature can ship as an ordinary S3 writer that reports compliance, which is worse than
no feature: the operator would believe the evidence is locked.

Serve a fake S3 from `httptest` and record the requests. Assert:

- a recording PUT (or the completing multipart request) carries
  `x-amz-object-lock-mode: COMPLIANCE` and an `x-amz-object-lock-retain-until-date`
  matching the configured retention
- the manifest PUT carries them too — **a locked recording beside an editable manifest is
  not evidence**, because the manifest holds the signature and the chain head
- a stream longer than one part becomes a multipart upload
- a failure mid-stream sends `AbortMultipartUpload` rather than leaving the upload dangling
- `Get` on a missing key returns `record.ErrNotFound`, not a transport error
- `URL` returns a presigned link, and its TTL is the one requested
- `Immutability` reports `ModeCompliance` for a bucket whose lock config says so,
  `ModeGovernance` for governance, and **`ModeMutable` for a bucket with no lock config even
  when our own config asked for compliance**

That last assertion is the feature. Write it first.

- [ ] **Step 2: Run it and watch it fail**

`go test ./internal/record/s3store/` — no such package.

- [ ] **Step 3: Implement**

`Config` carries: bucket, region, endpoint (empty means AWS), prefix, credentials
(access key / secret, or empty to use the environment), `UseSSL`, the requested lock mode,
and the retention period.

Keys: put the recording and its manifest under a stable, greppable prefix —
`<prefix>/<session-id>.cast` and `<prefix>/<session-id>.manifest.json`. A person with
bucket access and no gateway must be able to find a recording by session id.

`URL` returns a presigned GET. This is the method that keeps replay from streaming through
the gateway, so it must not return `ErrUnsupported`.

- [ ] **Step 4: Green, then commit**

```bash
go mod tidy && go build ./... && go test ./...
git add go.mod go.sum internal/record/s3store/
git commit -m "feat(record): an S3 backend that locks a recording against its own operator"
```

Report every transitive dependency `go mod tidy` added.

---

### Task 2: Configuration, the boot gate, and wiring

**Files:** `internal/config/config.go`, `internal/safety/safety.go`,
`cmd/oarlockd/app/app.go`, `docs/plugins.md`, `examples/oarlock.yaml`

**Interfaces:** consumes `s3store.Open` from Task 1.

**The seam is already there — do not add a constructor.** `record.New(Options{Store, Signer})`
(`internal/record/recorder.go:43`) takes any `Store`; `NewFileRecorder` is just a two-line
wrapper around it. So `app.go` builds an `s3store` and passes it to `record.New`. Nothing in
`internal/record` needs to change.

**Note the timing.** `record.New` asks the store for its immutability **once, at
construction** (`recorder.go:59-60`, with a comment explaining why: per-session would be a
log line per shell). So a bucket that is unreachable at boot yields `ModeUnknown` for the
lifetime of the process, and that is precisely the case Step 2 must refuse rather than
report as protected.

- [ ] **Step 1: The config block**

```yaml
recorder:
  signing_key: ./recording.key
  key_id: prod-recording-key
  s3:
    bucket: oarlock-recordings
    region: eu-west-1
    endpoint: ""            # empty for AWS; set for MinIO or Ceph
    prefix: recordings
    lock_mode: compliance   # compliance | governance | none
    retain_for: 2160h       # 90 days
```

Add `S3 *S3` to `config.Recorder` (`internal/config/config.go:360`). `dir` and `s3` are
mutually exclusive — refuse both rather than picking one. Unknown keys are already refused;
keep it that way.

**Two existing validations key off `Dir` alone and will now be wrong** — `config.go:759`
(*"signing_key is set but recorder.dir is not, so nothing is recorded"*) and `config.go:762`
(*"signing_key is required when recording"*). Both must read "dir or s3". A configured S3
bucket with no signing key would otherwise sail through, and an S3-only config would be told
nothing is recorded.

- [ ] **Step 2: The boot gate — this is the point of the task**

Two changes in `internal/safety/safety.go`, and one in `app.go`.

**(a) Fix `app.go:263`.** `recProtected = imm.Mode != "mutable"` becomes
`imm.Mode.Protected()`. See "The rule this whole feature turns on" above for why this is not
cosmetic: the string form counts `ModeUnknown` as protected, and `ModeUnknown` is what a
store returns when its `Immutability` call *fails*. Add a test that pins it — a store whose
`Immutability` returns an error must come out unprotected.

**(b) A new fatal check.** `Settings` gains the *requested* mode alongside the reported one
— `RecordingStoreRequested string` — because the gate cannot otherwise tell the difference
between two situations that deserve different answers:

| requested | reported | today | should be |
|---|---|---|---|
| nothing | mutable | warning at `safety.go:146` | **keep the warning** — nobody promised anything |
| compliance | mutable or unknown | *nothing* — there is no such config yet | **fatal** |

The second row is the whole point. An operator who wrote `lock_mode: compliance` has
asked for a guarantee, and every manifest written from then on records
`Storage Immutability` in its own JSON (`manifest.go:86`). Booting anyway means signing a
claim nobody checked into every piece of evidence.

Keep the existing warning exactly as it is. **Do not make the no-recorder or mutable-store
cases fatal** — a lab has no WORM storage and must still be able to record, which
`recorder.go:69` already says in as many words. If a change of yours turns an existing
`safety_test.go` expectation from warning to fatal, that is the signal you widened the gate
too far: stop and say so rather than editing the test.

**(c)** The gate reads the *reported* mode from the store, never the config. That plumbing
already exists — `app.go:262` calls `fr.Immutability()` and feeds `recStoreMode` into
`Settings`. Only the requested value is new.

- [ ] **Step 3: Wire it, document it**

`app.go` builds the s3 store when configured. `docs/plugins.md` § 4.2 already discusses
immutability — extend it with what each mode buys and what compliance costs (you cannot
delete a recording before retention expires, including by mistake, including if it contains
something it should not).

- [ ] **Step 4: Green, regenerate, commit**

---

## Done when

- A recording and its manifest are both written under an object lock the gateway's own
  operator cannot lift.
- `Immutability` reports what the bucket says, and `ModeMutable` when the bucket has no lock
  regardless of what the config asked for.
- The boot gate refuses `compliance` against an unlocked bucket.
- `go test ./...` green from the committed state.

## What "locked" actually buys, and the gap Task 1 found

Task 1 established a limit that changes what may honestly be claimed, so it is recorded
here rather than left in a package comment.

**S3 requires versioning for Object Lock, so a lock makes each object *version*
undeletable — it does not make the key unwritable.** Somebody with bucket write access can
still `PUT` a doctored recording over the key, and `Get` serves the latest version.

What they cannot do is destroy the locked original, and they cannot produce a manifest that
verifies, because the signing key is deliberately somewhere the recording store cannot
reach. So:

| claim | true? |
|---|---|
| an administrator cannot *delete* the evidence | **yes** — that is what the lock buys |
| an administrator cannot *forge* evidence undetectably | **yes** — that is what the signature buys |
| replay always serves the *locked* bytes | **no** — `Get` reads the latest version |

The third row is the gap. It is not a hole in the guarantee so much as a hole in what the
gateway *shows you*: the real recording survives and the substitute fails verification, but
an operator hitting replay sees the substitute until they check the verdict.

**Closing it is a follow-up increment: version-pinned reads.** Capture the `versionId` on
write, record it in the manifest, and read that version back. That needs a seam change —
`record.Store.Get(ctx, sessionID)` has no version parameter and the manifest is authored by
`internal/record`, not by the backend — which is exactly why it is not bolted onto this one.

**Task 2's § 4.2 must say all of this.** A compliance-locked recording that replay might
serve a substitute for is still a strong guarantee, and it is not the guarantee the words
"immutable recording" put in a reader's head.

## Not in this increment

Version-pinned reads (above), lifecycle policies, cross-region replication, KMS encryption
(S3 default encryption covers the common case and is a bucket setting, not ours), legal hold
as a separate operation, and migrating existing `file` recordings into a bucket.

Also unchecked: **bucket versioning can be *suspended* after Object Lock is enabled.**
`GetObjectLockConfig` still reports enabled, so the store would report a lock that new
versions no longer get. A `GetBucketVersioning` call in `Immutability` would catch it; it is
one request and belongs in the follow-up with version-pinned reads, which needs versioning
to be live anyway.
