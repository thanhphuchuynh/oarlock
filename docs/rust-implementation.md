# Building the agent again, in Rust

A guide for writing a second Oarlock agent, in Rust, against the protocol this repository
already specifies. It is a learning path, not a migration plan: the Go agent stays, keeps
shipping, and is the reference you check yourself against at every step.

## Why the agent, and why not the gateway

The agent is **3.9k lines** across `agent/`, `cmd/oarlock-agent/`, `pkg/frame/` and
`pkg/transport/`. It is self-contained, its wire protocol is written down in
[protocol.md](protocol.md), and `pkg/frame` is public API precisely *"so other agents can
be written"*. That sentence is an invitation.

The gateway is 22k lines and leans on `golang.org/x/crypto/ssh` — a mature, memory-safe
SSH server implementation. Rust's equivalent, `russh`, is real and production-proven, but
porting the front door means trading down on your most security-critical dependency while
also learning the language. Do not start there. Do not start with `internal/pump` either:
backpressure, coalescing, the ring buffer and the reattach handshake are elegant in Go
*because* goroutines and channels are cheap, and they are the hardest thing here to express
in async Rust.

## This is not wasted work

The frame codec already exists twice — Go (`pkg/frame`, 669 lines) and TypeScript
(`packages/terminal/src/frame.ts`, 161 lines) — sharing generated test vectors in
`tests/fixtures/frames.json`. A third implementation, in a language with a stricter type
system, is a **conformance test for the specification**:

- Every place Rust makes you guess is a place `docs/protocol.md` is underspecified.
- Every place the borrow checker rejects a direct port is a place Go left a lifetime
  assumption implicit.

Both are findings worth having. Write them down as you hit them.

## The rules

1. **The Go agent keeps working.** Nothing here touches it.
2. **`docs/protocol.md` is the spec, not the Go source.** Read the Go when you are stuck,
   but implement from the document — that is what makes this a conformance test rather
   than a transliteration.
3. **Every step has a pass/fail criterion.** Never move on because it "looks right".
4. **Do not port the comments.** Rewrite the reasoning in your own words, or leave it out.
   Copying prose you have not re-derived is how you end up with a document that describes
   code you did not write.

## Layout

Keep it in this repository, so the fixtures are one relative path away:

```
rust/
  Cargo.toml            # workspace
  oarlock-frame/        # step 1–2: the codec. No async, no I/O.
  oarlock-agent/        # step 3–5: the binary.
```

Add `rust/target/` to `.gitignore` before your first `cargo build`.

Crates you will want. Check current versions rather than pinning what is written here:

| need | crate | note |
|---|---|---|
| async runtime | `tokio` | features `rt-multi-thread`, `macros`, `net`, `io-util`, `sync`, `time` |
| WebSocket | `tokio-tungstenite` | pair with `rustls` |
| TLS | `rustls` + `tokio-rustls` | pure Rust — keeps cross-compiling simple, which is the whole reason the Go build is `CGO_ENABLED=0` |
| JSON | `serde`, `serde_json` | |
| Ed25519 | `ed25519-dalek` | |
| errors | `thiserror` | library errors; `anyhow` in `main` only |
| logging | `tracing` + `tracing-subscriber` | the `slog` analogue |
| pty / uid | `nix` or `rustix` | step 5 |
| confined FS | `cap-std` | the `os.Root` equivalent — see step 5 |
| CLI | `clap` | derive feature |
| fuzzing | `cargo-fuzz` | step 1 |

---

## Step 1 — the codec

**Port:** `pkg/frame/frame.go`, `pkg/frame/type.go`
**Read first:** [protocol.md § 2](protocol.md) — frame layout
**Async:** none. **Difficulty:** gentle.

The entire wire format is **one byte of type, then the payload**. There is no length
field and no stream id, because a frame occupies exactly one binary WebSocket message —
the message boundary *is* the frame boundary. Nothing in a frame can claim a length it
does not intend to send, so a decoder cannot be made to allocate on a peer's say-so.

That makes this a genuinely small first project with a real specification behind it.

Build, in order:

1. **`Type` as an `enum`.** Twenty variants across two scopes: `0x0x` session-scoped,
   `0x1x` connection-scoped. This is your first taste of the thing Rust does that Go
   cannot — in Go this is `type Type uint8` plus a `map[Type]string` plus a convention.
   In Rust an unknown byte cannot become a `Type` at all, so you must decide explicitly
   what an unrecognised byte *is*. That decision is `Disposition`, below.
2. **`scope()`, `is_raw()`, `universal()`, `known()`, `disposition()`.** Derive scope from
   the byte (`t & 0xF0`) rather than looking it up in a table — an unknown type still has
   a scope and therefore still has a defined disposition. That property is what makes
   additive protocol changes possible without a version bump.
3. **`decode(msg: &[u8]) -> Result<Frame<'_>, DecodeError>`.** Note the lifetime: the Go
   version documents that the payload aliases the caller's buffer and must be cloned to
   outlive it. In Rust, say it in the signature and the compiler enforces it. **This is
   the single best moment in the whole exercise** — a doc comment becoming a type.
4. **`encode(dst: &mut Vec<u8>, f: &Frame) -> Result<(), EncodeError>`.** Append into a
   caller-owned buffer so a sender can reuse one for the life of a connection.
5. **`expect(want: Scope, f: &Frame)`.** `ERROR`, `PING` and `PONG` are valid on either
   kind of connection; everything else on the wrong one is a connection-level fault.

Deliberately **not** in this step: any validation of what a payload *means*. The Go
decoder is structural only, on the grounds that a decoder which also validates semantics
has a second place for bugs to hide. Keep that property.

### Pass/fail

```bash
cargo test -p oarlock-frame
```

Load `../../tests/fixtures/frames.json` and assert every vector round-trips. The file is
generated (`go test ./pkg/frame/ -run TestSharedVectors -update`) and is already consumed by both
existing implementations — so on day one you have the same pass/fail criterion the Go and
TypeScript codecs are held to. If your Rust passes it, you are correct, not hopeful.

Then:

```bash
cargo fuzz run decode
```

`pkg/frame/fuzz_test.go` asserts four properties over arbitrary bytes. Port all of them —
they are the interesting part, not the "does not crash" that fuzzing is usually sold on:

1. **Every rejection maps to a wire code.** Otherwise the gateway has nothing truthful to
   put in an `ERROR` frame.
2. **Every decoded frame has a defined disposition** — `Handle`, `Ignore` or
   `CloseConnection` — so no input can reach a receiver that has no rule for it.
3. **Round trip is exact.** Re-encoding a frame you just decoded reproduces the input
   bytes.
4. **`Clone` does not alias the input.** Mutate the source buffer, assert the clone is
   unchanged.

Property 4 is worth pausing on: in Rust it is **untestable, because it is unrepresentable**.
`Frame<'a>` borrows; `Frame<'static>` owns; converting between them is `to_vec()`. There is
no way to write the bug. That is one Go test you get to delete, and the first concrete thing
this exercise will teach you about what a borrow checker actually buys.

### Rust you will learn

`enum` and exhaustive `match`; `&[u8]` versus `Vec<u8>`; lifetimes on a return type;
`Result` and `?`; `thiserror`; `#[cfg(test)]` modules.

---

## Step 2 — the payloads

**Port:** `pkg/frame/payload.go`
**Read first:** [protocol.md § 4](protocol.md) — frame reference
**Async:** none. **Difficulty:** gentle.

Twenty-ish structs behind `serde`. Mechanical, and worth doing carefully because the field
names are the wire contract.

Watch for:

- `#[serde(rename_all = "snake_case")]` and per-field `rename` where Go's tag differs from
  the Rust field name.
- Go's `omitempty` is `#[serde(skip_serializing_if = "Option::is_none")]`. Getting this
  wrong sends `"pty": null` where Go sends nothing — the gateway tolerates it, but the
  bytes differ and your vectors will notice.
- Unknown JSON fields must be **dropped, not rejected** (§ 7 versioning). That is serde's
  default; do not add `#[serde(deny_unknown_fields)]`.
- `Invitation` carries `pty`, `exec`, `file` and `tcp` as mutually exclusive optionals.
  Rust wants this to be an enum. **Resist** — the wire format is a struct with optional
  fields, and modelling it as an enum will bite you on an additive change. Model the wire
  faithfully; convert to an enum *after* deserialising if you want exhaustiveness.

That last point is the first real design tension you will hit between "what Rust wants"
and "what the protocol is". Note how you resolved it.

### Pass/fail

Round-trip every JSON example in `docs/protocol.md § 4` through your types and back, and
compare to the original with `serde_json::Value` equality.

---

## Step 3 — the handshake blob

**Port:** the signing input from [protocol.md § 3.1](protocol.md)
**Async:** none. **Difficulty:** moderate, but pure functions.

Before any networking, implement the bytes that get signed. They are **length-prefixed and
domain-separated**, not concatenated:

```
"oarlock-control-v0" 0x00
  u16(len) nonce_s   u16(len) nonce_c
  u16(len) device_id u16(len) gateway_id
```

Read the paragraph in § 3.1 explaining why. An earlier draft concatenated, and device `ab`
with gateway `c` produced the same bytes as device `a` with gateway `bc` — so a peer
controlling one field could shift the boundary and obtain a signature valid for values
nobody agreed to. Length prefixes make the encoding injective. This is a good, small
example of a real cryptographic bug class, and implementing it twice is how you internalise
it.

### Pass/fail

Follow the pattern `pkg/frame/vectors_test.go` already established: add a Go test that
writes `tests/fixtures/handshake.json` with a few `(device_id, gateway_id, nonce_c,
nonce_s) → signing_input` vectors under `-update`, then assert your Rust produces the same
bytes. Byte-for-byte, not "looks the same".

Sign with `ed25519-dalek` and verify against a key pair the Go agent generated
(`oarlock-agent -generate-key`). If the Go gateway accepts your signature, this step is
done.

---

## Step 4 — transport and the control channel

**Port:** `pkg/transport/`, `agent/control.go`
**Read first:** [protocol.md § 1, § 3.1](protocol.md)
**Async:** all of it. **Difficulty:** this is the spike.

Everything before this was pure logic. Now you meet tokio, and this is where people bounce
off Rust. Budget real time for it, and expect to be confused about lifetimes across
`.await` points. That confusion is normal and it passes.

Build:

1. **A `Transport` trait** mirroring `pkg/transport/transport.go`: `recv`, `send`, `close`,
   `remote_addr`. Enforce the read limit *before* buffering — the limit defends against an
   allocation, so checking after allocating is theatre.
2. **A `tokio-tungstenite` implementation** with `rustls`, plus certificate pinning
   (SHA-256 of the SubjectPublicKeyInfo). A Rust agent must also implement protocol v1's
   channel binding — 32 bytes of RFC 5705 exporter output, label
   `EXPORTER-oarlock-control-v1`, mixed into the signed input — or it can only ever
   negotiate v0 and is downgradeable by construction. Pinning is
   what stands between the handshake and a TLS-terminating middlebox. The Go agent pins by
   default; yours should too.
3. **The control loop**: connect → `HELLO` → `CHALLENGE` → `AUTH` → `WELCOME`, then
   dispatch `DIAL`, `CANCEL`, `PING` and `GOAWAY` — and nothing else. A session-scoped
   frame arriving here closes the connection.
4. **Reconnect with backoff and jitter.** `GOAWAY` carries `reconnect_after_ms`, jittered
   per agent during a drain, because otherwise every agent in the fleet reconnects on the
   same instant and kills the replacement.
5. **`WELCOME.resume`** names sessions the gateway is still holding. Dial back for each.

Two things that will feel wrong coming from Go:

- **Cancellation.** `context.Context` threaded through every call becomes either dropping
  the future or a `CancellationToken`. Dropping is idiomatic; a token is closer to what you
  know. Either is fine — pick one and be consistent.
- **`defer`.** There isn't one. Use `Drop`, or restructure so cleanup is unconditional.

### Pass/fail

Start the real gateway and watch your Rust agent connect:

```bash
cd demo && ../oarlockd -config ./oarlock.yaml
# expect: "control channel up" in the gateway log, device connected in the API
curl -s localhost:8443/api/v1/devices -H 'Authorization: Bearer <token>' | jq '.[].connected'
```

---

## Step 5 — the profiles

**Port:** `agent/session.go` and one file per profile
**Difficulty:** varies sharply. Do them in this order.

**`tcp` first** (`agent/tcp.go`, 250 lines). Simplest by a distance: match the port
against an allow-list, `TcpStream::connect` on loopback, two copy loops. No pty, no argv,
no filesystem. Read the module comment on why the target is a port and never a host.

**`exec`** (`agent/exec.go`). Exact-argv allow-list, `tokio::process::Command`, no shell
interpretation anywhere. Straightforward.

**`file`** (`agent/file.go`). Interesting: the Go version uses `os.Root`, which resolves
each path component in the kernel so check and use are the same syscall — no
time-of-check-to-time-of-use window. Rust's equivalent is **`cap-std`**'s `Dir`, built on
the same idea and arguably nicer. Read the 20-line comment at the top of `agent/file.go`
first; it is the best explanation of the bug class in this repository.

**`shell` last** (`agent/shell.go`). `forkpty` via `nix`, window resize, and dropping
privileges. Platform-specific and fiddly — worth doing once you are comfortable.

### Pass/fail — and the milestone

With `forward_ports` in your agent's config and a service on the device's port 3000:

```bash
ssh -L 8080:localhost:3000 <device>@gateway -N &
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8080/    # expect 200
```

A `200` there means: your Rust codec, your handshake, your transport, your control loop and
your `tcp` profile all agree with an independent Go implementation of the same
specification. That is a real milestone and a good place to stop and write up what you
found.

---

## Go to Rust, quick reference

| Go | Rust |
|---|---|
| `(T, error)` | `Result<T, E>`, `?` |
| `errors.Is(err, ErrX)` | `matches!(e, Error::X)`, `#[from]` on `thiserror` |
| `interface` | `trait`; `dyn Trait` where you need dynamic dispatch |
| nil-interface check (`c == nil \|\| c.Backend == nil`) | `Option<Box<dyn T>>` — the footgun does not exist |
| `go f()` | `tokio::spawn(f())` |
| `chan T` | `tokio::sync::mpsc::channel::<T>` |
| reply channel (`Done chan Result`) | `tokio::sync::oneshot` |
| `select { }` | `tokio::select!` |
| `ctx` cancellation | drop the future, or `CancellationToken` |
| `defer` | `Drop`, or `scopeguard::defer!` |
| `sync.Mutex` | `std::sync::Mutex` (sync) / `tokio::sync::Mutex` (held across `.await`) |
| `atomic.Value` | `arc_swap::ArcSwap`, or `Mutex<T>` |
| `[]byte` argument | `&[u8]` |
| owned bytes | `Vec<u8>`, or `bytes::Bytes` for cheap clones |
| `json:"x,omitempty"` | `#[serde(rename = "x", skip_serializing_if = "Option::is_none")]` |
| `os.Root` | `cap_std::fs::Dir` |
| `slog` | `tracing` |
| `go test -fuzz` | `cargo fuzz` |

## Cross-compiling for Android

The Go agent is `GOOS=android GOARCH=arm64 CGO_ENABLED=0` — one command, no NDK. Rust has
two routes:

1. **`aarch64-unknown-linux-musl`**, fully static. No NDK needed, and a static binary runs
   from `/data/local/tmp`. Try this first.
2. **`aarch64-linux-android`** via `cargo-ndk`, if (1) gives you trouble.

Either way keep `rustls` rather than OpenSSL, or you have reintroduced the C toolchain
dependency the Go build exists to avoid. Expect roughly 2–4 MB stripped with
`opt-level = "z"`, LTO and `panic = "abort"`, against the Go agent's measured 7.3 MB.

## What to do when you are stuck

Read the Go — but read the *comment*, not the code. This repository puts the reasoning in
prose above the implementation, and the reasoning is what ports. The code is one language's
answer to it.

If the reasoning does not survive the port — if Rust's type system makes a whole paragraph
of Go commentary unnecessary — that is the most interesting thing you will find. Write it
down. It belongs in this file.
