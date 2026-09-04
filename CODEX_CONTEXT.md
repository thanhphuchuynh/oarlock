# Codex Handoff Context

Date: 2026-08-23
Branch: `codex-e4-s3-webhook-authorizer`
Last commit: `777636b feat: add admin device management`

## User Preferences

- Commit `777636b` is the branch tip. Everything described as current work below was
  implemented after that commit and is intentionally uncommitted.
- Do not commit unless the user explicitly asks.
- Keep future changes scoped and preserve unrelated user changes in the dirty worktree.

## What Was Implemented

### Added 2026-08-23: the admin console, rebuilt device-first

The console is no longer described as a reference implementation. It is the admin UI, and
`web/src/App.tsx`'s header comment, README and ARCHITECTURE say so.

What was wrong, and is now gone: `treadmill-4821` appeared in a "Device registry" table
whose STATE column said ONLINE *and* in a "Live agents" table that existed to say ONLINE
again, under a stat row repeating both in 2xl type, above a shell form asking you to
retype a device id you were looking at. Four places to read one device's state, and no
answer to the question an administrator arrives with.

- `web/src/Fleet.tsx` (new): one expandable row per device. Inside it — open a shell (no
  id to retype), **who can reach it**, **who can administer it**, that device's recent
  sessions, and Edit / Disable / Stop agent / Delete. Connection state is a property of the
  row. `AdminStat`, `DeviceList`, `AgentList`, `StatusPill`, `DeviceStatusPill` deleted.
- Nav is now Fleet · Sessions · Permissions · SQL Explorer. The fleet-wide session history
  moved to its own page instead of duplicating the per-device list underneath it.
- `Open by id…` keeps the typed-id path — for a row that is not on screen, and so the
  unknown-device failure screen stays reachable through the UI.
- `GET /api/v1/devices/{id}/access` answers "who can reach this device", **on the server**,
  using `plugin.Permission.AppliesTo` / `MatchesPrincipal` / `Grants` — the same predicates
  `plugins/authz/sqlite` now calls, so there is one matcher rather than a copy in
  TypeScript that drifts towards saying somebody cannot reach a device they can. Denials
  first. Requires `admin:permissions`. Returns `admin_actions` so the console can separate
  reaching from administering without its own copy of the vocabulary.
- Permissions: denials sorted first with the effect leading the row and the deny's reason
  on it; `btn-quiet` given a real definition (it was referenced and undefined, which is why
  every button there looked identical); the "Enabled" column next to a "Disable" button
  replaced by one marker on the row.
- `SessionList`: the header and cell breakpoints disagreed — `State` was always shown while
  its cell was `hidden sm:table-cell`, so on a phone the recording badge sat under a STATE
  heading. Rebuilt around one always-visible set of columns, with the reason and the
  recording state each rendered **once**.
- Polling: was three endpoints every 4s = 45 requests/min against a default budget of 120,
  from an idle tab. Now the page asks only for what it renders (Permissions and SQL poll
  nothing), a hidden tab asks for nothing, and `/agents` is not called at all — the gateway
  computes `device.connected` from exactly that list, so fetching both was the same
  duplication the fleet page was showing.
- **`tsconfig.json` never typechecked `web/src`.** It referenced the two packages and the
  tests only, so the console was the one piece of TypeScript in the repository that nothing
  checked; `npm run typecheck` passing meant nothing about it. `tsconfig.web.json` adds it,
  and the pre-existing `exactOptionalPropertyTypes` violations it immediately found in
  `App.tsx` and `Permissions.tsx` are fixed.

Tests: six new console tests (agent state is not a separate list; reach vs administer;
denial first and marked; a refused access list is not rendered as an empty one; plus the
reworked shell, session-list, SSH, replay and device-admin journeys). `tests/console` seeds
three devices — connected, never-connected, and PCI-tagged — because a deployment with one
always-online device cannot test the row for the machine that is not there. Each new
guarantee was checked by injecting its inverse.

Verified: `go test ./...`, `go vet ./...`, `tsc --build --force`, `npm run build:ui`, and
`npm test` at **158 passing including `tests/live`** — a real gateway and agent, shell
opened in Chromium through the new fleet row.

### Added 2026-08-23: authorisation on the admin surface

The device and permission CRUD endpoints, `DELETE /agents/{id}` and `DELETE
/sessions/{id}` authenticated the caller and then discarded the principal — every handler
took `_ *plugin.Principal`. Under `authorizer.kind: sqlite` the store that answers
authorisation questions is the store the admin API writes to, so a token with no grants
could `POST /api/v1/permissions` a wildcard allow and then pass the `sql:read` check. That
path was walked and confirmed before it was closed.

- Three new actions in the closed set: `admin:devices`, `admin:permissions`, `admin:kill`.
  `Action.Administrative()` reports membership.
- `admin:devices` and `admin:kill` are checked against the **stored** device record, so a
  tag-scoped grant or deny reaches the admin surface. On create there is no stored record,
  so a create-capable grant can create a device whose tags a deny would have matched —
  documented, and a reason to scope create narrowly.
- `admin:permissions` is checked against the synthetic `gateway` device and gates the
  reads too: a list of who may reach what is a map of whom to go after.
- Ending your own session needs no grant. `admin:kill` governs ending somebody else's.
- `authorizer.admins` (config, exact principal ids, patterns refused at boot) is the
  break-glass for the empty-store bootstrap. It grants `admin:*` and nothing else, is
  logged at boot and on every use, and outranks a deny on the administrative actions only —
  so `deny`-beats-`allow` still holds for every session action. `internal/authz` owns it,
  so both surfaces get the same rule.
- Every administrative request emits `admin.change`, refusals included; a policy write
  records principals, devices, actions and effect rather than just the permission id.
- `not_authorized`'s copy was action-specific ("You don’t have shell access to this
  device") while the condition already answered observe, replay and `sql:read`. Now
  "You don’t have access to do that here"; `conditions.ts` regenerated.
- The console's Permissions tab renders a refusal panel instead of an empty table, and
  hides "Add permission". An empty table under that button says the opposite of what
  happened.
- `tests/console/console.spec.ts` seeds through `authorizer.admins` and then grants real
  admin permissions, so the console's own administration runs on a grant rather than the
  break-glass; a second token (`visitor@example.com`, shell only) drives the refusal.
- `demo/oarlock.yaml` gained `authorizer.admins: [admin@mail.com]`, and `make
  demo-seed-permissions` now seeds `gateway-admin` and `fleet-admin`.
- `demo/oarlock.yaml`'s `url` was stale at `ws://192.168.1.32:8443`; this machine is now
  `192.168.1.165`, which is why the agent could not dial back and `tests/live` failed.
  Updated. **Re-check this after any network change** — the Android APK also needs it.

Tests: `internal/apisrv/admin_test.go` (12 tests, including the escalation walk and the
break-glass boundary) and `TestAdminsAreExactPrincipalIds` in `internal/config`. Each
guarantee was checked by injecting its inverse — neutering the gate, making every action
administrative, removing the break-glass, gating your own session, and checking the
submitted body instead of the stored record — and every injection failed a test.

Verified: `go test ./...`, `go vet ./...`, `npm run typecheck`, `npm run build:ui`, and
`npm test` at **155 passing including `tests/live`**, against a real `oarlockd` + agent with
a shell opened in the browser.

### Current uncommitted work

- Rebuilt the admin UI into a compact fleet workspace with device editing, enable/disable,
  live agent controls, session history, and responsive desktop/mobile layouts.
- Device disabling now refuses handshakes and shells, stops the connected reference agent,
  and preserves session history.
- Added a read-only SQL Explorer:
  - `sql:read` is a distinct authorization action scoped to device id `gateway`.
  - `GET /api/v1/sql/schema` returns only curated operational tables/columns.
  - `POST /api/v1/sql/query` accepts one bounded `SELECT` or `WITH` query.
  - Queries run against an isolated in-memory snapshot; API token and device-key tables are
    never copied into it.
  - Maximum 500 rows, 64 columns, 16 KiB SQL, and a two-second API timeout.
  - Every attempt emits `sql.query`; the audit event stores a SHA-256 fingerprint rather
    than raw SQL or literals.
  - The admin tab includes schema filtering, a query editor, result grid, CSV export, and
    recent queries for the current browser tab.
- Split React and xterm into Rollup vendor chunks; the UI build no longer emits the chunk
  size warning.
- Added a standalone Android/VR APK under `android/`:
  - A gomobile-safe Go wrapper runs the existing agent core in-process.
  - A native Android foreground service keeps the control channel alive without `adb`.
  - The app generates its Ed25519 key in private storage and displays the public key.
  - Saved configuration survives Android recreating the sticky service.
  - Debug builds permit local `ws://`; release manifests default to TLS-only.
  - The ARM64 JNI library is linked for 16 KB Android memory pages.
  - `make android-apk` writes `dist/oarlock-agent-android-arm64-debug.apk`.

- Added admin device management:
  - SQLite-backed device registry in `internal/registry/sqlite`.
  - Device registry admin interface in `pkg/plugin/device.go`.
  - Device CRUD API:
    - `GET /api/v1/devices`
    - `GET /api/v1/devices/{id}`
    - `POST /api/v1/devices`
    - `PUT /api/v1/devices/{id}`
    - `DELETE /api/v1/devices/{id}`
  - Admin UI support in `web/src/App.tsx` and `web/src/api.ts` for listing, adding, and deleting devices.
  - Demo config now uses SQLite device registry via `demo/oarlock.yaml`.

- Fixed admin agent stop behavior:
  - `DELETE /api/v1/agents/{device_id}` now sends `admin_stop`.
  - The reference `oarlock-agent` exits instead of reconnecting after admin stop.
  - WebSocket close handling treats normal peer-close paths as clean.

- Added broader feature work in the same commit:
  - Webhook authorizer plugin.
  - MQTT dispatcher plugin.
  - Delegated API authentication support.
  - Audit sink plumbing.
  - Record input policy plumbing.
  - Docs and examples updated.

## Important Behavior Notes

- Legacy config remains supported:
  - `devices: ./devices.yaml` uses the file registry and keeps the old session DB placement behavior.

- SQLite registry config:
  ```yaml
  store:
    kind: sqlite
    path: ./oarlock.db

  devices:
    kind: sqlite

  authorizer:
    kind: sqlite
  ```

- `demo/oarlock.yaml` is set up for UI testing with SQLite:
  - device records are stored in `demo/oarlock.db`
  - permissions and sessions are stored in the same database
  - deleting `demo/oarlock.db` also removes registered Android keys and permissions; only
    use `make demo-reset` when a fully clean demo is intended

## Verification Already Run

All core checks passed for the current uncommitted tree:

```sh
go test ./...
go vet ./...
npm run typecheck
npm run build:ui
npx playwright test tests/console/console.spec.ts --project=console --grep 'SSH client|permission|shell'
make android-apk
cd android/agent-app && ./gradlew --offline --no-daemon lintDebug --rerun-tasks
```

The full `npm test` run had 152 passes. Its only failure was the optional external
`tests/live/live.spec.ts`, because no separately managed demo server was reachable at
`127.0.0.1:8443`. Browser layout was checked on desktop and at 390x844.

## Manual Test From Zero

```sh
cd /path/to/oarlock
make build
```

Start the server in terminal 1. This preserves the existing device registration:

```sh
make demo-server
```

After a database reset, seed authorization in terminal 2:

```sh
make demo-seed-permissions
```

For the local reference agent, also register its demo key and start it:

```sh
make demo-seed-device
make demo-agent
```

Open UI:

```text
http://127.0.0.1:8443/ui/
```

Token:

```text
dev-token-long-enough-for-the-check
```

For the installed Samsung APK, configure device `samsung-s23`, gateway
`ws://192.168.1.32:8443/ws/control`, and allow insecure WebSocket for this LAN-only dev
test. If the database was reset, copy the APK's displayed public key into a new Fleet
device record before starting the service.

Expected:

- UI shows the registered device.
- UI shows the connected agent.
- Opening a shell succeeds for `admin@mail.com` after permissions are seeded.
- The `SSH client` action downloads `oarlock_known_hosts.txt` and generates a command.
- For the demo operator, set the identity path to
  `/path/to/oarlock/demo/operator_key`.
- SSH listens on `127.0.0.1:2222`, so the generated command is for a client on this Mac;
  the HTTP/control endpoint is the one exposed to the LAN.
- Clicking `Stop` makes the reference CLI agent exit instead of reconnecting. Android
  service lifecycle remains controlled by the APK.

## Current Repo State At Handoff

- Commit `777636b` is still the branch tip; all work described under "Current uncommitted
  work" is intentionally uncommitted at the user's request.
- No server process should be assumed to be running. Rebuild and restart `oarlockd` after
  code/UI changes so the embedded assets and handlers match the current tree.
- `demo/oarlock.yaml` now listens on `0.0.0.0:8443`, advertises
  `ws://192.168.1.32:8443`, and uses `authorizer.kind: sqlite`.
- The Android debug APK is 2.9 MB, signed/aligned, and has SHA-256
  `fd8568d2c601fd30463edb84650e19e41a2f054cb3a4cc9b3d08029d20a9ebe5`.
- The APK was installed on a Samsung S23 and successfully authenticated as `samsung-s23`;
  the gateway logged `control channel up` with `agent=android-apk` over direct Wi-Fi.
- SQLite authorization is implemented in `plugins/authz/sqlite`. The admin UI has a
  Permissions tab and `/api/v1/permissions` CRUD. SQL Explorer exposes the public
  `oarlock_permissions` policy table.
- After rebuilding and restarting the demo, run `make demo-seed-permissions` before
  opening a shell. This migrates the previous demo YAML grants into SQLite idempotently.
- Startup now closes stale SQLite session rows left live by a previous process, releasing
  device concurrency slots. The browser console also rewrites attach WebSocket URLs to
  its own origin, avoiding localhost/LAN Origin mismatches.
- Verification for the permission work: full `go test ./...` passed, `go vet ./...`
  passed, typecheck/build passed, and the focused real-console shell plus Permissions UI
  tests passed. Full `pnpm test` had 152 passes; only the optional external live-demo test
  failed because no server was reachable at its expected `127.0.0.1:8443`.
- The Fleet shell form now has an `SSH client` action. Authenticated
  `GET /api/v1/ssh` returns only public connection metadata, host-key fingerprint and a
  `known_hosts` line. The dialog downloads `oarlock_known_hosts.txt` and generates a
  copyable SSH command using an operator-selected local identity path; private operator
  keys are never served. API, browser download, full Go tests and vet pass.
- Do not commit unless the user asks.
