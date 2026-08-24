# Android and VR agent

Two ways to run the agent on Android, and they differ in one thing that matters more than
the packaging: **what a session can touch.**

| | app (APK) | `init` service |
|---|---|---|
| Needs your own system image | no | **yes** |
| Foreground service and notification | required | none |
| Survives a reboot by itself | sticky service | yes, from `init` |
| A session can read | your app's files | whatever the uid allows |
| `pm`, `am`, `dumpsys`, `logcat` | no | yes, as `shell` |
| MDM can install it | yes | no — it ships in the image |

There is no third option where an MDM runs a shell command. Android Enterprise has no
such capability: the command set is `LOCK`, `REBOOT`, `RESET_PASSWORD`, `CLEAR_APP_DATA`,
`WIPE`. Apps are sandboxed under separate uids and nothing privileged is exposed to a
device-owner app. If you need a session that can see the system, the image has to be
yours.

The APK runs Oarlock in-process as a foreground service. It does not extract or execute
the `oarlock-agent` command, and it does not need `adb` after installation.

## Build

Requirements: Go 1.26, Java 17, Android SDK 35, Android NDK 27.1, and network access the
first time the pinned gomobile tools are installed.

```sh
make android-apk
```

The debug APK is written to:

```text
dist/oarlock-agent-android-arm64-debug.apk
```

It supports `arm64-v8a`, Android 8.0 (API 26) and newer. The debug certificate is for
device testing only; a store, MDM, or production sideload needs a release signing key.

## Install without adb

Transfer the APK through the headset browser, cloud storage, MDM, vendor device manager,
or a private app store. Allow installation from that source when Android asks, then open
**Oarlock Agent** from the headset's app library.

The app creates an Ed25519 key in its private storage and displays the public half. Add a
device in the Oarlock admin UI using the same device ID and that public key:

```text
Platform: Android
Mode: Dispatch
Profiles: shell
```

Set the gateway to a URL the headset can reach, for example:

```text
wss://gateway.example.com/ws/control
```

`127.0.0.1` on the headset is the headset, not the gateway. Cleartext `ws://` is enabled
for local development; production deployments should use `wss://` and configure the
gateway certificate pin shown by the deployment.

After **Start agent**, the foreground notification owns the control channel. The activity
may be closed. **Stop** in the notification, **Stop agent** in the app, disabling the
device in the admin UI, or disconnecting the live agent all terminate the service cleanly.

For the database-backed demo authorizer, initialize the standard grants after starting
the gateway:

```sh
make demo-seed-permissions
```

The **Permissions** tab can then grant `shell` or `exec` to an operator principal for the
Android device ID without editing `rules.yaml`.

## Android boundaries

The shell is `/system/bin/sh` running as the app's Android UID. It is not root and cannot
read other apps' private storage. Some headset vendors apply additional background or
battery policies; allow unrestricted background activity for Oarlock Agent if the service
is suspended while the headset sleeps.

## As an `init` service, on your own image

The binary, with no NDK and no gomobile — the same source and the same code path as the
agent that runs on a server:

```sh
make android-binary          # → dist/oarlock-agent-android-arm64
```

Three files go into the image:

| file | destination |
|---|---|
| `dist/oarlock-agent-android-arm64` | `/system/bin/oarlock-agent` |
| `android/system/oarlock.rc` | `/system/etc/init/oarlock.rc` |
| `android/system/agent.conf.example` | `/data/vendor/oarlock/agent.conf` |

The config lives in `/data` and not in the image because everything in it is a thing an
operator changes: the gateway moves, pins rotate, a privilege decision gets revisited.

### The one line that decides everything

`init` runs a service as root unless told otherwise, and the agent hands a session
whatever identity it holds. **Without `user shell` in the `.rc` file, every recorded
shell on every machine is a root shell.**

```
service oarlock /system/bin/oarlock-agent -config /data/vendor/oarlock/agent.conf
    user shell
    group shell log inet
    seclabel u:r:shell:s0
```

`uid 2000` (`AID_SHELL`) is what `adb shell` runs as: it reaches `pm`, `am`, `dumpsys`,
`logcat` and `settings`, it cannot reach another app's data, and its SELinux domain has
been hardened for a decade by people who do this full time. Start there and add only what
a technician demonstrably needs — a `capabilities NET_RAW` line for `tcpdump` is a far
smaller grant than `user root`.

`inet` (AID_INET, 3003) is not optional: without it `socket()` fails and the agent cannot
dial the gateway at all.

**SELinux is the real boundary, not the uid.** Even root is confined on Android. Reusing
`u:r:shell:s0` inherits a policy somebody already got right; a dedicated `u:r:oarlock:s0`
is better isolation and a week of chasing denials.

### Two privilege tiers on one device

Drop `user shell`, let `init` start the agent as root, and let the agent drop per session:

```yaml
sessions:
  user: "2000:2000"          # AID_SHELL — anything without an entry below
  groups: [1007, 3003]       # log, inet
  per_profile:
    shell: "2000:2000"       # on-call
    exec:  "9999:9999"       # field service, a dedicated lesser uid
```

This is the shape `sshd` has: the supervisor is privileged and no session ever is. It is
the only reason running this as root is defensible.

Two behaviours worth knowing:

- **A misconfiguration is refused at boot, not at the first session.** If the agent is not
  privileged enough to reach a configured uid it says so and exits, rather than failing
  thirty seconds after an operator clicked Open.
- **Asking to run sessions as the user the agent already is does nothing.** Changing
  identity goes through `setgroups`, which needs `CAP_SETGID` even when the uid is
  unchanged — so an unprivileged agent configured that way would fail every session. The
  agent treats it as "inherit" and the startup log says which of the two happened.

### DNS

`make android-binary` builds without cgo, which means Go's own resolver — and that reads
`/etc/resolv.conf`, which Android does not have. The fallback is `127.0.0.1:53`, where
nothing is listening, so a gateway URL with a hostname never resolves. Name the servers:

```yaml
dns: ["1.1.1.1", "8.8.8.8"]
```

An address without a port gets `:53`. The alternatives are an IP in the gateway URL, or
building with `CGO_ENABLED=1` and the NDK so bionic resolves instead.

### The device id

One image and one config serve the whole fleet, so the id comes from a file rather than
from the config or the service's argv — `init` cannot reliably expand a property into an
argument:

```yaml
device_file: /data/vendor/oarlock/device-id
```

`oarlock.rc` writes it once at first boot from `ro.serialno`. An asset id from your own
provisioning is usually the better choice.

### What this does not solve

- **Revocation kills the session's process group, not everything it started.** Each
  session gets its own session and process group and is `SIGHUP`ed on close, so ordinary
  background jobs die with it. A deliberate `setsid` escapes that, and on a privileged
  shell the residual is real. A per-session cgroup is the fix if it matters.
- **Root on the device compromises the device identity.** The key is a file; a privileged
  session can read it and impersonate the machine. Use a keystore or TEE if the hardware
  offers one. This is true of any design where the device holds a key.
- **Recordings are safe from all of this**, because they are written on the gateway rather
  than the device. Nothing a session does locally can edit or delete what it did — which
  is the property that makes a privileged device shell auditable at all.
