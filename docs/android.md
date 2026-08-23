# Android and VR agent

The Android APK runs Oarlock in-process as a foreground service. It does not extract or
execute the `oarlock-agent` command, and it does not need `adb` after installation.

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
