# `@oarlock/terminal`

A browser terminal for an [Oarlock](../../README.md) gateway: xterm.js, the wire codec,
and the disclosure rules that make an unrecorded session look different from a recorded
one.

```ts
import { mount } from "@oarlock/terminal";
import "@oarlock/terminal/oarlock.css";

const handle = mount(document.getElementById("shell")!, {
  url: attach.url,            // from POST /api/v1/sessions
  ticket: attach.ticket,       // single-use, 60 s
  device: "treadmill-4821",
  principal: "phuc@example.com",
  renewTicket: () => api.renewAttach(session.id),
});
```

`@oarlock/react` wraps this as `<Terminal>`. Both are thin: everything that matters is
here, so a wrapper for another framework inherits it rather than reimplementing it.

## What it will not do

**Render an unrecorded session without an acknowledgement.** When `READY` says the
session is unrecorded or in passthrough, `mount` shows a blocking gate and there is no
terminal behind it — a gate over a live terminal is decoration, because the operator can
read the screen through it and a stray keystroke reaches the shell. Output that arrives
while the gate is up is held and replayed afterwards, not shown and not dropped.

The one way past it is `acknowledgeUnrecordedWithoutPrompt`, named for its consequence
rather than its mechanism so that using it is a decision. `<StatusBar>` and
`<PreflightGate>` are exported separately for a host that wants its own layout, and
composing with them does not disable the refusal.

A `READY` with no `recording` field counts as unrecorded. Falling the other way would
make a missing byte indistinguishable from a promise.

**Let the device touch the operator's machine.** The device at the far end is the
untrusted party. OSC 52 clipboard writes are swallowed by a handler this package
registers — not merely absent upstream, because the risk is a default changing under a
dependency bump — and every window-reporting sequence is answered with silence: the
title, the size, the position. `allowDeviceClipboardWrites` and
`allowDeviceTitleChanges` opt in per instance.

**Style your application.** Every rule this package writes is scoped under one
`.oarlock-term` class and every custom property is namespaced `--oarlock-*`. There are
no resets and no bare element selectors. xterm's own stylesheet is imported and arrives
under its `.xterm*` namespace, which is the honest trade: scoping it would mean
rewriting a dependency's selectors on every upgrade, and making each integrator remember
a second CSS import fails as a silently broken terminal.

## Subpaths

| import | needs a DOM |
|---|---|
| `@oarlock/terminal` | yes — pulls in xterm.js |
| `@oarlock/terminal/frame` | no — the wire codec |
| `@oarlock/terminal/disclosure` | no — the policy and the four facts |
| `@oarlock/terminal/session` | no — the socket controller |

The three DOM-free subpaths exist so the policy can be tested in Node and reused by a
non-browser consumer.

## Tests

From the repository root: `pnpm test`. The disclosure policy and the codec are tested as
pure functions; everything about rendering is tested in real Chromium, because xterm.js
needs a real canvas.

## Replay

```ts
import { mountPlayer } from "@oarlock/terminal";
import "@oarlock/terminal/player.css";   // replay only

mountPlayer(document.getElementById("replay")!, {
  cast,                 // the asciicast text
  verdict,              // what your gateway's verifier said
  sessionID: "sess_01J8Z…",
});
```

**The integrity verdict is not a prop.** It renders above the recording, in the document as
well as visually, and there is no option that removes it. A player that shows a tampered
recording exactly like an intact one is a player that launders it, and the hash chain and
signed manifest exist so that somebody reading a session afterwards can tell the
difference.

You supply the verdict rather than the component computing one: verification needs the
manifest and a public key your *deployment* trusts, which is not a decision a browser can
make for itself. What the component guarantees is that the answer is on screen — including
when the answer is "you did not give me one", which renders as **unverified** rather than
as fine. A verdict claiming `valid` without `ok` resolves pessimistically, and a status
this build has never heard of withholds the claim of integrity rather than implying it.

The five outcomes are separate screens because they send somebody to different places: a
truncation usually means a process died and is often still useful; an alteration means
somebody edited the file; a bad signature may simply mean the recording belongs to another
deployment. `player.css` is separate from `oarlock.css` because asciinema-player ships
around 120 global rules, and embedding a live terminal should not drag them in.
