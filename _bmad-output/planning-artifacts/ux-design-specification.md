---
stepsCompleted: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
inputDocuments:
  - README.md
  - ARCHITECTURE.md
  - SECURITY.md
  - docs/protocol.md
  - docs/plugins.md
  - docs/sdk.md
  - docs/threat-model.md
  - _bmad-output/planning-artifacts/prd-oarlock-2026-08-20.md
  - _bmad-output/planning-artifacts/epics-oarlock-2026-08-20.md
  - _bmad-output/planning-artifacts/implementation-readiness-report-2026-08-20.md
  - _bmad-output/planning-artifacts/adversarial-review-spec-2026-08-20.md
  - _bmad-output/planning-artifacts/research-technical-oarlock-2026-08-20.md
  - _bmad-output/planning-artifacts/research-domain-oarlock-2026-08-20.md
workflowType: 'create-ux-design'
project_name: oarlock
unblocks: 'Epic 3 (M2 — the browser)'
---

# UX Design Specification oarlock

**Author:** Tphuc
**Date:** 2026-08-21

---

## Executive Summary

Oarlock's interface has one job: **let an operator work on a device without ever being
unsure what they are working on, who can see it, or whether it is being kept.**

That is not a generic goal. It follows from the one thing the architecture cannot give
the operator for free — in SSH, the gateway can print a banner into an authenticated
byte stream, and a browser has no such channel. Every decision below is downstream of
replacing that banner with something at least as trustworthy.

**Two audiences, deliberately unequal.**

| | who | what they get |
|---|---|---|
| **Primary** | an integrator embedding a terminal in an admin console they already own | `@oarlock/terminal`, plain CSS, `theme="inherit"`, typed failure events |
| **Secondary** | an operator or auditor using Oarlock directly | `/ui`, a small reference console: sessions, terminal, replay |

The component is the product; the console is the reference implementation and the
thing `go run` has to show. Where they disagree, the component wins.

**Four decisions taken in this session**, each with a cost accepted knowingly:

1. **Component *and* reference console.** More surface to maintain, but the six
   failure screens need a home and `go run` needs something to look at.
2. **Plain CSS for the component, Tailwind + shadcn/ui for the console.** Two styling
   systems in one repository — accepted so that integrators inherit no CSS framework,
   while the console can be built quickly and look considered.
3. **Status bar always; a blocking acknowledgement only when the session is
   unrecorded or passthrough.** Two code paths, so that friction lands where risk is
   and routine work stays frictionless.
4. **Observation shown as a persistent indicator, not a toast.** Easier to stop
   noticing, and true for exactly as long as it is true.

**What was not open for design.** `ARCHITECTURE.md` § 11 already fixes eleven
condition→screen mappings. The UI renders those; it does not invent states, and it
never infers a reason. If a screen has no server condition behind it, it is a bug.

## Core User Experience

The experience the whole design serves, in one sentence: **an operator opens a shell,
does the work, and leaves — and at no point has to wonder about the four facts that
would change their behaviour.**

Those four facts, in the order they matter:

| fact | why it changes behaviour | where it lives |
|---|---|---|
| **which device** | the wrong treadmill is somebody's afternoon | status bar, always |
| **recorded or not** | an unrecorded session is unauditable; a recorded one may capture what you paste | status bar, always; plus a gate when unrecorded |
| **who else is watching** | you behave differently when observed, and you are entitled to know | status bar, while true |
| **why it ended** | "connection lost" and "your access was revoked" mean different next actions | failure screen, one per server condition |

**The critical path is short and it is the common case.** From "I need a shell on
treadmill-4821" to a prompt: click Shell → two progress lines → prompt. Everything
else in the console is subordinate to not slowing that down.

**Reattach is invisible.** A dropped connection is the normal case, not an error: the
session stays attached server-side, the ring buffer replays, and the terminal shows a
reconnecting state rather than a dead pane. An operator who loses wifi mid-command
should discover that nothing happened.

## Desired Emotional Response

The register is **instrument, not dashboard.** An operator reaching for this is
usually mid-incident: something is broken, somebody is waiting, and the interface's
job is to disappear.

| we want them to feel | so we | we must never |
|---|---|---|
| **oriented** | state the four facts without being asked | make them hunt for which device this is |
| **unsurprised** | show progress as two named waits, not one spinner | let a slow doorbell look like a hang |
| **trusted, and trusting** | say plainly that the gateway reads every keystroke | imply privacy the architecture does not provide |
| **unhurried at the right moments** | put a deliberate gate in front of an unrecorded session | add friction to the routine path |

**The feeling to design against is *false confidence*.** A terminal that looks like a
normal terminal, in a product where some sessions are unrecorded and some are watched,
is the failure mode. Every ambient element on screen exists to prevent an operator
being confidently wrong about their situation.

**Tone of copy: flat and specific.** "The agent didn't answer." not "Something went
wrong". No apologies, no exclamation marks, no reassurance. An operator reading an
error at 2 a.m. wants a noun and a next step.

## UX Pattern Analysis & Inspiration

Studied, and what was taken:

| source | taken | rejected |
|---|---|---|
| **Tailscale SSH console** | the session list as the primary object, and recording state visible per row | its device-centric navigation — an operator here arrives knowing the device |
| **Teleport web terminal** | the persistent session header, and replay as a first-class artefact | the tab-per-session model; one session at a time is the honest shape when a device allows one |
| **Cloud shell / Cloud9** | connection-state as an ambient strip rather than a modal | the IDE furniture around it |
| **asciinema player** | the whole replay surface — do not build a player | nothing; take it as it is |
| **GitHub Actions logs** | progress as *named* sequential steps, each with its own state | the collapsible-group nesting; two steps need no tree |
| **Stripe's dangerous-action dialogs** | the shape of a blocking acknowledgement that names the consequence rather than asking "are you sure?" | typing a resource name to confirm; wrong friction for a routine shell |

**The pattern most worth stealing** is the GitHub Actions step list, and the reason is
specific: the architecture has *two separate waits* — waking the agent and opening the
tunnel — and either can be the one that stalls. A single spinner would throw away
information the gateway already has and the operator needs.

**The pattern most worth refusing** is a terminal that looks exactly like a local
terminal. Familiarity is usually a virtue and here it is a hazard.

## Design System Foundation

Two systems, one token vocabulary. The split is deliberate and the boundary is
absolute.

### The component: plain CSS, no framework

`@oarlock/terminal` ships **CSS custom properties and nothing else** — no Tailwind, no
CSS-in-JS, no build step imposed on the consumer.

- **Why:** it renders inside somebody else's application. A framework's reset or
  utility classes would either collide with the host's styles or force the host to
  adopt our toolchain. Neither is acceptable for the primary audience.
- **`theme="inherit"`** reads the host's own custom properties where they exist,
  falling back to ours. An integrator gets a terminal that looks like their product
  without configuring anything.
- **Scoped:** every selector lives under a single `.oarlock-term` root, and every
  property is namespaced `--oarlock-*`. No bare element selectors, ever.

### The console: Tailwind + shadcn/ui

`/ui` uses Tailwind and shadcn/ui, and imports the component as-is.

- **Why:** the console is a reference implementation and a demo. Building it quickly
  and having it look considered matters more than architectural purity, and no
  integrator inherits it.
- **Accepted cost:** two systems to keep coherent. Mitigated by one rule — **the
  token values are defined once**, in a single source that emits both the component's
  custom properties and the Tailwind theme. A colour is never written twice.

### Tokens

Semantic, never literal. `--oarlock-state-recorded`, not `--oarlock-green`: the point
of the token is that it survives a change of mind about the colour.

| token group | members |
|---|---|
| surface | `bg`, `bg-raised`, `bg-terminal`, `border`, `border-strong` |
| text | `fg`, `fg-muted`, `fg-faint`, `fg-inverse` |
| state | `recorded`, `unrecorded`, `observed`, `reconnecting`, `ended`, `refused` |
| terminal | 16 ANSI slots plus `cursor`, `selection` |

**Themes:** light and dark, both first-class, and the component must render correctly
in a host that has stamped neither — so every value is defined on the bare root and
only *overridden* under a dark selector.

## Defining Experience

The one interaction that has to be right, and which the product would be judged on:
**the moment between clicking Shell and getting a prompt.**

It is the defining experience because it is where the architecture is most visible and
least forgiving. The gateway has to wake a device that may be asleep on a cellular
radio, pair two connections, start a recording, and hand over a terminal — and any of
those can be slow or fail, each for a different reason with a different remedy.

**Designed as two named waits, never one spinner:**

```
  ✓  Authorised as phuc@example.com
  ⟳  Waking treadmill-4821…            up to 30s
  ○  Opening the tunnel
```

- Each step shows its own state, and a step that is waiting says **what it is waiting
  for and roughly how long is reasonable.** A doorbell that takes twenty seconds is
  normal on a sleeping radio; a spinner cannot say that, and an operator who thinks
  the UI has hung will reload and open a second session.
- A failure replaces its own step, in place, with the sentence for that condition —
  not a generic error banner. The step that failed *is* the diagnosis.
- **On success the steps disappear.** They are scaffolding for a wait, not a log.

**Why this over a progress bar:** a bar implies a knowable fraction. Nothing here has
one. Two honest states beat a dishonest percentage.

## Visual Design Foundation

**Typography.** Two faces, both with a job.

- **Interface:** a neutral grotesque, 14 px base, 1.5 line height. Deliberately not
  characterful — the terminal's content is the subject and the chrome must not
  compete.
- **Terminal:** a monospace with a genuinely distinguishable `0/O`, `1/l/I`, and
  visible punctuation. This is not aesthetics: an operator copying a device id or
  reading a hex hash out of a `verify` result cannot afford an ambiguous glyph. The
  same face is used for device ids, session ids and hashes **everywhere in the
  console**, so those values are recognisably machine values wherever they appear.

**Colour.** Restrained, and load-bearing only where it carries meaning.

| meaning | treatment | never relies on colour alone |
|---|---|---|
| recorded | calm accent, filled dot | the word `RECORDED` |
| **not recorded** | amber, hollow dot | the words `NOT RECORDED` |
| passthrough | amber, hollow dot | the word `PASSTHROUGH` |
| observed | distinct hue, eye glyph | "watched by \<name\>" |
| reconnecting | muted, pulsing dot | the word `Reconnecting` |
| ended / refused | neutral / red | the close reason, spelled out |

**Density.** The terminal gets the space; everything else is compact. The status bar is
two lines at most and never grows. A session list is a table, not cards — an operator
scanning for one device wants rows.

**Motion.** Almost none. A pulse on `reconnecting`, a fade on the progress steps
disappearing. `prefers-reduced-motion` removes both. Nothing animates on the terminal
surface, because a moving element next to scrolling text is a distraction in exactly
the situation where attention matters.

## Design Direction Decision

**Chosen direction: instrument.**

The interface presents itself as a piece of equipment with a readout — closer to a
console than to a web application. Chrome is thin, values are monospaced, state is
ambient and always-on, and the terminal is the only thing with visual weight.

**Considered and rejected:**

- **Dashboard.** Charts, tiles, fleet overview. Rejected because the operator arrives
  knowing which device they want; a dashboard optimises for browsing, and browsing is
  not the journey. E6.S5's operational dashboard is a different artefact for a
  different reader.
- **Chat-like session view.** Rejected because a terminal is not a conversation and
  pretending otherwise breaks the mental model of a shell.
- **IDE.** Rejected outright. File trees and panels imply capabilities Oarlock
  deliberately does not have, and the spec is explicit that this is not a development
  environment.

**The risk in "instrument"** is coldness reading as unfinished. The mitigation is
craft in the small: exact alignment, real empty states, copy that sounds like a person
wrote it.

## User Journey Flows

### J2 — Operator, browser, no terminal to hand

```
 admin console                    Oarlock
 ─────────────                    ───────
 [Shell] on treadmill-4821
        │
        ├─ backend: POST /api/v1/sessions ──▶ 201 {session, attach ticket 60s}
        │
        ▼
 ┌──────────────────────────────────────────────┐
 │ ✓ Authorised as phuc@example.com             │
 │ ⟳ Waking treadmill-4821…          up to 30s  │   two named waits
 │ ○ Opening the tunnel                         │
 └──────────────────────────────────────────────┘
        │
        ├─ unrecorded or passthrough? ─▶ blocking acknowledgement
        │
        ▼
 ┌──────────────────────────────────────────────┐
 │ ● treadmill-4821   RECORDED    phuc@…        │   status bar, always
 ├──────────────────────────────────────────────┤
 │ $ █                                          │
 └──────────────────────────────────────────────┘
        │
        ├─ wifi drops ─▶ bar: "Reconnecting…"  terminal dims, input queues
        │               fresh ticket, reattach, scrollback replays
        │               (authorisation is re-checked for free)
        ▼
 session ends ─▶ summary: reason · duration · exit code · [Replay]
```

**The two moments that carry the design:** the named waits, and reattach being
undramatic. A dropped connection must not look like a failure, because it is not one.

### J5 — Auditor

```
 sessions list                       replay
 ─────────────                       ──────
 filter: device · operator · state   ┌────────────────────────────┐
 ┌────────────────────────────────┐  │ ✓ integrity verified       │
 │ ● sess_01J8Z  treadmill-4821   │  │   chain intact, 402 events │
 │   phuc@…  4m  RECORDED  ▸      │  ├────────────────────────────┤
 │ ○ sess_01J8Y  rower-9001       │  │  [asciinema player]        │
 │   sam@…   1m  NOT RECORDED     │  │                            │
 └────────────────────────────────┘  └────────────────────────────┘
```

- **`NOT RECORDED` is a row state, not a missing link.** An unrecorded session is a
  queryable fact and the list shows it as one; an auditor must never have to notice an
  absence.
- **The integrity verdict is above the player, before playback.** It is the first
  thing read, because a recording that does not verify should not be watched as though
  it does. A failed verdict states which of the five outcomes it was — `truncated`
  reads differently from `altered`.
- **Replay requires the `replay` grant**, and having `shell` does not confer it. The
  list is visible to an auditor who cannot open a single session.

### J-observer — FR13, read-only attachment

```
 the observer                      the operator being observed
 ────────────                      ───────────────────────────
 [Watch] on a live session         │ ● treadmill-4821  RECORDED  │
        │                          │   👁 watched by sam@example… │
        ▼                          └──────────────────────────────┘
 ┌──────────────────────────────┐
 │ ⊘ READ-ONLY · watching phuc@ │   input disabled, visibly
 ├──────────────────────────────┤
 │ $ logcat -d                  │
 └──────────────────────────────┘
```

- The observer's own terminal says `READ-ONLY` and its input is **disabled rather than
  ignored** — a keystroke that silently does nothing is worse than one that cannot be
  typed.
- The observed operator's indicator persists for as long as it is true and **names the
  watcher**. Anonymous observation is not offered at any level of the UI.

## Component Strategy

### Shipped to integrators

| component | responsibility | notes |
|---|---|---|
| `<Terminal>` | xterm.js, resize, reconnect, ticket renewal, typed failure events | the whole product for the primary audience |
| `<StatusBar>` | the four facts | exported separately, so an integrator who wants their own chrome cannot accidentally ship without the disclosure |
| `<PreflightGate>` | blocking acknowledgement | exported; **rendered by `<Terminal>` automatically** when the session is unrecorded, so opting out has to be deliberate |
| `<Player>` | asciinema-player plus the integrity verdict | verdict is not optional and not suppressible |

**The rule that shapes this list:** the disclosure components are *default-on*. An
integrator has to take an explicit step to remove them, and the prop that does it is
named to make its consequence obvious.

### Console only

`SessionList`, `SessionRow`, `ProgressSteps`, `FailureScreen`, `FilterBar`,
`EmptyState`, `DeviceBadge` — shadcn primitives underneath, no export surface.

### State

Server state is the truth; the UI holds almost none. Session state comes from the API
and from typed events on the socket; there is no client-side state machine mirroring
the server's, because two state machines disagree eventually and the UI's copy would
be the wrong one.

## UX Consistency Patterns

Rules, so that six screens built at different times still feel like one product.

**1. A screen renders exactly one server condition.** Eleven conditions,
eleven screens (`ARCHITECTURE.md` § 11). The UI never infers, never combines, never
guesses. A state with no condition behind it is a bug, not a design decision.

**2. Every failure names the thing and the next action.** "The agent didn't answer.
The device may be asleep — try again in a moment." Never "Error", never a code as the
headline. The correlation id is shown small, copyable, and labelled *for support* —
present for the report, not shouted at the operator.

**3. Machine values are monospaced everywhere.** Device ids, session ids, hashes,
principals. Consistently, so they are recognisable as values rather than prose.

**4. Destructive and irreversible actions state the consequence, not the question.**
"End this session" with what happens beneath it, rather than "Are you sure?".

**5. Nothing important is only a colour.** Every state carries a word or a glyph.

**6. Empty states say what would fill them.** "No sessions in the last 24 hours" with
the filter that would widen it — never an illustration and never a blank panel.

**7. Time is absolute on hover, relative at rest.** `4m ago`, with the RFC 3339
timestamp in a tooltip and in copy. An auditor needs the exact instant; an operator
needs "recently".

**8. The status bar never disappears, never scrolls, never collapses.** It is the one
element with no dismissal affordance at all.

## Responsive Design & Accessibility

**Responsive.** The terminal is the layout.

| width | layout |
|---|---|
| ≥ 1024 px | session list beside the terminal; status bar two lines |
| 640–1024 px | list collapses to a drawer; terminal full width |
| < 640 px | terminal only, status bar condenses to one line with the recording state kept and the principal dropped |

A phone is not a realistic place to run a shell, and the design does not pretend
otherwise — but a status bar that reads correctly on a phone is worth having, because
somebody will open a link on one to check whether a session is still live.

**Accessibility.** Not a checklist item; two of these are security requirements
wearing accessibility clothes.

- **The disclosure is announced.** The status bar is an `aria-live="polite"` region,
  so a screen-reader user learns the recording state and the observer without polling
  it. A disclosure only sighted users receive is not a disclosure.
- **The preflight gate is a real modal**: focus trapped, `Escape` cancels rather than
  proceeds, and the acknowledging control is not the default focus — an accidental
  `Enter` must not open an unrecorded session.
- **Keyboard:** every action reachable without a pointer. The terminal captures most
  keys by design, so entering and leaving it is one documented, discoverable shortcut,
  shown in the chrome rather than hidden.
- **Contrast:** WCAG AA minimum for chrome; the terminal's ANSI palette is checked for
  AA against its own background, which most default terminal palettes fail.
- **Motion:** `prefers-reduced-motion` removes the pulse and the fade. Nothing depends
  on either.
- **Focus:** always visible, never removed — including inside the terminal, where the
  focus ring is how a keyboard user knows their keys are going to the device.

## Open questions for implementation

Named rather than assumed, so E3 story planning starts from a known edge:

1. **Where does the preflight gate live for an integrator who renders their own
   chrome?** It is default-on inside `<Terminal>`, but an integrator using only
   `<StatusBar>` could compose their way around it. Decide whether the component
   refuses to render an unrecorded session without an acknowledged gate.
2. **Observer consent, not just notification.** FR13 requires the observed operator to
   be *told*. Whether they may *refuse* is a product decision nobody has made, and the
   UI shape differs sharply between the two.
3. **Scrollback size on reattach.** The ring is 256 KiB server-side; how much a
   browser renders on replay without janking is an implementation measurement, not a
   design choice.
4. **Multi-session console layout** if `sessions_per_device` is ever raised above one.
   The current design assumes one session at a time and would need tabs, which the
   direction deliberately rejected.
