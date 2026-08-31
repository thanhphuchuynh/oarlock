# Diagrams

Three views of how Oarlock protects itself, drawn from the code rather than from the
design documents. Each is a self-contained HTML page: no server, no build step, no
network. Open one in a browser.

| | what it answers | type |
|---|---|---|
| `security-boundaries` | Who is trusted with what, and where each control sits | architecture |
| `port-forwarding` | What `ssh -L` passes through, and every way it is refused | workflow |
| `authentication` | The two authentications — the operator's and the device's | sequence |

## The JSON is the source, and the only thing committed

Each `*.json` is the specification; each `*.html` is compiled from it and is **gitignored**.
Run the commands below to produce the HTML, then open it.

That split is deliberate. The generated artefacts this repository does commit — the wire
vectors, the condition table, the recording fixtures — are small data files. A rendered
diagram is 700 KB, and most of those bytes are a copy of the Archify viewer runtime, three
times over; built web assets are excluded on the same reasoning a few lines above them in
`.gitignore`. The cost of that choice is that you cannot read a diagram straight from a
clean checkout, which is why the regeneration command is right here.

Rendering needs [Archify](https://github.com/tt-a1i/archify), which is **not vendored
here**. It installs as an agent skill:

```sh
npx skills add tt-a1i/archify -g
```

Then, from the repository root:

```sh
A=~/.claude/skills/archify
node $A/bin/archify.mjs deliver architecture docs/diagrams/security-boundaries.architecture.json docs/diagrams/security-boundaries.html --quality showcase --json
node $A/bin/archify.mjs deliver workflow     docs/diagrams/port-forwarding.workflow.json        docs/diagrams/port-forwarding.html      --quality showcase --json
node $A/bin/archify.mjs deliver sequence     docs/diagrams/authentication.sequence.json         docs/diagrams/authentication.html       --quality showcase --json
```

`deliver` is the acceptance command, not `render`: it freezes the specification bytes,
renders that snapshot, runs the artifact checks, and only then commits the HTML. A
non-zero exit means nothing was written and the previous file still stands.

**There is no CI check that these are current, and the HTML is not committed to compare
against.** The generated files elsewhere in this
repository have one — `TestSharedVectorsAreCurrent`, `TestGeneratedTableIsCurrent`,
`TestRecordingFixturesAreCurrent` — and these deliberately do not, because the renderer is
an external tool at a version this repository does not pin. That is a real gap and it is
recorded here rather than discovered later: **a diagram can go stale and nothing will say
so.** Re-render when you change what one of them claims.

## What they claim, and where it came from

The facts on the diagrams were read out of the code, not the design documents, because the
two have drifted before:

- The 15 s pre-authentication budget and the 1024-connection ceiling are
  `internal/sshsrv/preauth.go` and `cmd/oarlockd/app`.
- The refusal reason codes on the port-forwarding diagram — `Prohibited`,
  `ResourceShortage`, `ConnectionFailed` — are the actual `newChan.Reject` arguments in
  `internal/sshsrv/tcpip.go`, so what the diagram shows is what the operator's own `ssh`
  prints.
- The 16-per-device forwarding cap and the rule that a forward never claims the device's
  session slot are `sessions.DefaultTCPConnsPerDevice` and `sessions.HoldsDevice`.
- The Ed25519 exchange is `internal/handshake`, including that the signing input is
  length-prefixed and domain-separated.
- The 30 s re-check is `authz.DefaultRecheckInterval`.

Each diagram also carries a card naming what is **thin** about the area it covers. The one
worth reading first: authorisation is checked per action, per device *and* per target — a
port, a path glob, an argv — but the device keeps its own allow-list underneath, and it has
to. The gateway's compromise is total, so a device that trusted the gateway's target check
and dropped its own would have moved its last line of defence inside the blast radius. The
asymmetry worth knowing before an incident is speed: a gateway grant changes in thirty
seconds; the device's list changes at the pace of a fleet rollout.

## One known defect

`authentication.html` is taller than one screen and scrolls. Every content check passes —
9/9 artifact checks, no composition errors or warnings — but the viewport-containment check
fails, because a sequence diagram's width is fixed by its participant count and the viewer
scales it up to the reading width, which multiplies its height. Archify's own packaged
sequence example overflows harder than this one does. The other two contain at 1440×900,
1600×1000, 1920×1080 and 2048×1320 in both themes.

## Related

[`../threat-model.md`](../threat-model.md) is the prose these draw on, and is the more
complete account: the diagrams show structure, and the threat model is where the residual
risks and the accepted ones are written down.
