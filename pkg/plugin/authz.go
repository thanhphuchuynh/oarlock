package plugin

import (
	"context"
	"strconv"
	"strings"
	"time"
)

// Action is what an operator is trying to do. The closed set from
// ARCHITECTURE § 7: a backend that receives an action it does not recognise should deny
// rather than guess, because guessing widens a grant.
type Action string

const (
	ActionShell     Action = "shell"
	ActionExec      Action = "exec"
	ActionFileRead  Action = "file:read"
	ActionFileWrite Action = "file:write"
	ActionTCP       Action = "tcp"
	// ActionLog streams a device log source. Its own action rather than a flavour of
	// `file:read`, because the two answer different questions: a log tail names a source
	// the *device* published, and a file read names a path the *operator* chose. One of
	// those a policy can be written about across a mixed fleet; the other cannot.
	ActionLog Action = "log"
	// ActionPassthrough is asking for a session the gateway cannot read.
	ActionPassthrough Action = "passthrough"
	// ActionReplay is reading a recording afterwards.
	ActionReplay Action = "replay"
	// ActionObserve is watching somebody else's live session read-only.
	ActionObserve Action = "observe"
	// ActionSQLRead is querying the gateway's curated operational SQL view.
	ActionSQLRead Action = "sql:read"

	// The administrative actions. These govern changing the gateway's own
	// configuration rather than using a device, and they exist because
	// authentication is not authorisation: a bearer token that proves who you are
	// says nothing about whether you may rewrite the policy that decides what you
	// may do. Without them, every token holder is a super-administrator and every
	// other action in this set is advisory — anyone refused `shell` could grant
	// themselves `shell`.

	// ActionAdminDevices is changing a device's registry record: creating it,
	// editing it, disabling it, deleting it. Checked against the device being
	// changed, so a grant can be scoped to part of a fleet.
	ActionAdminDevices Action = "admin:devices"
	// ActionAdminPermissions is reading or changing the authorisation policy
	// itself. Checked against the gateway rather than a device, because a
	// permission is not device-scoped — and reading the policy is administrative
	// too: it names exactly which principal to go after.
	ActionAdminPermissions Action = "admin:permissions"
	// ActionAdminKill is ending somebody else's live session, or dropping a
	// device's control channel. Checked against the device the session is on.
	ActionAdminKill Action = "admin:kill"
)

// AdministrativeActions is the administrative subset of the action set.
//
// Exported because a caller displaying policy needs to tell "can open a shell on this
// device" apart from "can change this device's record", and the alternative is every such
// caller keeping its own list of which is which — including the browser console, one
// network hop from this one.
func AdministrativeActions() []Action {
	return []Action{ActionAdminDevices, ActionAdminPermissions, ActionAdminKill}
}

// Administrative reports whether an action governs the gateway's own configuration
// rather than the use of a device.
//
// The distinction earns its keep in one place: a break-glass administrator declared in
// the gateway's config file is allowed these and *only* these (see the gateway's
// `authorizer.admins`). Whoever owns the config file can always repair the policy, and
// still cannot open a shell without writing a grant that everybody can see.
func (a Action) Administrative() bool {
	switch a {
	case ActionAdminDevices, ActionAdminPermissions, ActionAdminKill:
		return true
	}
	return false
}

// GrantLimits are per-grant overrides an Authorizer may return.
//
// **They may only tighten.** A grant that widened a limit would let an authorisation
// backend raise the ceilings the gateway operator set, which inverts who is in charge.
// The gateway takes the minimum of the two, always — and because "minimum" is meaningless
// for an unset field, every one is a pointer: absent means "no opinion", not zero.
type GrantLimits struct {
	MaxDuration *time.Duration `json:"max_duration,omitempty"`
	Idle        *time.Duration `json:"idle,omitempty"`
	Rate        *int           `json:"rate,omitempty"`
}

// Decision is an Authorizer's answer.
//
// # Three outcomes, not two
//
// `(Decision{Allow: true}, nil)` allows. `(Decision{Allow: false}, nil)` denies.
// `(_, err)` means the backend **could not decide** — and that is a third thing, not a
// denial with extra steps.
//
// The distinction is the reason this interface returns an error at all. A backend that
// answers `Allow: false` when its own dependency is down writes `revoked` into an audit
// trail for an outage, tells an operator their access was withdrawn when it was not, and
// converts one service's bad minute into a fleet-wide session kill — during the incident
// that put those operators on those devices. `plugintest` fails a backend that does this,
// because documentation has not been enough.
type Decision struct {
	Allow bool
	// Reason is shown to the operator on a deny. Make it actionable: "not in the
	// on-call group" tells somebody what to do, "denied" does not.
	Reason string
	// Limits is an optional per-grant tightening. Nil means no opinion.
	Limits *GrantLimits
	// TTL asks the gateway to re-check this grant sooner than the default. Zero means
	// the default interval. It cannot ask for *later*: a backend that wanted a longer
	// leash would be choosing how stale its own revocations may be.
	TTL time.Duration
}

// RevocationEvent withdraws a grant, as it happens.
//
// Empty fields mean "every": an event with no PrincipalID and no DeviceID revokes
// everything, which is what a backend sends when it has lost track of its own state and
// wants the gateway to stop trusting anything it said. Deliberately expressible, because
// the alternative is a backend with no way to say it.
type RevocationEvent struct {
	PrincipalID string
	DeviceID    string
	Reason      string
}

// Target is the specific thing an action is aimed at, for the actions that have one.
//
// Without it a backend can answer "may this principal forward ports on this device" and
// nothing narrower — and the difference matters, because the ports worth forwarding and
// the ports bound to loopback *precisely so that nobody reaches them* live on the same
// device. The same argument applies to a path under the file root and to an argv under
// `exec`.
//
// # A zero Target means the action names nothing
//
// It does not mean "everything". `shell` has no target: it is a whole device either way,
// which is the point of it being its own action. `admin:permissions` is checked against
// the gateway. A backend that sees a zero Target is being asked about the action itself.
//
// # A backend that ignores Target grants every target
//
// That is the behaviour every backend had before this field existed, and it stays the
// default so that adding the parameter did not silently narrow anybody's policy. It also
// means the widening direction is the *quiet* one, which is worth knowing when reviewing
// a backend: forgetting to read Target is not a compile error.
//
// # The device still refuses on its own
//
// This does not replace the agent's allow-lists, and must not be allowed to. The
// gateway's compromise is total (threat model § 4), so a device that trusted the
// gateway's target check and dropped its own would have moved its last line of defence
// inside the blast radius. Gateway-side targets are policy an operator can edit centrally
// and revoke in thirty seconds; device-side allow-lists are what holds when the gateway
// is lying. Both, always.
type Target struct {
	// Port is the device-local TCP port, for ActionTCP.
	Port int
	// Path is the path relative to the device's file root, for ActionFileRead and
	// ActionFileWrite. Exactly as the operator wrote it: untrusted, and not yet
	// resolved against anything.
	Path string
	// Argv is the command and its arguments, for ActionExec. Argv[0] is the command.
	Argv []string
	// Log is the logical log source, for ActionLog. Not a path: see frame.LogSource for
	// why the gateway names a source the device published rather than a file.
	Log string
}

// IsZero reports whether the action named no target.
func (t Target) IsZero() bool {
	return t.Port == 0 && t.Path == "" && len(t.Argv) == 0 && t.Log == ""
}

// Equal compares two targets.
//
// Target holds a slice, so `==` does not compile on it — which is a good accident: a
// caller reaching for equality is usually a cache key or a re-check assertion, and both
// want to be explicit that Argv compares element by element.
func (t Target) Equal(o Target) bool {
	if t.Port != o.Port || t.Path != o.Path || t.Log != o.Log || len(t.Argv) != len(o.Argv) {
		return false
	}
	for i := range t.Argv {
		if t.Argv[i] != o.Argv[i] {
			return false
		}
	}
	return true
}

// String renders a target for a log line or an audit event.
//
// Deliberately terse and deliberately not round-trippable: this is for a human reading
// a denial, not for a parser. An empty target renders as "-" rather than as nothing at
// all, so a log line never loses a column.
func (t Target) String() string {
	switch {
	case t.Port != 0:
		return "port " + strconv.Itoa(t.Port)
	case t.Path != "":
		return "path " + t.Path
	case len(t.Argv) > 0:
		return "argv " + strings.Join(t.Argv, " ")
	case t.Log != "":
		return "log " + t.Log
	default:
		return "-"
	}
}

// Authorizer answers whether a principal may do something, on a device, right now.
//
// Called more than once per session: at open, every recheck_interval, and on a
// RevocationEvent. The re-check interval is the guarantee and Watch is the optimisation —
// a backend whose Watch is disconnected for a minute costs a minute of staleness, not a
// missed revocation.
//
// Every one of those calls carries the *same* Target the session opened with. A re-check
// that asked about a different target — or about no target — would re-authorise something
// nobody had asked for, and a grant narrowed to one port would never be revoked when that
// narrowing changed.
type Authorizer interface {
	Authorize(ctx context.Context, p *Principal, dev *Device, a Action, t Target) (Decision, error)

	// Watch streams revocations. Returning ErrUnsupported is fine and common: the
	// gateway falls back to polling Authorize.
	//
	// The channel is closed when the stream ends. A closed channel is not a denial —
	// the gateway reconnects with backoff — so a backend must never close it to mean
	// "everything is revoked". Say that with a RevocationEvent.
	Watch(ctx context.Context) (<-chan RevocationEvent, error)
}
