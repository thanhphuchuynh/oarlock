// Package condition is the closed set of reasons a session can fail or end, with what
// each one means to the person looking at the screen.
//
// # Why this exists as data rather than as prose in a doc
//
// ARCHITECTURE § 11 says the UI never infers why a session died: each state is rendered
// from exactly one condition, and the mapping is part of the contract. Nothing enforced
// that. The codes were bare string literals in a dozen places, the operator-facing
// sentences lived in comments and in a table in a Markdown file, and the two had already
// drifted — the planning documents specify "eleven conditions, eleven screens" while the
// table listed nine and the epic's own acceptance criterion names a tenth that was in
// neither.
//
// So the set is here, once, and both surfaces read it: the SSH front door prints
// Headline and NextAction, and the browser component renders a screen per condition from
// a generated copy of the same table. A condition that exists in one place and not the
// other is now a build failure rather than a screen somebody notices missing during an
// incident.
//
// # Audience, and why not every code gets its own screen
//
// The wire's closed set includes conditions no operator can act on — a malformed frame,
// a protocol version mismatch, a ticket used twice. Giving each of those a bespoke
// screen would be writing eight ways to say "this is a bug in the application you are
// using". They are marked Integrator instead, and share one screen that says exactly
// that, plus the code and the correlation id for the report.
//
// The distinction is the point: an operator-facing condition tells somebody what to do
// next, and an integrator-facing one tells them it is not their fault.
package condition

import "sort"

// Audience says who can act on a condition.
type Audience uint8

const (
	// Operator conditions have a next action a person at a terminal can take.
	Operator Audience = iota
	// Integrator conditions are faults in the application or the deployment. An
	// operator can only report them, so they share one screen and carry the code.
	Integrator
)

func (a Audience) String() string {
	if a == Integrator {
		return "integrator"
	}
	return "operator"
}

// Kind says where a condition appears on the wire.
//
// It matters because the two arrive at different times and mean different things: an
// error code means the session never started, and a close reason means it ran and
// stopped. "You don't have access" and "your access was withdrawn while you worked" are
// the same fact at two moments, and they are not the same screen.
type Kind uint8

const (
	// Error is a code in an ERROR frame, or in an API problem document.
	Error Kind = 1 << iota
	// Close is a reason in a CLOSE frame, and in the ledger's close_reason.
	Close
)

func (k Kind) String() string {
	switch k {
	case Error:
		return "error"
	case Close:
		return "close"
	case Error | Close:
		return "error|close"
	}
	return "unknown"
}

// Fault says whose problem it is.
//
// Encoded rather than implied, because getting it wrong sends somebody to the wrong
// place: a broken doorbell reported as "device offline" sends an engineer to look at
// hardware in a gym when the push broker is what is down.
type Fault uint8

const (
	// FaultNone: nothing went wrong. A session that ended normally.
	FaultNone Fault = iota
	// FaultDevice: the device or its network.
	FaultDevice
	// FaultGateway: us, or a service we depend on.
	FaultGateway
	// FaultPrincipal: the operator lacks something, or asked for something refused.
	FaultPrincipal
	// FaultClient: the application talking to us is wrong.
	FaultClient
)

var faultNames = map[Fault]string{
	FaultNone: "none", FaultDevice: "device", FaultGateway: "gateway",
	FaultPrincipal: "principal", FaultClient: "client",
}

func (f Fault) String() string { return faultNames[f] }

// Condition is one reason, with everything a surface needs to render it.
type Condition struct {
	// ID is the wire value: the ERROR code, or the CLOSE reason.
	ID       string
	Kind     Kind
	Audience Audience
	Fault    Fault
	// Retryable says whether trying the same thing again could work.
	Retryable bool

	// Headline names the thing. Flat and specific: "The agent didn't answer." — never
	// "Error", never a code, never an apology.
	Headline string
	// NextAction is what to do about it, in one sentence. Empty only where there is
	// genuinely nothing to do.
	NextAction string
}

// set is the whole vocabulary. Adding a code anywhere else in the tree without adding it
// here is what the tests in this package exist to catch.
var set = []Condition{
	// ── the device ───────────────────────────────────────────────────────────────
	{
		ID: "device_not_connected", Kind: Error, Audience: Operator,
		Fault: FaultDevice, Retryable: true,
		Headline:   "This device isn’t connected.",
		NextAction: "It may be powered off or off the network. Check it, then try again.",
	},
	// ── the caller's own retries ─────────────────────────────────────────────────
	{
		// Two different requests under one Idempotency-Key. Refused rather than
		// answered with the first request's session, because answering would hand
		// somebody a shell on a device they did not ask for.
		ID: "idempotency_key_reused", Kind: Error, Audience: Operator,
		Fault: FaultClient, Retryable: false,
		Headline:   "That idempotency key was already used for a different request.",
		NextAction: "Use a new key, or send the original request again unchanged.",
	},
	{
		// The caller retried before its first attempt finished. Retryable on purpose:
		// waiting and asking again is exactly the right move, and it is an answer an
		// SDK can act on without a human.
		ID: "idempotency_in_flight", Kind: Error, Audience: Operator,
		Fault: FaultClient, Retryable: true,
		Headline:   "An earlier request with this idempotency key is still running.",
		NextAction: "Wait a moment and send the same request again.",
	},
	{
		// Told apart from device_not_connected because they send somebody to different
		// places. "Not connected" sends an operator to look at hardware; this one is a
		// device that is connected, holding a control channel to another replica of
		// this gateway, which this node cannot reach across yet. Saying the first when
		// the second is true costs somebody a trip to a machine that is fine.
		ID: "device_on_another_node", Kind: Error, Audience: Operator,
		Fault: FaultGateway, Retryable: true,
		Headline:   "This device is connected to a different gateway node.",
		NextAction: "Try again \u2014 a retry usually reaches the node holding it.",
	},
	{
		ID: "device_offline", Kind: Error | Close, Audience: Operator,
		Fault: FaultDevice, Retryable: true,
		Headline:   "The agent didn’t answer.",
		NextAction: "The device may be asleep — try again in a moment.",
	},
	{
		ID: "device_unreachable", Kind: Error, Audience: Operator,
		Fault: FaultDevice, Retryable: true,
		Headline:   "This device isn’t reachable right now.",
		NextAction: "The wake-up service says it can’t be reached. Try again shortly.",
	},
	{
		ID: "doorbell_failed", Kind: Error, Audience: Operator,
		Fault: FaultGateway, Retryable: true,
		// Deliberately not "device offline". A broken doorbell is our fault, and
		// saying "offline" sends somebody to look at hardware in a gym.
		Headline:   "Can’t reach the device right now.",
		NextAction: "The wake-up service isn’t responding. This is a problem on our side; try again shortly.",
	},
	{
		// The sentence names both possibilities on purpose. An authenticated caller must
		// not be able to enumerate the fleet by trying ids, so the answer has to be
		// identical whether the device does not exist or they simply cannot see it —
		// and saying both out loud is what makes the two indistinguishable, rather
		// than leaving the operator to infer which one they got.
		ID: "device_unknown", Kind: Error, Audience: Operator,
		Fault:      FaultPrincipal,
		Headline:   "No such device, or you don't have access to it.",
		NextAction: "Check the device id, and check with whoever manages access for this fleet.",
	},
	{
		ID: "device_close", Kind: Close, Audience: Operator,
		Fault:      FaultNone,
		Headline:   "The device ended the session.",
		NextAction: "The shell exited, or the agent shut down.",
	},

	// ── authorisation ────────────────────────────────────────────────────────────
	{
		// Not "shell access": this one condition answers every action in the set —
		// opening a shell, watching somebody's session, reading a recording, querying
		// the database, changing the policy. Naming shell here made four of those
		// screens say something that was not true, and the specifics arrive anyway in
		// the detail line, which carries whoever-wrote-the-rule's own sentence.
		ID: "not_authorized", Kind: Error, Audience: Operator,
		Fault:      FaultPrincipal,
		Headline:   "You don’t have access to do that here.",
		NextAction: "Ask whoever manages access for this fleet.",
	},
	{
		ID: "revoked", Kind: Error | Close, Audience: Operator,
		Fault:      FaultPrincipal,
		Headline:   "Your access was revoked.",
		NextAction: "The session was ended because your access was withdrawn. Ask whoever manages access for this fleet.",
	},
	{
		// The pair this whole package exists to keep apart. "Your access was removed"
		// and "we could not check your access" send somebody to entirely different
		// places, and an operator told the first when the second happened will go and
		// ask a manager about a permission that was never taken away.
		ID: "authz_unavailable", Kind: Error | Close, Audience: Operator,
		Fault: FaultGateway, Retryable: true,
		Headline:   "We couldn’t confirm your access.",
		NextAction: "The service that checks permissions isn’t responding. Your access hasn’t changed — try again shortly.",
	},
	{
		ID: "auth_failed", Kind: Error, Audience: Operator,
		Fault:      FaultPrincipal,
		Headline:   "Your credentials were rejected.",
		NextAction: "Sign in again, or check the key you offered.",
	},

	// ── policy ───────────────────────────────────────────────────────────────────
	{
		ID: "policy_denied", Kind: Error | Close, Audience: Operator,
		Fault:      FaultPrincipal,
		Headline:   "Unrecorded sessions aren’t allowed here.",
		NextAction: "This device can only be reached in a mode the gateway can record.",
	},
	{
		ID: "profile_unsupported", Kind: Error, Audience: Operator,
		Fault:      FaultDevice,
		Headline:   "This device can’t do that.",
		NextAction: "The agent didn’t advertise the capability you asked for.",
	},
	{
		ID: "session_limit", Kind: Error, Audience: Operator,
		Fault: FaultPrincipal, Retryable: true,
		Headline:   "That device already has a session open.",
		NextAction: "Wait for it to finish, or end it from the session list.",
	},
	{
		ID: "already_attached", Kind: Error, Audience: Operator,
		Fault:      FaultPrincipal,
		Headline:   "Somebody is already attached to this session.",
		NextAction: "Two operators can’t share one shell. Open your own session, or ask them to leave.",
	},

	// ── limits and administration ────────────────────────────────────────────────
	{
		ID: "idle_timeout", Kind: Close, Audience: Operator,
		Fault: FaultNone, Retryable: true,
		Headline:   "The session closed after being idle.",
		NextAction: "Nothing was typed for a while, so the device’s slot was released. Open a new session when you need it.",
	},
	{
		ID: "max_duration", Kind: Close, Audience: Operator,
		Fault: FaultNone, Retryable: true,
		Headline:   "The session reached its time limit.",
		NextAction: "Sessions have a ceiling on how long they can run. Open a new one if you still need it.",
	},
	{
		ID: "admin_kill", Kind: Close, Audience: Operator,
		Fault:      FaultNone,
		Headline:   "An administrator ended this session.",
		NextAction: "It was closed from the session list, not by a failure.",
	},
	{
		ID: "gateway_shutdown", Kind: Error | Close, Audience: Operator,
		Fault: FaultGateway, Retryable: true,
		Headline:   "The gateway is restarting.",
		NextAction: "Sessions are being closed for a deploy. Try again in a moment.",
	},
	{
		ID: "operator_close", Kind: Close, Audience: Operator,
		Fault:      FaultNone,
		Headline:   "Session ended.",
		NextAction: "",
	},
	{
		// The operator stopped waiting before the device answered. Found by the source
		// scan in the tests rather than by design: it was emitted by the SSH surface
		// and had no screen, which is exactly the drift this package exists to stop.
		ID: "operator_gave_up", Kind: Close, Audience: Operator,
		Fault: FaultNone, Retryable: true,
		Headline:   "You stopped waiting before the device answered.",
		NextAction: "Nothing was opened. Try again when the device is awake.",
	},
	{
		// The operator declined at the pre-flight gate rather than work unrecorded.
		ID: "operator_declined", Kind: Close, Audience: Operator,
		Fault: FaultNone, Retryable: true,
		Headline:   "You chose not to continue.",
		NextAction: "The session was closed because it couldn’t be recorded.",
	},

	// ── recording ────────────────────────────────────────────────────────────────
	{
		// Not an integrator condition, even though an operator cannot fix it: the
		// consequence is theirs to know. A session that stopped because it could no
		// longer be recorded is the one case where the gateway would rather have no
		// session than an unrecorded one, and saying so is the point.
		ID: "recorder_failed", Kind: Error | Close, Audience: Operator,
		Fault:      FaultGateway,
		Headline:   "The session stopped because it could no longer be recorded.",
		NextAction: "Rather than continue unrecorded, the gateway ended it. This is a problem on our side.",
	},

	// ── the connection ───────────────────────────────────────────────────────────
	{
		// Emitted by the client, not the gateway, and in the set because it is a
		// screen an operator sees. It is the one condition that is normal.
		ID: "connection_lost", Kind: Error, Audience: Operator,
		Fault: FaultNone, Retryable: true,
		Headline:   "Connection lost.",
		NextAction: "Reconnecting — the session is still open and nothing has been lost.",
	},
	{
		ID: "transport_error", Kind: Close, Audience: Operator,
		Fault: FaultNone, Retryable: true,
		Headline:   "The connection failed.",
		NextAction: "Something between here and the gateway dropped the session. Try again.",
	},
	{
		// A dispatch-mode device with no wake-up method configured. A deployment
		// mistake, and it must not be reported as the device's problem — an engineer
		// sent to look at a treadmill will find nothing wrong with it.
		ID: "no_wake_method", Kind: Error, Audience: Operator,
		Fault:      FaultGateway,
		Headline:   "This device can’t be reached.",
		NextAction: "No wake-up method is configured for it. This is a deployment problem on our side.",
	},
	{
		ID: "wrong_node", Kind: Error, Audience: Operator,
		Fault: FaultGateway, Retryable: true,
		Headline:   "That session is running somewhere else.",
		NextAction: "Ask for a fresh connection and you’ll be sent to the right gateway.",
	},
	{
		ID: "session_closed", Kind: Error, Audience: Operator,
		Fault:      FaultNone,
		Headline:   "That session has ended.",
		NextAction: "Open a new one.",
	},

	// ── the integrator's problems ────────────────────────────────────────────────
	//
	// One screen between them. Eight ways of saying "this is a bug in the application
	// you are using" is eight screens nobody reads.
	{ID: "ticket_invalid", Kind: Error, Audience: Integrator, Fault: FaultClient},
	{ID: "ticket_scope", Kind: Error, Audience: Integrator, Fault: FaultClient},
	{ID: "protocol_error", Kind: Error | Close, Audience: Integrator, Fault: FaultClient},
	{ID: "version_unsupported", Kind: Error, Audience: Integrator, Fault: FaultClient},
	{ID: "frame_too_large", Kind: Error, Audience: Integrator, Fault: FaultClient},
	{ID: "policy_conflict", Kind: Error, Audience: Integrator, Fault: FaultGateway},
	{ID: "invalid_argument", Kind: Error, Audience: Integrator, Fault: FaultClient},
	{
		// Operator-facing, not integrator-facing. It was in the integrator group until the
		// console rendered it: asking for a device that does not exist produced
		// "Something in this application is wrong", which is both untrue and unhelpful.
		// A caller asking for something that is not there has made an ordinary mistake.
		ID: "not_found", Kind: Error, Audience: Operator,
		Fault:      FaultPrincipal,
		Headline:   "That isn't there, or you don't have access to it.",
		NextAction: "Check the id you asked for, and check with whoever manages access.",
	},
	{ID: "internal", Kind: Error | Close, Audience: Integrator, Fault: FaultGateway},
}

// IntegratorHeadline and IntegratorNextAction are the shared screen for a condition an
// operator cannot act on. The code and the correlation id go with them, small and
// copyable and labelled for support.
const (
	IntegratorHeadline   = "Something in this application is wrong."
	IntegratorNextAction = "This isn’t something you can fix from here. Quote the reference below if you report it."
)

var byID = func() map[string]Condition {
	m := make(map[string]Condition, len(set))
	for _, c := range set {
		m[c.ID] = c
	}
	return m
}()

// Lookup returns a condition by its wire value.
func Lookup(id string) (Condition, bool) {
	c, ok := byID[id]
	return c, ok
}

// Get returns a condition, falling back to a well-formed unknown rather than a zero
// value.
//
// An unknown code is a gateway newer than this client, which the protocol's versioning
// rules allow. It must render as "we don't recognise this" rather than as a blank screen
// or, worse, as whatever the first entry in the table happens to be.
func Get(id string) Condition {
	if c, ok := byID[id]; ok {
		return c
	}
	return Condition{
		ID: id, Kind: Error, Audience: Integrator, Fault: FaultClient,
		Headline:   IntegratorHeadline,
		NextAction: IntegratorNextAction,
	}
}

// All returns the whole set, sorted by id, for generators and tests.
func All() []Condition {
	out := make([]Condition, len(set))
	copy(out, set)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Text is what a surface with no components — the SSH front door — prints.
func (c Condition) Text() string {
	head, next := c.Headline, c.NextAction
	if c.Audience == Integrator && head == "" {
		head, next = IntegratorHeadline, IntegratorNextAction
	}
	if next == "" {
		return head
	}
	return head + " " + next
}

// IsCloseReason reports whether id is a close reason from the closed set.
//
// It exists because `close_reason` is specified as a closed set and arrives from a peer.
// A device sends CLOSE with whatever string it likes, and that string is written to the
// ledger and printed in the gateway's own closing disclosure — so "the single source of
// truth for what the UI says" was, until this was consulted, whatever an untrusted party
// put on the wire.
func IsCloseReason(id string) bool {
	c, ok := Lookup(id)
	return ok && c.Kind&Close != 0
}
