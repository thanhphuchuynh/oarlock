// Package authz applies the three-outcome contract.
//
// A re-check has three outcomes, not two, and conflating the last two is how an
// authorisation service's bad minute becomes a fleet-wide outage during an incident:
//
//	| outcome       | new sessions        | live sessions                          |
//	|---------------|---------------------|----------------------------------------|
//	| Allow: true   | open                | continue                               |
//	| Allow: false  | not_authorized      | closed, revoked                        |
//	| error         | authz_unavailable   | continue for Grace re-checks, then     |
//	|               | (refused at once)   | closed with authz_unavailable          |
//
// Two things this buys that a bare fail-closed does not.
//
// **A transient outage does not kill work in progress.** Fail-closed with no tolerance
// means a thirty-second blip in the permissions API terminates every shell in the fleet —
// at the moment operators most need shells, because the same infrastructure event is
// usually why they are logged in.
//
// **The close reason is true.** `revoked` means a human decided to withdraw access;
// `authz_unavailable` means the gateway could not find out. Recording the first when the
// second happened poisons every audit query built on top of it.
//
// New sessions are refused from the *first* failure, not after the grace window: opening a
// session on a stale decision is a different risk from letting an operator finish a
// command on one.
package authz

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/oarlock/oarlock/pkg/plugin"
)

// DefaultGrace is how many consecutive failures a live session survives.
//
// Three, which is about ninety seconds at the default re-check interval — long enough for
// a rolling restart of a permissions service, short enough that a real revocation is not
// meaningfully delayed.
const DefaultGrace = 3

// Outcome is which of the three answers came back.
type Outcome int

const (
	// Allowed: the backend said yes.
	Allowed Outcome = iota
	// Denied: the backend said no. A decision.
	Denied
	// Unavailable: the backend could not decide. Not a decision.
	Unavailable
)

func (o Outcome) String() string {
	switch o {
	case Allowed:
		return "allowed"
	case Denied:
		return "denied"
	default:
		return "unavailable"
	}
}

// Result is what a check produced.
type Result struct {
	Outcome Outcome
	// Reason is the operator-facing sentence for a denial.
	Reason string
	// Code is the condition to report: "" when allowed, otherwise `not_authorized` or
	// `authz_unavailable`. Taken from pkg/condition's vocabulary so that both surfaces
	// render the same screen.
	Code string
	// Limits is the grant's tightening, if any.
	Limits *plugin.GrantLimits
	// Err is the backend's error, for logs. Never shown to an operator: an operator
	// cannot act on "dial tcp: connection refused".
	Err error
	// TTL is the grant's request for a sooner re-check than the default. Zero means
	// the default interval; it can only shorten it.
	TTL time.Duration
}

// Allow reports whether the session may proceed.
func (r Result) Allow() bool { return r.Outcome == Allowed }

// Checker applies the contract to a backend.
//
// A nil Checker allows everything, which is what a deployment with no Authorizer
// configured gets. That is deliberate and it is not a security hole waiting to happen:
// authentication still applies, the device registry still applies, and `internal/safety`
// refuses to boot a production deployment with no authorizer at all. A gateway that
// refused every session until somebody wrote a rules file would be a gateway nobody could
// evaluate.
type Checker struct {
	Backend plugin.Authorizer

	// Grace is how many consecutive failures a live session survives.
	//
	// A pointer, because zero has a meaning here and it is not "unset": ARCHITECTURE
	// § 7.1 and the boot gate in internal/safety both say `authz.grace: 0` is strict
	// fail-closed, which is the right setting where a session is more dangerous than an
	// outage. An int would make an operator who explicitly disabled the window get the
	// default three instead — silently, and in the direction that keeps sessions alive.
	//
	// Nil means DefaultGrace.
	Grace *int

	// Admins are principal ids the gateway's own config file declares as
	// administrators. They are allowed the administrative actions — and nothing else.
	//
	// # Why this exists
	//
	// The policy store is edited through the API, and the API is authorised by the
	// policy store. On an empty store nobody can write the first permission, and a
	// store whose last `admin:permissions` grant is deleted is a locked room. One of
	// the two has to be able to break the cycle, and it should be whoever owns the
	// config file rather than whoever holds a token.
	//
	// # Why it is narrow
	//
	// It grants `admin:*` only. A config administrator may repair the policy; they may
	// not open a shell, watch a session or read the database without writing themselves
	// a grant first — and that grant is a row in the Permissions tab and a line in the
	// audit trail, which is the difference between an administrator and a back door.
	//
	// Deny still wins. Nothing here overrides a `deny` rule on a session action,
	// because the admin actions and the session actions are disjoint sets.
	//
	// Exact principal ids, not patterns: `*@example.com` in this field would be a
	// footgun with the blast radius of the whole fleet.
	Admins []string

	Log *slog.Logger
}

// administrator reports whether the config file declares this principal an administrator.
func (c *Checker) administrator(p *plugin.Principal) bool {
	if c == nil || p == nil {
		return false
	}
	for _, id := range c.Admins {
		if id != "" && id == p.ID {
			return true
		}
	}
	return false
}

// GraceOf is a convenience for building a Checker with an explicit window.
func GraceOf(n int) *int { return &n }

func (c *Checker) grace() int {
	if c == nil || c.Grace == nil {
		return DefaultGrace
	}
	if *c.Grace < 0 {
		// The boot gate refuses a negative value, so this is unreachable in a
		// configured deployment. Clamping rather than panicking, because a library
		// should not be the thing that takes a gateway down over a number.
		return 0
	}
	return *c.Grace
}

func (c *Checker) log() *slog.Logger {
	if c != nil && c.Log != nil {
		return c.Log
	}
	return slog.Default()
}

// AtOpen checks whether a session may start.
//
// An error refuses immediately, with no grace: the grace window exists to let work in
// progress finish, and there is no work in progress yet.
func (c *Checker) AtOpen(ctx context.Context, p *plugin.Principal, dev *plugin.Device,
	act plugin.Action) Result {
	if c == nil || c.Backend == nil {
		return Result{Outcome: Allowed}
	}
	if act.Administrative() && c.administrator(p) {
		// The config file's break-glass. Logged every time, because an administrative
		// change made on the strength of a config entry rather than a policy grant is
		// exactly the one an auditor will want to find.
		c.log().Info("allowed by a config-declared administrator",
			"principal", p.ID, "device", dev.ID, "action", act)
		return Result{Outcome: Allowed}
	}
	d, err := c.Backend.Authorize(ctx, p, dev, act)
	switch {
	case err != nil:
		c.log().Warn("authorization is unavailable; refusing a new session",
			"principal", p.ID, "device", dev.ID, "action", act, "error", err)
		return Result{
			Outcome: Unavailable,
			Code:    "authz_unavailable",
			Err:     err,
		}
	case !d.Allow:
		return Result{
			Outcome: Denied,
			Code:    "not_authorized",
			Reason:  d.Reason,
		}
	default:
		return Result{Outcome: Allowed, Limits: d.Limits, TTL: d.TTL}
	}
}

// Session tracks one live session's re-checks.
//
// Created by whoever runs the session; its whole job is to remember how many consecutive
// failures have happened, because that count is the difference between "this operator's
// access was withdrawn" and "we could not ask".
type Session struct {
	c   *Checker
	p   *plugin.Principal
	dev *plugin.Device
	act plugin.Action

	mu sync.Mutex
	// failures is the consecutive-failure count. Reset by any answer, including a
	// denial: a backend that answers has stopped being unavailable.
	failures int
	degraded bool
}

// Track begins re-checking a live session.
func (c *Checker) Track(p *plugin.Principal, dev *plugin.Device, act plugin.Action) *Session {
	return &Session{c: c, p: p, dev: dev, act: act}
}

// Recheck applies the contract to a live session.
//
// Returns Allowed while the session may continue — including during the grace window,
// which is the point — and Denied or Unavailable when it must close, with the Code the
// operator will be shown.
func (s *Session) Recheck(ctx context.Context) Result {
	if s == nil || s.c == nil || s.c.Backend == nil {
		return Result{Outcome: Allowed}
	}
	d, err := s.c.Backend.Authorize(ctx, s.p, s.dev, s.act)

	s.mu.Lock()
	defer s.mu.Unlock()

	if err != nil {
		s.failures++
		grace := s.c.grace()
		if s.failures <= grace {
			if !s.degraded {
				s.degraded = true
				// Emitted on the *first* failure, not when the window expires: by then
				// the session is already closed and the interesting minute is over.
				s.c.log().Warn("authorization is unavailable; a live session is in its grace window",
					"principal", s.p.ID, "device", s.dev.ID,
					"failures", s.failures, "grace", grace, "error", err)
			}
			// Continue on the last successful decision. The gateway is explicitly
			// choosing a stale yes over a wrong no.
			return Result{Outcome: Allowed, Err: err}
		}
		s.c.log().Error("authorization unavailable past the grace window; closing the session",
			"principal", s.p.ID, "device", s.dev.ID, "failures", s.failures, "grace", grace)
		return Result{Outcome: Unavailable, Code: "authz_unavailable", Err: err}
	}

	// Any answer ends the outage, including a denial: a backend that can say no is a
	// backend that is reachable.
	if s.degraded {
		s.c.log().Info("authorization recovered",
			"principal", s.p.ID, "device", s.dev.ID, "after_failures", s.failures)
	}
	s.failures = 0
	s.degraded = false

	if !d.Allow {
		reason := d.Reason
		if reason == "" {
			reason = "access was withdrawn"
		}
		return Result{Outcome: Denied, Code: "revoked", Reason: reason}
	}
	return Result{Outcome: Allowed, Limits: d.Limits, TTL: d.TTL}
}

// Failures is the current consecutive-failure count, for metrics and tests.
func (s *Session) Failures() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failures
}

// ErrUnavailable is returned by helpers that need an error rather than a Result.
var ErrUnavailable = errors.New("authz: authorization is unavailable")
