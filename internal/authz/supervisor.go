package authz

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/oarlock/oarlock/internal/backoff"
	"github.com/oarlock/oarlock/pkg/plugin"
)

// DefaultRecheckInterval is how often a live session's grant is re-checked.
//
// **This interval is the guarantee.** `Watch` makes a revocation feel instant, but a
// backend that has no Watch, or whose stream is down, must still lose its grants within
// one interval — so the loop below runs whether or not Watch is working, and the tests
// that matter kill the stream first.
const DefaultRecheckInterval = 30 * time.Second

// Killer is the part of the live-session registry a Supervisor needs.
type Killer interface {
	// Kill ends one session by id.
	Kill(ctx context.Context, id, reason string) error
	// KillMatching ends every live session for a principal and/or device, and returns
	// how many. An empty principal or device means "every", which is what a backend
	// sends when it has lost track of its own state.
	KillMatching(principal, device, reason string) int
}

// Supervisor re-checks live sessions and closes the ones that lose their grant.
//
// Two mechanisms, deliberately unequal:
//
//   - **The re-check loop** runs per session on its own interval. It is the guarantee: a
//     grant cannot outlive one interval past its withdrawal, whatever else is broken.
//   - **Watch** turns a revocation into a sub-second closure. It is the optimisation, and
//     a broken Watch is not a security failure — it is a minute of staleness.
//
// Building it the other way round is the trap R-003 describes: a system where Watch does
// the work and the interval is a backstop nobody exercises passes every happy-path test
// and stops revoking the day the stream breaks.
type Supervisor struct {
	Checker *Checker
	Live    Killer

	// Interval is the re-check period. Zero means DefaultRecheckInterval.
	Interval time.Duration
	// Backoff is the reconnect schedule for Watch. The zero value uses the default.
	Backoff backoff.Policy
	Log     *slog.Logger

	// Sleep is injectable so a test does not wait out a real interval.
	Sleep func(ctx context.Context, d time.Duration) error

	watchState atomic.Int32 // 0 unknown, 1 connected, 2 disconnected, 3 unsupported
	watchDrops atomic.Int64
	events     atomic.Int64
}

// WatchStatus is what the Watch stream is doing, for health output and metrics.
type WatchStatus int

const (
	WatchUnknown WatchStatus = iota
	WatchConnected
	WatchDisconnected
	// WatchUnsupported: the backend does not stream, and the interval carries the load.
	// Not a degraded state — most backends are like this.
	WatchUnsupported
)

func (w WatchStatus) String() string {
	switch w {
	case WatchConnected:
		return "connected"
	case WatchDisconnected:
		return "disconnected"
	case WatchUnsupported:
		return "unsupported"
	}
	return "unknown"
}

// WatchStatus reports the stream's state.
//
// Observable on purpose: R-003 is a revocation that never arrives because a stream died
// quietly. A gateway whose Watch has been disconnected for an hour is still correct — the
// interval is the guarantee — but somebody should be able to see it.
func (s *Supervisor) WatchStatus() WatchStatus { return WatchStatus(s.watchState.Load()) }

// WatchDrops is how many times the stream has dropped and been reconnected.
func (s *Supervisor) WatchDrops() int64 { return s.watchDrops.Load() }

// Events is how many revocation events have been received.
func (s *Supervisor) Events() int64 { return s.events.Load() }

func (s *Supervisor) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Supervisor) interval() time.Duration {
	if s.Interval > 0 {
		return s.Interval
	}
	return DefaultRecheckInterval
}

func (s *Supervisor) sleep(ctx context.Context, d time.Duration) error {
	if s.Sleep != nil {
		return s.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Guard re-checks one live session until it ends.
//
// Returns when the session's context ends or when the grant is lost, having killed it with
// the true reason: `revoked` for a withdrawal, `authz_unavailable` for an outage past the
// grace window. Intended to be run in a goroutine by whoever owns the session.
// tgt must be the target the session opened with: a re-check that asked about a wider
// target would keep a narrowed grant alive after the narrowing was withdrawn.
func (s *Supervisor) Guard(ctx context.Context, sessionID string, p *plugin.Principal,
	dev *plugin.Device, act plugin.Action, tgt plugin.Target) {
	if s.Checker == nil || s.Checker.Backend == nil {
		return // nothing to re-check against
	}
	tracked := s.Checker.Track(p, dev, act, tgt)
	interval := s.interval()

	for {
		if err := s.sleep(ctx, interval); err != nil {
			return // the session ended first
		}
		res := tracked.Recheck(ctx)
		if res.Allow() {
			// A grant may ask to be re-checked sooner, never later: a backend that
			// wanted a longer leash would be choosing how stale its own revocations
			// may be.
			interval = s.interval()
			if res.TTL > 0 && res.TTL < interval {
				interval = res.TTL
			}
			continue
		}
		if ctx.Err() != nil {
			return
		}
		s.log().Info("closing a session that lost its grant",
			"session", sessionID, "principal", p.ID, "device", dev.ID,
			"reason", res.Code, "outcome", res.Outcome.String())
		if s.Live != nil {
			// The reason travels with the kill. A session ended by a withdrawn grant
			// and one ended because the gateway could not ask must not both be
			// recorded as "the transport went away".
			_ = s.Live.Kill(ctx, sessionID, res.Code)
		}
		return
	}
}

// WatchRevocations consumes the backend's revocation stream, reconnecting until the
// context ends.
//
// Run once per gateway, not per session: the stream is a property of the backend.
func (s *Supervisor) WatchRevocations(ctx context.Context) {
	if s.Checker == nil || s.Checker.Backend == nil {
		return
	}
	policy := s.Backoff
	attempt := 0

	for {
		if ctx.Err() != nil {
			return
		}
		ch, err := s.Checker.Backend.Watch(ctx)
		switch {
		case errors.Is(err, plugin.ErrUnsupported):
			// Most backends. The interval carries the load, and saying so once beats a
			// reconnect loop against a method that will never work.
			s.watchState.Store(int32(WatchUnsupported))
			s.log().Debug("the authorizer does not stream revocations; " +
				"the re-check interval carries the load")
			return
		case err != nil || ch == nil:
			s.watchState.Store(int32(WatchDisconnected))
			delay := policy.Delay(attempt, nil)
			attempt++
			s.log().Warn("could not subscribe to revocations; retrying",
				"attempt", attempt, "in", delay, "error", err)
			if serr := s.sleep(ctx, delay); serr != nil {
				return
			}
			continue
		}

		s.watchState.Store(int32(WatchConnected))
		if attempt > 0 {
			s.log().Info("revocation stream reconnected", "after_attempts", attempt)
		}
		attempt = 0
		s.drain(ctx, ch)

		// The stream ended. **Not a revocation**: a dropped stream means the gateway
		// stopped hearing, not that everybody's access was withdrawn. Closing every
		// session here would turn a network blip into a fleet-wide kill — the exact
		// failure the three-outcome contract exists to prevent, arriving by a different
		// door.
		if ctx.Err() != nil {
			return
		}
		s.watchState.Store(int32(WatchDisconnected))
		s.watchDrops.Add(1)
		delay := policy.Delay(attempt, nil)
		attempt++
		s.log().Warn("the revocation stream dropped; reconnecting",
			"drops", s.watchDrops.Load(), "in", delay)
		if err := s.sleep(ctx, delay); err != nil {
			return
		}
	}
}

func (s *Supervisor) drain(ctx context.Context, ch <-chan plugin.RevocationEvent) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, open := <-ch:
			if !open {
				return
			}
			s.events.Add(1)
			reason := "revoked"
			n := 0
			if s.Live != nil {
				n = s.Live.KillMatching(ev.PrincipalID, ev.DeviceID, reason)
			}
			// Logged whether or not it matched anything: a revocation for somebody with
			// no live session is the normal case, and an event that matches nothing
			// repeatedly is worth being able to see.
			s.log().Info("revocation received",
				"principal", orEvery(ev.PrincipalID), "device", orEvery(ev.DeviceID),
				"backend_reason", ev.Reason, "sessions_closed", n)
		}
	}
}

func orEvery(s string) string {
	if s == "" {
		return "(every)"
	}
	return s
}
