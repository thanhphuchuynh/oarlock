// Package backoff is the reconnect schedule for agents.
//
// The jitter is not politeness, it is the difference between a rolling restart and
// an outage. Every agent in a `persistent` fleet loses its control channel at the
// same instant when a replica goes away, and without jitter they all come back at
// the same instant too — so the replacement pod meets the entire fleet at once and
// dies of it. That is the failure mode of persistent mode that bites hardest at
// scale, and it is self-inflicted.
package backoff

import (
	"math"
	"math/rand/v2"
	"time"
)

// Policy is an exponential schedule with proportional jitter.
type Policy struct {
	Base   time.Duration // delay before the first retry
	Cap    time.Duration // ceiling, before jitter
	Factor float64       // multiplier per attempt
	Jitter float64       // fraction of the delay, applied as ±Jitter
}

// Default is the schedule from ARCHITECTURE § 3.1: base 1 s, ×1.6, cap 60 s, ±25 %.
//
// The cap matters as much as the growth. A device that has been unreachable for an
// hour must still be trying often enough that fixing the network fixes the fleet
// within a minute, rather than whenever each device's own exponential happens to
// come round.
var Default = Policy{
	Base:   time.Second,
	Cap:    time.Minute,
	Factor: 1.6,
	Jitter: 0.25,
}

func (p Policy) withDefaults() Policy {
	if p.Base <= 0 {
		p.Base = Default.Base
	}
	if p.Cap <= 0 {
		p.Cap = Default.Cap
	}
	if p.Factor < 1 {
		p.Factor = Default.Factor
	}
	if p.Jitter < 0 {
		p.Jitter = 0
	}
	if p.Jitter > 1 {
		p.Jitter = 1
	}
	return p
}

// Delay returns how long to wait before attempt n, counting from zero.
//
// rnd returns a value in [0,1) — pass nil for crypto-free math/rand/v2. Injecting
// it is what makes the jitter testable; a schedule whose randomness cannot be
// pinned is a schedule nobody verifies.
func (p Policy) Delay(attempt int, rnd func() float64) time.Duration {
	p = p.withDefaults()
	if attempt < 0 {
		attempt = 0
	}
	if rnd == nil {
		rnd = rand.Float64
	}

	d := float64(p.Base) * math.Pow(p.Factor, float64(attempt))
	if d > float64(p.Cap) || math.IsInf(d, 0) {
		d = float64(p.Cap)
	}
	// ±Jitter, proportional. Multiplicative rather than additive so the spread
	// stays meaningful at both ends of the schedule.
	if p.Jitter > 0 {
		d *= 1 + p.Jitter*(2*rnd()-1)
	}
	if d < 0 {
		d = 0
	}
	return time.Duration(d)
}

// Sleeper counts attempts and waits. It resets on success, so a channel that
// stayed up for an hour and then dropped retries immediately rather than inheriting
// the delay from the last outage.
type Sleeper struct {
	Policy Policy
	Rand   func() float64

	attempt int
}

// Next returns the next delay and advances the attempt counter.
func (s *Sleeper) Next() time.Duration {
	d := s.Policy.Delay(s.attempt, s.Rand)
	s.attempt++
	return d
}

// Reset clears the attempt counter. Call it after a *successful handshake*, not
// after a successful dial: a gateway that accepts connections and then rejects
// every handshake would otherwise be hammered at the base interval forever.
func (s *Sleeper) Reset() { s.attempt = 0 }

// Attempt is how many failures have accrued since the last Reset.
func (s *Sleeper) Attempt() int { return s.attempt }
