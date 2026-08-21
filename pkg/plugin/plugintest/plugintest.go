// Package plugintest is a conformance suite for Oarlock's plugin interfaces.
//
// Call it from your own tests. It checks the parts that are easy to get wrong and hard to
// notice: that you distinguish "no" from "I could not decide", that you honour
// cancellation, that concurrent calls are safe, that a per-grant limit can only tighten,
// and that a dropped Watch stream is not reported as a revocation.
//
//	func TestConformance(t *testing.T) {
//	    plugintest.Authorizer(t, plugintest.AuthorizerHarness{
//	        New:     func(t *testing.T) plugin.Authorizer { return newMyAuthz(t) },
//	        Allowed: ...,
//	        Denied:  ...,
//	        BreakDependency: ...,
//	    })
//	}
//
// # Why a suite rather than documentation
//
// The failure this exists to prevent — a backend answering "denied" when its own
// dependency is down — is silent, writes `revoked` into an audit trail for an outage, and
// turns one service's bad minute into a fleet-wide session kill during the incident that
// put operators on those devices. It is also entirely in the hands of somebody who does
// not work on Oarlock. Documenting the contract was the first attempt; this is the second.
//
// # Nothing here skips quietly
//
// A conformance suite whose most important case can be omitted by leaving a field nil is
// a suite that reports success for a backend it never tested. So the cases that carry a
// contract *fail* when their harness is incomplete, and opting out takes a field whose
// name says what it costs.
package plugintest

import (
	"fmt"
	"strings"
	"testing"
)

// reporter is the seam that lets this package test itself.
//
// The suites are written against it rather than against *testing.T so that plugintest's
// own tests can run a suite against a deliberately-broken backend and assert that it
// *fails*. A conformance suite that passes a wrong backend is worthless, and the only way
// to know it does not is to try.
type reporter interface {
	errorf(format string, args ...any)
	fatalf(format string, args ...any)
	run(name string, f func(reporter))
	// t is the *testing.T a harness callback needs. Nil under the self-tests, which
	// only use harnesses that do not touch it.
	t() *testing.T
}

type liveReporter struct{ tt *testing.T }

func (r liveReporter) errorf(format string, args ...any) {
	r.tt.Helper()
	r.tt.Errorf(format, args...)
}

func (r liveReporter) fatalf(format string, args ...any) {
	r.tt.Helper()
	r.tt.Fatalf(format, args...)
}

func (r liveReporter) run(name string, f func(reporter)) {
	r.tt.Run(name, func(sub *testing.T) { f(liveReporter{sub}) })
}

func (r liveReporter) t() *testing.T { return r.tt }

// recorded is a reporter that collects failures instead of reporting them, for the
// self-tests.
type recorded struct {
	name     string
	failures []string
	subs     []*recorded
	fatal    bool
}

func (r *recorded) errorf(format string, args ...any) {
	r.failures = append(r.failures, fmt.Sprintf(format, args...))
}

func (r *recorded) fatalf(format string, args ...any) {
	r.failures = append(r.failures, fmt.Sprintf(format, args...))
	r.fatal = true
	// A real Fatalf unwinds the goroutine. panicking with a sentinel reproduces that
	// closely enough for the self-tests, and run() catches it.
	panic(fatalSentinel{})
}

type fatalSentinel struct{}

func (r *recorded) run(name string, f func(reporter)) {
	sub := &recorded{name: name}
	r.subs = append(r.subs, sub)
	func() {
		defer func() {
			if p := recover(); p != nil {
				if _, ok := p.(fatalSentinel); !ok {
					panic(p)
				}
			}
		}()
		f(sub)
	}()
}

func (r *recorded) t() *testing.T { return nil }

// failed reports whether this reporter or any of its subtests failed.
func (r *recorded) failed() bool {
	if len(r.failures) > 0 {
		return true
	}
	for _, s := range r.subs {
		if s.failed() {
			return true
		}
	}
	return false
}

// failedCases lists the names of the subtests that failed, deepest name last.
func (r *recorded) failedCases() []string {
	var out []string
	if len(r.failures) > 0 && r.name != "" {
		out = append(out, r.name)
	}
	for _, s := range r.subs {
		out = append(out, s.failedCases()...)
	}
	return out
}

// messages is every failure message, flattened.
func (r *recorded) messages() string {
	var b strings.Builder
	for _, f := range r.failures {
		b.WriteString(r.name)
		b.WriteString(": ")
		b.WriteString(f)
		b.WriteString("\n")
	}
	for _, s := range r.subs {
		b.WriteString(s.messages())
	}
	return b.String()
}
