package plugintest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/oarlock/oarlock/pkg/plugin"
)

// AuthorizerHarness is what a backend author supplies.
type AuthorizerHarness struct {
	// New returns a fresh backend. Called once per case, so a case cannot be
	// contaminated by the one before it.
	New func(t *testing.T) plugin.Authorizer

	// Allowed is a request the backend permits.
	Allowed func() (*plugin.Principal, *plugin.Device, plugin.Action)
	// Denied is a request the backend refuses — a real denial, not a broken dependency.
	Denied func() (*plugin.Principal, *plugin.Device, plugin.Action)

	// BreakDependency makes whatever the backend depends on unavailable, and returns a
	// function that restores it.
	//
	// This is the whole point of the suite. Without it, the case that distinguishes
	// "denied" from "could not decide" cannot run — so leaving it nil is a failure, not
	// a skip, unless NoDependencyToBreak says otherwise.
	BreakDependency func(t *testing.T) (restore func())

	// NoDependencyToBreak asserts that this backend has nothing that can be unavailable
	// — a rules file already in memory, a hard-coded allow-list.
	//
	// Named for what it claims rather than for what it disables. A backend that reads a
	// file, calls a service, or queries a database has a dependency that can break, and
	// setting this for one of those buys a passing suite that tested nothing.
	NoDependencyToBreak bool

	// Revoke withdraws a grant, for the Watch cases. Optional: a backend that does not
	// implement Watch does not need it.
	Revoke func(t *testing.T, p *plugin.Principal, dev *plugin.Device)

	// SupportsWatch says the backend implements Watch. When false, the suite asserts it
	// returns ErrUnsupported rather than something else — an unimplemented Watch that
	// returns a nil channel and a nil error would hang the gateway's watcher forever.
	SupportsWatch bool
}

// Authorizer runs the conformance suite against an Authorizer implementation.
func Authorizer(t *testing.T, h AuthorizerHarness) {
	t.Helper()
	runAuthorizer(liveReporter{t}, h)
}

func runAuthorizer(r reporter, h AuthorizerHarness) {
	if h.New == nil {
		r.fatalf("plugintest: AuthorizerHarness.New is required")
		return
	}
	if h.Allowed == nil || h.Denied == nil {
		r.fatalf("plugintest: AuthorizerHarness needs both Allowed and Denied — a suite " +
			"that only ever sees one answer cannot tell them apart")
		return
	}

	r.run("allows what it should", func(r reporter) {
		a := h.New(r.t())
		p, dev, act := h.Allowed()
		d, err := a.Authorize(context.Background(), p, dev, act)
		if err != nil {
			r.errorf("an allowed request returned an error: %v", err)
			return
		}
		if !d.Allow {
			r.errorf("an allowed request was denied: %q", d.Reason)
		}
	})

	r.run("denies what it should, without an error", func(r reporter) {
		a := h.New(r.t())
		p, dev, act := h.Denied()
		d, err := a.Authorize(context.Background(), p, dev, act)
		// A denial is an answer. Returning an error alongside it makes the gateway
		// treat a decision as an outage and hold the session open through a grace
		// window that should never have started.
		if err != nil {
			r.errorf("a denial came back as an error (%v) — a denial is a decision, "+
				"and reporting it as a failure to decide means the gateway waits out a "+
				"grace window instead of refusing", err)
			return
		}
		if d.Allow {
			r.errorf("a request that should be denied was allowed")
		}
		if d.Reason == "" {
			r.errorf("a denial with no Reason — the operator is shown this, and " +
				"\"denied\" tells them nothing they can act on")
		}
	})

	// ── the case this package exists for ─────────────────────────────────────────
	r.run("a broken dependency is an error, not a denial", func(r reporter) {
		if h.BreakDependency == nil {
			if !h.NoDependencyToBreak {
				r.errorf("plugintest: BreakDependency is nil.\n\n" +
					"This is the case the suite exists for: a backend that answers " +
					"Allow:false when its own dependency is down writes `revoked` into " +
					"an audit trail for an outage, tells an operator their access was " +
					"withdrawn when it was not, and turns one service's bad minute into " +
					"a fleet-wide session kill.\n\n" +
					"Supply BreakDependency, or set NoDependencyToBreak if this backend " +
					"genuinely has nothing that can be unavailable.")
				return
			}
			// Even the opt-out is checked: a backend with no dependency should still
			// answer, and answer the same way twice.
			a := h.New(r.t())
			p, dev, act := h.Allowed()
			first, err1 := a.Authorize(context.Background(), p, dev, act)
			second, err2 := a.Authorize(context.Background(), p, dev, act)
			if err1 != nil || err2 != nil {
				r.errorf("NoDependencyToBreak is set, but Authorize errored: %v / %v",
					err1, err2)
			}
			if first.Allow != second.Allow {
				r.errorf("NoDependencyToBreak is set, but two identical calls disagreed")
			}
			return
		}

		a := h.New(r.t())
		restore := h.BreakDependency(r.t())
		if restore == nil {
			r.errorf("BreakDependency returned no restore function")
			return
		}
		p, dev, act := h.Allowed()
		d, err := a.Authorize(context.Background(), p, dev, act)
		restore()

		switch {
		case err != nil:
			// Correct. The gateway will report authz_unavailable and, for a live
			// session, hold it through the grace window.
		case !d.Allow:
			r.errorf("with its dependency down, the backend answered Allow:false.\n\n"+
				"That is the failure this suite exists to catch. It is not a denial — "+
				"nothing about the operator's access changed — and reporting it as one "+
				"records `revoked` for an outage, tells the operator their access was "+
				"withdrawn, and closes every live session this backend covers.\n\n"+
				"Return a non-nil error instead. Reason given: %q", d.Reason)
		default:
			// Allowed while broken. Worse in the other direction, and worth its own
			// sentence: this is a backend that fails *open*.
			r.errorf("with its dependency down, the backend answered Allow:true.\n\n" +
				"A backend that cannot reach its own source of truth must not vouch " +
				"for anybody. Return a non-nil error.")
		}
	})

	r.run("cancellation is honoured", func(r reporter) {
		a := h.New(r.t())
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		p, dev, act := h.Allowed()
		d, err := a.Authorize(ctx, p, dev, act)
		// Either answer is defensible — a cached decision needs no I/O — but an
		// *allow* on a cancelled context is not: the gateway cancels when it has
		// stopped caring, and a backend that keeps working and returns a grant is one
		// whose latency nobody can bound.
		if err == nil && d.Allow {
			r.errorf("a cancelled context produced a grant; return ctx.Err() instead")
		}
	})

	r.run("concurrent calls are safe", func(r reporter) {
		a := h.New(r.t())
		p, dev, act := h.Allowed()
		dp, ddev, dact := h.Denied()

		// The gateway re-checks every live session on the same interval, so a busy
		// node calls this from many goroutines at once. Run with -race for this to
		// mean anything, which the suite's own CI does.
		var wg sync.WaitGroup
		errs := make(chan error, 64)
		for i := range 32 {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				var d plugin.Decision
				var err error
				if i%2 == 0 {
					d, err = a.Authorize(context.Background(), p, dev, act)
					if err == nil && !d.Allow {
						errs <- errors.New("an allowed request was denied under concurrency")
					}
				} else {
					d, err = a.Authorize(context.Background(), dp, ddev, dact)
					if err == nil && d.Allow {
						errs <- errors.New("a denied request was allowed under concurrency")
					}
				}
				if err != nil {
					errs <- err
				}
			}(i)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			r.errorf("under concurrency: %v", err)
		}
	})

	r.run("a per-grant limit only tightens", func(r reporter) {
		a := h.New(r.t())
		p, dev, act := h.Allowed()
		d, err := a.Authorize(context.Background(), p, dev, act)
		if err != nil || !d.Allow || d.Limits == nil {
			return // nothing to check; not every backend returns limits
		}
		// The gateway takes the minimum of its own limit and the grant's, so a grant
		// cannot widen anything — but a backend returning a deliberately huge value is
		// trying to, and saying so early beats letting it look like it worked.
		if d.Limits.MaxDuration != nil && *d.Limits.MaxDuration > 24*time.Hour {
			r.errorf("the grant asks for a max duration of %v. Limits may only tighten; "+
				"the gateway takes the minimum, so this has no effect and the intent is "+
				"the problem", *d.Limits.MaxDuration)
		}
		if d.Limits.Rate != nil && *d.Limits.Rate <= 0 {
			r.errorf("the grant asks for a rate of %d, which is not a tightening but a "+
				"stall", *d.Limits.Rate)
		}
		if d.TTL < 0 {
			r.errorf("a negative TTL (%v)", d.TTL)
		}
	})

	r.run("Watch says what it is", func(r reporter) {
		a := h.New(r.t())
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		ch, err := a.Watch(ctx)

		if !h.SupportsWatch {
			// An unimplemented Watch that returns a nil channel and a nil error would
			// leave the gateway's watcher blocked on a channel nobody will ever send
			// to — waiting forever for revocations that were never coming.
			if err == nil {
				r.errorf("SupportsWatch is false but Watch returned no error. Return " +
					"plugin.ErrUnsupported so the gateway knows to poll instead")
				return
			}
			if !errors.Is(err, plugin.ErrUnsupported) {
				r.errorf("Watch returned %v; return plugin.ErrUnsupported so the "+
					"gateway can tell \"not implemented\" from \"the stream is down\"", err)
			}
			return
		}

		if err != nil {
			r.errorf("SupportsWatch is true but Watch returned %v", err)
			return
		}
		if ch == nil {
			r.errorf("Watch returned a nil channel and no error; the gateway would " +
				"block on it forever")
			return
		}

		// A dropped stream is not a revocation. Cancelling the context has to close the
		// channel, not leave a goroutine holding it — and closing it must not be the
		// backend's way of saying "everything is revoked", which is why the gateway
		// treats a close as "reconnect" and never as "deny".
		cancel()
		select {
		case _, open := <-ch:
			if open {
				// A final event on the way out is fine; the channel still has to close.
				select {
				case _, stillOpen := <-ch:
					if stillOpen {
						r.errorf("Watch's channel is still open after its context was " +
							"cancelled")
					}
				case <-time.After(2 * time.Second):
					r.errorf("Watch's channel did not close within 2s of cancellation")
				}
			}
		case <-time.After(2 * time.Second):
			r.errorf("Watch's channel did not close within 2s of cancellation; the " +
				"gateway's watcher goroutine leaks one per reconnect")
		}
	})

	if h.SupportsWatch && h.Revoke != nil {
		r.run("a revocation reaches Watch", func(r reporter) {
			a := h.New(r.t())
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ch, err := a.Watch(ctx)
			if err != nil || ch == nil {
				r.errorf("Watch: %v", err)
				return
			}
			p, dev, _ := h.Allowed()
			h.Revoke(r.t(), p, dev)

			select {
			case ev, open := <-ch:
				if !open {
					r.errorf("Watch's channel closed instead of delivering the revocation")
					return
				}
				// An event that names neither the principal nor the device means
				// "everything", which is legitimate — so the only wrong answer is an
				// event for somebody else entirely.
				if ev.PrincipalID != "" && ev.PrincipalID != p.ID {
					r.errorf("the revocation named %q, not %q", ev.PrincipalID, p.ID)
				}
			case <-time.After(5 * time.Second):
				r.errorf("no revocation arrived within 5s.\n\n" +
					"This is not fatal to security — the re-check interval is the " +
					"guarantee and Watch is the optimisation — but a Watch that never " +
					"delivers is one the gateway is paying for and not getting.")
			}
		})
	}
}
