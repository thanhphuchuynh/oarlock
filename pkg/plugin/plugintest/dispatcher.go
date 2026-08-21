package plugintest

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
)

// DispatcherHarness is what a doorbell author supplies.
type DispatcherHarness struct {
	New func(t *testing.T) plugin.Dispatcher
	// Device is one this dispatcher can wake.
	Device func() *plugin.Device
	// Invitation is a plausible payload.
	Invitation func() frame.Invitation

	// BreakTransport makes the doorbell's own transport fail — the broker is down, the
	// HTTP endpoint refuses. Required, because the distinction it tests is the one this
	// interface exists to get right.
	BreakTransport func(t *testing.T) (restore func())
	// NoTransportToBreak asserts the dispatcher has no transport that can fail. True of
	// an in-process one and almost nothing else.
	NoTransportToBreak bool

	// UnreachableDevice returns a device the transport can reach but that is *not
	// there* — a stale push token, an unsubscribed topic. Optional; without it the
	// suite cannot check the distinction between the two failures, and says so.
	UnreachableDevice func() *plugin.Device
}

// Dispatcher runs the conformance suite against a Dispatcher implementation.
func Dispatcher(t *testing.T, h DispatcherHarness) {
	t.Helper()
	runDispatcher(liveReporter{t}, h)
}

func runDispatcher(r reporter, h DispatcherHarness) {
	if h.New == nil || h.Device == nil || h.Invitation == nil {
		r.fatalf("plugintest: DispatcherHarness needs New, Device and Invitation")
		return
	}

	r.run("wakes a device", func(r reporter) {
		d := h.New(r.t())
		if err := d.Wake(context.Background(), h.Device(), h.Invitation()); err != nil {
			r.errorf("waking a reachable device failed: %v", err)
		}
	})

	// The distinction ARCHITECTURE § 11 is emphatic about: a broken doorbell is *our*
	// fault and must not be reported as the device being offline, because "offline"
	// sends an engineer to look at hardware in a gym when the broker is what is down.
	r.run("a broken transport is not reported as an absent device", func(r reporter) {
		if h.BreakTransport == nil {
			if !h.NoTransportToBreak {
				r.errorf("plugintest: BreakTransport is nil.\n\n" +
					"A dispatcher has two distinct failures and the gateway shows " +
					"different screens for them: the doorbell itself failing " +
					"(doorbell_failed — ours) and the device not being there " +
					"(device_unreachable — theirs). Conflating them sends somebody to " +
					"inspect hardware because a message broker is down.\n\n" +
					"Supply BreakTransport, or set NoTransportToBreak if this dispatcher " +
					"has no transport that can fail.")
			}
			return
		}
		d := h.New(r.t())
		restore := h.BreakTransport(r.t())
		if restore == nil {
			r.errorf("BreakTransport returned no restore function")
			return
		}
		err := d.Wake(context.Background(), h.Device(), h.Invitation())
		restore()

		switch {
		case err == nil:
			r.errorf("with its transport broken, Wake reported success. The gateway " +
				"then waits out the answer deadline for a device that was never told " +
				"anything, and reports the device as offline")
		case errors.Is(err, plugin.ErrDeviceUnreachable):
			r.errorf("with its transport broken, Wake returned ErrDeviceUnreachable.\n\n" +
				"That means \"the doorbell worked and the device is not there\", and it " +
				"is shown to an operator as a problem with the device. Return an " +
				"ordinary error instead: the gateway reports doorbell_failed and says " +
				"the fault is ours.")
		}
	})

	r.run("an unreachable device says so specifically", func(r reporter) {
		if h.UnreachableDevice == nil {
			// Not a failure: plenty of transports cannot tell. But it is worth being
			// visible that this half of the distinction went unchecked.
			r.run("skipped: no UnreachableDevice in the harness", func(reporter) {})
			return
		}
		d := h.New(r.t())
		err := d.Wake(context.Background(), h.UnreachableDevice(), h.Invitation())
		if err == nil {
			r.errorf("waking a device that is not there reported success")
			return
		}
		if !errors.Is(err, plugin.ErrDeviceUnreachable) {
			r.errorf("waking an absent device returned %v; return "+
				"plugin.ErrDeviceUnreachable so the gateway can tell the operator it is "+
				"the device rather than the doorbell", err)
		}
	})

	r.run("cancellation is honoured", func(r reporter) {
		d := h.New(r.t())
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := d.Wake(ctx, h.Device(), h.Invitation()); err == nil {
			r.errorf("Wake on a cancelled context reported success; the gateway has " +
				"already stopped waiting for this device")
		}
	})

	r.run("concurrent wakes are safe", func(r reporter) {
		d := h.New(r.t())
		var wg sync.WaitGroup
		errs := make(chan error, 16)
		for range 16 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := d.Wake(context.Background(), h.Device(), h.Invitation()); err != nil {
					errs <- err
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			r.errorf("under concurrency: %v", err)
		}
	})

	r.run("the invitation is not logged", func(r reporter) {
		// A doorbell payload contains a single-use ticket, and a log line is the one
		// place a single-use secret becomes multi-use. The suite cannot read a
		// backend's logs, so this checks the part it can: that Wake does not hand the
		// ticket back in an error message.
		d := h.New(r.t())
		inv := h.Invitation()
		if inv.Ticket == "" {
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := d.Wake(ctx, h.Device(), inv); err != nil {
			if containsSecret(err.Error(), inv.Ticket) {
				r.errorf("Wake's error contains the ticket. Errors reach logs, and a " +
					"single-use secret in a log is a multi-use secret")
			}
		}
	})
}

func containsSecret(haystack, secret string) bool {
	if len(secret) < 8 {
		return false
	}
	return len(haystack) > 0 && strings.Contains(haystack, secret)
}
