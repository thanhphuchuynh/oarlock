package plugintest

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
)

// The same discipline as the Authorizer suite: prove these reject the backends they exist
// to reject, or they are decoration.

// ── Authenticator ───────────────────────────────────────────────────────────────

type fakeKey struct{ name string }

func (k fakeKey) Type() string                        { return "ssh-fake" }
func (k fakeKey) Marshal() []byte                     { return []byte(k.name) }
func (k fakeKey) Verify([]byte, *ssh.Signature) error { return nil }

var goodKey = fakeKey{"good"}
var badKey = fakeKey{"bad"}

type authn struct {
	// what the fake gets wrong
	vagueUnsupported bool
	acceptsAnyKey    bool
	usesUserField    bool
	principalAndErr  bool
}

func (a *authn) AuthPublicKey(_ context.Context, user string, key ssh.PublicKey) (*plugin.Principal, error) {
	if a.usesUserField && user != "treadmill-4821" {
		return &plugin.Principal{ID: "somebody-else@example.com"}, nil
	}
	if a.acceptsAnyKey || (key != nil && string(key.Marshal()) == "good") {
		return &plugin.Principal{ID: "phuc@example.com"}, nil
	}
	if a.principalAndErr {
		return &plugin.Principal{ID: "phuc@example.com"}, errors.New("refused")
	}
	return nil, errors.New("unknown key")
}

func (a *authn) AuthDelegated(context.Context, *plugin.Principal, string) (*plugin.Principal, error) {
	if a.vagueUnsupported {
		return nil, errors.New("not implemented")
	}
	return nil, plugin.ErrUnsupported
}

func (a *authn) AuthHTTP(context.Context, *http.Request) (*plugin.Principal, error) {
	if a.vagueUnsupported {
		return nil, errors.New("no")
	}
	return nil, plugin.ErrUnsupported
}

func authnHarness(a plugin.Authenticator) AuthenticatorHarness {
	return AuthenticatorHarness{
		New:     func(*testing.T) plugin.Authenticator { return a },
		GoodKey: func(*testing.T) (ssh.PublicKey, string) { return goodKey, "phuc@example.com" },
		BadKey:  func(*testing.T) ssh.PublicKey { return badKey },
	}
}

func runAuthn(h AuthenticatorHarness) *recorded {
	r := &recorded{name: "suite"}
	func() {
		defer func() {
			if p := recover(); p != nil {
				if _, ok := p.(fatalSentinel); !ok {
					panic(p)
				}
			}
		}()
		runAuthenticator(r, h)
	}()
	return r
}

func TestAConformingAuthenticatorPasses(t *testing.T) {
	if got := runAuthn(authnHarness(&authn{})); got.failed() {
		t.Errorf("a conforming authenticator failed:\n%s", got.messages())
	}
}

func TestAnAuthenticatorThatIsVagueAboutUnsupportedFails(t *testing.T) {
	// A backend that returns a generic error from a method it does not implement makes
	// every API request look like a bad password, and every On-Behalf-Of call look like
	// a rejected assertion.
	got := runAuthn(authnHarness(&authn{vagueUnsupported: true}))
	if !got.failed() {
		t.Fatal("the suite passed a backend that cannot say 'I do not do that'")
	}
	if !strings.Contains(got.messages(), "ErrUnsupported") {
		t.Errorf("the failure does not say what to return:\n%s", got.messages())
	}
}

func TestAnAuthenticatorThatAcceptsAnyKeyFails(t *testing.T) {
	got := runAuthn(authnHarness(&authn{acceptsAnyKey: true}))
	if !got.failed() {
		t.Fatal("the suite passed a backend that accepts every key")
	}
}

func TestAnAuthenticatorThatAuthenticatesOnTheUserFieldFails(t *testing.T) {
	// `user` is the device id. A backend that changes who somebody is based on it is
	// enforcing an access rule nobody can see, and the gateway checks the device
	// separately anyway.
	got := runAuthn(authnHarness(&authn{usesUserField: true}))
	if !got.failed() {
		t.Fatal("the suite passed a backend whose answer depends on the device id")
	}
	if !contains(got.failedCases(), "the user field is not used for authentication") {
		t.Errorf("the wrong case failed: %v", got.failedCases())
	}
}

func TestAnAuthenticatorThatReturnsBothFails(t *testing.T) {
	// A middleware that checks the principal before the error would authenticate
	// somebody the backend refused.
	got := runAuthn(authnHarness(&authn{principalAndErr: true}))
	if !got.failed() {
		t.Fatal("the suite passed a backend that returns a principal alongside an error")
	}
}

func TestAnAuthenticatorHarnessWithNoRefusalFails(t *testing.T) {
	h := authnHarness(&authn{})
	h.BadKey = nil
	got := runAuthn(h)
	if !got.failed() {
		t.Fatal("a harness that never sees a key refused passed — it cannot tell this " +
			"backend from one that accepts everything")
	}
}

func TestAnAuthenticatorThatAuthenticatesNobodyFails(t *testing.T) {
	got := runAuthn(AuthenticatorHarness{
		New: func(*testing.T) plugin.Authenticator { return &authn{} },
	})
	if !got.failed() {
		t.Fatal("a harness with neither GoodKey nor GoodRequest passed")
	}
}

// ── Dispatcher ──────────────────────────────────────────────────────────────────

type doorbell struct {
	broken bool
	// what it gets wrong
	unreachableOnBreak bool
	successOnBreak     bool
	vagueOnAbsent      bool
	leaksTicket        bool
	ignoresCancel      bool
}

func (d *doorbell) Wake(ctx context.Context, dev *plugin.Device, inv frame.Invitation) error {
	if !d.ignoresCancel {
		if err := ctx.Err(); err != nil {
			if d.leaksTicket {
				return errors.New("wake failed with ticket " + inv.Ticket)
			}
			return err
		}
	}
	if d.broken {
		switch {
		case d.successOnBreak:
			return nil
		case d.unreachableOnBreak:
			return plugin.ErrDeviceUnreachable
		default:
			return errors.New("doorbell: broker unavailable")
		}
	}
	if strings.HasPrefix(dev.ID, "gone-") {
		if d.vagueOnAbsent {
			return errors.New("could not deliver")
		}
		return plugin.ErrDeviceUnreachable
	}
	return nil
}

func doorbellHarness(d *doorbell) DispatcherHarness {
	return DispatcherHarness{
		New:    func(*testing.T) plugin.Dispatcher { return d },
		Device: func() *plugin.Device { return &plugin.Device{ID: "treadmill-4821"} },
		UnreachableDevice: func() *plugin.Device {
			return &plugin.Device{ID: "gone-4821"}
		},
		Invitation: func() frame.Invitation {
			return frame.Invitation{
				SessionID: "sess_1",
				Ticket:    "a-ticket-long-enough-to-matter",
			}
		},
		BreakTransport: func(*testing.T) func() {
			d.broken = true
			return func() { d.broken = false }
		},
	}
}

func runDisp(h DispatcherHarness) *recorded {
	r := &recorded{name: "suite"}
	func() {
		defer func() {
			if p := recover(); p != nil {
				if _, ok := p.(fatalSentinel); !ok {
					panic(p)
				}
			}
		}()
		runDispatcher(r, h)
	}()
	return r
}

func TestAConformingDispatcherPasses(t *testing.T) {
	if got := runDisp(doorbellHarness(&doorbell{})); got.failed() {
		t.Errorf("a conforming dispatcher failed:\n%s", got.messages())
	}
}

func TestADispatcherThatBlamesTheDeviceForItsOwnFailureFails(t *testing.T) {
	// The distinction ARCHITECTURE § 11 is emphatic about: saying "offline" sends an
	// engineer to look at hardware in a gym when the broker is what is down.
	got := runDisp(doorbellHarness(&doorbell{unreachableOnBreak: true}))
	if !got.failed() {
		t.Fatal("the suite passed a dispatcher that reports its own outage as the " +
			"device being absent")
	}
	if !strings.Contains(got.messages(), "doorbell_failed") {
		t.Errorf("the failure does not name the screen it corrupts:\n%s", got.messages())
	}
}

func TestADispatcherThatReportsSuccessWhileBrokenFails(t *testing.T) {
	got := runDisp(doorbellHarness(&doorbell{successOnBreak: true}))
	if !got.failed() {
		t.Fatal("the suite passed a dispatcher that reports success while broken — the " +
			"gateway then waits out the answer deadline for a device nobody told anything")
	}
}

func TestADispatcherThatIsVagueAboutAnAbsentDeviceFails(t *testing.T) {
	got := runDisp(doorbellHarness(&doorbell{vagueOnAbsent: true}))
	if !got.failed() {
		t.Fatal("the suite passed a dispatcher that cannot say the device is absent")
	}
}

func TestADispatcherThatLeaksTheTicketFails(t *testing.T) {
	// A doorbell payload contains a single-use ticket, and an error message reaches
	// logs. A single-use secret in a log is a multi-use secret.
	got := runDisp(doorbellHarness(&doorbell{leaksTicket: true}))
	if !got.failed() {
		t.Fatal("the suite passed a dispatcher that puts the ticket in its error")
	}
	if !contains(got.failedCases(), "the invitation is not logged") {
		t.Errorf("the wrong case failed: %v", got.failedCases())
	}
}

func TestADispatcherThatIgnoresCancellationFails(t *testing.T) {
	got := runDisp(doorbellHarness(&doorbell{ignoresCancel: true}))
	if !got.failed() {
		t.Fatal("the suite passed a dispatcher that wakes a device the gateway has " +
			"stopped waiting for")
	}
}

func TestADispatcherHarnessWithoutBreakTransportFails(t *testing.T) {
	h := doorbellHarness(&doorbell{})
	h.BreakTransport = nil
	got := runDisp(h)
	if !got.failed() {
		t.Fatal("a harness with no BreakTransport passed, so the case that distinguishes " +
			"the two failures never ran")
	}
	if !strings.Contains(got.messages(), "NoTransportToBreak") {
		t.Errorf("the failure does not say how to proceed:\n%s", got.messages())
	}
}

func TestADispatcherHarnessMayOptOutOfBreaking(t *testing.T) {
	h := doorbellHarness(&doorbell{})
	h.BreakTransport = nil
	h.NoTransportToBreak = true
	if got := runDisp(h); got.failed() {
		t.Errorf("an in-process dispatcher with no transport failed:\n%s", got.messages())
	}
}
