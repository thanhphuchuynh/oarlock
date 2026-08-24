package oidc_test

// The device-code login, which is how SSH authenticates without a key or a password.
//
// What these cover that the HTTP tests do not: the flow's *protocol*. A pending login is
// an HTTP 400 with a JSON body, so a client that reads the status instead of the body
// treats every unfinished login as a hard failure — and that is the mistake that turns
// "waiting for you to tap approve" into "authentication failed".

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/auth/oidc"
	"github.com/oarlock/oarlock/pkg/plugin"
)

// prompts records what the operator was shown and answers immediately.
type prompts struct {
	shown  []string
	rounds atomic.Int32
}

func (p *prompts) ask() plugin.Challenge {
	return func(instruction string, questions []string, echos []bool) ([]string, error) {
		p.rounds.Add(1)
		p.shown = append(p.shown, instruction)
		out := make([]string, len(questions))
		return out, nil
	}
}

func TestADeviceLoginShowsTheCodeAndReturnsThePrincipal(t *testing.T) {
	p := newProvider(t)
	a := open(t, p, nil)
	p.idToken = p.mint(t, "RS256", "rsa-1", p.key("rsa-1"), p.good(clientID))

	ask := &prompts{}
	got, err := a.AuthInteractive(context.Background(), "treadmill-4821", ask.ask())
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "amelia@example.com" {
		t.Fatalf("ID = %q", got.ID)
	}
	if len(ask.shown) == 0 {
		t.Fatal("the operator was shown nothing")
	}
	first := ask.shown[0]
	// The code and a URL, because one without the other is not a login anybody can
	// complete from a terminal.
	for _, want := range []string{"WXYZ-1234", "/approve"} {
		if !strings.Contains(first, want) {
			t.Fatalf("the prompt does not contain %q:\n%s", want, first)
		}
	}
	// And the reassurance that this is not a password prompt, because the whole reason
	// for this flow is that an operator should never type their provider password into a
	// terminal that could be anything.
	if !strings.Contains(first, "never sees your password") {
		t.Fatalf("the prompt does not say the gateway sees no password:\n%s", first)
	}
}

// TestAPendingLoginIsNotAFailure. RFC 8628 reports "not yet" as a 400.
func TestAPendingLoginIsNotAFailure(t *testing.T) {
	p := newProvider(t)
	p.pendingPolls = 2
	a := open(t, p, nil)
	p.idToken = p.mint(t, "RS256", "rsa-1", p.key("rsa-1"), p.good(clientID))

	ask := &prompts{}
	if _, err := a.AuthInteractive(context.Background(), "dev", ask.ask()); err != nil {
		t.Fatalf("a login that took two rounds failed: %v", err)
	}
	if p.polls < 3 {
		t.Fatalf("polled %d times; the pending rounds were not retried", p.polls)
	}
	// A prompt that goes silent for a minute looks like a hang, and an operator who
	// thinks it hung opens a second session.
	if ask.rounds.Load() < 2 {
		t.Fatalf("the operator saw %d prompts across three polls; a long wait must say "+
			"something", ask.rounds.Load())
	}
}

func TestSlowDownIsHonoured(t *testing.T) {
	p := newProvider(t)
	p.slowDownOnce = true
	a := open(t, p, nil)
	p.idToken = p.mint(t, "RS256", "rsa-1", p.key("rsa-1"), p.good(clientID))

	start := time.Now()
	ask := &prompts{}
	if _, err := a.AuthInteractive(context.Background(), "dev", ask.ask()); err != nil {
		t.Fatalf("slow_down was treated as a failure: %v", err)
	}
	// The interval started at one second and slow_down adds five, so the second poll
	// cannot have happened promptly. Asserting the floor rather than an exact figure:
	// this is about not ignoring the provider, not about precise timing.
	if elapsed := time.Since(start); elapsed < 5*time.Second {
		t.Fatalf("the second poll came after %s; slow_down asks for five more seconds",
			elapsed.Round(time.Millisecond))
	}
}

func TestTerminalDeviceErrors(t *testing.T) {
	for _, tc := range []struct{ providerError, want string }{
		{"access_denied", "declined"},
		{"expired_token", "expired"},
		{"invalid_client", "refused the login"},
	} {
		t.Run(tc.providerError, func(t *testing.T) {
			p := newProvider(t)
			p.deviceError = tc.providerError
			a := open(t, p, nil)
			ask := &prompts{}
			_, err := a.AuthInteractive(context.Background(), "dev", ask.ask())
			if err == nil {
				t.Fatal("the login succeeded despite the provider refusing")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestAProviderWithoutTheDeviceGrantSaysSo. The fix is at the provider, so an operator
// reading "authentication failed" would go looking in the wrong place.
func TestAProviderWithoutTheDeviceGrantSaysSo(t *testing.T) {
	p := newProvider(t)
	p.noDeviceEndpoint = true
	a := open(t, p, nil)
	_, err := a.AuthInteractive(context.Background(), "dev", (&prompts{}).ask())
	if err == nil {
		t.Fatal("a provider with no device endpoint somehow logged somebody in")
	}
	for _, want := range []string{"device_authorization_endpoint", "SSH-CA"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
}

// TestTheIDTokenFromTheDeviceFlowIsStillVerified.
//
// The tempting shortcut is "we just fetched this from the provider over TLS, so trust
// it". Two doors into one system enforcing different rules is how one of them ends up
// being the way in.
func TestTheIDTokenFromTheDeviceFlowIsStillVerified(t *testing.T) {
	p := newProvider(t)
	other := newProvider(t)
	a := open(t, p, nil)
	// A well-formed token from the wrong issuer, handed over by the right provider.
	p.idToken = other.mint(t, "RS256", "rsa-1", other.key("rsa-1"), other.good(clientID))

	_, err := a.AuthInteractive(context.Background(), "dev", (&prompts{}).ask())
	if err == nil {
		t.Fatal("an id_token from another issuer was accepted because it arrived over TLS")
	}
}

func TestNoIDTokenIsNamedPrecisely(t *testing.T) {
	p := newProvider(t)
	a := open(t, p, nil)
	p.idToken = "" // the provider returned only an access token
	_, err := a.AuthInteractive(context.Background(), "dev", (&prompts{}).ask())
	if err == nil || !strings.Contains(err.Error(), "openid scope") {
		t.Fatalf("error = %v; a missing id_token is nearly always a missing scope", err)
	}
}

// TestAnOperatorWhoHangsUpEndsTheLogin: the challenge returning an error means the SSH
// client is gone, and polling for a login nobody is waiting on is just load.
func TestAnOperatorWhoHangsUpEndsTheLogin(t *testing.T) {
	p := newProvider(t)
	p.pendingPolls = 100
	a := open(t, p, nil)
	hangUp := func(string, []string, []bool) ([]string, error) {
		return nil, context.Canceled
	}
	if _, err := a.AuthInteractive(context.Background(), "dev", hangUp); err == nil {
		t.Fatal("the login continued after the client hung up")
	}
}

func TestTheLoginGivesUp(t *testing.T) {
	p := newProvider(t)
	p.pendingPolls = 1000
	a := open(t, p, func(c *oidc.Config) { c.DeviceTimeout = 1200 * time.Millisecond })
	start := time.Now()
	_, err := a.AuthInteractive(context.Background(), "dev", (&prompts{}).ask())
	if err == nil {
		t.Fatal("an unapproved login waited forever")
	}
	if time.Since(start) > 10*time.Second {
		t.Fatalf("it took %s to give up", time.Since(start))
	}
}
