package oidc_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/auth/oidc"
	"github.com/oarlock/oarlock/pkg/plugin"
)

const clientID = "oarlock-gateway"

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func open(t *testing.T, p *provider, tweak func(*oidc.Config)) *oidc.Authenticator {
	t.Helper()
	cfg := oidc.Config{
		Issuer:   p.issuer(),
		ClientID: clientID,
		Log:      quiet(),
	}
	if tweak != nil {
		tweak(&cfg)
	}
	a, err := oidc.Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func request(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

// ── the happy paths, so the attacks below mean something ────────────────────────

func TestAValidTokenBecomesAPrincipal(t *testing.T) {
	p := newProvider(t)
	a := open(t, p, nil)
	token := p.mint(t, "RS256", "rsa-1", p.key("rsa-1"), p.good(clientID))

	got, err := a.AuthHTTP(context.Background(), request(token))
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "amelia@example.com" {
		t.Fatalf("ID = %q; the default mapping is the email claim, because authorisation "+
			"rules are globs over principal ids", got.ID)
	}
	if got.Email != "amelia@example.com" {
		t.Fatalf("Email = %q", got.Email)
	}
	if len(got.Groups) != 2 || got.Groups[0] != "oncall" {
		t.Fatalf("Groups = %v", got.Groups)
	}
	if got.Attrs["sub"] != "subject-1" || got.Attrs["iss"] != p.issuer() {
		t.Fatalf("Attrs = %v; the immutable subject and issuer should survive even when "+
			"the id is the email", got.Attrs)
	}
	// The credential's expiry becomes the session's ceiling. Without it a shell opened a
	// minute before the token expired would outlive it by hours.
	if got.Expiry.IsZero() {
		t.Fatal("Expiry is zero, so a session could outlive the token that opened it")
	}
}

func TestES256IsAccepted(t *testing.T) {
	p := newProvider(t)
	a := open(t, p, nil)
	token := p.mint(t, "ES256", "ec-1", p.key("ec-1"), p.good(clientID))
	if _, err := a.AuthHTTP(context.Background(), request(token)); err != nil {
		t.Fatalf("a valid ES256 token was refused: %v", err)
	}
}

// ── the attacks ─────────────────────────────────────────────────────────────────

// TestTheAttacksOnTokenVerification is the reason this package owns its verifier rather
// than importing one. Each case is a documented way to make a JWT library accept a token
// it should not.
func TestTheAttacksOnTokenVerification(t *testing.T) {
	p := newProvider(t)
	a := open(t, p, nil)
	rsaKey := p.key("rsa-1")

	// A second provider, to mint tokens signed by a key this gateway has never seen.
	other := newProvider(t)

	for _, tc := range []struct {
		name  string
		token func(t *testing.T) string
		// want is a fragment the refusal must mention, so the log tells an operator
		// which attack arrived rather than just "authentication failed".
		want string
	}{
		{
			name: "alg none asks the verifier to skip the signature",
			token: func(t *testing.T) string {
				return p.mint(t, "none", "rsa-1", rsaKey, p.good(clientID))
			},
			want: "refusing algorithm",
		},
		{
			name: "HS256 with the public key as the HMAC secret",
			token: func(t *testing.T) string {
				return p.mint(t, "HS256", "rsa-1", rsaKey, p.good(clientID))
			},
			want: "refusing algorithm",
		},
		{
			name: "an RSA key with an ECDSA header",
			token: func(t *testing.T) string {
				// Signed properly by the EC key but labelled against the RSA kid: a
				// verifier that trusts the header to pick a key type is confused here.
				return p.mint(t, "ES256", "rsa-1", p.key("ec-1"), p.good(clientID))
			},
			want: "is RSA",
		},
		{
			name: "a token signed by a key we have never seen",
			token: func(t *testing.T) string {
				c := p.good(clientID)
				return other.mint(t, "RS256", "rsa-1", other.key("rsa-1"), c)
			},
			want: "does not verify",
		},
		{
			name: "an unknown kid",
			token: func(t *testing.T) string {
				return p.mint(t, "RS256", "not-a-kid", rsaKey, p.good(clientID))
			},
			want: "kid",
		},
		{
			name: "the payload edited after signing",
			token: func(t *testing.T) string {
				return tamper(p.mint(t, "RS256", "rsa-1", rsaKey, p.good(clientID)))
			},
			want: "does not verify",
		},
		{
			name: "another provider's issuer",
			token: func(t *testing.T) string {
				c := p.good(clientID)
				c["iss"] = "https://issuer.example.com"
				return p.mint(t, "RS256", "rsa-1", rsaKey, c)
			},
			want: "issuer",
		},
		{
			name: "an issuer that only looks like ours",
			token: func(t *testing.T) string {
				c := p.good(clientID)
				c["iss"] = p.issuer() + ".attacker.test"
				return p.mint(t, "RS256", "rsa-1", rsaKey, c)
			},
			want: "issuer",
		},
		{
			name: "a token minted for another relying party",
			token: func(t *testing.T) string {
				c := p.good(clientID)
				c["aud"] = "somebody-elses-app"
				return p.mint(t, "RS256", "rsa-1", rsaKey, c)
			},
			want: "audience",
		},
		{
			name: "no exp, so the token never expires",
			token: func(t *testing.T) string {
				c := p.good(clientID)
				delete(c, "exp")
				return p.mint(t, "RS256", "rsa-1", rsaKey, c)
			},
			want: "no exp",
		},
		{
			name: "expired",
			token: func(t *testing.T) string {
				c := p.good(clientID)
				c["exp"] = time.Now().Add(-2 * time.Hour).Unix()
				return p.mint(t, "RS256", "rsa-1", rsaKey, c)
			},
			want: "expired",
		},
		{
			name: "not valid yet",
			token: func(t *testing.T) string {
				c := p.good(clientID)
				c["nbf"] = time.Now().Add(2 * time.Hour).Unix()
				return p.mint(t, "RS256", "rsa-1", rsaKey, c)
			},
			want: "not valid until",
		},
		{
			name: "issued in the future",
			token: func(t *testing.T) string {
				c := p.good(clientID)
				c["iat"] = time.Now().Add(2 * time.Hour).Unix()
				return p.mint(t, "RS256", "rsa-1", rsaKey, c)
			},
			want: "issued in the future",
		},
		{
			name: "no sub",
			token: func(t *testing.T) string {
				c := p.good(clientID)
				delete(c, "sub")
				return p.mint(t, "RS256", "rsa-1", rsaKey, c)
			},
			want: "no sub",
		},
		{
			name: "an unverified email, which is a name its owner chose",
			token: func(t *testing.T) string {
				c := p.good(clientID)
				c["email_verified"] = false
				return p.mint(t, "RS256", "rsa-1", rsaKey, c)
			},
			want: "email_verified",
		},
		{
			name: "a JWE, whose first three segments are not a JWS",
			token: func(t *testing.T) string {
				return "a.b.c.d.e"
			},
			want: "5 segments",
		},
		{
			name:  "an empty segment",
			token: func(t *testing.T) string { return "a..c" },
			want:  "empty segment",
		},
		{
			name:  "not a token at all",
			token: func(t *testing.T) string { return "hello" },
			want:  "segments",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := a.AuthHTTP(context.Background(), request(tc.token(t)))
			if err == nil {
				t.Fatal("ACCEPTED — this token should not have verified")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refused, but for the wrong reason.\n  got:  %v\n  want it to mention: %q",
					err, tc.want)
			}
		})
	}
}

// TestStandardBase64IsNotAccepted: a decoder that takes both encodings accepts two
// spellings of one token, and anything downstream that keys on the string sees two.
func TestStandardBase64IsNotAccepted(t *testing.T) {
	p := newProvider(t)
	a := open(t, p, nil)
	token := p.mint(t, "RS256", "rsa-1", p.key("rsa-1"), p.good(clientID))
	// Padding is what standard base64 adds and base64url-unpadded does not.
	padded := strings.Replace(token, ".", "==.", 1)
	if _, err := a.AuthHTTP(context.Background(), request(padded)); err == nil {
		t.Fatal("a padded segment was accepted")
	}
}

// ── key rotation ────────────────────────────────────────────────────────────────

// TestAKeyRotationIsSurvived. A provider rotates on its own schedule and tells nobody,
// so the first token signed by a new key is the notification.
func TestAKeyRotationIsSurvived(t *testing.T) {
	p := newProvider(t)
	a := open(t, p, func(c *oidc.Config) { c.JWKSRefresh = time.Nanosecond })
	fetchesAfterOpen := p.jwksFetches

	fresh := p.rotate(t)
	token := p.mint(t, "RS256", fresh.kid, fresh, p.good(clientID))

	if _, err := a.AuthHTTP(context.Background(), request(token)); err != nil {
		t.Fatalf("a token signed by a rotated-in key was refused: %v", err)
	}
	if p.jwksFetches <= fetchesAfterOpen {
		t.Fatal("the key set was never refetched, so this passed for the wrong reason")
	}
}

// TestARetiredKeyStopsVerifying, separately and explicitly.
func TestARetiredKeyStopsVerifying(t *testing.T) {
	p := newProvider(t)
	a := open(t, p, func(c *oidc.Config) { c.JWKSRefresh = time.Nanosecond })
	retiring := p.key("rsa-1")

	// A token signed by the key that is about to be withdrawn.
	token := p.mint(t, "RS256", "rsa-1", retiring, p.good(clientID))
	if _, err := a.AuthHTTP(context.Background(), request(token)); err != nil {
		t.Fatalf("the token was not valid before the rotation either: %v", err)
	}

	p.rotate(t) // publishes only rsa-2 from now on
	if _, err := a.AuthHTTP(context.Background(), request(token)); err == nil {
		t.Fatal("a token signed by a withdrawn key still verifies — the key set is " +
			"being merged rather than replaced")
	}
}

// TestARefetchIsRateLimited: an unknown kid triggers a refetch, so a stream of invented
// kids must not become a stream of requests pointed at the provider.
func TestARefetchIsRateLimited(t *testing.T) {
	p := newProvider(t)
	a := open(t, p, func(c *oidc.Config) { c.JWKSRefresh = time.Hour })
	before := p.jwksFetches

	for i := range 20 {
		token := p.mint(t, "RS256", "invented-kid", p.key("rsa-1"), p.good(clientID))
		if _, err := a.AuthHTTP(context.Background(), request(token)); err == nil {
			t.Fatalf("attempt %d: an invented kid was accepted", i)
		}
	}
	if fetches := p.jwksFetches - before; fetches > 1 {
		t.Fatalf("twenty invented kids caused %d key fetches; the rate limit is not "+
			"holding and this is an amplifier pointed at the provider", fetches)
	}
}

// ── discovery ───────────────────────────────────────────────────────────────────

func TestDiscoveryChecksTheIssuerItGot(t *testing.T) {
	p := newProvider(t)
	p.issuerOverride = "https://somebody-else.example.com"
	_, err := oidc.Open(context.Background(), oidc.Config{
		Issuer: p.issuer(), ClientID: clientID, Log: quiet(),
	})
	if err == nil {
		t.Fatal("a discovery document claiming another issuer was accepted")
	}
	if !strings.Contains(err.Error(), "claims issuer") {
		t.Fatalf("error = %v", err)
	}
}

func TestAnHTTPIssuerIsRefusedUnlessItIsLoopback(t *testing.T) {
	// Every check in the package rests on a document fetched from the issuer, and over
	// http anyone on the path writes it.
	_, err := oidc.Open(context.Background(), oidc.Config{
		Issuer: "http://issuer.example.com", ClientID: clientID, Log: quiet(),
	})
	if err == nil || !strings.Contains(err.Error(), "must be https") {
		t.Fatalf("a plaintext issuer was accepted or refused unclearly: %v", err)
	}
	// The loopback exemption is what makes a test double and a developer's own provider
	// usable, and it is the only exemption.
	p := newProvider(t)
	if _, err := oidc.Open(context.Background(), oidc.Config{
		Issuer: p.issuer(), ClientID: clientID, Log: quiet(),
	}); err != nil {
		t.Fatalf("a loopback provider was refused: %v", err)
	}
}

func TestOpenValidates(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		cfg        oidc.Config
	}{
		{"no issuer", "issuer is required", oidc.Config{ClientID: "x"}},
		{"no client id", "client_id is required", oidc.Config{Issuer: "https://x"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.Log = quiet()
			if _, err := oidc.Open(context.Background(), tc.cfg); err == nil ||
				!strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// ── claim mapping ───────────────────────────────────────────────────────────────

func TestTheSubjectClaimIsAChoice(t *testing.T) {
	p := newProvider(t)
	// A deployment that wants immutability over legibility maps `sub` instead, and then
	// an unverified email is no longer a way to claim somebody's identity.
	a := open(t, p, func(c *oidc.Config) { c.Claims.Subject = "sub"; c.Claims.Email = "sub" })
	c := p.good(clientID)
	c["email_verified"] = false
	got, err := a.AuthHTTP(context.Background(), request(p.mint(t, "RS256", "rsa-1", p.key("rsa-1"), c)))
	if err != nil {
		t.Fatalf("mapping to sub was refused: %v", err)
	}
	if got.ID != "subject-1" {
		t.Fatalf("ID = %q, want the sub claim", got.ID)
	}
}

func TestGroupsFromEitherShape(t *testing.T) {
	p := newProvider(t)
	a := open(t, p, nil)

	// A space-separated string, which some providers send instead of a list.
	c := p.good(clientID)
	c["groups"] = "oncall platform"
	got, err := a.AuthHTTP(context.Background(), request(p.mint(t, "RS256", "rsa-1", p.key("rsa-1"), c)))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Groups) != 2 || got.Groups[1] != "platform" {
		t.Fatalf("Groups = %v, want the string split", got.Groups)
	}

	// Absent is not an error: a deployment may authorise on principal id alone.
	c = p.good(clientID)
	delete(c, "groups")
	got, err = a.AuthHTTP(context.Background(), request(p.mint(t, "RS256", "rsa-1", p.key("rsa-1"), c)))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Groups) != 0 {
		t.Fatalf("Groups = %v, want none", got.Groups)
	}
}

func TestACustomGroupsClaim(t *testing.T) {
	p := newProvider(t)
	a := open(t, p, func(c *oidc.Config) { c.Claims.Groups = "roles" })
	c := p.good(clientID)
	delete(c, "groups")
	c["roles"] = []string{"sre"}
	got, err := a.AuthHTTP(context.Background(), request(p.mint(t, "RS256", "rsa-1", p.key("rsa-1"), c)))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Groups) != 1 || got.Groups[0] != "sre" {
		t.Fatalf("Groups = %v", got.Groups)
	}
}

func TestAMissingSubjectClaimSaysWhichOne(t *testing.T) {
	p := newProvider(t)
	a := open(t, p, nil)
	c := p.good(clientID)
	delete(c, "email")
	_, err := a.AuthHTTP(context.Background(), request(p.mint(t, "RS256", "rsa-1", p.key("rsa-1"), c)))
	if err == nil {
		t.Fatal("a token with no email became a principal with no id")
	}
	// The message has to name the claim and hint at scopes, because that is nearly
	// always the cause and it is fixed at the provider.
	for _, want := range []string{"email", "scopes"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
}

// ── the other surfaces ──────────────────────────────────────────────────────────

func TestNoBearerNoPrincipal(t *testing.T) {
	p := newProvider(t)
	a := open(t, p, nil)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	if _, err := a.AuthHTTP(context.Background(), r); err == nil {
		t.Fatal("a request with no Authorization header was accepted")
	}
	// The scheme is case-insensitive per RFC 7235, and clients differ.
	r.Header.Set("Authorization", "bearer "+p.mint(t, "RS256", "rsa-1", p.key("rsa-1"), p.good(clientID)))
	if _, err := a.AuthHTTP(context.Background(), r); err != nil {
		t.Fatalf("a lowercase scheme was refused: %v", err)
	}
}

func TestSSHKeysAndDelegationAreRefusedExplicitly(t *testing.T) {
	p := newProvider(t)
	a := open(t, p, nil)
	if _, err := a.AuthPublicKey(context.Background(), "dev", nil); !errors.Is(err, plugin.ErrUnsupported) {
		t.Fatalf("AuthPublicKey err = %v, want ErrUnsupported", err)
	}
	if _, err := a.AuthDelegated(context.Background(), nil, "x"); !errors.Is(err, plugin.ErrUnsupported) {
		t.Fatalf("AuthDelegated err = %v, want ErrUnsupported", err)
	}
}
