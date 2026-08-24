package authsrv_test

// The browser login, tested through a real provider double.
//
// Three things here are worth more than the rest put together, because each one is a
// vulnerability rather than a bug: the `state` check, the single-use redemption of both
// the flow and the handoff, and the refusal to redirect anywhere but this origin. A login
// endpoint with an open redirect is a phishing link that carries a real domain.

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/auth/oidc"
	"github.com/oarlock/oarlock/internal/authsrv"
)

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// harness is a gateway with a browser login, plus a client that keeps cookies and does
// not follow redirects — so a test can inspect each hop.
type harness struct {
	t        *testing.T
	provider *fakeProvider
	srv      *httptest.Server
	client   *http.Client
}

func newHarness(t *testing.T, tweak func(*authsrv.Options)) *harness {
	t.Helper()
	p := newFakeProvider(t)
	a, err := oidc.Open(context.Background(), oidc.Config{
		Issuer: p.issuer(), ClientID: clientID, Log: quiet(),
	})
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, provider: p}
	mux := http.NewServeMux()
	h.srv = httptest.NewServer(mux)
	t.Cleanup(h.srv.Close)

	o := authsrv.Options{
		OIDC:        a,
		RedirectURL: h.srv.URL + authsrv.Prefix + "/callback",
		Log:         quiet(),
	}
	if tweak != nil {
		tweak(&o)
	}
	s, err := authsrv.New(o)
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle(authsrv.Prefix+"/", s)

	jar, _ := cookiejar.New(nil)
	h.client = &http.Client{
		Jar: jar,
		// Every redirect is a fact this test wants to assert about.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       10 * time.Second,
	}
	return h
}

func (h *harness) get(path string) *http.Response {
	h.t.Helper()
	resp, err := h.client.Get(h.srv.URL + path)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

func (h *harness) post(path string) *http.Response {
	h.t.Helper()
	resp, err := h.client.Post(h.srv.URL+path, "", nil)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

// startLogin follows /auth/login and returns the parameters the provider would receive.
func (h *harness) startLogin(query string) url.Values {
	h.t.Helper()
	resp := h.get(authsrv.Prefix + "/login" + query)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		h.t.Fatalf("login status %d, want 303", resp.StatusCode)
	}
	target, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		h.t.Fatal(err)
	}
	return target.Query()
}

// ── the happy path ──────────────────────────────────────────────────────────────

func TestSignInEndToEnd(t *testing.T) {
	h := newHarness(t, nil)
	params := h.startLogin("")

	// PKCE, with S256. `plain` would make the challenge equal the verifier, which
	// protects against nobody who can read the authorization request.
	if params.Get("code_challenge") == "" || params.Get("code_challenge_method") != "S256" {
		t.Fatalf("no S256 pkce challenge: %v", params)
	}
	if params.Get("response_type") != "code" || params.Get("state") == "" {
		t.Fatalf("authorization request = %v", params)
	}
	if !strings.Contains(params.Get("scope"), "openid") {
		t.Fatalf("scope = %q, want openid", params.Get("scope"))
	}

	// The provider approves and sends the browser back.
	h.provider.expectVerifier(params.Get("code_challenge"))
	resp := h.get(authsrv.Prefix + "/callback?code=good-code&state=" + params.Get("state"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("callback status %d: %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Location"); got != "/ui/" {
		t.Fatalf("redirected to %q, want the console", got)
	}

	// The console picks the token up, once.
	tok := h.post(authsrv.Prefix + "/token")
	defer tok.Body.Close()
	if tok.StatusCode != http.StatusOK {
		t.Fatalf("token status %d", tok.StatusCode)
	}
	var out struct {
		Token     string `json:"token"`
		Principal string `json:"principal"`
	}
	if err := json.NewDecoder(tok.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Principal != "amelia@example.com" {
		t.Fatalf("principal = %q", out.Principal)
	}
	// The provider's own id_token, not something this gateway minted: a self-signed
	// token would be a second credential system to rotate and revoke.
	if strings.Count(out.Token, ".") != 2 {
		t.Fatalf("token is not a JWT: %q", out.Token)
	}

	// And only once. A handoff left redeemable is a token sitting in a cookie jar.
	again := h.post(authsrv.Prefix + "/token")
	defer again.Body.Close()
	if again.StatusCode != http.StatusNoContent {
		t.Fatalf("a second pickup returned %d; the handoff is not single-use",
			again.StatusCode)
	}
}

// ── the attacks ─────────────────────────────────────────────────────────────────

// TestTheStateIsChecked. Without it an attacker starts a flow, gets a victim's browser to
// finish it, and the victim ends up holding the attacker's session — or the reverse,
// depending on which way the flow was set up.
func TestTheStateIsChecked(t *testing.T) {
	h := newHarness(t, nil)
	params := h.startLogin("")
	h.provider.expectVerifier(params.Get("code_challenge"))

	resp := h.get(authsrv.Prefix + "/callback?code=good-code&state=not-the-state")
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusSeeOther {
		t.Fatal("a callback with the wrong state completed the login")
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", resp.StatusCode)
	}
}

// TestAFlowIsRedeemableOnce: a callback URL sits in browser history, in a referrer log
// and in a screenshot. Replaying one must not produce a second session.
func TestAFlowIsRedeemableOnce(t *testing.T) {
	h := newHarness(t, nil)
	params := h.startLogin("")
	h.provider.expectVerifier(params.Get("code_challenge"))
	callback := authsrv.Prefix + "/callback?code=good-code&state=" + params.Get("state")

	first := h.get(callback)
	first.Body.Close()
	if first.StatusCode != http.StatusSeeOther {
		t.Fatalf("the first callback failed: %d", first.StatusCode)
	}
	// The cookie is cleared by the first callback, so a replay has no flow to find.
	second := h.get(callback)
	second.Body.Close()
	if second.StatusCode == http.StatusSeeOther {
		t.Fatal("a replayed callback produced a second sign-in")
	}
}

// TestNoOpenRedirect. This is the one worth the most to an attacker: a link to the
// gateway's own login endpoint that lands on their page is a phishing link with a real
// domain in it.
func TestNoOpenRedirect(t *testing.T) {
	for _, returnTo := range []string{
		"https://evil.example.com/",
		"//evil.example.com/",
		"http://evil.example.com",
		// A backslash: url.Parse reports no host, and the browser normalises it to a
		// slash — so the gateway sees a path and the browser follows a redirect off
		// this origin. The same class of trick as the two below.
		`/\evil.example.com`,
		`/\/evil.example.com`,
		"/\tevil.example.com",
		"/\nevil.example.com",
		"javascript:alert(1)",
		"\\evil.example.com",
	} {
		t.Run(returnTo, func(t *testing.T) {
			h := newHarness(t, nil)
			params := h.startLogin("?return_to=" + url.QueryEscape(returnTo))
			h.provider.expectVerifier(params.Get("code_challenge"))
			resp := h.get(authsrv.Prefix + "/callback?code=good-code&state=" +
				params.Get("state"))
			defer resp.Body.Close()
			if got := resp.Header.Get("Location"); got != "/ui/" {
				t.Fatalf("return_to %q redirected to %q; only a path on this origin may "+
					"be honoured", returnTo, got)
			}
		})
	}
}

// TestAPathOnThisOriginIsHonoured, so the refusal above is not just "always /ui/".
func TestAPathOnThisOriginIsHonoured(t *testing.T) {
	h := newHarness(t, nil)
	params := h.startLogin("?return_to=%2Fui%2F%23%2Fsessions")
	h.provider.expectVerifier(params.Get("code_challenge"))
	resp := h.get(authsrv.Prefix + "/callback?code=good-code&state=" + params.Get("state"))
	defer resp.Body.Close()
	if got := resp.Header.Get("Location"); got != "/ui/#/sessions" {
		t.Fatalf("redirected to %q, want the requested path", got)
	}
}

// TestAProviderRefusalIsShownNotSwallowed. "access_denied" from an identity provider is
// usually a policy an operator can act on, not a gateway bug.
func TestAProviderRefusalIsShownNotSwallowed(t *testing.T) {
	h := newHarness(t, nil)
	h.startLogin("")
	resp := h.get(authsrv.Prefix + "/callback?error=access_denied&error_description=not+in+group")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, want 403", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "refused") {
		t.Fatalf("the page does not say it was refused: %s", body)
	}
}

// TestTheErrorPageReflectsNothing. A login error page that echoes a query parameter is
// cross-site scripting on the one endpoint every operator visits.
func TestTheErrorPageReflectsNothing(t *testing.T) {
	h := newHarness(t, nil)
	h.startLogin("")
	payload := "<script>alert(1)</script>"
	resp := h.get(authsrv.Prefix + "/callback?error=access_denied&error_description=" +
		url.QueryEscape(payload))
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "<script>") {
		t.Fatalf("the error page reflected markup from the query string:\n%s", body)
	}
}

// TestABadCodeDoesNotSignAnybodyIn.
func TestABadCodeDoesNotSignAnybodyIn(t *testing.T) {
	h := newHarness(t, nil)
	params := h.startLogin("")
	h.provider.refuseCode = "invalid_grant"
	resp := h.get(authsrv.Prefix + "/callback?code=stale&state=" + params.Get("state"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, want 403", resp.StatusCode)
	}
	// And no token is waiting to be collected.
	tok := h.post(authsrv.Prefix + "/token")
	defer tok.Body.Close()
	if tok.StatusCode != http.StatusNoContent {
		t.Fatalf("a failed login left a token to pick up: %d", tok.StatusCode)
	}
}

// TestThePKCEVerifierIsSent, checked at the provider rather than asserted here: the point
// of PKCE is that the code is useless without it.
func TestThePKCEVerifierIsSent(t *testing.T) {
	h := newHarness(t, nil)
	params := h.startLogin("")
	h.provider.expectVerifier(params.Get("code_challenge"))
	h.provider.requireVerifier = true

	resp := h.get(authsrv.Prefix + "/callback?code=good-code&state=" + params.Get("state"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("the provider rejected the exchange, so no verifier reached it: %d %s",
			resp.StatusCode, body)
	}
}

// TestAnIDTokenFromAnotherIssuerIsRefused: the exchange happens over TLS with the
// provider, and that is not a reason to skip verification.
func TestAnIDTokenFromAnotherIssuerIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	other := newFakeProvider(t)
	h.provider.idTokenFrom = other

	params := h.startLogin("")
	h.provider.expectVerifier(params.Get("code_challenge"))
	resp := h.get(authsrv.Prefix + "/callback?code=good-code&state=" + params.Get("state"))
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusSeeOther {
		t.Fatal("an id_token from another issuer signed somebody in")
	}
}

// ── plumbing ────────────────────────────────────────────────────────────────────

func TestNoHandoffIsNotAnError(t *testing.T) {
	// The console asks on every load, and most loads are not just after a sign-in.
	h := newHarness(t, nil)
	resp := h.post(authsrv.Prefix + "/token")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d, want 204", resp.StatusCode)
	}
}

func TestConfigTellsTheConsoleHowToLogIn(t *testing.T) {
	h := newHarness(t, nil)
	resp := h.get(authsrv.Prefix + "/config")
	defer resp.Body.Close()
	var out struct{ Login string }
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Login != "oidc" {
		t.Fatalf("login = %q", out.Login)
	}
}

func TestNewValidates(t *testing.T) {
	p := newFakeProvider(t)
	a, err := oidc.Open(context.Background(), oidc.Config{
		Issuer: p.issuer(), ClientID: clientID, Log: quiet(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authsrv.New(authsrv.Options{RedirectURL: "https://x/cb"}); err == nil {
		t.Fatal("a server with no provider was accepted")
	}
	// The redirect URL is required rather than derived from the request: a provider
	// matches it byte for byte, and deriving it from a Host header would let a proxy
	// choose where the authorization code is delivered.
	_, err = authsrv.New(authsrv.Options{OIDC: a})
	if err == nil || !strings.Contains(err.Error(), "RedirectURL") {
		t.Fatalf("err = %v, want it to require RedirectURL", err)
	}
}

func TestAProviderWithNoAuthorizationEndpointIsRefusedAtBoot(t *testing.T) {
	p := newFakeProvider(t)
	p.noAuthorizationEndpoint = true
	a, err := oidc.Open(context.Background(), oidc.Config{
		Issuer: p.issuer(), ClientID: clientID, Log: quiet(),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = authsrv.New(authsrv.Options{OIDC: a, RedirectURL: "https://x/cb"})
	if err == nil || !strings.Contains(err.Error(), "authorization_endpoint") {
		t.Fatalf("err = %v; a provider that cannot do the browser flow should be a boot "+
			"failure, not a surprise at the first sign-in", err)
	}
}
