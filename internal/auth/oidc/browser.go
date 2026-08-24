package oidc

// The authorization code flow, for the browser.
//
// The device grant works at an SSH prompt because there is nowhere to redirect to. A
// browser has somewhere to redirect to, so it gets the flow designed for that — with PKCE,
// which is not optional here even though this client has a secret:
//
//   - The authorization code travels through the operator's own browser and lands in a
//     URL. URLs end up in history, in referrers, in proxy logs and in screenshots.
//   - PKCE binds the code to the one browser that started the flow, so a code somebody
//     else obtains is a code they cannot spend.
//
// The `state` parameter is a separate concern from PKCE and both are needed: PKCE stops a
// stolen code being spent, `state` stops an attacker starting a flow and getting the
// victim's browser to finish it.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/oarlock/oarlock/pkg/plugin"
)

// PKCE is a verifier and the challenge derived from it.
//
// The verifier stays on the gateway; only the challenge is sent to the provider, and only
// the verifier is sent when redeeming the code. That is the whole mechanism: whoever holds
// the code cannot spend it without a secret they never saw.
type PKCE struct {
	Verifier  string
	Challenge string
}

// NewPKCE generates a verifier and its S256 challenge.
//
// S256 only. The spec also allows `plain`, where the challenge *is* the verifier — which
// provides nothing at all against anyone who can read the authorization request.
func NewPKCE() (PKCE, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return PKCE{}, fmt.Errorf("oidc: generating a pkce verifier: %w", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	return PKCE{Verifier: verifier, Challenge: base64.RawURLEncoding.EncodeToString(sum[:])}, nil
}

// NewState generates an opaque anti-forgery value.
func NewState() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("oidc: generating state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// SupportsBrowserFlow reports whether the provider published an authorization endpoint.
func (a *Authenticator) SupportsBrowserFlow() bool {
	return a.disco.AuthorizationEndpoint != "" && a.disco.TokenEndpoint != ""
}

// AuthorizeURL is where to send the operator's browser.
func (a *Authenticator) AuthorizeURL(redirectURI, state string, pkce PKCE) (string, error) {
	if !a.SupportsBrowserFlow() {
		return "", errors.New("oidc: this provider publishes no authorization_endpoint")
	}
	u, err := url.Parse(a.disco.AuthorizationEndpoint)
	if err != nil {
		return "", fmt.Errorf("oidc: authorization_endpoint is not a URL: %w", err)
	}
	scopes := dedupe(append([]string{"openid"}, a.cfg.Scopes...))
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", a.cfg.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("state", state)
	q.Set("code_challenge", pkce.Challenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// ExchangeCode redeems an authorization code and returns the operator it belongs to.
//
// The raw id_token comes back alongside the principal because the browser needs to send
// something on later requests, and it must be the provider's own token rather than one
// this gateway minted: a token the gateway signs itself is a second credential system to
// rotate, revoke and get wrong, and the API already knows how to verify this one.
func (a *Authenticator) ExchangeCode(ctx context.Context, code, redirectURI,
	verifier string) (*plugin.Principal, string, error) {

	if code == "" {
		return nil, "", errors.New("oidc: no authorization code")
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {a.cfg.ClientID},
		"code_verifier": {verifier},
	}
	if a.cfg.ClientSecret != "" {
		form.Set("client_secret", a.cfg.ClientSecret)
	}
	body, err := a.postAllowingError(ctx, a.disco.TokenEndpoint, form)
	if err != nil {
		return nil, "", fmt.Errorf("oidc: redeeming the authorization code: %w", err)
	}
	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, "", fmt.Errorf("oidc: the token response is not JSON: %w", err)
	}
	if tok.Error != "" {
		// The provider's own words, because they name the cause: a redirect_uri that
		// does not match the registration, an expired code, a reused one.
		return nil, "", fmt.Errorf("oidc: the provider refused the code: %s (%s)",
			tok.Error, tok.ErrorDesc)
	}
	if tok.IDToken == "" {
		return nil, "", errors.New("oidc: the provider returned no id_token; the client " +
			"may not be requesting the openid scope")
	}
	// Verified by the same code path as a token arriving on a header. A shortcut here —
	// "we fetched it from the provider over TLS, so trust it" — is how two doors into one
	// system end up enforcing different rules.
	v, err := verifyToken(tok.IDToken, a.keys, a.cfg.Issuer, a.cfg.Audience,
		a.cfg.Skew, a.now())
	if err != nil {
		return nil, "", err
	}
	p, err := a.principal(v)
	if err != nil {
		return nil, "", err
	}
	return p, tok.IDToken, nil
}
