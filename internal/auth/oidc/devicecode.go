package oidc

// The device authorization grant, over SSH keyboard-interactive.
//
// SSH has no place to put a bearer token, and the alternatives are worse: a password
// prompt trains operators to type their identity provider's password into a terminal that
// could be anything, and a key on a laptop is a credential that survives the laptop being
// stolen and cannot be revoked centrally.
//
// So the gateway becomes an OAuth client and prints a URL. The operator approves in a
// browser they already trust — with whatever MFA the provider enforces, which the gateway
// never sees and cannot weaken — and the shell opens. RFC 8628.
//
// Keyboard-interactive is a request/response protocol: the server sends prompts and the
// client sends answers. A challenge with *no* questions is how a server displays text, and
// a challenge with one is how it waits. Both are used here: display the code, wait for the
// operator to say they are done, poll, and repeat if the provider is still waiting.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/oarlock/oarlock/pkg/plugin"
)

// deviceAuth is the provider's answer to a device authorization request.
type deviceAuth struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// AuthInteractive logs an operator in by device code.
func (a *Authenticator) AuthInteractive(ctx context.Context, _ string,
	ask plugin.Challenge) (*plugin.Principal, error) {

	if a.disco.DeviceAuthorizationEndpoint == "" {
		// Said precisely, because the fix is at the provider and not here. An operator
		// reading "authentication failed" would go looking at the gateway.
		return nil, errors.New("oidc: this provider publishes no " +
			"device_authorization_endpoint, so SSH cannot log in against it; use an " +
			"SSH-CA or authorized_keys backend for the SSH surface")
	}

	ctx, cancel := context.WithTimeout(ctx, a.cfg.DeviceTimeout)
	defer cancel()

	auth, err := a.startDeviceAuth(ctx)
	if err != nil {
		return nil, err
	}

	interval := time.Duration(auth.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second // RFC 8628's default.
	}
	deadline := a.now().Add(a.cfg.DeviceTimeout)
	if auth.ExpiresIn > 0 {
		if exp := a.now().Add(time.Duration(auth.ExpiresIn) * time.Second); exp.Before(deadline) {
			deadline = exp
		}
	}

	// The first prompt. `verification_uri_complete` embeds the code so the operator can
	// click once; the plain URI and the code are shown too, because the complete URI is
	// long, wraps in a terminal, and is optional in the spec.
	instruction := a.instructions(auth)
	if _, err := ask(instruction, []string{"Press Enter once you have approved it: "},
		[]bool{false}); err != nil {
		return nil, fmt.Errorf("oidc: the operator's client hung up: %w", err)
	}

	for attempt := 0; ; attempt++ {
		if a.now().After(deadline) {
			return nil, errors.New("oidc: the login was not approved in time")
		}
		tok, err := a.poll(ctx, auth.DeviceCode)
		switch {
		case err != nil:
			return nil, err
		case tok.Error == "":
			return a.fromIDToken(tok)
		case tok.Error == "authorization_pending":
			// Expected: the operator has not finished yet. Ask again rather than
			// silently spinning, so the terminal shows something is still happening.
		case tok.Error == "slow_down":
			// The provider is telling us the interval is too short. RFC 8628 says add
			// five seconds and keep going.
			interval += 5 * time.Second
		case tok.Error == "access_denied":
			return nil, errors.New("oidc: the login was declined")
		case tok.Error == "expired_token":
			return nil, errors.New("oidc: the login code expired before it was approved")
		default:
			return nil, fmt.Errorf("oidc: the provider refused the login: %s (%s)",
				tok.Error, tok.ErrorDesc)
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}

		// Every few rounds, say something. A prompt that has been silent for a minute
		// looks like a hang, and an operator who thinks it hung opens a second session.
		if attempt%2 == 1 {
			if _, err := ask("Still waiting for approval.",
				[]string{"Press Enter to check again: "}, []bool{false}); err != nil {
				return nil, fmt.Errorf("oidc: the operator's client hung up: %w", err)
			}
		}
	}
}

func (a *Authenticator) instructions(auth *deviceAuth) string {
	var b strings.Builder
	b.WriteString("\r\nSign in to continue.\r\n\r\n")
	if auth.VerificationURIComplete != "" {
		b.WriteString("  Open: " + auth.VerificationURIComplete + "\r\n")
		b.WriteString("  or go to " + auth.VerificationURI + " and enter code " +
			auth.UserCode + "\r\n")
	} else {
		b.WriteString("  Open: " + auth.VerificationURI + "\r\n")
		b.WriteString("  Code: " + auth.UserCode + "\r\n")
	}
	// The code is shown, never typed here. Worth saying: an operator who has been
	// trained to paste secrets into terminals is an operator who can be phished.
	b.WriteString("\r\nThe gateway never sees your password or your second factor.\r\n")
	return b.String()
}

func (a *Authenticator) startDeviceAuth(ctx context.Context) (*deviceAuth, error) {
	scopes := append([]string{"openid"}, a.cfg.Scopes...)
	form := url.Values{
		"client_id": {a.cfg.ClientID},
		"scope":     {strings.Join(dedupe(scopes), " ")},
	}
	if a.cfg.ClientSecret != "" {
		form.Set("client_secret", a.cfg.ClientSecret)
	}
	body, err := a.post(ctx, a.disco.DeviceAuthorizationEndpoint, form)
	if err != nil {
		return nil, fmt.Errorf("oidc: starting the login: %w", err)
	}
	var auth deviceAuth
	if err := json.Unmarshal(body, &auth); err != nil {
		return nil, fmt.Errorf("oidc: the device authorization response is not JSON: %w", err)
	}
	if auth.DeviceCode == "" || auth.UserCode == "" || auth.VerificationURI == "" {
		return nil, errors.New("oidc: the device authorization response is missing " +
			"device_code, user_code or verification_uri")
	}
	return &auth, nil
}

func (a *Authenticator) poll(ctx context.Context, deviceCode string) (*tokenResponse, error) {
	form := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
		"client_id":   {a.cfg.ClientID},
	}
	if a.cfg.ClientSecret != "" {
		form.Set("client_secret", a.cfg.ClientSecret)
	}
	// A pending login is an HTTP 400 with a JSON body, so the status is not the signal
	// here — the body is. That is what RFC 8628 specifies and it is easy to get wrong by
	// treating any 4xx as fatal.
	body, err := a.postAllowingError(ctx, a.disco.TokenEndpoint, form)
	if err != nil {
		return nil, fmt.Errorf("oidc: polling for approval: %w", err)
	}
	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("oidc: the token response is not JSON: %w", err)
	}
	return &tok, nil
}

// fromIDToken verifies the id_token the flow produced and maps it.
//
// Verified with exactly the same code path as a token arriving on an HTTP header. A
// shortcut here — "we just fetched it from the provider over TLS, so trust it" — is how
// two doors into one system end up enforcing different rules.
func (a *Authenticator) fromIDToken(tok *tokenResponse) (*plugin.Principal, error) {
	if tok.IDToken == "" {
		return nil, errors.New("oidc: the provider returned no id_token; the client may " +
			"not be requesting the openid scope")
	}
	v, err := verifyToken(tok.IDToken, a.keys, a.cfg.Issuer, a.cfg.Audience,
		a.cfg.Skew, a.now())
	if err != nil {
		return nil, err
	}
	return a.principal(v)
}

func (a *Authenticator) post(ctx context.Context, endpoint string, form url.Values) ([]byte, error) {
	body, status, err := a.doPost(ctx, endpoint, form)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("%s: %d", endpoint, status)
	}
	return body, nil
}

// postAllowingError returns the body for any status, because a pending device login is
// reported as a 400 with a meaningful body.
func (a *Authenticator) postAllowingError(ctx context.Context, endpoint string,
	form url.Values) ([]byte, error) {
	body, _, err := a.doPost(ctx, endpoint, form)
	return body, err
}

func (a *Authenticator) doPost(ctx context.Context, endpoint string,
	form url.Values) ([]byte, int, error) {

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
