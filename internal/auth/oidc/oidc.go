// Package oidc authenticates operators against an OpenID Connect provider.
//
// It is the backend that makes a production deployment possible. `authorized_keys` means
// revocation is a file edit on every replica; static tokens are long-lived shared secrets
// that cannot be revoked without a config push, and refuse to start outside dev. Both are
// fine for a handful of people and wrong past that.
//
// # Two surfaces, one identity
//
// The API and the browser send a token on a header, verified offline against the
// provider's published keys. SSH has no header, so it uses the device authorization grant
// over keyboard-interactive: the gateway prints a URL and a short code, the operator
// approves in a browser they already trust, and the shell opens. Nobody types a password
// into a terminal and no key material lands on a laptop.
//
// The point of doing both here rather than in two backends is that they produce the same
// principal from the same claims, so an authorisation rule written for `*@oncall.example.com`
// means the same thing whichever door somebody came through.
package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oarlock/oarlock/pkg/plugin"
)

// Defaults chosen rather than inherited.
const (
	// DefaultSkew tolerates clock drift between the gateway and the provider. Sixty
	// seconds is generous for NTP-synced hosts and still far short of a token lifetime.
	DefaultSkew = 60 * time.Second
	// DefaultJWKSRefresh is how long a cached key set may be used before it is
	// refetched. It is the upper bound on how long a key the provider has *withdrawn*
	// keeps verifying tokens, which is the only thing making key revocation mean
	// anything here.
	DefaultJWKSRefresh = 5 * time.Minute
	// DefaultDeviceTimeout is how long a device-code login may sit unapproved. Longer
	// than a person needs to find their phone, shorter than a forgotten SSH session.
	DefaultDeviceTimeout = 5 * time.Minute
)

// ClaimMap says which claims become which parts of a principal.
//
// Configurable because providers disagree about all of it — `groups`, `roles`, and
// Entra's `wids` are all the same idea under different names — and because the choice of
// what becomes Principal.ID is a policy decision, not a default worth hiding.
type ClaimMap struct {
	// Subject is the claim that becomes Principal.ID: what gets recorded, and what an
	// authorisation rule matches against.
	//
	// Defaults to `email`, because the policy language is globs over principal ids and
	// operators write `*@oncall.example.com`, not a list of opaque subject uuids. The
	// cost is that email is mutable at the provider, so an unverified one is refused
	// outright. Set this to `sub` where immutability matters more than legibility.
	Subject string
	Email   string
	Groups  string
}

// Config configures the authenticator.
type Config struct {
	Issuer   string
	ClientID string
	// ClientSecret is used for the device-code token exchange. Public clients omit it.
	ClientSecret string
	// Audience is what a token must name. Defaults to ClientID.
	Audience string
	// Scopes are requested during the device flow. `openid` is always included.
	Scopes []string

	Claims        ClaimMap
	Skew          time.Duration
	JWKSRefresh   time.Duration
	DeviceTimeout time.Duration

	HTTPClient *http.Client
	Now        func() time.Time
	Log        *slog.Logger
}

// Authenticator is an OIDC-backed plugin.Authenticator.
type Authenticator struct {
	cfg   Config
	disco *Discovery
	keys  *keySet
	http  *http.Client
	now   func() time.Time
	log   *slog.Logger
}

var (
	_ plugin.Authenticator            = (*Authenticator)(nil)
	_ plugin.InteractiveAuthenticator = (*Authenticator)(nil)
)

// Open discovers the provider and prepares the key set.
//
// Discovery happens here rather than lazily on the first request, so a typo in the issuer
// is a boot failure rather than an outage the first time somebody tries to log in.
func Open(ctx context.Context, cfg Config) (*Authenticator, error) {
	switch {
	case strings.TrimSpace(cfg.Issuer) == "":
		return nil, errors.New("oidc: issuer is required")
	case strings.TrimSpace(cfg.ClientID) == "":
		return nil, errors.New("oidc: client_id is required")
	}
	if cfg.Audience == "" {
		cfg.Audience = cfg.ClientID
	}
	if cfg.Claims.Subject == "" {
		cfg.Claims.Subject = "email"
	}
	if cfg.Claims.Email == "" {
		cfg.Claims.Email = "email"
	}
	if cfg.Claims.Groups == "" {
		cfg.Claims.Groups = "groups"
	}
	if cfg.Skew <= 0 {
		cfg.Skew = DefaultSkew
	}
	if cfg.JWKSRefresh <= 0 {
		cfg.JWKSRefresh = DefaultJWKSRefresh
	}
	if cfg.DeviceTimeout <= 0 {
		cfg.DeviceTimeout = DefaultDeviceTimeout
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	disco, err := discover(ctx, client, cfg.Issuer)
	if err != nil {
		return nil, err
	}
	keys := newKeySet(client, disco.JWKSURI, cfg.JWKSRefresh, cfg.Now, cfg.Log)
	// Fetched now so that a provider whose keys are unreachable is a boot failure too.
	if err := keys.refresh(ctx); err != nil {
		return nil, fmt.Errorf("oidc: fetching %s: %w", disco.JWKSURI, err)
	}
	return &Authenticator{cfg: cfg, disco: disco, keys: keys, http: client,
		now: cfg.Now, log: cfg.Log}, nil
}

// AuthPublicKey refuses: an SSH key is not an OIDC credential.
//
// Not "try the key against the provider somehow" — there is no such operation, and a
// backend that invented one would be authenticating something the provider never saw.
// Pair this with an SSH-CA or authorized_keys backend if you want keys as well.
func (a *Authenticator) AuthPublicKey(context.Context, string, ssh.PublicKey) (*plugin.Principal, error) {
	return nil, plugin.ErrUnsupported
}

// AuthDelegated refuses. Delegation is the `delegated` wrapper's job, and it wraps this.
func (a *Authenticator) AuthDelegated(context.Context, *plugin.Principal, string) (*plugin.Principal, error) {
	return nil, plugin.ErrUnsupported
}

// AuthHTTP verifies a bearer token.
//
// The token must be a JWT this gateway can verify offline against the provider's
// published keys. An opaque access token is refused rather than sent to the userinfo
// endpoint: that would turn every API request into a second network round trip to the
// provider, and make the provider's availability a dependency of every list of sessions.
// Send the `id_token`.
func (a *Authenticator) AuthHTTP(_ context.Context, r *http.Request) (*plugin.Principal, error) {
	raw := bearer(r)
	if raw == "" {
		return nil, errors.New("oidc: no bearer token")
	}
	v, err := verifyToken(raw, a.keys, a.cfg.Issuer, a.cfg.Audience, a.cfg.Skew, a.now())
	if err != nil {
		return nil, err
	}
	return a.principal(v)
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	// Case-insensitive on the scheme, exact on the rest: RFC 7235 says the scheme is
	// case-insensitive and clients differ.
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// principal maps verified claims onto an operator.
func (a *Authenticator) principal(v *verified) (*plugin.Principal, error) {
	id, err := a.stringClaim(v, a.cfg.Claims.Subject)
	if err != nil {
		return nil, fmt.Errorf("oidc: the %q claim is the principal id: %w",
			a.cfg.Claims.Subject, err)
	}
	// An email that the provider has not verified is a name the operator chose. Since
	// the default mapping makes it the principal id — and authorisation rules are globs
	// over that — an unverified one would let somebody claim a colleague's identity by
	// typing it into a profile page.
	if a.cfg.Claims.Subject == "email" || a.cfg.Claims.Email == "email" {
		if verified, ok := boolClaim(v, "email_verified"); ok && !verified {
			return nil, errors.New("oidc: email_verified is false, and an unverified " +
				"email is a name its owner chose rather than an identity the provider " +
				"vouches for")
		}
	}
	email, _ := a.stringClaim(v, a.cfg.Claims.Email)
	groups := a.groupsClaim(v)

	p := &plugin.Principal{
		ID:     id,
		Email:  email,
		Groups: groups,
		Attrs:  map[string]string{"iss": v.claims.Iss, "sub": v.claims.Sub},
	}
	// The credential's own expiry becomes the session's ceiling. Without this a shell
	// opened one minute before a token expired would outlive it by hours, and the
	// authorisation re-check — which asks a different question — would not notice.
	if v.claims.Exp != nil {
		p.Expiry = v.claims.Exp.time()
	}
	return p, nil
}

func (a *Authenticator) stringClaim(v *verified, name string) (string, error) {
	raw, ok := v.Raw[name]
	if !ok {
		return "", fmt.Errorf("the token has no %q claim (scopes may be missing)", name)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("the %q claim is not a string", name)
	}
	if strings.TrimSpace(s) == "" {
		return "", fmt.Errorf("the %q claim is empty", name)
	}
	return s, nil
}

func boolClaim(v *verified, name string) (bool, bool) {
	raw, ok := v.Raw[name]
	if !ok {
		return false, false
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		return b, true
	}
	// Some providers send it as a string. Accepting "true"/"false" here is not
	// leniency for its own sake: reading a *false* as absent would skip the check.
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s == "true", true
	}
	return false, false
}

// groupsClaim accepts a list or a space-separated string, because providers do both.
func (a *Authenticator) groupsClaim(v *verified) []string {
	raw, ok := v.Raw[a.cfg.Claims.Groups]
	if !ok {
		return nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return list
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil && strings.TrimSpace(s) != "" {
		return strings.Fields(s)
	}
	a.log.Warn("the groups claim is neither a list nor a string; treating it as absent",
		"claim", a.cfg.Claims.Groups)
	return nil
}
