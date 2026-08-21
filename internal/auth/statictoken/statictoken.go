// Package statictoken authenticates API callers from tokens in configuration.
//
// It exists for tests, CI and local development, and it **refuses to start outside
// a development environment**. Static tokens are long-lived shared secrets: they
// cannot be revoked without a config push, they end up in shell history and
// screenshots, and nothing about them expires. That is fine on a laptop and not
// fine anywhere else, so the constraint is enforced in code rather than written in
// a comment nobody reads.
package statictoken

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/oarlock/oarlock/pkg/plugin"
)

// MinTokenLength is the shortest token accepted. Short enough to type, long enough
// that guessing is not the easy path.
const MinTokenLength = 24

// Authenticator maps bearer tokens to principals.
type Authenticator struct {
	byToken map[string]*plugin.Principal
}

var _ plugin.Authenticator = (*Authenticator)(nil)

// Open builds the authenticator. env must be "dev" or "test"; anything else is
// refused, including the empty string — an unset environment is not a development
// one.
func Open(env string, tokens map[string]string) (*Authenticator, error) {
	switch env {
	case "dev", "test":
	default:
		return nil, fmt.Errorf(
			"statictoken: refusing to start in env %q — static tokens are long-lived "+
				"shared secrets that cannot be revoked without a config push; use oidc "+
				"or sshca", env)
	}
	if len(tokens) == 0 {
		return nil, errors.New("statictoken: no tokens configured")
	}
	a := &Authenticator{byToken: make(map[string]*plugin.Principal, len(tokens))}
	for token, principal := range tokens {
		if len(token) < MinTokenLength {
			return nil, fmt.Errorf("statictoken: a token is %d characters, minimum %d",
				len(token), MinTokenLength)
		}
		if principal == "" {
			return nil, errors.New("statictoken: every token needs a principal — a " +
				"session attributed to nobody is a session nobody can act on")
		}
		a.byToken[token] = &plugin.Principal{ID: principal, Email: emailOf(principal)}
	}
	return a, nil
}

func emailOf(id string) string {
	if strings.Contains(id, "@") && !strings.Contains(id, " ") {
		return id
	}
	return ""
}

// AuthHTTP reads a bearer token.
func (a *Authenticator) AuthHTTP(_ context.Context, r *http.Request) (*plugin.Principal, error) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		return nil, errors.New("statictoken: no bearer token")
	}
	// Constant-time comparison against each token rather than a map lookup: a map
	// lookup on a secret is a timing signal, and there are few enough tokens here
	// that walking them costs nothing.
	var found *plugin.Principal
	for candidate, p := range a.byToken {
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(token)) == 1 {
			found = p
		}
	}
	if found == nil {
		return nil, errors.New("statictoken: unknown token")
	}
	out := *found
	return &out, nil
}

// AuthPublicKey is not supported: this backend knows about tokens, not keys.
func (a *Authenticator) AuthPublicKey(context.Context, string, ssh.PublicKey) (*plugin.Principal, error) {
	return nil, plugin.ErrUnsupported
}

// AuthDelegated is not supported. A shared token cannot attest to anything about a
// third party.
func (a *Authenticator) AuthDelegated(context.Context, *plugin.Principal, string) (*plugin.Principal, error) {
	return nil, plugin.ErrUnsupported
}

// Len is the number of tokens loaded.
func (a *Authenticator) Len() int { return len(a.byToken) }
