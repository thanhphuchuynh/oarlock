package plugin

import (
	"context"
	"net/http"
	"time"

	"golang.org/x/crypto/ssh"
)

// Principal is an authenticated operator.
//
// ID is what gets recorded, and it is deliberately not the SSH username: the SSH
// user names the *device*, so one operator's credentials address a whole fleet.
// That is the one piece of SSH convention Oarlock breaks, and it earns it.
type Principal struct {
	ID     string
	Email  string
	Groups []string

	// Attrs is opaque, passed to Authorizer and to the record_input policy — which
	// is how an operator's jurisdiction reaches a decision without a tenancy
	// concept being invented to carry it.
	Attrs map[string]string

	// Expiry, when non-zero, puts a ceiling on how long a session may outlive the
	// credential that opened it, independent of the authorisation re-check interval.
	// Worth setting.
	Expiry time.Time
}

// Authenticator answers *who* an operator is. Authorizer answers whether they may.
type Authenticator interface {
	// AuthPublicKey is called during SSH publickey auth. A nil error accepts the
	// key and binds the connection to the returned principal.
	//
	// user is the **device id**, not the operator. Backends should ignore it for
	// authentication; the gateway checks it against the registry separately.
	AuthPublicKey(ctx context.Context, user string, key ssh.PublicKey) (*Principal, error)

	// AuthDelegated verifies that a service may act for the subject named in a
	// signed assertion, and returns the SUBJECT's principal. Returning
	// ErrUnsupported refuses every On-Behalf-Of call, which is the safe default.
	AuthDelegated(ctx context.Context, service *Principal, assertion string) (*Principal, error)

	// AuthHTTP authenticates the API and browser surface: a session cookie, a
	// bearer token, an OIDC id_token. Returning ErrUnsupported refuses every API
	// request, which is the right answer for a backend that has no way to
	// authenticate an HTTP caller — a file of SSH keys, for instance.
	AuthHTTP(ctx context.Context, r *http.Request) (*Principal, error)
}
