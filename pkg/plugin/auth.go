package plugin

import (
	"context"
	"net"
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

	// OpenedBy is the service account that authenticated to the API when this
	// principal came from AuthDelegated. ID remains the human subject.
	OpenedBy string

	// Unattended marks a service session with no human subject. An unattended
	// principal is authorised as itself, but the session row and recording carry the
	// flag so robot activity is queryable separately from human work.
	Unattended bool
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

// Challenge asks the operator something during SSH keyboard-interactive auth, and
// returns their answers in order.
//
// A challenge with no questions is how a server *tells* the operator something: the
// client displays the instruction and returns immediately. That is the whole mechanism
// behind a device-code login at an SSH prompt — there is nothing to type, only a URL to
// visit — and it is why this signature carries an instruction separately from the
// questions rather than folding it into a prompt.
type Challenge func(instruction string, questions []string, echos []bool) ([]string, error)

// InteractiveAuthenticator is the optional keyboard-interactive surface.
//
// Optional, and asserted for rather than added to Authenticator, because most backends
// have no use for it: a file of SSH keys authenticates a key, and a bearer token arrives
// on a header. Only a backend that has to send the operator somewhere — a browser, a
// phone, an authenticator app — needs a conversation, and making every implementation
// carry a method to refuse would be worse than a type assertion here.
//
// A backend that implements this is offered to SSH clients as `keyboard-interactive`, and
// a client that fails publickey auth will try it. That is not a bypass — it is a second,
// independent authentication of the same person — but it does change what revocation
// means: deleting somebody's key no longer removes their access, because they can still
// prove who they are. Withdraw access at the identity provider or in the authorizer.
type InteractiveAuthenticator interface {
	// AuthInteractive authenticates by conversation. user is the **device id**, as
	// everywhere else on this interface, and should be ignored for authentication.
	//
	// It may block for as long as the operator takes, so honour ctx: an SSH client
	// that hung up is a login nobody is waiting for.
	AuthInteractive(ctx context.Context, user string, ask Challenge) (*Principal, error)
}

// ── the peer behind a credential ────────────────────────────────────────────────

// peerKey carries the network address a credential arrived from.
type peerKey struct{}

// WithPeer records the address the credential being authenticated arrived from.
//
// It exists for one reason: an SSH certificate can carry a `source-address` critical
// option, and a restriction the gateway cannot check is a restriction the gateway must
// refuse rather than ignore. x/crypto enforces that option from the `Permissions` its own
// callback returns, and this interface returns a Principal instead — so without the
// address here, a certificate valid only from one office would be accepted from anywhere,
// silently, and the CA operator would have no way to find out.
//
// Surfaces set it where they know it. A backend that needs it must treat *absent* as a
// reason to refuse an address-restricted credential, never as permission to skip the
// check.
func WithPeer(ctx context.Context, addr net.Addr) context.Context {
	if addr == nil {
		return ctx
	}
	return context.WithValue(ctx, peerKey{}, addr)
}

// PeerFrom returns the address a credential arrived from, and whether one was recorded.
func PeerFrom(ctx context.Context) (net.Addr, bool) {
	addr, ok := ctx.Value(peerKey{}).(net.Addr)
	return addr, ok && addr != nil
}
