package plugintest

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/oarlock/oarlock/pkg/plugin"
)

// AuthenticatorHarness is what an identity backend author supplies.
type AuthenticatorHarness struct {
	New func(t *testing.T) plugin.Authenticator

	// GoodKey is a public key the backend accepts, and the principal it maps to.
	// Leave nil for a backend that does not authenticate SSH keys — the suite then
	// asserts AuthPublicKey returns ErrUnsupported rather than a principal.
	GoodKey func(t *testing.T) (ssh.PublicKey, string)
	// BadKey is a well-formed key the backend does not know.
	BadKey func(t *testing.T) ssh.PublicKey

	// GoodRequest is an HTTP request the backend accepts, and the principal it maps to.
	// Leave nil for a backend with no way to authenticate an HTTP caller.
	GoodRequest func(t *testing.T) (*http.Request, string)
	// BadRequest is a request the backend rejects.
	BadRequest func(t *testing.T) *http.Request

	// SupportsDelegation says the backend implements AuthDelegated. When false, the
	// suite asserts it returns ErrUnsupported — which refuses every On-Behalf-Of call,
	// the right default for a backend that cannot verify one.
	SupportsDelegation bool
}

// Authenticator runs the conformance suite against an Authenticator implementation.
func Authenticator(t *testing.T, h AuthenticatorHarness) {
	t.Helper()
	runAuthenticator(liveReporter{t}, h)
}

func runAuthenticator(r reporter, h AuthenticatorHarness) {
	if h.New == nil {
		r.fatalf("plugintest: AuthenticatorHarness.New is required")
		return
	}
	if h.GoodKey == nil && h.GoodRequest == nil {
		r.fatalf("plugintest: an Authenticator that accepts neither a key nor an HTTP " +
			"request cannot authenticate anybody — supply GoodKey, GoodRequest, or both")
		return
	}

	r.run("an unsupported method says so, rather than failing vaguely", func(r reporter) {
		a := h.New(r.t())
		// The distinction matters at the call site: ErrUnsupported means "this backend
		// has no way to do that", which the gateway reports as a configuration problem.
		// Any other error means "that credential was refused", which it reports to the
		// operator as an authentication failure. A file of SSH keys returning a generic
		// error from AuthHTTP makes every API request look like a bad password.
		if h.GoodKey == nil {
			_, err := a.AuthPublicKey(context.Background(), "dev-1", nil)
			if !errors.Is(err, plugin.ErrUnsupported) {
				r.errorf("GoodKey is nil, so this backend does not do SSH keys — but "+
					"AuthPublicKey returned %v instead of plugin.ErrUnsupported", err)
			}
		}
		if h.GoodRequest == nil {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
			_, err := a.AuthHTTP(context.Background(), req)
			if !errors.Is(err, plugin.ErrUnsupported) {
				r.errorf("GoodRequest is nil, so this backend cannot authenticate an "+
					"HTTP caller — but AuthHTTP returned %v instead of "+
					"plugin.ErrUnsupported", err)
			}
		}
		if !h.SupportsDelegation {
			_, err := a.AuthDelegated(context.Background(),
				&plugin.Principal{ID: "svc-crm"}, "an-assertion")
			if !errors.Is(err, plugin.ErrUnsupported) {
				r.errorf("SupportsDelegation is false but AuthDelegated returned %v.\n\n"+
					"Return plugin.ErrUnsupported: it refuses every On-Behalf-Of call, "+
					"which is the safe default. Any other error is indistinguishable "+
					"from a rejected assertion, and a backend that cannot verify "+
					"delegation must not look like one that just refused this one.", err)
			}
		}
	})

	if h.GoodKey != nil {
		r.run("a known key authenticates, and an unknown one does not", func(r reporter) {
			a := h.New(r.t())
			key, want := h.GoodKey(r.t())
			p, err := a.AuthPublicKey(context.Background(), "treadmill-4821", key)
			if err != nil {
				r.errorf("a known key was refused: %v", err)
			} else if p == nil {
				r.errorf("a known key returned a nil principal and no error")
			} else if p.ID != want {
				r.errorf("a known key mapped to %q, want %q", p.ID, want)
			}

			if h.BadKey == nil {
				r.errorf("plugintest: GoodKey without BadKey — a suite that never sees " +
					"a key refused cannot tell this backend from one that accepts every key")
				return
			}
			bad, _ := h.BadKey(r.t()), 0
			if p, err := a.AuthPublicKey(context.Background(), "treadmill-4821", bad); err == nil {
				r.errorf("an unknown key authenticated as %v", p)
			}
		})

		r.run("the user field is not used for authentication", func(r reporter) {
			// `user` is the device id, not the operator. A backend that authenticated
			// on it would let anybody in by naming a device — and the gateway checks
			// the device separately, so a backend disagreeing about it is a backend
			// enforcing an access rule nobody can see.
			a := h.New(r.t())
			key, want := h.GoodKey(r.t())
			for _, user := range []string{"treadmill-4821", "somebody-else", ""} {
				p, err := a.AuthPublicKey(context.Background(), user, key)
				if err != nil {
					r.errorf("a known key was refused when user was %q: %v", user, err)
					continue
				}
				if p != nil && p.ID != want {
					r.errorf("with user %q the key mapped to %q, want %q — the user "+
						"field is the device id and must not change who somebody is",
						user, p.ID, want)
				}
			}
		})
	}

	if h.GoodRequest != nil {
		r.run("a valid request authenticates, and an invalid one does not", func(r reporter) {
			a := h.New(r.t())
			req, want := h.GoodRequest(r.t())
			p, err := a.AuthHTTP(context.Background(), req)
			if err != nil {
				r.errorf("a valid request was refused: %v", err)
			} else if p == nil {
				r.errorf("a valid request returned a nil principal and no error")
			} else if p.ID != want {
				r.errorf("a valid request mapped to %q, want %q", p.ID, want)
			}

			if h.BadRequest == nil {
				r.errorf("plugintest: GoodRequest without BadRequest — a suite that " +
					"never sees a request refused cannot tell this backend from one " +
					"that accepts every request")
				return
			}
			if p, err := a.AuthHTTP(context.Background(), h.BadRequest(r.t())); err == nil {
				r.errorf("an invalid request authenticated as %v", p)
			}
		})
	}

	r.run("concurrent authentication is safe", func(r reporter) {
		a := h.New(r.t())
		var wg sync.WaitGroup
		errs := make(chan error, 64)
		for range 32 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if h.GoodKey != nil {
					key, want := h.GoodKey(r.t())
					p, err := a.AuthPublicKey(context.Background(), "treadmill-4821", key)
					switch {
					case err != nil:
						errs <- err
					case p == nil || p.ID != want:
						errs <- errors.New("a known key mapped to the wrong principal")
					}
				}
				if h.GoodRequest != nil {
					req, want := h.GoodRequest(r.t())
					p, err := a.AuthHTTP(context.Background(), req)
					switch {
					case err != nil:
						errs <- err
					case p == nil || p.ID != want:
						errs <- errors.New("a valid request mapped to the wrong principal")
					}
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			r.errorf("under concurrency: %v", err)
		}
	})

	r.run("a principal is never returned alongside an error", func(r reporter) {
		// A caller that checks the principal before the error — which is an easy
		// mistake in a middleware chain — would authenticate somebody the backend
		// refused. Returning both is an invitation to that bug.
		a := h.New(r.t())
		if h.BadKey != nil {
			if p, err := a.AuthPublicKey(context.Background(), "d", h.BadKey(r.t())); err != nil && p != nil {
				r.errorf("AuthPublicKey returned both a principal (%q) and an error", p.ID)
			}
		}
		if h.BadRequest != nil {
			if p, err := a.AuthHTTP(context.Background(), h.BadRequest(r.t())); err != nil && p != nil {
				r.errorf("AuthHTTP returned both a principal (%q) and an error", p.ID)
			}
		}
	})
}
