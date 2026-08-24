package oidc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/oarlock/oarlock/internal/auth/oidc"
	"github.com/oarlock/oarlock/pkg/plugin"
	"github.com/oarlock/oarlock/pkg/plugin/plugintest"
)

// TestConformance runs the OIDC backend through the shared authenticator suite, so it is
// held to the same contract as every other backend rather than only to its own tests.
func TestConformance(t *testing.T) {
	p := newProvider(t)
	good := p.mint(t, "RS256", "rsa-1", p.key("rsa-1"), p.good(clientID))

	plugintest.Authenticator(t, plugintest.AuthenticatorHarness{
		New: func(t *testing.T) plugin.Authenticator {
			a, err := oidc.Open(context.Background(), oidc.Config{
				Issuer: p.issuer(), ClientID: clientID, Log: quiet(),
			})
			if err != nil {
				t.Fatal(err)
			}
			return a
		},
		GoodRequest: func(*testing.T) (*http.Request, string) {
			r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
			r.Header.Set("Authorization", "Bearer "+good)
			return r, "amelia@example.com"
		},
		BadRequest: func(*testing.T) *http.Request {
			r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
			// Structurally a token, verifiable by nobody.
			r.Header.Set("Authorization", "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.bm90")
			return r
		},
		// No GoodKey: an SSH key is not an OIDC credential, and this backend says so.
	})
}
