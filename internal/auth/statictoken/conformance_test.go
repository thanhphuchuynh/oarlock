package statictoken_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/oarlock/oarlock/internal/auth/statictoken"
	"github.com/oarlock/oarlock/pkg/plugin"
	"github.com/oarlock/oarlock/pkg/plugin/plugintest"
)

// TestConformance runs the static-token backend through the conformance suite.
func TestConformance(t *testing.T) {
	const token = "conformance-token-long-enough-ok"

	plugintest.Authenticator(t, plugintest.AuthenticatorHarness{
		New: func(t *testing.T) plugin.Authenticator {
			a, err := statictoken.Open("test", map[string]string{token: "phuc@example.com"})
			if err != nil {
				t.Fatal(err)
			}
			return a
		},
		GoodRequest: func(*testing.T) (*http.Request, string) {
			r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
			r.Header.Set("Authorization", "Bearer "+token)
			return r, "phuc@example.com"
		},
		BadRequest: func(*testing.T) *http.Request {
			r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
			r.Header.Set("Authorization", "Bearer not-a-real-token-but-long")
			return r
		},
		// No GoodKey: a bearer-token backend does not do SSH keys.
	})
}
