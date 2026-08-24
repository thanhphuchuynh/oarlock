package authsrv_test

// A provider double for the browser flow.
//
// Separate from the one in internal/auth/oidc because this one has to *check* what the
// gateway sent — the PKCE verifier especially. A double that accepts anything cannot tell
// you whether PKCE is in the request at all, and PKCE that is sent but never checked is
// PKCE that could be removed without a test noticing.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

const clientID = "oarlock-gateway"

type fakeProvider struct {
	t   *testing.T
	srv *httptest.Server
	key *rsa.PrivateKey
	ec  *ecdsa.PrivateKey

	mu sync.Mutex
	// noAuthorizationEndpoint drops it from discovery, which is a provider that cannot
	// do this flow at all.
	noAuthorizationEndpoint bool
	// refuseCode makes the token endpoint answer with an OAuth error.
	refuseCode string
	// challenge is what the authorization request carried, so the token endpoint can
	// check the verifier against it.
	challenge string
	// requireVerifier makes a missing or wrong code_verifier fatal, which is what a
	// real provider enforcing PKCE does.
	requireVerifier bool
	// idTokenFrom mints the id_token with another provider's key and issuer.
	idTokenFrom *fakeProvider
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeProvider{t: t, key: key, ec: ec}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("/jwks", p.jwks)
	mux.HandleFunc("/authorize", func(http.ResponseWriter, *http.Request) {})
	mux.HandleFunc("/token", p.token)
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakeProvider) issuer() string { return p.srv.URL }

func (p *fakeProvider) expectVerifier(challenge string) {
	p.mu.Lock()
	p.challenge = challenge
	p.mu.Unlock()
}

func (p *fakeProvider) discovery(w http.ResponseWriter, _ *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	doc := map[string]any{
		"issuer":         p.srv.URL,
		"jwks_uri":       p.srv.URL + "/jwks",
		"token_endpoint": p.srv.URL + "/token",
	}
	if !p.noAuthorizationEndpoint {
		doc["authorization_endpoint"] = p.srv.URL + "/authorize"
	}
	writeJSONTest(w, http.StatusOK, doc)
}

func (p *fakeProvider) jwks(w http.ResponseWriter, _ *http.Request) {
	writeJSONTest(w, http.StatusOK, map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "kid": "rsa-1", "use": "sig", "alg": "RS256",
		"n": b64(p.key.N.Bytes()),
		"e": b64(big.NewInt(int64(p.key.E)).Bytes()),
	}}})
}

func (p *fakeProvider) token(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := r.ParseForm(); err != nil {
		writeJSONTest(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
		return
	}
	if p.refuseCode != "" {
		writeJSONTest(w, http.StatusBadRequest, map[string]any{"error": p.refuseCode})
		return
	}
	// PKCE, checked rather than assumed. The verifier's S256 hash must equal the
	// challenge the authorization request carried.
	verifier := r.Form.Get("code_verifier")
	if p.requireVerifier || verifier != "" {
		sum := sha256.Sum256([]byte(verifier))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != p.challenge {
			writeJSONTest(w, http.StatusBadRequest, map[string]any{
				"error":             "invalid_grant",
				"error_description": "the code_verifier does not match the challenge",
			})
			return
		}
	}
	if r.Form.Get("grant_type") != "authorization_code" {
		writeJSONTest(w, http.StatusBadRequest, map[string]any{"error": "unsupported_grant_type"})
		return
	}

	minter := p
	if p.idTokenFrom != nil {
		minter = p.idTokenFrom
	}
	writeJSONTest(w, http.StatusOK, map[string]any{
		"access_token": "opaque", "token_type": "Bearer", "expires_in": 3600,
		"id_token": minter.mintID(),
	})
}

// mintID signs an id_token with this provider's own key and issuer.
func (p *fakeProvider) mintID() string {
	head, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": "rsa-1"})
	now := time.Now()
	body, _ := json.Marshal(map[string]any{
		"iss": p.srv.URL, "sub": "subject-1", "aud": clientID,
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
		"email": "amelia@example.com", "email_verified": true,
		"groups": []string{"oncall"},
	})
	signing := b64(head) + "." + b64(body)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, sum[:])
	if err != nil {
		p.t.Fatal(err)
	}
	return signing + "." + b64(sig)
}

func writeJSONTest(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
