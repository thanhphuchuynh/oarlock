package oidc_test

// An identity provider, in process.
//
// Not a mock of this package's own calls — a real HTTP server that serves discovery, a
// key set, and the two device-flow endpoints, and mints tokens the way a provider does.
// The point is that the attacks in oidc_test.go are performed with the same machinery as
// the legitimate logins: an attack that has to be simulated differently from a real token
// tests the simulation.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type signingKey struct {
	kid string
	rsa *rsa.PrivateKey
	ec  *ecdsa.PrivateKey
}

// provider is a test double for an OpenID Connect provider.
type provider struct {
	t   *testing.T
	srv *httptest.Server

	mu sync.Mutex
	// keys is the published key set, replaceable to simulate rotation.
	keys []signingKey
	// issuerOverride makes discovery claim an issuer it is not, which is the check that
	// stops one provider answering for another.
	issuerOverride string
	// noDeviceEndpoint drops device_authorization_endpoint from discovery.
	noDeviceEndpoint bool

	// device-flow state
	pendingPolls int    // how many polls answer authorization_pending first
	deviceError  string // a terminal error to answer with instead
	slowDownOnce bool
	polls        int
	idToken      string
	jwksFetches  int
}

func newProvider(t *testing.T) *provider {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &provider{t: t, keys: []signingKey{
		{kid: "rsa-1", rsa: rsaKey},
		{kid: "ec-1", ec: ecKey},
	}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("/jwks", p.jwks)
	mux.HandleFunc("/device", p.deviceAuth)
	mux.HandleFunc("/token", p.token)
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func (p *provider) issuer() string { return p.srv.URL }

func (p *provider) discovery(w http.ResponseWriter, _ *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	iss := p.srv.URL
	if p.issuerOverride != "" {
		iss = p.issuerOverride
	}
	doc := map[string]any{
		"issuer":         iss,
		"jwks_uri":       p.srv.URL + "/jwks",
		"token_endpoint": p.srv.URL + "/token",
	}
	if !p.noDeviceEndpoint {
		doc["device_authorization_endpoint"] = p.srv.URL + "/device"
	}
	writeJSON(w, http.StatusOK, doc)
}

func (p *provider) jwks(w http.ResponseWriter, _ *http.Request) {
	p.mu.Lock()
	p.jwksFetches++
	keys := make([]map[string]any, 0, len(p.keys))
	for _, k := range p.keys {
		switch {
		case k.rsa != nil:
			keys = append(keys, map[string]any{
				"kty": "RSA", "kid": k.kid, "use": "sig", "alg": "RS256",
				"n": b64(k.rsa.N.Bytes()),
				"e": b64(big.NewInt(int64(k.rsa.E)).Bytes()),
			})
		case k.ec != nil:
			size := (k.ec.Curve.Params().BitSize + 7) / 8
			keys = append(keys, map[string]any{
				"kty": "EC", "kid": k.kid, "use": "sig", "alg": "ES256", "crv": "P-256",
				"x": b64(pad(k.ec.X.Bytes(), size)),
				"y": b64(pad(k.ec.Y.Bytes(), size)),
			})
		}
	}
	p.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

func (p *provider) deviceAuth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"device_code":               "dev-code-1",
		"user_code":                 "WXYZ-1234",
		"verification_uri":          p.srv.URL + "/approve",
		"verification_uri_complete": p.srv.URL + "/approve?code=WXYZ-1234",
		"expires_in":                300,
		// One second, so a test that has to see a pending round does not take five.
		"interval": 1,
	})
}

func (p *provider) token(w http.ResponseWriter, _ *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.polls++
	if p.deviceError != "" {
		// RFC 8628: a pending or refused login is a 400 with a JSON body, which is why
		// the client cannot treat the status as the signal.
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": p.deviceError})
		return
	}
	if p.slowDownOnce && p.polls == 1 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "slow_down"})
		return
	}
	if p.polls <= p.pendingPolls {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "authorization_pending"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": "opaque", "token_type": "Bearer", "expires_in": 3600,
		"id_token": p.idToken,
	})
}

// rotate replaces the published keys, which is what a provider does on its own schedule
// and without telling anybody.
func (p *provider) rotate(t *testing.T) signingKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fresh := signingKey{kid: "rsa-2", rsa: key}
	p.mu.Lock()
	p.keys = []signingKey{fresh}
	p.mu.Unlock()
	return fresh
}

func (p *provider) key(kid string) signingKey {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, k := range p.keys {
		if k.kid == kid {
			return k
		}
	}
	p.t.Fatalf("no key %q", kid)
	return signingKey{}
}

// claimSet is the token body a test wants minted.
type claimSet map[string]any

// mint builds a signed token. alg and kid are separate arguments from the key so that a
// test can deliberately mismatch them.
func (p *provider) mint(t *testing.T, alg, kid string, key signingKey, c claimSet) string {
	t.Helper()
	head := map[string]any{"alg": alg, "typ": "JWT"}
	if kid != "" {
		head["kid"] = kid
	}
	headJSON, _ := json.Marshal(head)
	bodyJSON, _ := json.Marshal(map[string]any(c))
	signing := b64(headJSON) + "." + b64(bodyJSON)

	switch alg {
	case "none":
		return signing + "."
	case "HS256":
		// The algorithm-confusion attack: HMAC the signing input with the *public* key
		// as the secret. A verifier that picks its routine from the header rather than
		// from the key type accepts this.
		mac := hmac.New(sha256.New, []byte(b64(key.rsa.N.Bytes())))
		mac.Write([]byte(signing))
		return signing + "." + b64(mac.Sum(nil))
	case "RS256":
		sum := sha256.Sum256([]byte(signing))
		sig, err := rsa.SignPKCS1v15(rand.Reader, key.rsa, crypto.SHA256, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		return signing + "." + b64(sig)
	case "ES256":
		sum := sha256.Sum256([]byte(signing))
		r, s, err := ecdsa.Sign(rand.Reader, key.ec, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		return signing + "." + b64(append(pad(r.Bytes(), 32), pad(s.Bytes(), 32)...))
	default:
		t.Fatalf("the double cannot mint %q", alg)
		return ""
	}
}

// good is a claim set that should pass every check, so a test can change one thing.
func (p *provider) good(clientID string) claimSet {
	now := time.Now()
	return claimSet{
		"iss": p.issuer(), "sub": "subject-1", "aud": clientID,
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
		"email": "amelia@example.com", "email_verified": true,
		"groups": []string{"oncall", "platform"},
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func pad(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

// tamper flips a character in the payload segment without re-signing, which is the
// check that the signature covers the bytes that were parsed.
func tamper(token string) string {
	parts := strings.SplitN(token, ".", 3)
	body, _ := base64.RawURLEncoding.DecodeString(parts[1])
	altered := strings.Replace(string(body), "amelia@example.com", "root@example.com", 1)
	return parts[0] + "." + b64([]byte(altered)) + "." + parts[2]
}
