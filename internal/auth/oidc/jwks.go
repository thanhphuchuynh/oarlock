package oidc

// Discovery and the key set.
//
// Two caches with different rules, because they answer different questions. The
// discovery document changes about never, so it is fetched once and kept. The key set
// changes whenever the provider rotates, which it does without telling anybody — so the
// rule there is "refetch when a token names a key we do not have", rate-limited so that a
// stream of garbage kids cannot turn into a stream of outbound requests.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Discovery is the part of the provider metadata this package uses.
type Discovery struct {
	Issuer                      string `json:"issuer"`
	JWKSURI                     string `json:"jwks_uri"`
	AuthorizationEndpoint       string `json:"authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	UserinfoEndpoint            string `json:"userinfo_endpoint"`
}

// discover fetches the provider metadata.
//
// The returned issuer must equal the one asked for. That check is not a formality: the
// discovery URL is derived from the configured issuer, so a document claiming a different
// issuer means either a misconfiguration or something answering for a host it does not
// own — and every later token check compares against this value.
func discover(ctx context.Context, c *http.Client, issuer string) (*Discovery, error) {
	if !strings.HasPrefix(issuer, "https://") {
		// Refused rather than warned about: every check in this package rests on the
		// document fetched from here, and over http anyone on the path writes it.
		if !isLoopback(issuer) {
			return nil, fmt.Errorf("oidc: issuer %q must be https", issuer)
		}
	}
	u := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	body, err := fetch(ctx, c, u, 256<<10)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery: %w", err)
	}
	var d Discovery
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("oidc: discovery document is not JSON: %w", err)
	}
	if d.Issuer != issuer {
		return nil, fmt.Errorf("oidc: discovery at %s claims issuer %q, not %q",
			u, d.Issuer, issuer)
	}
	if d.JWKSURI == "" {
		return nil, errors.New("oidc: discovery document has no jwks_uri")
	}
	return &d, nil
}

// isLoopback allows http for a provider on localhost, which is what a test double and a
// developer's own provider look like. Nothing else gets the exemption.
func isLoopback(issuer string) bool {
	u, err := url.Parse(issuer)
	if err != nil {
		return false
	}
	host := u.Hostname()
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

type publicKey struct {
	kid string
	// kind is "RSA" or "EC", taken from the key itself. The token header does not get
	// to assert this.
	kind string
	pub  any
}

// missRefetchFloor bounds how often an unknown kid may cause an outbound request.
//
// Small, and not configurable. A rotation has to be picked up quickly or every login
// fails until the cache expires; a flood of invented kids must not become a flood of
// requests aimed at the provider. Thirty seconds satisfies both and is not a number
// anybody needs to tune.
const missRefetchFloor = 30 * time.Second

// keySet is the provider's signing keys, with two separate reasons to refetch.
//
// **Staleness**, because a provider withdraws a key without telling anybody and a
// withdrawn key must stop verifying tokens. This is the one that matters for revocation:
// without it, a key the provider retired keeps working for as long as this process lives.
//
// **A missing kid**, because a rotation shows up as a token naming a key we have not got,
// and waiting out the staleness window would fail every login in the meantime.
type keySet struct {
	client *http.Client
	uri    string
	now    func() time.Time
	// staleAfter is the age at which the cached set is refetched before use. It is the
	// upper bound on how long a retired key keeps working.
	staleAfter time.Duration
	log        *slog.Logger

	mu        sync.RWMutex
	keys      map[string]publicKey
	lastFetch time.Time
}

func newKeySet(c *http.Client, uri string, staleAfter time.Duration, now func() time.Time,
	log *slog.Logger) *keySet {
	if now == nil {
		now = time.Now
	}
	if log == nil {
		log = slog.Default()
	}
	return &keySet{client: c, uri: uri, now: now, staleAfter: staleAfter, log: log,
		keys: map[string]publicKey{}}
}

func (k *keySet) age() time.Duration {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.lastFetch.IsZero() {
		return 1 << 62 // never fetched: infinitely stale
	}
	return k.now().Sub(k.lastFetch)
}

// byKID returns the key, refetching when the set is stale or the kid is unknown.
func (k *keySet) byKID(kid string) (publicKey, error) {
	if k.age() > k.staleAfter {
		if err := k.refresh(context.Background()); err != nil {
			// Serving a stale set beats refusing every login while the provider is
			// unreachable — an identity provider's bad minute should not be a fleet-wide
			// outage. The cost is that a key retired during the outage keeps working
			// until it ends, which is why this is loud.
			k.log.Warn("could not refresh the provider's signing keys; continuing with "+
				"a stale set, so a key retired since the last fetch would still verify",
				"jwks", k.uri, "age", k.age().Round(time.Second), "error", err)
		}
	}
	if key, ok := k.lookup(kid); ok {
		return key, nil
	}
	// Unknown kid. After a rotation this is the normal case and a refetch fixes it;
	// under a flood of invented kids a refetch per token would be an amplifier pointed
	// at the provider.
	if k.age() < missRefetchFloor {
		return publicKey{}, fmt.Errorf("%w (a refetch was rate-limited; if the provider "+
			"rotated in the last %s, retry)", ErrUnknownKey, missRefetchFloor)
	}
	if err := k.refresh(context.Background()); err != nil {
		return publicKey{}, fmt.Errorf("oidc: refreshing keys for kid %q: %w", kid, err)
	}
	if key, ok := k.lookup(kid); ok {
		return key, nil
	}
	return publicKey{}, ErrUnknownKey
}

func (k *keySet) lookup(kid string) (publicKey, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if key, ok := k.keys[kid]; ok {
		return key, true
	}
	// A key set with exactly one key and a token with no kid is common enough to be
	// worth handling — but only when it is unambiguous. Guessing among several keys
	// would mean trying signatures until one passes, which is a different thing.
	if kid == "" && len(k.keys) == 1 {
		for _, only := range k.keys {
			return only, true
		}
	}
	return publicKey{}, false
}

func (k *keySet) refresh(ctx context.Context) error {
	body, err := fetch(ctx, k.client, k.uri, 512<<10)
	if err != nil {
		return err
	}
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Use string `json:"use"`
			Alg string `json:"alg"`
			N   string `json:"n"`
			E   string `json:"e"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("jwks is not JSON: %w", err)
	}
	parsed := make(map[string]publicKey, len(doc.Keys))
	for _, j := range doc.Keys {
		// A key published for encryption is not a key for checking signatures, and a
		// provider that publishes both should not have them conflated.
		if j.Use != "" && j.Use != "sig" {
			continue
		}
		switch j.Kty {
		case "RSA":
			n, err := decodeSegment(j.N)
			if err != nil {
				continue
			}
			e, err := decodeSegment(j.E)
			if err != nil {
				continue
			}
			pub := &rsa.PublicKey{
				N: new(big.Int).SetBytes(n),
				E: int(new(big.Int).SetBytes(e).Int64()),
			}
			if pub.N.BitLen() < 2048 {
				// A short modulus is not a key, it is a finding.
				continue
			}
			parsed[j.Kid] = publicKey{kid: j.Kid, kind: "RSA", pub: pub}
		case "EC":
			var curve elliptic.Curve
			switch j.Crv {
			case "P-256":
				curve = elliptic.P256()
			case "P-384":
				curve = elliptic.P384()
			case "P-521":
				curve = elliptic.P521()
			default:
				continue
			}
			x, err := decodeSegment(j.X)
			if err != nil {
				continue
			}
			y, err := decodeSegment(j.Y)
			if err != nil {
				continue
			}
			// Assembled into the uncompressed SEC 1 encoding and parsed, rather than
			// filling in X and Y directly: the parser does the on-curve check, and an
			// off-curve point is not a key, it is a finding.
			size := (curve.Params().BitSize + 7) / 8
			if len(x) > size || len(y) > size {
				continue
			}
			point := make([]byte, 1+2*size)
			point[0] = 4
			copy(point[1+size-len(x):1+size], x)
			copy(point[1+2*size-len(y):], y)
			pub, err := ecdsa.ParseUncompressedPublicKey(curve, point)
			if err != nil {
				continue
			}
			parsed[j.Kid] = publicKey{kid: j.Kid, kind: "EC", pub: pub}
		}
	}
	if len(parsed) == 0 {
		return errors.New("jwks contained no usable signing key")
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	// Replaced wholesale rather than merged: a key the provider has withdrawn should
	// stop verifying tokens, and merging would keep a retired key alive forever.
	k.keys = parsed
	k.lastFetch = k.now()
	return nil
}

func fetch(ctx context.Context, c *http.Client, u string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", u, resp.Status)
	}
	// Bounded: a provider that streams forever should not become this process's memory
	// problem.
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) == limit {
		return nil, fmt.Errorf("%s: response exceeded %d bytes", u, limit)
	}
	return body, nil
}

// base64url is exported for the test double, which has to mint the same encoding.
func base64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
