package oidc

// JWT verification, owned rather than imported.
//
// This is the one file in the package where a mistake is silent and total: a token that
// verifies when it should not admits anybody to the whole fleet. The classic ways to get
// it wrong are well known, so they are listed here and each one has a test that tries it:
//
//   - `alg: none`, which asks the verifier to skip the signature.
//   - Algorithm confusion: a token signed HS256 with the *public* key as the HMAC secret,
//     against a verifier that reads `alg` from the header and then looks up "a key". The
//     defence is to choose the verification routine from the key's own type and require
//     the header to agree, rather than letting the header choose.
//   - An unrecognised `kid`, which after a key rotation is legitimate and after an attack
//     is not — so it triggers one rate-limited refetch and nothing more.
//   - A missing or wrong `aud`, which lets a token minted for another relying party in.
//   - A missing `exp`, which makes a token immortal.
//   - Re-serialising the payload before verifying, so the signature covers different
//     bytes than the ones parsed.
//
// The last one is why the signing input is sliced out of the original string rather than
// rebuilt.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"slices"
	"strings"
	"time"
)

// ErrUnknownKey means the token names a key this verifier has not got. It is the one
// verification failure worth retrying, because it is what a key rotation looks like.
var ErrUnknownKey = errors.New("oidc: no known key matches the token's kid")

// signatureAlgs is an allow-list, not a lookup table.
//
// Asymmetric only. There is no shared secret between a gateway and an identity provider
// that could make an HMAC meaningful here, so accepting HS* would only ever be the
// algorithm-confusion attack succeeding.
var signatureAlgs = map[string]struct {
	hash    crypto.Hash
	newHash func() hash.Hash
	// keyKind is what the JWKS key must be for this alg to apply. The header does not
	// get to pick a key type.
	keyKind string
	// coordBytes is the fixed size of each half of an ECDSA signature.
	coordBytes int
}{
	"RS256": {crypto.SHA256, sha256.New, "RSA", 0},
	"RS384": {crypto.SHA384, sha512.New384, "RSA", 0},
	"RS512": {crypto.SHA512, sha512.New, "RSA", 0},
	"ES256": {crypto.SHA256, sha256.New, "EC", 32},
	"ES384": {crypto.SHA384, sha512.New384, "EC", 48},
	"ES512": {crypto.SHA512, sha512.New, "EC", 66},
}

type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// claims is the subset with a defined meaning here. Everything else is kept raw so a
// deployment can map its own group claim without this file knowing its name.
type claims struct {
	Iss string    `json:"iss"`
	Sub string    `json:"sub"`
	Aud audience  `json:"aud"`
	Exp *jsonTime `json:"exp"`
	Nbf *jsonTime `json:"nbf"`
	Iat *jsonTime `json:"iat"`
	raw map[string]json.RawMessage
}

// audience is one string or a list of them. Both are legal and providers differ.
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return errors.New("aud is neither a string nor a list of strings")
	}
	*a = many
	return nil
}

// jsonTime is a NumericDate: seconds since the epoch, possibly fractional.
type jsonTime time.Time

func (t *jsonTime) UnmarshalJSON(b []byte) error {
	var f float64
	if err := json.Unmarshal(b, &f); err != nil {
		return errors.New("a timestamp claim is not a number")
	}
	sec, frac := int64(f), f-float64(int64(f))
	*t = jsonTime(time.Unix(sec, int64(frac*1e9)))
	return nil
}

func (t *jsonTime) time() time.Time {
	if t == nil {
		return time.Time{}
	}
	return time.Time(*t)
}

// verified is a token that passed every check.
type verified struct {
	claims claims
	// Raw gives the mapper access to claims this file has no opinion about — a group
	// claim's name is a deployment's choice, not this package's.
	Raw map[string]json.RawMessage
}

// verifyToken checks a compact JWS against a key set and the required issuer/audience.
//
// keys is consulted by kid; a token whose kid is unknown returns ErrUnknownKey so the
// caller can refetch once and try again.
func verifyToken(token string, keys *keySet, issuer, audience string, skew time.Duration,
	now time.Time) (*verified, error) {

	// Exactly three parts. A JWE (five parts) is not a thing this accepts: an encrypted
	// token cannot be verified without also decrypting it, and silently treating the
	// first three segments of one as a JWS is how a verifier reads attacker-chosen
	// plaintext.
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("oidc: a token has %d segments, want 3", len(parts))
	}
	if parts[0] == "" || parts[1] == "" {
		return nil, errors.New("oidc: a token has an empty segment")
	}
	// The signature segment is checked *after* the algorithm, not here: an `alg: none`
	// token has an empty signature by construction, so rejecting it for the empty
	// segment would hide which attack arrived behind a generic complaint.

	headerBytes, err := decodeSegment(parts[0])
	if err != nil {
		return nil, fmt.Errorf("oidc: token header: %w", err)
	}
	var h header
	if err := json.Unmarshal(headerBytes, &h); err != nil {
		return nil, fmt.Errorf("oidc: token header is not JSON: %w", err)
	}

	spec, ok := signatureAlgs[h.Alg]
	if !ok {
		// Named rather than lumped in with "bad signature": `alg: none` and `alg: HS256`
		// are attacks with a literature, and an operator reading a log should see which
		// one arrived.
		return nil, fmt.Errorf("oidc: refusing algorithm %q — only RS256/384/512 and "+
			"ES256/384/512 are accepted, and never a symmetric or absent one", h.Alg)
	}

	key, err := keys.byKID(h.Kid)
	if err != nil {
		return nil, err
	}
	// The header agreed to an alg; the key decides whether that alg is even applicable.
	// This is the line that stops algorithm confusion: a header claiming ES256 over an
	// RSA key gets nowhere, and neither does the reverse.
	if key.kind != spec.keyKind {
		return nil, fmt.Errorf("oidc: token says %s but key %q is %s",
			h.Alg, h.Kid, key.kind)
	}

	if parts[2] == "" {
		return nil, errors.New("oidc: a token has an empty signature")
	}
	sig, err := decodeSegment(parts[2])
	if err != nil {
		return nil, fmt.Errorf("oidc: token signature: %w", err)
	}
	// The received text, verified as received. (For a three-segment token this is the
	// same string as rejoining parts[0] and parts[1] — the distinction that matters is
	// not slicing versus rejoining, but that neither one round-trips the payload through
	// a JSON decode and re-encode. That is the mistake that lets a signature cover
	// different bytes than the claims which then get used.)
	signing := token[:len(parts[0])+1+len(parts[1])]
	digest := spec.newHash()
	digest.Write([]byte(signing))
	sum := digest.Sum(nil)

	switch pub := key.pub.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(pub, spec.hash, sum, sig); err != nil {
			return nil, errors.New("oidc: the token's signature does not verify")
		}
	case *ecdsa.PublicKey:
		// Fixed-width r‖s, per RFC 7518. An ASN.1 signature here is a different
		// encoding and must not be accepted by accident.
		if len(sig) != 2*spec.coordBytes {
			return nil, fmt.Errorf("oidc: an %s signature is %d bytes, want %d",
				h.Alg, len(sig), 2*spec.coordBytes)
		}
		r := new(big.Int).SetBytes(sig[:spec.coordBytes])
		s := new(big.Int).SetBytes(sig[spec.coordBytes:])
		if !ecdsa.Verify(pub, sum, r, s) {
			return nil, errors.New("oidc: the token's signature does not verify")
		}
	default:
		return nil, fmt.Errorf("oidc: key %q is of an unsupported type", h.Kid)
	}

	payload, err := decodeSegment(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oidc: token payload: %w", err)
	}
	var c claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("oidc: token payload is not JSON: %w", err)
	}
	if err := json.Unmarshal(payload, &c.raw); err != nil {
		return nil, fmt.Errorf("oidc: token payload is not an object: %w", err)
	}

	// Issuer, exactly. Not a prefix and not a suffix: a provider at
	// https://issuer.example.com and one at https://issuer.example.com.attacker.test
	// are different providers.
	if c.Iss != issuer {
		return nil, fmt.Errorf("oidc: token issuer %q is not %q", c.Iss, issuer)
	}
	if audience != "" && !c.Aud.has(audience) {
		// A token minted for another relying party is a valid token; it is just not
		// for us. Accepting it is how one tenant's login becomes another's.
		return nil, fmt.Errorf("oidc: token audience %v does not include %q",
			[]string(c.Aud), audience)
	}
	if c.Exp == nil {
		return nil, errors.New("oidc: token has no exp, so it would never expire")
	}
	if now.After(c.Exp.time().Add(skew)) {
		return nil, fmt.Errorf("oidc: token expired at %s", c.Exp.time().UTC().Format(time.RFC3339))
	}
	if c.Nbf != nil && now.Add(skew).Before(c.Nbf.time()) {
		return nil, fmt.Errorf("oidc: token is not valid until %s",
			c.Nbf.time().UTC().Format(time.RFC3339))
	}
	if c.Iat != nil && now.Add(skew).Before(c.Iat.time()) {
		return nil, errors.New("oidc: token was issued in the future")
	}
	if strings.TrimSpace(c.Sub) == "" {
		return nil, errors.New("oidc: token has no sub")
	}
	return &verified{claims: c, Raw: c.raw}, nil
}

func (a audience) has(want string) bool { return slices.Contains(a, want) }

// decodeSegment is base64url without padding, which is what a JWS uses. Standard base64
// is not accepted: a decoder that takes both will accept two encodings of one token.
func decodeSegment(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.New("not valid unpadded base64url")
	}
	return b, nil
}
