// Package delegated adds service-signed On-Behalf-Of assertions to an HTTP
// authenticator.
package delegated

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oarlock/oarlock/pkg/plugin"
)

const DefaultMaxTTL = 60 * time.Second

type Authenticator struct {
	Base      plugin.Authenticator
	Secret    []byte
	Audience  string
	MayActFor map[string][]string
	MaxTTL    time.Duration
	Now       func() time.Time

	mu   sync.Mutex
	seen map[string]time.Time
}

var _ plugin.Authenticator = (*Authenticator)(nil)

type Assertion struct {
	Subject  string   `json:"sub"`
	Email    string   `json:"email,omitempty"`
	Groups   []string `json:"groups,omitempty"`
	Audience string   `json:"aud"`
	Expires  int64    `json:"exp"`
	ID       string   `json:"jti"`
}

func New(base plugin.Authenticator, secret []byte, audience string,
	mayActFor map[string][]string, maxTTL time.Duration) (*Authenticator, error) {
	if base == nil {
		return nil, errors.New("delegated: base authenticator is required")
	}
	if len(secret) < 32 {
		return nil, errors.New("delegated: secret must be at least 32 bytes")
	}
	if audience == "" {
		return nil, errors.New("delegated: audience is required")
	}
	if maxTTL <= 0 {
		maxTTL = DefaultMaxTTL
	}
	return &Authenticator{
		Base: base, Secret: append([]byte(nil), secret...), Audience: audience,
		MayActFor: mayActFor, MaxTTL: maxTTL, seen: make(map[string]time.Time),
	}, nil
}

func (a *Authenticator) AuthPublicKey(ctx context.Context, user string,
	key ssh.PublicKey) (*plugin.Principal, error) {
	return a.Base.AuthPublicKey(ctx, user, key)
}

func (a *Authenticator) AuthHTTP(ctx context.Context, r *http.Request) (*plugin.Principal, error) {
	return a.Base.AuthHTTP(ctx, r)
}

func (a *Authenticator) AuthDelegated(ctx context.Context, svc *plugin.Principal,
	assertion string) (*plugin.Principal, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if svc == nil || svc.ID == "" {
		return nil, errors.New("delegated: service principal is required")
	}
	payload, err := Verify(assertion, a.Secret)
	if err != nil {
		return nil, err
	}
	if payload.Subject == "" {
		return nil, errors.New("delegated: assertion has no subject")
	}
	if payload.Audience != a.Audience {
		return nil, errors.New("delegated: wrong audience")
	}
	now := a.now()
	exp := time.Unix(payload.Expires, 0)
	if !now.Before(exp) {
		return nil, errors.New("delegated: assertion expired")
	}
	if exp.After(now.Add(a.MaxTTL)) {
		return nil, errors.New("delegated: assertion lifetime is too long")
	}
	if payload.ID == "" {
		return nil, errors.New("delegated: assertion has no jti")
	}
	if err := a.spend(payload.ID, exp, now); err != nil {
		return nil, err
	}
	if !allowed(a.MayActFor[svc.ID], payload.Subject, payload.Groups) {
		return nil, errors.New("delegated: service may not act for subject")
	}
	return &plugin.Principal{
		ID: payload.Subject, Email: payload.Email, Groups: payload.Groups,
		Expiry: exp,
	}, nil
}

func (a *Authenticator) spend(id string, exp, now time.Time) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, until := range a.seen {
		if !now.Before(until) {
			delete(a.seen, k)
		}
	}
	if _, ok := a.seen[id]; ok {
		return errors.New("delegated: assertion replayed")
	}
	a.seen[id] = exp
	return nil
}

func (a *Authenticator) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func allowed(patterns []string, subject string, groups []string) bool {
	for _, p := range patterns {
		if match(p, subject) {
			return true
		}
		if g, ok := strings.CutPrefix(p, "group:"); ok {
			for _, have := range groups {
				if match(g, have) {
					return true
				}
			}
		}
	}
	return false
}

func match(pattern, value string) bool {
	ok, err := filepath.Match(pattern, value)
	return err == nil && ok
}

func Sign(a Assertion, secret []byte) (string, error) {
	payload, err := json.Marshal(a)
	if err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(body))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return body + "." + sig, nil
}

func Verify(token string, secret []byte) (Assertion, error) {
	body, sig, ok := strings.Cut(token, ".")
	if !ok || body == "" || sig == "" {
		return Assertion{}, errors.New("delegated: malformed assertion")
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(body))
	want := mac.Sum(nil)
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return Assertion{}, fmt.Errorf("delegated: signature is not base64: %w", err)
	}
	if !hmac.Equal(got, want) {
		return Assertion{}, errors.New("delegated: signature does not verify")
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return Assertion{}, fmt.Errorf("delegated: payload is not base64: %w", err)
	}
	var a Assertion
	if err := json.Unmarshal(raw, &a); err != nil {
		return Assertion{}, fmt.Errorf("delegated: payload is not JSON: %w", err)
	}
	return a, nil
}
