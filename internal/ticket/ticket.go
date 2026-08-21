// Package ticket mints and redeems the single-use credentials that authenticate a
// session connection.
//
// Every session, in both reachability modes, is its own connection opened with a
// ticket (ADR-024). Neither end holds a standing credential for it: the device has
// no bearer token to reuse — enrollment hands back reachability configuration and
// nothing else — and an operator's admin JWT is large enough to trip a WebSocket
// read limit, which is a bug worth not shipping twice.
//
// A ticket is not a credential for the gateway. It is a credential for exactly one
// pending session, and it stops existing the moment it is used.
package ticket

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Length in bytes before encoding. 32 bytes of crypto/rand is 43 base64url
// characters and 256 bits of entropy — guessing is not a threat, so the whole
// defence is single use plus a short deadline.
const Length = 32

// DefaultTTL is how long a ticket may sit unredeemed.
//
// It is a deadline for *connecting*, not a session lifetime. Sixty seconds is
// generous for a warm control channel and tight for a sleeping Android radio; see
// the answer-deadline note in internal/invite.
const DefaultTTL = 60 * time.Second

// Kind says which leg a ticket authenticates. A device ticket cannot be used by a
// browser and vice versa, so a leaked attach ticket cannot be spent as a device.
type Kind string

const (
	KindDevice Kind = "device"
	KindAttach Kind = "attach"
	// KindObserve authenticates a read-only watcher (FR13).
	KindObserve Kind = "observe"
)

var (
	// ErrInvalid covers unknown, expired and already-redeemed alike, on purpose.
	// Telling a caller which one it was would confirm that a token existed.
	ErrInvalid = errors.New("ticket: invalid, expired, or already redeemed")
	// ErrScope means the ticket is real but not for this device, profile or kind.
	ErrScope = errors.New("ticket: not valid for this scope")
)

// Claims are what a ticket authorises. Scoped narrowly on purpose: one device, one
// profile, one principal, one leg.
type Claims struct {
	SessionID string
	DeviceID  string
	Profile   string
	Principal string
	Kind      Kind
	ExpiresAt time.Time
}

// Want is the scope a redeemer expects. Empty fields are not checked.
type Want struct {
	DeviceID string
	Profile  string
	Kind     Kind
}

// Check verifies a redeemed ticket is being used for what it was minted for.
//
// Redemption already proves the token existed; this proves it is being spent on the
// right thing. Without it a ticket minted for a `log` stream would open a shell.
func (c *Claims) Check(w Want) error {
	if w.DeviceID != "" && c.DeviceID != w.DeviceID {
		return fmt.Errorf("%w: device %q, want %q", ErrScope, c.DeviceID, w.DeviceID)
	}
	if w.Profile != "" && c.Profile != w.Profile {
		return fmt.Errorf("%w: profile %q, want %q", ErrScope, c.Profile, w.Profile)
	}
	if w.Kind != "" && c.Kind != w.Kind {
		return fmt.Errorf("%w: kind %q, want %q", ErrScope, c.Kind, w.Kind)
	}
	return nil
}

// Store mints and redeems tickets.
//
// Redeem must be atomic — a compare-and-delete, never a read followed by a delete.
// A ticket that can be redeemed twice is a ticket an attacker can race the real
// agent for, and the race is winnable: the attacker knows when the invitation was
// sent because they are the one who intercepted it.
type Store interface {
	Mint(ctx context.Context, c Claims, ttl time.Duration) (string, error)
	Redeem(ctx context.Context, token string) (*Claims, error)
	Revoke(ctx context.Context, token string) error
}

// Memory is the default Store: single node, no dependencies.
//
// Multi-node needs a shared store — but note that a *ticket* does not need to be
// reachable from every replica, because an invitation names the node that minted it
// (ADR-025). What a shared store buys is surviving a restart, not routing.
type Memory struct {
	mu     sync.Mutex
	issued map[string]Claims
	now    func() time.Time
}

var _ Store = (*Memory)(nil)

// NewMemory returns an empty store. now may be nil.
func NewMemory(now func() time.Time) *Memory {
	if now == nil {
		now = time.Now
	}
	return &Memory{issued: make(map[string]Claims), now: now}
}

// Mint returns a fresh token. ttl of zero means DefaultTTL.
func (m *Memory) Mint(_ context.Context, c Claims, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if c.Kind == "" {
		return "", errors.New("ticket: Kind is required")
	}
	if c.DeviceID == "" || c.SessionID == "" {
		return "", errors.New("ticket: SessionID and DeviceID are required")
	}
	b := make([]byte, Length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("ticket: reading randomness: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	c.ExpiresAt = m.now().Add(ttl)

	m.mu.Lock()
	m.issued[token] = c
	m.mu.Unlock()
	return token, nil
}

// Redeem spends a token. It is a compare-and-delete under one lock, so a second
// attempt — a replay, or the real agent retrying — finds nothing.
func (m *Memory) Redeem(_ context.Context, token string) (*Claims, error) {
	m.mu.Lock()
	c, ok := m.issued[token]
	if ok {
		delete(m.issued, token)
	}
	m.mu.Unlock()

	if !ok {
		return nil, ErrInvalid
	}
	if !m.now().Before(c.ExpiresAt) {
		// Deleted anyway: an expired token is spent, not left for later.
		return nil, ErrInvalid
	}
	return &c, nil
}

// Revoke discards a token without spending it, for an invitation the gateway gave
// up on. It never reports whether the token existed.
func (m *Memory) Revoke(_ context.Context, token string) error {
	m.mu.Lock()
	delete(m.issued, token)
	m.mu.Unlock()
	return nil
}

// Sweep drops expired tokens and returns how many went. Lazy expiry in Redeem is
// enough for correctness; this is what stops an abandoned-invitation storm from
// being a slow memory leak.
func (m *Memory) Sweep() int {
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for token, c := range m.issued {
		if !now.Before(c.ExpiresAt) {
			delete(m.issued, token)
			n++
		}
	}
	return n
}

// Outstanding is the number of unredeemed tokens, for metrics and tests.
func (m *Memory) Outstanding() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.issued)
}

// RunGC sweeps until ctx is done.
func (m *Memory) RunGC(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = 30 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.Sweep()
		}
	}
}
