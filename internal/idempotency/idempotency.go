// Package idempotency makes a retried request stop opening a second session.
//
// `POST /sessions` does real work: it creates a row, wakes a device and mints a
// credential. A client whose connection times out cannot tell whether any of that
// happened, so it retries — and without a key, the retry opens a second session, burns
// a second invitation, and leaves the caller unable to distinguish "my retry worked"
// from "somebody else has the device". FR34.
//
// # Nothing is cached, which is the point
//
// The obvious design stores the first response and replays it. It is also the design
// with a bug the planning notes flagged before it was written: that response contains a
// 60-second attach ticket, so a replay two minutes later hands the caller a credential
// that is already dead and calls it success.
//
// So a record here holds a *session id*, not a response. A replay looks the session up
// as it is now and mints a fresh ticket through the same path the renewal endpoint
// uses. There is no cached credential to expire, no stale session state to serve, and
// the awkward case disappears rather than being handled.
//
// # A key belongs to a principal
//
// Every operation takes the principal, and the record is namespaced by it. Two callers
// that pick the same key — which they will, because "1", "retry" and a fixed UUID all
// happen — must not be able to see, collide with, or steal each other's sessions, and
// making that structural is cheaper than remembering to check it at each call site.
//
// # A failed request releases its key
//
// If the work fails, the key is freed rather than consumed. The common failure is a
// device that did not answer, which is exactly the case where the caller *should* be
// able to retry with the same key — and a key that stayed consumed after a transient
// failure would be a key the client can never use again, for a session that does not
// exist.
package idempotency

import (
	"context"
	"errors"
	"sync"
	"time"
)

// DefaultTTL is how long a completed record is remembered.
//
// Long enough to cover a client that retries after a long backoff or a human re-running
// a script, short enough that the memory is bounded by a day of traffic. It is not a
// session lifetime: the record outliving the session it names is fine and expected,
// because a replay resolves the session id against the store rather than trusting the
// record for anything but the id.
const DefaultTTL = 24 * time.Hour

var (
	// ErrInFlight means another request holds this key right now. The caller has
	// retried before the first attempt finished; the answer is to wait, not to work.
	ErrInFlight = errors.New("idempotency: another request holds this key")

	// ErrFingerprintMismatch means the key was used before with a different request.
	// A client bug, and a dangerous one to paper over: returning the first request's
	// session for a second request's body hands somebody a shell on the wrong device.
	ErrFingerprintMismatch = errors.New("idempotency: this key was used with a different request")

	errIncomplete = errors.New("idempotency: principal and key are both required")
)

// Record is what a completed key remembers.
type Record struct {
	SessionID string
}

// Store tracks which requests have already been done.
//
// Begin is a compare-and-set, not a read followed by a write. Two concurrent retries of
// the same request are the ordinary case rather than the exotic one — a client library
// with a hedged request does it deliberately — and a check-then-act would let both
// through to open two sessions.
type Store interface {
	// Begin claims the key for a new attempt.
	//
	// It returns (Record{}, false, nil) when the caller now owns the key and must
	// finish with Complete or Release; (record, true, nil) when the key is already
	// complete and this is a replay; ErrInFlight when another attempt owns it; and
	// ErrFingerprintMismatch when the key was completed for a different request.
	Begin(ctx context.Context, principal, key, fingerprint string) (rec Record, replay bool, err error)

	// Complete records the session the attempt produced.
	Complete(ctx context.Context, principal, key, sessionID string) error

	// Release gives the key back after a failed attempt.
	Release(ctx context.Context, principal, key string) error
}

// entry is one key's state. A zero Done means an attempt is still running.
type entry struct {
	fingerprint string
	sessionID   string
	done        bool
	expires     time.Time
}

// sweepEvery amortises expiry over Begin calls; expiry itself is lazy, checked on read.
const sweepEvery = 256

// Memory is the default Store: one process, no dependencies.
//
// A retry usually lands within seconds on the connection it was made on, so this covers
// the case it exists for on the deployment shape that is supported today. A gateway
// behind a load balancer needs a shared store, for the same reason and with the same
// caveat as every other piece of per-node state here.
type Memory struct {
	mu         sync.Mutex
	entries    map[string]*entry
	ttl        time.Duration
	now        func() time.Time
	sinceSweep int
}

var _ Store = (*Memory)(nil)

// NewMemory returns an empty store. now may be nil; ttl of zero means DefaultTTL.
func NewMemory(ttl time.Duration, now func() time.Time) *Memory {
	if now == nil {
		now = time.Now
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Memory{entries: map[string]*entry{}, ttl: ttl, now: now}
}

// id namespaces a key by its principal.
//
// The separator is a NUL because it cannot appear in either half: a principal ending in
// the separator could otherwise be made to collide with another principal's key, which
// is the one way this composition can go wrong.
func id(principal, key string) string { return principal + "\x00" + key }

// containsNUL guards the separator's one assumption.
//
// The composition is only injective while neither half can contain the byte that joins
// them, and "a principal will never contain a NUL" is the kind of thing that is true
// until an identity provider hands one over. Refusing is a line of code; the bug it
// prevents is one caller's key resolving to another caller's session.
func containsNUL(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			return true
		}
	}
	return false
}

func (m *Memory) Begin(_ context.Context, principal, key, fingerprint string) (Record, bool, error) {
	if principal == "" || key == "" || containsNUL(principal) || containsNUL(key) {
		return Record{}, false, errIncomplete
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweepLocked()

	k := id(principal, key)
	cur, ok := m.entries[k]
	if ok && !m.now().Before(cur.expires) {
		// Expired, and deliberately regardless of whether it finished. A completed
		// record is older than any retry this covers; an *unfinished* one is a handler
		// that died without completing or releasing, and expiring it is the only thing
		// that stops that key being wedged for the life of the process.
		delete(m.entries, k)
		ok = false
	}
	if ok {
		if cur.fingerprint != fingerprint {
			return Record{}, false, ErrFingerprintMismatch
		}
		if !cur.done {
			return Record{}, false, ErrInFlight
		}
		return Record{SessionID: cur.sessionID}, true, nil
	}

	// An in-flight entry gets an expiry too, so a handler that dies without completing
	// or releasing cannot wedge a key forever. It is the TTL rather than something
	// shorter because an abandoned key is rare and a key freed too early is a duplicate
	// session, which is the thing this package exists to prevent.
	m.entries[k] = &entry{fingerprint: fingerprint, expires: m.now().Add(m.ttl)}
	return Record{}, false, nil
}

func (m *Memory) Complete(_ context.Context, principal, key, sessionID string) error {
	if principal == "" || key == "" || containsNUL(principal) || containsNUL(key) {
		return errIncomplete
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.entries[id(principal, key)]
	if !ok {
		return nil
	}
	cur.done = true
	cur.sessionID = sessionID
	cur.expires = m.now().Add(m.ttl)
	return nil
}

func (m *Memory) Release(_ context.Context, principal, key string) error {
	if principal == "" || key == "" || containsNUL(principal) || containsNUL(key) {
		return errIncomplete
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	k := id(principal, key)
	// Only an unfinished attempt is released. Releasing a completed key would undo a
	// successful request's record, and the deferred-release shape at the call site
	// means this is reached on the success path too.
	if cur, ok := m.entries[k]; ok && !cur.done {
		delete(m.entries, k)
	}
	return nil
}

// Len is the number of records held. For tests.
func (m *Memory) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

func (m *Memory) sweepLocked() {
	m.sinceSweep++
	if m.sinceSweep < sweepEvery {
		return
	}
	m.sinceSweep = 0
	now := m.now()
	for k, e := range m.entries {
		if !now.Before(e.expires) {
			delete(m.entries, k)
		}
	}
}
