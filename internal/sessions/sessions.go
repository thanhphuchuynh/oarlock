// Package sessions is the session ledger: one row per session, with one true
// reason for having ended.
//
// A command is a request with a terminal state; a session is a long-lived thing
// with bytes, a recording and a close reason. They are separate concepts for that
// reason, and this is the second one.
//
// The in-memory store here is M0's. E2.S3 replaces it with SQLite and Postgres —
// the interface is what stays.
package sessions

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// State is where a session is in its lifecycle (ARCHITECTURE § 6).
type State string

const (
	StateWaking   State = "waking"   // the doorbell rang
	StateOpening  State = "opening"  // the agent is dialling
	StateAttached State = "attached" // both ends present
	StateClosed   State = "closed"   // ended, with a reason
	StateRejected State = "rejected" // never opened
)

// RecordingState makes an unrecorded session a fact that can be queried for,
// rather than an absence somebody has to notice.
type RecordingState string

const (
	Recorded    RecordingState = "recorded"
	NotRecorded RecordingState = "not_recorded"
)

// Session is one row.
type Session struct {
	ID       string
	DeviceID string
	Profile  string
	Mode     string // persistent | dispatch — how the device was reached

	// Principal is the human. OpenedBy is the service that acted for them, if any:
	// both are kept, because a trail whose every entry says svc-crm is one nobody
	// can use, and one that hides which service was involved is one nobody can debug.
	Principal  string
	OpenedBy   string
	Unattended bool

	// Reason is why the session opened — free text from the operator. Costs the
	// caller nothing and turns the session list from a log into an explanation.
	Reason string

	State          State
	RecordingState RecordingState
	RecordInput    bool
	CloseReason    string
	ExitCode       *int

	BytesIn      int64
	BytesOut     int64
	BytesDropped int64

	CreatedAt  time.Time
	AttachedAt time.Time
	ClosedAt   time.Time
}

// Live reports whether this session still holds a device.
func (s *Session) Live() bool {
	return s.State != StateClosed && s.State != StateRejected
}

// Result is what a finished session produced.
type Result struct {
	CloseReason  string
	ExitCode     *int
	BytesIn      int64
	BytesOut     int64
	BytesDropped int64
}

// Limits are the concurrency caps. Server-side, because a client-side limit is a
// suggestion.
type Limits struct {
	PerDevice    int // default 1
	PerPrincipal int // default 5
	// TCPConnsPerDevice caps live `tcp` sessions on one device — see HoldsDevice for
	// why they are counted apart from everything else. Default 16.
	TCPConnsPerDevice int
}

// ProfileTCP is the port-forwarding profile. Named here because the concurrency caps
// treat it differently and more than one file has to agree which string that is.
const ProfileTCP = "tcp"

// HoldsDevice reports whether a live session of this profile counts against PerDevice
// and PerPrincipal.
//
// Every profile does except `tcp`. A shell, an exec or a file transfer is one operator
// doing one thing, and "one session per device" is a real guarantee about that. A forward
// is not one of anything: `ssh -L` opens as many TCP connections as whatever is on the
// other end asks for, and a browser loading a single page opens six. Counted against the
// same cap, the second image on that page fails with "this device already has a session
// open", and a forward starves the shell somebody needs in order to fix it.
//
// So forwards get their own cap, and the interactive guarantee keeps meaning what the
// session list and the console say it means.
func HoldsDevice(profile string) bool { return profile != ProfileTCP }

// DefaultTCPConnsPerDevice is the default cap on live forwarded connections per device.
//
// Sixteen rather than a handful: HTTP/1.1 clients open up to six connections per origin,
// and a cap that a single page load can reach is a cap that produces intermittent,
// unexplainable failures rather than a clear refusal.
const DefaultTCPConnsPerDevice = 16

// Errors.
var (
	ErrNotFound = errors.New("sessions: no such session")
	ErrExists   = errors.New("sessions: session already exists")
	// ErrLimit is the per-device or per-principal cap. Retryable: the answer is to
	// wait for the other session to end, or to kill it.
	ErrLimit = errors.New("sessions: concurrency limit reached")
)

// Query filters a List.
type Query struct {
	DeviceID   string
	Principal  string
	State      State
	Live       bool // only sessions still holding a device
	Unattended *bool
	Limit      int
	After      string
}

// Store is the ledger.
type Store interface {
	// Create inserts a row and enforces the caps. It must be atomic: two operators
	// opening a shell on the same device in the same second is exactly the race
	// this exists to lose gracefully, and "we checked and it was fine" is not an
	// enforcement mechanism.
	Create(ctx context.Context, s *Session) error
	Update(ctx context.Context, id string, f func(*Session) error) error
	// Finish finalises a row. Named Finish rather than Close because a Store is
	// also a thing you close — and a type with both meanings of Close is a type
	// somebody will call the wrong one of.
	Finish(ctx context.Context, id string, r Result) error
	Get(ctx context.Context, id string) (*Session, error)
	List(ctx context.Context, q Query) ([]*Session, string, error)
}

// Memory is the single-node store. Sessions are lost on restart, which is honest
// rather than surprising: there is nothing durable behind it to recover from.
type Memory struct {
	limits Limits
	now    func() time.Time

	mu sync.Mutex
	by map[string]*Session
}

var _ Store = (*Memory)(nil)

// NewMemory returns an empty store.
func NewMemory(l Limits, now func() time.Time) *Memory {
	if l.PerDevice <= 0 {
		l.PerDevice = 1
	}
	if l.PerPrincipal <= 0 {
		l.PerPrincipal = 5
	}
	if l.TCPConnsPerDevice <= 0 {
		l.TCPConnsPerDevice = DefaultTCPConnsPerDevice
	}
	if now == nil {
		now = time.Now
	}
	return &Memory{limits: l, now: now, by: make(map[string]*Session)}
}

// Create inserts under one lock, so the check and the insert cannot be separated.
func (m *Memory) Create(_ context.Context, s *Session) error {
	if s == nil || s.ID == "" || s.DeviceID == "" {
		return errors.New("sessions: ID and DeviceID are required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, dup := m.by[s.ID]; dup {
		return fmt.Errorf("%w: %s", ErrExists, s.ID)
	}
	var perDevice, perPrincipal, tcpPerDevice int
	for _, e := range m.by {
		if !e.Live() {
			continue
		}
		holds := HoldsDevice(e.Profile)
		if e.DeviceID == s.DeviceID {
			if holds {
				perDevice++
			} else {
				tcpPerDevice++
			}
		}
		if holds && s.Principal != "" && e.Principal == s.Principal {
			perPrincipal++
		}
	}
	if !HoldsDevice(s.Profile) {
		if tcpPerDevice >= m.limits.TCPConnsPerDevice {
			return fmt.Errorf("%w: %s already has %d of %d forwarded connections",
				ErrLimit, s.DeviceID, tcpPerDevice, m.limits.TCPConnsPerDevice)
		}
	} else {
		if perDevice >= m.limits.PerDevice {
			return fmt.Errorf("%w: %s already has %d of %d sessions",
				ErrLimit, s.DeviceID, perDevice, m.limits.PerDevice)
		}
		if s.Principal != "" && perPrincipal >= m.limits.PerPrincipal {
			return fmt.Errorf("%w: %s already has %d of %d sessions",
				ErrLimit, s.Principal, perPrincipal, m.limits.PerPrincipal)
		}
	}

	cp := *s
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = m.now()
	}
	if cp.State == "" {
		cp.State = StateWaking
	}
	if cp.RecordingState == "" {
		// M0 records nothing, and says so in the row rather than leaving it blank.
		// An unrecorded session must be queryable, not merely unmarked.
		cp.RecordingState = NotRecorded
	}
	m.by[cp.ID] = &cp
	return nil
}

// Update mutates a row under the lock.
func (m *Memory) Update(_ context.Context, id string, f func(*Session) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.by[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return f(s)
}

// Finish finalises a row. The close reason is written once: a session that already
// has one keeps it, because the first reason is the true one and whatever noticed
// second is a consequence.
func (m *Memory) Finish(_ context.Context, id string, r Result) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.by[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if s.State == StateClosed {
		return nil
	}
	s.State = StateClosed
	if s.CloseReason == "" {
		s.CloseReason = r.CloseReason
	}
	if r.ExitCode != nil {
		s.ExitCode = r.ExitCode
	}
	s.BytesIn, s.BytesOut, s.BytesDropped = r.BytesIn, r.BytesOut, r.BytesDropped
	s.ClosedAt = m.now()
	return nil
}

// Get returns a copy, so a caller cannot mutate the ledger by accident.
func (m *Memory) Get(_ context.Context, id string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.by[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	cp := *s
	return &cp, nil
}

// List returns copies, ordered by creation time then id so pagination is stable.
func (m *Memory) List(_ context.Context, q Query) ([]*Session, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	all := make([]*Session, 0, len(m.by))
	for _, s := range m.by {
		if q.DeviceID != "" && s.DeviceID != q.DeviceID {
			continue
		}
		if q.Principal != "" && s.Principal != q.Principal {
			continue
		}
		if q.State != "" && s.State != q.State {
			continue
		}
		if q.Live && !s.Live() {
			continue
		}
		if q.Unattended != nil && s.Unattended != *q.Unattended {
			continue
		}
		cp := *s
		all = append(all, &cp)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].CreatedAt.Equal(all[j].CreatedAt) {
			return all[i].ID < all[j].ID
		}
		return all[i].CreatedAt.Before(all[j].CreatedAt)
	})

	limit := q.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	out := make([]*Session, 0, limit)
	for _, s := range all {
		if q.After != "" && s.ID <= q.After {
			continue
		}
		if len(out) == limit {
			return out, out[len(out)-1].ID, nil
		}
		out = append(out, s)
	}
	return out, "", nil
}

// Len is the number of rows, for metrics.
func (m *Memory) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.by)
}
