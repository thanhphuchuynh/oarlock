// Package ownership records which gateway node holds a device's control channel.
//
// A device in persistent mode dials one replica and holds one channel to it. That
// replica is the only process that can send it a `DIAL`, so "which node holds this
// device" is the question a multi-replica deployment has to be able to answer — and
// today it cannot, which is why a gateway behind a load balancer tells an operator
// `device_not_connected` about a device that is connected, to the node next door.
//
// # A routing hint, not a lock
//
// Nothing here grants or withholds permission. The registry cannot make a device
// reachable and cannot make it unreachable; a device holding a channel to this node
// *is* reachable through this node whatever the record says. So a registry that is
// unavailable, stale or wrong costs a retry, never a refusal — and `Claim` therefore
// takes over an existing lease rather than failing, mirroring the hub's own rule that
// the newest channel wins because it is the one demonstrably alive (ADR-025).
//
// This is worth being explicit about because the alternative is tempting and wrong:
// if `Claim` refused when another node held the lease, a crashed replica would make
// its devices unreachable for the length of a lease, and a registry outage would take
// the fleet down with it. A hint that fails open is worth having; a lock that fails
// closed on a dependency the session path does not otherwise need is not.
//
// # What is owner-checked, and why it has to be
//
// `Renew` and `Release` are. A departing node must not be able to clobber its
// successor, and the case is ordinary rather than exotic: a device loses its radio and
// reconnects to another replica while the first replica's socket is still half-open.
// The old node's `Serve` returns some seconds later and releases — and without the
// owner check that release deletes the *new* owner's lease, leaving the device
// unroutable until it reconnects again. Same discipline as the ticket store's
// compare-and-delete: the check is what makes the operation mean what it says.
//
// # For whoever builds the forwarding hop (E6.S2)
//
// A lease names a node so that another replica can hand it an invitation. That
// invitation carries a live single-use ticket, so **a node name from this registry
// must never be dialled on the registry's authority alone.** Resolve it against the
// replica set the deployment was configured with, and refuse a name that is not in it.
// The registry sits in the trusted box in the threat model's §2 diagram, but "trusted"
// there means "can break us", and a poisoned record that could redirect a ticket to an
// arbitrary URL turns a compromised registry into a device takeover rather than an
// outage. Bound the blast radius where the record is consumed.
package ownership

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Lease durations.
//
// The multiple is E6.S1's: a lease outlives three renew intervals, so a node has to
// miss three in a row before another replica may take over. One missed renew is a GC
// pause or a slow registry; three is a node that has stopped.
const (
	DefaultRenewInterval = 10 * time.Second
	LeaseMultiple        = 3
	DefaultTTL           = DefaultRenewInterval * LeaseMultiple
)

var (
	// ErrNotHeld means no node holds the device, or the lease that did has expired.
	// Expiry is not distinguished from absence on purpose: to a caller deciding where
	// to send an invitation they are the same answer, and a lease that expired is a
	// node that stopped saying it was there.
	ErrNotHeld = errors.New("ownership: no node holds this device")

	// ErrHeldByAnother is returned by Renew and Release when the lease belongs to a
	// different node. It is the expected outcome of losing a device to another
	// replica, not a malfunction.
	ErrHeldByAnother = errors.New("ownership: another node holds this device")

	errIncomplete = errors.New("ownership: deviceID and node are both required")
)

// Lease is one device's claim by one node.
type Lease struct {
	DeviceID  string
	Node      string
	ExpiresAt time.Time
}

// Held reports whether the lease is a live claim at the given instant.
func (l Lease) Held(at time.Time) bool {
	return l.Node != "" && at.Before(l.ExpiresAt)
}

// Registry is the shared record. A single-node gateway does not need one.
//
// Implementations must be safe for concurrent use. Every method takes a context
// because the implementation that matters is over a network.
type Registry interface {
	// Claim records that node holds deviceID, taking over from any other node. It is
	// idempotent for the same node, which is what lets a restarted replica reclaim
	// its own devices without waiting out a lease.
	Claim(ctx context.Context, deviceID, node string, ttl time.Duration) (Lease, error)

	// Renew extends a lease this node still holds. It returns ErrHeldByAnother if the
	// device has moved and ErrNotHeld if the lease lapsed; neither is a reason to drop
	// the device's channel.
	Renew(ctx context.Context, deviceID, node string, ttl time.Duration) (Lease, error)

	// Release gives up a lease this node holds. Releasing one that has already gone,
	// or expired, is not an error: release is a cleanup path, and cleanup that fails
	// noisily on an already-clean state is noise at every shutdown.
	Release(ctx context.Context, deviceID, node string) error

	// Lookup answers which node holds the device, or ErrNotHeld.
	Lookup(ctx context.Context, deviceID string) (Lease, error)
}

// sweepEvery amortises expiry cleanup over Claim calls.
//
// Expiry is otherwise lazy — every read checks the clock — so the sweep is only about
// memory, and the thing it reclaims is a record for a device that departed without
// releasing. That is bounded by the fleet, so the sweep can be this cheap.
const sweepEvery = 256

// Memory is the default Registry: one process, no dependencies.
//
// It is the single-node deployment's implementation, where every lookup answers "this
// node" and nothing crosses a network. It is also what makes the multi-replica paths
// testable, because two gateways in one test process can share one of these and
// exercise the same code a shared registry will.
type Memory struct {
	mu         sync.Mutex
	leases     map[string]Lease
	now        func() time.Time
	sinceSweep int
}

var _ Registry = (*Memory)(nil)

// NewMemory returns an empty registry. now may be nil.
func NewMemory(now func() time.Time) *Memory {
	if now == nil {
		now = time.Now
	}
	return &Memory{leases: make(map[string]Lease), now: now}
}

func ttlOr(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		return DefaultTTL
	}
	return ttl
}

// Claim takes the device for this node.
func (m *Memory) Claim(_ context.Context, deviceID, node string, ttl time.Duration) (Lease, error) {
	if deviceID == "" || node == "" {
		return Lease{}, errIncomplete
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweepLocked()
	l := Lease{DeviceID: deviceID, Node: node, ExpiresAt: m.now().Add(ttlOr(ttl))}
	m.leases[deviceID] = l
	return l, nil
}

// Renew extends a lease this node still holds.
func (m *Memory) Renew(_ context.Context, deviceID, node string, ttl time.Duration) (Lease, error) {
	if deviceID == "" || node == "" {
		return Lease{}, errIncomplete
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	cur, ok := m.leases[deviceID]
	if !ok || !cur.Held(now) {
		return Lease{}, ErrNotHeld
	}
	if cur.Node != node {
		return Lease{}, ErrHeldByAnother
	}
	cur.ExpiresAt = now.Add(ttlOr(ttl))
	m.leases[deviceID] = cur
	return cur, nil
}

// Release gives up a lease held by this node.
func (m *Memory) Release(_ context.Context, deviceID, node string) error {
	if deviceID == "" || node == "" {
		return errIncomplete
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.leases[deviceID]
	if !ok {
		return nil
	}
	if !cur.Held(m.now()) {
		// Expired, so it belongs to nobody. Dropping it here is cleanup rather than a
		// takeover, and the node it names has already lost the device by the clock.
		delete(m.leases, deviceID)
		return nil
	}
	if cur.Node != node {
		return ErrHeldByAnother
	}
	delete(m.leases, deviceID)
	return nil
}

// Lookup answers which node holds the device.
func (m *Memory) Lookup(_ context.Context, deviceID string) (Lease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.leases[deviceID]
	if !ok || !cur.Held(m.now()) {
		return Lease{}, ErrNotHeld
	}
	return cur, nil
}

// Len is the number of records, expired ones included. For tests.
func (m *Memory) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.leases)
}

func (m *Memory) sweepLocked() {
	m.sinceSweep++
	if m.sinceSweep < sweepEvery {
		return
	}
	m.sinceSweep = 0
	now := m.now()
	for id, l := range m.leases {
		if !l.Held(now) {
			delete(m.leases, id)
		}
	}
}
