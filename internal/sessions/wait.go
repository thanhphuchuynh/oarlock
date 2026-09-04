package sessions

import (
	"context"
	"fmt"
)

// Waiter is an optional Store capability: it can say when a session moved, instead of
// being asked over and over.
//
// Optional rather than part of Store, for the same reason `plugin.Recorder.URL` may
// answer ErrUnsupported: the capability is real for some backends and not others, and an
// interface that demanded it would force every implementation to fake it. The `Memory`
// store can do this exactly — every write goes through it — while a SQL store shared
// with another process cannot see writes it did not make, and would have to poll
// internally while claiming not to.
//
// A caller that finds no Waiter polls instead. That is a worse implementation of the
// same promise, not a different promise, and the client-facing behaviour is identical.
type Waiter interface {
	// WaitForState blocks until the session's State differs from since, the session is
	// gone, or ctx ends.
	//
	// It returns nil to mean "look again", not "here is the new value". A wakeup is a
	// hint: the caller re-reads through Get and decides for itself, which keeps the one
	// copy-on-read path in Get rather than growing a second one here that could drift
	// from it.
	WaitForState(ctx context.Context, id string, since State) error
}

var _ Waiter = (*Memory)(nil)

// WaitForState implements Waiter.
func (m *Memory) WaitForState(ctx context.Context, id string, since State) error {
	for {
		m.mu.Lock()
		s, ok := m.by[id]
		if !ok {
			m.mu.Unlock()
			return fmt.Errorf("%w: %s", ErrNotFound, id)
		}
		if s.State != since {
			m.mu.Unlock()
			return nil
		}
		// Taken under the lock and selected on after releasing it. A change landing in
		// between closes this exact channel, so the select returns immediately rather
		// than missing the wakeup — which is the bug this ordering exists to avoid.
		ch := m.changed
		m.mu.Unlock()

		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// bumpLocked wakes every waiter. Callers hold m.mu.
//
// One channel for the whole store rather than one per session: a gateway has tens of
// waiters, not thousands, so waking all of them to re-check a string comparison is
// cheaper than the bookkeeping that would avoid it — and impossible to leak, which
// per-session channels are not.
func (m *Memory) bumpLocked() {
	close(m.changed)
	m.changed = make(chan struct{})
}
