package sessions

import (
	"context"
	"errors"
	"sort"
	"sync"

	"github.com/oarlock/oarlock/internal/ring"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/transport"
)

// ErrNoReattach means this session cannot take a replacement operator.
//
// True of every SSH session, and deliberately so: a second `ssh` invocation is a new
// session, so there is nothing to reattach *to*, and a detached SSH session would be a
// shell nobody can reach holding the device's only slot until the idle timer fired.
var ErrNoReattach = errors.New("sessions: this session does not support reattach")

// ErrNoObserve means this session cannot be watched.
var ErrNoObserve = errors.New("sessions: this session cannot be observed")

// ErrNotLive means the session is not running on this node.
//
// Not the same as "does not exist": the ledger is shared and durable, the registry
// is per-node and in-memory. A session in the ledger that is not in this registry is
// running somewhere else, or already over.
var ErrNotLive = errors.New("sessions: session is not live on this node")

// Handle is a live session this node is running.
type Handle struct {
	ID        string
	DeviceID  string
	Principal string
	Profile   string

	// kill ends the session with a reason. It is expected to be a pump cancel plus
	// whatever the owner needs to do, and to be safe to call more than once.
	kill func(reason string)
	once sync.Once

	// reattach hands a replacement operator connection to the running pump. Nil for a
	// session that cannot take one.
	reattach ReattachFunc
	// observe attaches a read-only watcher. Nil where observation is not offered.
	observe ObserveFunc

	// done is closed when the session ends. A reattached operator's HTTP handler waits
	// on it: that handler no longer owns the connection — the pump writes to it — so
	// without this it would hold a goroutine and a socket until the *browser* gave up,
	// long after the session was over.
	doneMu   sync.Mutex
	done     chan struct{}
	doneOnce sync.Once
}

// Done is closed when the session ends.
func (h *Handle) Done() <-chan struct{} { return h.doneChan() }

func (h *Handle) doneChan() chan struct{} {
	h.doneMu.Lock()
	defer h.doneMu.Unlock()
	if h.done == nil {
		h.done = make(chan struct{})
	}
	return h.done
}

// finish marks the session over. Idempotent.
func (h *Handle) finish() {
	ch := h.doneChan()
	h.doneOnce.Do(func() { close(ch) })
}

// ReattachFunc installs a replacement operator connection on a live session.
//
// greet is called with the scrollback the new operator is about to be sent, while the
// write lock is held, and returns the frame to send before the replay. That is what
// keeps READY's `scrollback_len` exact and keeps live output from overtaking the
// scrollback: the greeting, the replay and any live DATA are serialised by one lock
// rather than by hope.
type ReattachFunc func(ctx context.Context, conn transport.Conn,
	greet func(ring.Snapshot) (frame.Frame, error)) error

// SetReattach records how to hand this session a replacement operator. Called by the
// owner before Add.
func (h *Handle) SetReattach(f ReattachFunc) { h.reattach = f }

// ObserveFunc attaches a read-only watcher to a live session (FR13).
//
// greet builds the watcher's own READY from the list they are joining, under the same
// lock the operator's notification is sent from — so a watcher's view of who is present
// cannot disagree with what the operator was just told.
type ObserveFunc func(ctx context.Context, principal string, conn transport.Conn,
	greet func([]frame.Observer) (frame.Frame, error)) (Watcher, error)

// Watcher is a live observation.
type Watcher interface {
	// Gone is closed when the observation ends, for any reason.
	Gone() <-chan struct{}
	// Leave ends it.
	Leave()
}

// SetObserve records how to attach a watcher. Called by the owner before Add.
func (h *Handle) SetObserve(f ObserveFunc) { h.observe = f }

// Observe attaches a read-only watcher.
func (h *Handle) Observe(ctx context.Context, principal string, conn transport.Conn,
	greet func([]frame.Observer) (frame.Frame, error)) (Watcher, error) {
	if h.observe == nil {
		return nil, ErrNoObserve
	}
	return h.observe(ctx, principal, conn, greet)
}

// Reattach installs a replacement operator connection.
func (h *Handle) Reattach(ctx context.Context, conn transport.Conn,
	greet func(ring.Snapshot) (frame.Frame, error)) error {
	if h.reattach == nil {
		return ErrNoReattach
	}
	return h.reattach(ctx, conn, greet)
}

// Kill ends the session. Idempotent: two administrators pressing the button at the
// same moment is one kill, and the first reason is the one recorded.
func (h *Handle) Kill(reason string) {
	h.once.Do(func() {
		if h.kill != nil {
			h.kill(reason)
		}
	})
}

// Registry holds the sessions running on this node.
//
// It exists because ending a live session needs a handle on the goroutines running
// it, and the ledger — being a database — has none. Every path that ends a session
// from outside goes through here: the API's admin kill (FR19), authorisation
// withdrawal (FR16, E4.S5), and drain (FR41, E6.S3).
type Registry struct {
	mu sync.RWMutex
	by map[string]*Handle
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{by: make(map[string]*Handle)}
}

// Add registers a live session and returns its handle. Re-adding an id replaces the
// entry, which matches the ledger's rule that one id is one session.
func (r *Registry) Add(h *Handle, kill func(reason string)) *Handle {
	h.kill = kill
	_ = h.Done() // created up front, so a waiter cannot miss the close
	r.mu.Lock()
	r.by[h.ID] = h
	r.mu.Unlock()
	return h
}

// Remove deregisters a session. Safe to call for an id that is not present, because
// the owner calls it from a defer that may run after a kill already removed it.
func (r *Registry) Remove(id string) {
	r.mu.Lock()
	h := r.by[id]
	delete(r.by, id)
	r.mu.Unlock()
	if h != nil {
		h.finish()
	}
}

// Get returns a handle, or ErrNotLive.
func (r *Registry) Get(id string) (*Handle, error) {
	r.mu.RLock()
	h, ok := r.by[id]
	r.mu.RUnlock()
	if !ok {
		return nil, ErrNotLive
	}
	return h, nil
}

// Kill ends one session by id.
func (r *Registry) Kill(_ context.Context, id, reason string) error {
	h, err := r.Get(id)
	if err != nil {
		return err
	}
	h.Kill(reason)
	return nil
}

// KillMatching ends every live session for a principal and/or device.
//
// An empty principal or device means "every", which is what an authorisation backend
// sends when it has lost track of its own state and wants the gateway to stop trusting
// anything it said. Deliberately expressible: the alternative is a backend with no way to
// say it, and a revocation nobody can act on.
//
// Both empty therefore kills everything — which is why the caller passing them is a
// backend making an explicit statement rather than a loop with an uninitialised variable.
func (r *Registry) KillMatching(principal, device, reason string) int {
	r.mu.RLock()
	var matched []*Handle
	for _, h := range r.by {
		if principal != "" && h.Principal != principal {
			continue
		}
		if device != "" && h.DeviceID != device {
			continue
		}
		matched = append(matched, h)
	}
	r.mu.RUnlock()

	for _, h := range matched {
		h.Kill(reason)
	}
	return len(matched)
}

// KillAll ends every session on this node, for a drain. Returns how many.
func (r *Registry) KillAll(reason string) int {
	r.mu.RLock()
	handles := make([]*Handle, 0, len(r.by))
	for _, h := range r.by {
		handles = append(handles, h)
	}
	r.mu.RUnlock()
	for _, h := range handles {
		h.Kill(reason)
	}
	return len(handles)
}

// IDs lists the live session ids, sorted, for metrics and health output.
func (r *Registry) IDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.by))
	for id := range r.by {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Len is the number of live sessions on this node.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.by)
}
