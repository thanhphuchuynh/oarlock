package pump

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/transport"
)

// MaxObservers is the ceiling on watchers per session.
//
// Not a policy number so much as a memory one: every observer is a socket the output
// path writes to, and a slow one holds a write timeout's worth of the pump's attention.
// Somebody who needs thirty watchers wants a broadcast, which is a different product.
const MaxObservers = 8

// ErrTooManyObservers is returned when the ceiling is reached.
var ErrTooManyObservers = errors.New("pump: too many observers on this session")

// observer is one read-only watcher.
//
// # Read-only is structural here, not enforced
//
// The pump never reads an observer's connection. There is no code path from an observer's
// socket to the device, so an observer's keystrokes cannot reach the shell even if the
// gateway is wrong about who they are — which is a stronger guarantee than a check,
// because a check is a line somebody can later move.
//
// Their connection is still read, by the handler that owns it, for two reasons: to notice
// when they leave, and so that a keystroke can be *counted* rather than vanishing. The
// component disables input, so a counted keystroke means either an old client or somebody
// probing, and both are worth being able to see.
type observer struct {
	principal string
	since     time.Time
	conn      transport.Conn
	// port is how Leave removes this observer rather than merely marking it gone. The
	// operator's indicator has to clear when a watcher leaves, not on the session's
	// next output byte — a session sitting at a prompt produces none.
	port *operatorPort
	// gone is closed when the observer is removed, so the handler holding the socket
	// can return rather than blocking until the browser gives up.
	gone chan struct{}
	once sync.Once
}

func (o *observer) leave() {
	o.once.Do(func() { close(o.gone) })
}

// Gone is closed when this observer has been removed from the session.
func (o *observer) Gone() <-chan struct{} { return o.gone }

// Leave removes this observer. Idempotent, and safe to call from the handler that owns
// the socket.
func (o *observer) Leave() {
	if o.port != nil {
		o.port.removeObserver(context.Background(), o)
		return
	}
	o.leave()
}

// ObserverHandle is what a caller gets for a watcher it added.
type ObserverHandle interface {
	// Gone is closed when the observer is removed, or the session ends.
	Gone() <-chan struct{}
	// Leave removes the observer.
	Leave()
}

// addObserver attaches a read-only watcher and tells the operator.
func (p *operatorPort) addObserver(ctx context.Context, principal string,
	conn transport.Conn, greet func([]frame.Observer) (frame.Frame, error)) (*observer, error) {
	o := &observer{
		principal: principal, since: p.now(), conn: conn,
		port: p, gone: make(chan struct{}),
	}

	p.mu.Lock()
	if len(p.observers) >= MaxObservers {
		p.mu.Unlock()
		return nil, ErrTooManyObservers
	}
	p.observers = append(p.observers, o)
	list := p.observerListLocked()

	// The greeting goes out under the write lock, from the same list the operator is
	// about to be told about, so the observer's own READY cannot disagree with the
	// notification the operator receives.
	var err error
	if greet != nil {
		var f frame.Frame
		if f, err = greet(list); err == nil {
			err = p.sendToLocked(ctx, conn, f)
		}
	}
	p.mu.Unlock()

	if err != nil {
		p.removeObserver(ctx, o)
		return nil, err
	}
	p.announceObservers(ctx)
	return o, nil
}

// removeObserver detaches a watcher and tells the operator.
func (p *operatorPort) removeObserver(ctx context.Context, o *observer) {
	p.mu.Lock()
	out := p.observers[:0]
	found := false
	for _, existing := range p.observers {
		if existing == o {
			found = true
			continue
		}
		out = append(out, existing)
	}
	p.observers = out
	p.mu.Unlock()

	o.leave()
	if found {
		p.announceObservers(ctx)
	}
}

// observerListLocked is the current watchers, oldest first.
func (p *operatorPort) observerListLocked() []frame.Observer {
	if len(p.observers) == 0 {
		// Explicitly empty rather than nil: the operator has to be told when the last
		// watcher leaves, and an omitted field would leave the indicator up forever.
		return []frame.Observer{}
	}
	list := make([]frame.Observer, 0, len(p.observers))
	for _, o := range p.observers {
		list = append(list, frame.Observer{
			Principal: o.principal,
			Since:     o.since.UTC().Format(time.RFC3339),
		})
	}
	return list
}

// Observers is the current watcher list.
func (p *operatorPort) observerList() []frame.Observer {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.observerListLocked()
}

// announceObservers tells the operator who is watching.
//
// The whole list rather than a delta: a client that missed one frame would otherwise be
// wrong about the single fact this exists to convey, and being quietly wrong about who is
// watching is worse than not showing it at all.
func (p *operatorPort) announceObservers(ctx context.Context) {
	f, err := frame.Marshal(frame.TypeObservers, frame.Observers{Observers: p.observerList()})
	if err != nil {
		return
	}
	// Best effort to the operator: if they have dropped, the list is in their next
	// READY, which is sent on reattach.
	_ = p.sendFrame(ctx, f)
}

// fanOutLocked copies a frame to every observer.
//
// Failures remove the observer rather than propagating: a watcher whose socket died must
// not be able to interrupt the session they were watching. That asymmetry is the point of
// observation being read-only in both directions.
func (p *operatorPort) fanOutLocked(ctx context.Context, wire []byte) {
	if len(p.observers) == 0 {
		return
	}
	var dead []*observer
	for _, o := range p.observers {
		sendCtx, cancel := context.WithTimeout(ctx, p.timeout)
		err := o.conn.Send(sendCtx, wire)
		cancel()
		if err != nil {
			dead = append(dead, o)
		}
	}
	if len(dead) == 0 {
		return
	}
	kept := p.observers[:0]
	for _, o := range p.observers {
		if slicesContains(dead, o) {
			continue
		}
		kept = append(kept, o)
	}
	p.observers = kept
	// Announced outside the lock by the caller's next announce; leaving is immediate so
	// the handler holding the socket can return.
	for _, o := range dead {
		o.leave()
	}
}

func slicesContains(list []*observer, want *observer) bool {
	for _, o := range list {
		if o == want {
			return true
		}
	}
	return false
}
