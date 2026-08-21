package pump

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/oarlock/oarlock/internal/ring"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/transport"
)

// operatorPort is the operator end of the pump, which can come and go.
//
// A dropped operator socket is not a close (ARCHITECTURE § 6). The session stays
// attached, the device keeps producing into the ring, and a reconnecting operator gets
// the scrollback replayed. Operators lose wifi constantly; a shell that dies with it is
// a shell nobody trusts with a long command.
//
// Everything that writes to the operator goes through here, which is what makes the
// ordering safe: the replay is written under the same mutex as live output, so a DATA
// frame produced a microsecond after the reattach cannot overtake the scrollback and
// leave the screen assembled in the wrong order.
type operatorPort struct {
	timeout time.Duration
	ring    *ring.Ring

	mu   sync.Mutex
	conn transport.Conn
	buf  []byte
	// observers are read-only watchers. Guarded by mu because the output path fans out
	// to them under the same lock that serialises writes to the operator, which is what
	// stops a watcher seeing bytes in a different order from the person being watched.
	observers []*observer
	// now is injectable so a test can assert on an observer's "since".
	nowFn func() time.Time
	// gen increments on every attach, so a stale reader can tell that the connection
	// it was reading from is no longer the session's.
	gen uint64

	// present is closed while an operator is attached, and replaced on detach. A
	// reader waits on it rather than polling.
	presentMu sync.Mutex
	present   chan struct{}
}

// ErrOperatorPresent is returned when something tries to attach a second operator to a
// session that already has one. Two operators writing into one shell would interleave
// their keystrokes; a read-only observer is a different feature (FR13, E3.S5).
var ErrOperatorPresent = errors.New("pump: the session already has an operator")

func newOperatorPort(conn transport.Conn, timeout time.Duration, r *ring.Ring) *operatorPort {
	p := &operatorPort{timeout: timeout, ring: r, conn: conn, present: make(chan struct{})}
	if conn != nil {
		close(p.present)
	}
	return p
}

// current returns the connection to read from, and the generation it belongs to.
func (p *operatorPort) current() (transport.Conn, uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.conn, p.gen
}

// detach removes the operator, if the generation given is still the current one.
//
// The generation check is what stops a slow reader from detaching a *newer* operator
// after its own connection died: by the time it notices, somebody else may already have
// reattached.
func (p *operatorPort) detach(gen uint64) bool {
	p.mu.Lock()
	if p.gen != gen || p.conn == nil {
		p.mu.Unlock()
		return false
	}
	p.conn = nil
	p.mu.Unlock()
	p.markAbsent()
	return true
}

// releaseObservers detaches every watcher, so the handlers holding their sockets return
// when the session ends rather than waiting for the browsers to give up.
func (p *operatorPort) releaseObservers() {
	p.mu.Lock()
	list := p.observers
	p.observers = nil
	p.mu.Unlock()
	for _, o := range list {
		o.leave()
	}
}

// markAbsent resets the "an operator is here" gate. Callers must not hold presentMu.
func (p *operatorPort) markAbsent() {
	p.presentMu.Lock()
	p.present = make(chan struct{})
	p.presentMu.Unlock()
}

// attach installs a new operator connection and replays the scrollback to it.
//
// The replay happens while the write mutex is held, so nothing live interleaves with it.
func (p *operatorPort) attach(ctx context.Context, conn transport.Conn,
	greet func(ring.Snapshot) (frame.Frame, error)) (ring.Snapshot, error) {
	var snap ring.Snapshot

	p.mu.Lock()
	if p.conn != nil {
		p.mu.Unlock()
		return snap, ErrOperatorPresent
	}
	p.conn = conn
	p.gen++
	if p.ring != nil {
		snap = p.ring.Snapshot()
	}
	// The greeting is built and sent inside the lock, from the same snapshot that is
	// about to be replayed. That is what makes READY's scrollback_len exact rather
	// than approximately right, and it is why greet is a callback and not a frame the
	// caller prepared in advance.
	var err error
	if greet != nil {
		var f frame.Frame
		if f, err = greet(snap); err == nil {
			err = p.sendFrameLocked(ctx, f)
		}
	}
	if err == nil {
		err = p.replayLocked(ctx, snap)
	}
	p.mu.Unlock()

	p.presentMu.Lock()
	close(p.present)
	p.presentMu.Unlock()
	return snap, err
}

// replayLocked writes the scrollback, in batches the operator's decoder will accept.
func (p *operatorPort) replayLocked(ctx context.Context, snap ring.Snapshot) error {
	const batch = 32 << 10
	for off := 0; off < len(snap.Replay); off += batch {
		end := min(off+batch, len(snap.Replay))
		if err := p.sendFrameLocked(ctx, frame.Data(snap.Replay[off:end])); err != nil {
			return err
		}
	}
	return nil
}

// waitPresent blocks until an operator is attached, or the context ends.
func (p *operatorPort) waitPresent(ctx context.Context) error {
	p.presentMu.Lock()
	ch := p.present
	p.presentMu.Unlock()
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ── Sink ────────────────────────────────────────────────────────────────────────

func (p *operatorPort) SendData(ctx context.Context, b []byte) error {
	return p.broadcast(ctx, frame.Data(b))
}

func (p *operatorPort) SendThrottle(ctx context.Context, dropped int64) error {
	f, err := frame.Marshal(frame.TypeThrottle, frame.Throttle{DroppedBytes: dropped})
	if err != nil {
		return err
	}
	return p.broadcast(ctx, f)
}

// broadcast sends to the operator and to every watcher.
//
// Separate from sendFrame on purpose. Fanning out everything would send each connection's
// own greeting to all the others: a reattaching operator's READY, carrying *their*
// scrollback length, would arrive at a watcher who is about to be told a different one,
// and the replay that follows it would arrive twice. So the two are different methods and
// each call site says which it means.
func (p *operatorPort) broadcast(ctx context.Context, f frame.Frame) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	err := p.sendFrameLocked(ctx, f)
	// Encoded again rather than reusing the port's buffer: fanOutLocked hands the same
	// bytes to several sockets, and p.buf is about to be reused by the next write.
	wire, encErr := frame.Codec{}.Encode(nil, f)
	if encErr == nil {
		p.fanOutLocked(ctx, wire)
	}
	return err
}

// errDetached is returned when there is no operator and no ring to hold for one.
var errDetached = errors.New("pump: no operator is attached")

func (p *operatorPort) sendFrame(ctx context.Context, f frame.Frame) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sendFrameLocked(ctx, f)
}

func (p *operatorPort) now() time.Time {
	if p.nowFn != nil {
		return p.nowFn()
	}
	return time.Now()
}

// sendToLocked writes one frame to one connection, using the port's shared buffer.
func (p *operatorPort) sendToLocked(ctx context.Context, conn transport.Conn, f frame.Frame) error {
	wire, err := frame.Codec{}.Encode(p.buf[:0], f)
	if err != nil {
		return err
	}
	p.buf = wire
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	return conn.Send(ctx, wire)
}

func (p *operatorPort) sendFrameLocked(ctx context.Context, f frame.Frame) error {
	if p.conn == nil {
		// Nobody is listening. Discarding rather than erroring is the point: the
		// device must keep draining, because the alternative is backpressure all the
		// way to a PTY whose program then blocks — a background job that stalls
		// because somebody's wifi dropped. The ring is what the operator gets back,
		// and it is fed upstream of here.
		if p.ring != nil {
			return nil
		}
		return errDetached
	}
	wire, err := frame.Codec{}.Encode(p.buf[:0], f)
	if err != nil {
		return err
	}
	p.buf = wire
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	if err := p.conn.Send(ctx, wire); err != nil {
		// A write failure means this operator is gone. Dropping the connection here
		// rather than propagating turns it into a detach, which is the whole point:
		// the reader will notice too, and whichever notices first wins.
		if p.ring != nil {
			p.conn = nil
			p.presentMu.Lock()
			p.present = make(chan struct{})
			p.presentMu.Unlock()
			return nil
		}
		return err
	}
	return nil
}
