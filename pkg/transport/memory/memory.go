// Package memory is an in-process transport.Conn pair.
//
// It exists so the gateway, the agent and the codec can be tested against each
// other with no network, no TLS and no WebSocket — which is what lets the layering
// test prove that nothing above pkg/transport/websocket depends on a WebSocket type.
package memory

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"

	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/transport"
)

type msg struct {
	data []byte
	text bool
}

// pipe is one end of a connected pair.
//
// # No channel is ever closed while it might be sent on
//
// An earlier version signalled closure by closing the peer's inbox, and had a
// recover() in the send path to swallow the resulting "send on closed channel"
// panic. That recover was not defensive programming, it was a real race being
// hidden: closing a channel concurrently with a send on it is undefined, and -race
// found it the moment a test had two senders.
//
// So closure is signalled by closing a *separate* `dead` channel per side, which
// nothing ever sends on, and both Recv and send select on both sides' dead channels.
// Modelling this correctly matters beyond tidiness: a double that diverges from a
// real socket's semantics hides whole classes of bug rather than finding them.
type pipe struct {
	in   chan msg      // messages arriving for this side
	dead chan struct{} // closed when *this* side closes
	peer *pipe
	max  int
	name string

	// binding stands in for RFC 5705 exported keying material. Nil means this pair has
	// no channel to bind to, which is what an in-memory pipe honestly is and what
	// PairBound exists to override.
	binding []byte

	once sync.Once
}

var _ transport.Conn = (*pipe)(nil)

// Pair returns two connected Conns. maxMessageBytes of zero means frame.MaxFrame.
//
// Each direction is buffered by one, so a send followed by a recv on the same
// goroutine works without a second goroutine — which keeps protocol tests readable
// as straight-line code.
func Pair(maxMessageBytes int) (a, b transport.Conn) {
	return PairBound(maxMessageBytes, nil)
}

// PairBound returns two connected Conns that report `binding` as their channel binding.
//
// It exists so the channel-bound handshake can be tested without standing up TLS, and —
// more importantly — so the attack it defends against can be. A TLS-terminating middlebox
// relaying a handshake has *two* TLS sessions and therefore two different exporter values;
// simulating that is two pairs built with two different bindings, which is a thing this
// function makes possible and a real network makes tedious.
//
// A nil binding means no channel, which is what Pair gives and what an in-memory pipe
// truthfully is.
func PairBound(maxMessageBytes int, binding []byte) (a, b transport.Conn) {
	if maxMessageBytes <= 0 {
		maxMessageBytes = frame.MaxFrame
	}
	p := &pipe{in: make(chan msg, 1), dead: make(chan struct{}), max: maxMessageBytes,
		name: "a", binding: binding}
	q := &pipe{in: make(chan msg, 1), dead: make(chan struct{}), max: maxMessageBytes,
		name: "b", binding: binding}
	p.peer, q.peer = q, p
	return p, q
}

// Recv returns the next binary message.
//
// Closing either end unblocks it, which is what a real WebSocket does: closing a
// connection makes your own pending Read return, not only the peer's.
func (p *pipe) Recv(ctx context.Context) ([]byte, error) {
	// Checked before the select, not inside it: select chooses at random among ready
	// cases, so a closed connection with a queued message would sometimes deliver it
	// and sometimes not. A closed conn must be closed every time.
	if closed(p.dead) {
		return nil, transport.ErrClosed
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.dead:
		return nil, transport.ErrClosed
	case <-p.peer.dead:
		// Drain anything already queued before reporting the close, so a message
		// sent immediately before the peer hung up is not lost.
		select {
		case m := <-p.in:
			return p.deliver(m)
		default:
			return nil, transport.ErrClosed
		}
	case m := <-p.in:
		return p.deliver(m)
	}
}

func (p *pipe) deliver(m msg) ([]byte, error) {
	if m.text {
		return nil, transport.ErrTextMessage
	}
	if len(m.data) > p.max {
		return nil, transport.ErrTooLarge
	}
	return m.data, nil
}

func (p *pipe) Send(ctx context.Context, b []byte) error { return p.send(ctx, b, false) }

// SendText injects a text message so the binary-only rule can be exercised without
// standing up a real WebSocket.
func SendText(ctx context.Context, c transport.Conn, b []byte) error {
	p, ok := c.(*pipe)
	if !ok {
		return errors.New("memory: not a memory conn")
	}
	return p.send(ctx, b, true)
}

func (p *pipe) send(ctx context.Context, b []byte, text bool) error {
	// Copy on send. A real transport hands the receiver its own buffer, and a test
	// that shared one would hide aliasing bugs rather than find them.
	cp := make([]byte, len(b))
	copy(cp, b)

	// Same reason as Recv: with both a dead channel and a free buffer slot ready,
	// select would sometimes accept a send on a closed connection.
	if closed(p.dead) || closed(p.peer.dead) {
		return transport.ErrClosed
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.dead:
		return transport.ErrClosed
	case <-p.peer.dead:
		return transport.ErrClosed
	case p.peer.in <- msg{data: cp, text: text}:
		return nil
	}
}

func closed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// Close is idempotent and safe to call concurrently with Send and Recv on either
// end.
func (p *pipe) Close(transport.CloseCode, string) error {
	p.once.Do(func() { close(p.dead) })
	return nil
}

func (p *pipe) RemoteAddr() string { return "memory:" + p.peer.name }

// ChannelBinding returns the pair's binding, mixed with the label so that two different
// labels on one channel do not produce the same bytes — which is the property a real
// exporter has and a test double that ignored the label would not.
func (p *pipe) ChannelBinding(label string, length int) ([]byte, error) {
	if len(p.binding) == 0 {
		return nil, transport.ErrNoChannelBinding
	}
	sum := sha256.Sum256(append([]byte(label+"\x00"), p.binding...))
	if length <= 0 || length > len(sum) {
		length = len(sum)
	}
	return sum[:length], nil
}

var _ transport.ChannelBound = (*pipe)(nil)
