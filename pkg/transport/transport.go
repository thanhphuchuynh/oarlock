// Package transport is the seam between Oarlock's framing and whatever moves the
// bytes.
//
// # Why this interface exists
//
// WebSocket is the only implementation today and the right one: 99 %+ browser
// support, mature tooling, and WebSocket-over-HTTP/3 has no browser implementation
// to wait for. WebTransport reached Baseline in March 2026 and is the likely
// successor; its native QUIC streams would also let one connection carry several
// sessions again, which Oarlock deliberately does not do today (ADR-024).
//
// So the point of this package is not portability for its own sake. It is that
// adopting WebTransport later should *remove* code rather than add a second
// protocol. Nothing above this package may name a WebSocket type; a test in this
// package enforces that by walking the imports.
package transport

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// Errors a transport returns. Every one maps to a wire code in
// docs/protocol.md § 6 via Code.
var (
	// ErrTextMessage means the peer sent a text frame. Every Oarlock frame is
	// binary; a text frame is a protocol error, not something to coerce.
	ErrTextMessage = errors.New("transport: text message on a binary protocol")

	// ErrTooLarge means the peer sent a message over the read limit. A transport
	// must refuse it *without* buffering it — the limit is a defence against an
	// allocation, so enforcing it after allocating would be theatre.
	ErrTooLarge = errors.New("transport: message exceeds the read limit")

	ErrClosed = errors.New("transport: connection closed")
)

// Code maps a transport error to the wire error code to report.
func Code(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrTooLarge):
		return "frame_too_large"
	case errors.Is(err, ErrTextMessage):
		return "protocol_error"
	default:
		return "internal"
	}
}

// CloseCode is why we are closing, expressed independently of any transport's
// own numbering so that mapping stays inside the implementation.
type CloseCode uint8

const (
	CloseNormal CloseCode = iota
	CloseGoingAway
	CloseProtocolError
	ClosePolicyViolation
	CloseTooLarge
	CloseInternal
)

func (c CloseCode) String() string {
	switch c {
	case CloseNormal:
		return "normal"
	case CloseGoingAway:
		return "going_away"
	case CloseProtocolError:
		return "protocol_error"
	case ClosePolicyViolation:
		return "policy_violation"
	case CloseTooLarge:
		return "too_large"
	default:
		return "internal"
	}
}

// Conn is a bidirectional, message-oriented connection.
//
// Message boundaries are preserved and are load-bearing: one message is exactly
// one frame, which is why the frame format needs no length field and Decode never
// allocates. A transport that cannot preserve boundaries cannot implement this
// interface without adding a length prefix — and that would hand back the
// allocation surface the framing was designed to remove. It is also why Oarlock
// does not wrap this in a stream multiplexer: every such library wants a byte
// stream, and turning messages back into bytes is exactly the trade this refuses.
type Conn interface {
	// Recv returns the next binary message. The returned slice is valid until
	// the next Recv on this connection: a transport may recycle read buffers, so
	// anything outliving the call must be copied (see frame.Frame.Clone).
	//
	// A text message returns ErrTextMessage. Oversized returns ErrTooLarge.
	Recv(ctx context.Context) ([]byte, error)

	// Send writes one binary message. Send may be called concurrently with Recv
	// but not with itself.
	Send(ctx context.Context, b []byte) error

	// Close closes with a reason. It is safe to call more than once.
	Close(code CloseCode, reason string) error

	// RemoteAddr is for logs and rate limiting. It may be empty.
	RemoteAddr() string
}

// Options configure a connection. MaxMessageBytes must be enforced by the
// implementation at read time.
type Options struct {
	// MaxMessageBytes caps an inbound message. Zero means frame.MaxFrame.
	MaxMessageBytes int

	// HandshakeTimeout bounds connection setup. Zero means 10s.
	HandshakeTimeout time.Duration

	// Subprotocol is the negotiated subprotocol, e.g. "oarlock.v0".
	Subprotocol string

	// Header carries request headers on dial. Never put a ticket here: a ticket
	// belongs in the OPEN frame body, because headers and query strings end up in
	// ingress logs, load-balancer logs and browser history.
	Header http.Header

	// PinSHA256 is a list of base64 SHA-256 SubjectPublicKeyInfo pins. Non-empty
	// means the server certificate must match one. The reference agent pins by
	// default. It is the earlier and weaker of the two defences against a
	// TLS-terminating middlebox — the other being the channel binding below, which the
	// handshake mixes into what the device signs.
	PinSHA256 []string
}

// Dialer opens outbound connections. Both legs of the data plane are dialed
// outward — the device to the gateway, the browser to the gateway — so the only
// public listener stays the one that is already there.
type Dialer interface {
	Dial(ctx context.Context, url string, opts Options) (Conn, error)
}

// Upgrader turns an inbound HTTP request into a Conn. net/http is stdlib, so
// naming it here leaks nothing about which transport is underneath.
type Upgrader interface {
	Upgrade(w http.ResponseWriter, r *http.Request, opts Options) (Conn, error)
}

// ── channel binding ─────────────────────────────────────────────────────────────

// ErrNoChannelBinding means this connection has no encrypted channel to bind to, or the
// one it has cannot export keying material.
//
// It is not a failure. An in-memory pipe has no channel, and a development gateway on
// `ws://` has no encryption to bind to — both are legitimate, and the caller decides
// whether to proceed. What is not legitimate is treating it as *permission* to skip the
// check: see the note on ChannelBound.
var ErrNoChannelBinding = errors.New("transport: no channel binding available")

// ChannelBound is implemented by a transport that can bind a handshake to the encrypted
// channel underneath it.
//
// # Why this is asserted for rather than added to Conn
//
// Five of the seven Conn implementations in this repository are not network connections
// at all — an SSH channel adapter, an HTTP request body, an in-memory pipe — and have no
// channel to bind to. Making each of them carry a method that returns an error would be
// worse than a type assertion here, which is the same trade plugin.InteractiveAuthenticator
// makes for the same reason.
//
// # Why the caller cannot treat absence as permission
//
// A handshake bound to the channel is what stops a TLS-terminating middlebox from relaying
// it: the relay's two TLS sessions export different keying material, so a signature made
// over one does not verify over the other. That protection evaporates the moment a peer can
// say "I have no binding" and be believed — which is exactly what an attacker in the middle
// would say.
//
// So the decision is a *policy* on each side and not a property of the connection.
// internal/handshake requires binding when it is configured to, and refuses the handshake
// when it cannot have it — rather than asking the connection and accepting the answer.
type ChannelBound interface {
	// ChannelBinding returns RFC 5705 exported keying material for label, or
	// ErrNoChannelBinding.
	//
	// The label is the caller's domain separation, and the same label on two different
	// connections must not produce the same bytes — which is what makes the value
	// identify *this* channel rather than merely being a shared secret.
	ChannelBinding(label string, length int) ([]byte, error)
}

// Binding is ChannelBinding on conn when it supports it, and ErrNoChannelBinding when it
// does not — so a caller needs one branch rather than two.
func Binding(conn Conn, label string, length int) ([]byte, error) {
	cb, ok := conn.(ChannelBound)
	if !ok {
		return nil, ErrNoChannelBinding
	}
	return cb.ChannelBinding(label, length)
}
