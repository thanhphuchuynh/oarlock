// Package frame implements the Oarlock wire codec: one byte of type, then the
// payload. That is the whole header.
//
// # There is no length field, and no stream id
//
// A frame occupies exactly one binary WebSocket message, so the message boundary
// *is* the frame boundary. Nothing in a frame tells the decoder how long anything
// is, which means no peer can claim a length it does not intend to send and make
// the decoder allocate on the strength of the claim. Decode does not allocate at
// all: payloads alias the caller's buffer.
//
// There is no stream id because Oarlock does not multiplex. A connection is either
// one session or the control channel, never several sessions at once:
//
//   - A **session connection** carries 0x0x frames. The agent dials one per
//     session, in both reachability modes.
//   - A **control channel** carries 0x1x frames. A persistent-mode agent holds one
//     open; it is the doorbell and nothing else, so no session traffic crosses it.
//
// Multiplexing was specified and then removed (ADR-024). Adopting an established
// multiplexer would have meant wrapping the WebSocket as a byte stream, which puts
// length-prefixed framing back inside it and hands back the allocation surface
// this format exists to remove. Hand-rolling one meant owning a flow-control
// protocol. Not multiplexing costs a TLS handshake per session — against a warm
// control channel, for sessions that are rare and short — and deletes both.
//
// # Stability
//
// Wire version v0, unstable. This package is public API, so a change here is a
// change third-party agents feel. Additive changes — a new type, a new optional
// JSON field — do not bump the version: unknown session-scoped types are ignored
// and unknown JSON fields are dropped. Anything that changes the meaning of an
// existing frame does bump it.
package frame

import (
	"errors"
	"fmt"
)

// Wire limits. These are chosen as one set with the throughput limits in
// ARCHITECTURE § 9.3 rather than independently, which is how a spec ends up with a
// 1 MiB ceiling on a 256 KiB/s stream and no way to tell which number is wrong.
const (
	// MaxFrame is the protocol-wide ceiling for any single frame. DATA never
	// approaches it — MaxBatch binds first — so a frame at this size is a bug or an
	// attack, never traffic.
	MaxFrame = 1 << 20 // 1 MiB

	// MaxBatch is the ceiling on one coalesced DATA frame. A 25 ms window at the
	// sustained rate holds roughly 6.5 KiB; this sits an order of magnitude above so
	// that a burst — a full-screen redraw, a dmesg dump — travels in one frame
	// instead of ten.
	MaxBatch = 64 << 10 // 64 KiB

	// HeaderLen is the entire header: one type byte.
	HeaderLen = 1
)

// Errors returned by Decode and Encode. Each maps to a wire error code from
// docs/protocol.md § 6 via ErrorCode.
var (
	ErrEmpty      = errors.New("frame: empty message")
	ErrTooLarge   = errors.New("frame: exceeds MaxFrame")
	ErrBadType    = errors.New("frame: 0x00 is not a frame type")
	ErrPayloadLen = errors.New("frame: payload has the wrong fixed length")
	ErrWrongChan  = errors.New("frame: frame is on the wrong kind of connection")
)

// ErrorCode maps a decode failure to the wire code an ERROR frame or an API
// response should carry, so one vocabulary covers the wire and the HTTP surface.
func ErrorCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrTooLarge):
		return "frame_too_large"
	default:
		return "protocol_error"
	}
}

// Frame is one decoded frame.
//
// Payload aliases the buffer Decode was given. It is valid only until that buffer
// is reused, which for a transport recycling read buffers means until the next
// Recv. Anything that outlives the read must Clone.
type Frame struct {
	Type Type
	// Payload is raw bytes for DATA, DATA_ERR, PING and PONG, and JSON otherwise.
	Payload []byte
}

// Clone returns a Frame that owns its payload. Call it when a frame outlives the
// read buffer it came from — queueing it, spooling it, keeping it for a retry.
func (f Frame) Clone() Frame {
	if f.Payload == nil {
		return f
	}
	p := make([]byte, len(f.Payload))
	copy(p, f.Payload)
	f.Payload = p
	return f
}

func (f Frame) String() string {
	return fmt.Sprintf("%s(%d bytes)", f.Type, len(f.Payload))
}

// Codec encodes and decodes frames for one connection. The zero Codec is valid
// and uses MaxFrame.
type Codec struct {
	// MaxFrameBytes overrides MaxFrame. Zero means MaxFrame. A transport should
	// also enforce this so an oversized message is refused before it is buffered;
	// the check here is the second line, not the first.
	MaxFrameBytes int
}

func (c Codec) maxFrame() int {
	if c.MaxFrameBytes > 0 {
		return c.MaxFrameBytes
	}
	return MaxFrame
}

// Decode parses one binary message. It never allocates: the returned payload
// aliases msg.
//
// Decode is structural only. It validates framing and says nothing about whether a
// payload means anything, because a decoder that also validates semantics is a
// decoder with a second place for bugs to hide. Unknown types decode successfully;
// ask Type.Disposition what to do with them, and Expect whether the frame belongs
// on this connection at all.
func (c Codec) Decode(msg []byte) (Frame, error) {
	if len(msg) == 0 {
		return Frame{}, ErrEmpty
	}
	if len(msg) > c.maxFrame() {
		return Frame{}, fmt.Errorf("%w: %d bytes", ErrTooLarge, len(msg))
	}
	f := Frame{Type: Type(msg[0])}
	if f.Type == 0 {
		return Frame{}, ErrBadType
	}
	if len(msg) > HeaderLen {
		f.Payload = msg[HeaderLen:]
	}
	return f, nil
}

// Encode appends one frame to dst and returns the extended slice, so a sender can
// reuse one buffer for the life of a connection. Pass nil for a fresh slice.
func (c Codec) Encode(dst []byte, f Frame) ([]byte, error) {
	if f.Type == 0 {
		return dst, ErrBadType
	}
	if total := HeaderLen + len(f.Payload); total > c.maxFrame() {
		return dst, fmt.Errorf("%w: %d bytes", ErrTooLarge, total)
	}
	dst = append(dst, byte(f.Type))
	return append(dst, f.Payload...), nil
}

// Expect reports whether a frame belongs on this kind of connection.
//
// A session frame arriving up the control channel, or a DIAL arriving down a
// session connection, means the peer is confused about which connection it is
// holding. That is a connection-level fault: there is no sane per-frame recovery,
// because whatever state the peer thinks it has does not exist.
//
// ERROR is exempt, because it is how a peer explains itself on the way out.
func Expect(want Scope, f Frame) error {
	if f.Type.Universal() {
		return nil
	}
	got := f.Type.Scope()
	if got == want {
		return nil
	}
	// An unknown session-scoped type on a control channel is still wrong, but the
	// Disposition rules decide whether to skip or close; report the mismatch and
	// let the caller combine the two.
	return fmt.Errorf("%w: %s is %s, connection carries %s",
		ErrWrongChan, f.Type, scopeName(got), scopeName(want))
}

func scopeName(s Scope) string {
	switch s {
	case ScopeSession:
		return "session-scoped"
	case ScopeConnection:
		return "connection-scoped"
	default:
		return "unscoped"
	}
}

// Overhead is the bytes this codec adds per frame.
func (c Codec) Overhead() int { return HeaderLen }
