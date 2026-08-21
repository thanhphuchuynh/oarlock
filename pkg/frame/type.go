package frame

// Type is the one-byte frame type that opens every frame.
//
// The high nibble encodes scope, which is not decoration: it is what lets a
// receiver decide what to do with a type it has never heard of. Session-scoped
// types (0x0x) can be skipped, because the worst case is one session missing a
// feature the peer has and it does not. Connection-scoped types (0x1x) cannot,
// because they carry the state the connection itself runs on.
type Type uint8

// Session-scoped frames. These travel on a connection that *is* one session.
const (
	TypeData      Type = 0x01 // raw bytes, the stream
	TypeDataErr   Type = 0x02 // raw bytes on the error channel; exec only
	TypeOpen      Type = 0x03 // JSON: first frame on a session connection
	TypeReady     Type = 0x04 // JSON: both ends present, pump live
	TypeResize    Type = 0x05 // JSON: operator -> device
	TypeSignal    Type = 0x06 // JSON: operator -> device
	TypeExit      Type = 0x07 // JSON: process exited
	TypeClose     Type = 0x08 // JSON: one close reason
	TypeThrottle  Type = 0x09 // JSON: bytes dropped; never on a shell session
	TypeError     Type = 0x0A // JSON: a code from the closed set
	TypeObservers Type = 0x0B // JSON: who else is watching this session
)

// Connection-scoped frames. These travel on the control channel a persistent-mode
// agent holds open, which carries no session traffic at all.
const (
	TypeHello     Type = 0x10 // JSON: agent identity and offered versions
	TypeChallenge Type = 0x11 // JSON: gateway nonce
	TypeAuth      Type = 0x12 // JSON: signature over both nonces
	TypeWelcome   Type = 0x13 // JSON: negotiated version, limits, resume
	TypePing      Type = 0x14 // 8 bytes: monotonic microseconds
	TypePong      Type = 0x15 // 8 bytes: echoed verbatim
	TypeDial      Type = 0x16 // JSON: gateway asks the agent to dial for a session
	TypeCancel    Type = 0x17 // JSON: that invitation is dead, do not dial
	TypeGoAway    Type = 0x18 // JSON: connection is going away
)

// Scope says whether a frame belongs to a session or to the connection.
type Scope uint8

const (
	ScopeSession    Scope = iota // 0x0x
	ScopeConnection              // 0x1x
	ScopeUnknown                 // anything else
)

// Scope is derived from the type byte rather than looked up, so an unknown type
// still has a scope and therefore still has a defined disposition.
func (t Type) Scope() Scope {
	switch t & 0xF0 {
	case 0x00:
		if t == 0 {
			return ScopeUnknown // 0x00 is not a frame type
		}
		return ScopeSession
	case 0x10:
		return ScopeConnection
	default:
		return ScopeUnknown
	}
}

var names = map[Type]string{
	TypeData: "DATA", TypeDataErr: "DATA_ERR", TypeOpen: "OPEN", TypeReady: "READY",
	TypeResize: "RESIZE", TypeSignal: "SIGNAL", TypeExit: "EXIT", TypeClose: "CLOSE",
	TypeThrottle: "THROTTLE", TypeError: "ERROR", TypeObservers: "OBSERVERS",
	TypeHello: "HELLO", TypeChallenge: "CHALLENGE", TypeAuth: "AUTH", TypeWelcome: "WELCOME",
	TypePing: "PING", TypePong: "PONG", TypeDial: "DIAL", TypeCancel: "CANCEL",
	TypeGoAway: "GOAWAY",
}

// Known reports whether this build understands the type.
func (t Type) Known() bool { _, ok := names[t]; return ok }

func (t Type) String() string {
	if n, ok := names[t]; ok {
		return n
	}
	const hex = "0123456789abcdef"
	return "Type(0x" + string([]byte{hex[t>>4], hex[t&0x0F]}) + ")"
}

// IsRaw reports whether the payload is opaque bytes rather than JSON. Terminal
// traffic is binary, and a JSON envelope would put base64 on the one path where
// volume and latency matter.
func (t Type) IsRaw() bool {
	switch t {
	case TypeData, TypeDataErr, TypePing, TypePong:
		return true
	}
	return false
}

// Universal reports whether a frame is valid on either kind of connection.
//
// Three are, and the common thread is that they are about the *connection* rather
// than about what the connection carries:
//
//   - ERROR explains why a connection is about to end. A control-channel handshake
//     that fails has to be able to say why; scoping it to sessions only — where it
//     was first specified — left a rejected agent with nothing but "the socket
//     closed", unable to tell "no shared protocol version" from "your key is wrong".
//   - PING and PONG establish that a peer is gone rather than quiet. A control
//     channel idle for an hour still has to be known to be alive, and so does a
//     session where nobody is typing.
//
// Everything else belongs to exactly one connection kind, and arriving on the wrong
// one closes it.
func (t Type) Universal() bool {
	switch t {
	case TypeError, TypePing, TypePong:
		return true
	}
	return false
}

// Disposition is what a receiver does with a frame it cannot handle.
type Disposition uint8

const (
	// Handle: the type is known to this build.
	Handle Disposition = iota
	// Ignore: unknown, session-scoped. Skip it and count it. This is what makes
	// additive protocol changes possible without a version bump.
	Ignore
	// CloseConnection: unknown or malformed at connection scope. Strictness here
	// is deliberate — guessing about connection state is worse than reconnecting.
	CloseConnection
)

// Disposition answers the only question that matters about an unrecognised frame,
// without the caller needing a table of its own.
func (t Type) Disposition() Disposition {
	if t.Known() {
		return Handle
	}
	if t.Scope() == ScopeSession {
		return Ignore
	}
	return CloseConnection
}
