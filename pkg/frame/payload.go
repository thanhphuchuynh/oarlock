package frame

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
)

// Control-frame payloads. Every one of these is JSON, because control frames
// happen a handful of times per session and readable beats compact when you are
// debugging a handshake at 2 a.m.
//
// Unknown JSON fields are dropped rather than rejected: that is what makes a new
// optional field an additive change instead of a version bump. Do not add
// DisallowUnknownFields here — it would make every field addition breaking.

// PTY is a terminal's shape and type. Term matters more than it looks: a PTY
// told TERM=dumb will not emit the sequences a browser terminal renders, and one
// told xterm-256color when the client is not will emit sequences it cannot.
type PTY struct {
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
	Term string `json:"term,omitempty"`
}

// AgentInfo identifies the agent build, for logs and for refusing a session a
// given build cannot serve.
type AgentInfo struct {
	Version  string `json:"version"`
	Platform string `json:"platform,omitempty"` // e.g. "android/34", "linux/6.6"
	Arch     string `json:"arch,omitempty"`
}

// Limits are the wire-visible limits the gateway tells a peer about in WELCOME,
// so an agent sizes its buffers from the gateway's numbers rather than its own.
type Limits struct {
	Frame        int `json:"frame,omitempty"`         // bytes
	Batch        int `json:"batch,omitempty"`         // bytes, one coalesced DATA
	Rate         int `json:"rate,omitempty"`          // bytes/second, sustained
	PingInterval int `json:"ping_interval,omitempty"` // seconds
}

// Open is the first frame on a connection that is itself one session.
type Open struct {
	Ticket   string    `json:"ticket"`
	DeviceID string    `json:"device_id,omitempty"`
	Profile  string    `json:"profile"`
	PTY      *PTY      `json:"pty,omitempty"`
	Agent    AgentInfo `json:"agent,omitzero"`
}

// Ready says both ends are present and the pump is live. Recording and Mode are
// here so a client can say which it is out loud: a session the gateway cannot
// read must be visibly different from one it can.
type Ready struct {
	SessionID     string  `json:"session_id"`
	ScrollbackLen int     `json:"scrollback_len"`
	Recording     bool    `json:"recording"`
	Mode          string  `json:"mode"` // "gateway" | "passthrough"
	Limits        *Limits `json:"limits,omitempty"`

	// Observers is who is already watching. Carried here as well as in OBSERVERS
	// because an operator who attaches to a session that is already being watched must
	// not have to wait for the list to change before being told.
	Observers []Observer `json:"observers,omitempty"`

	// ReadOnly says this connection cannot write. Sent to an observer, so their client
	// disables input rather than accepting keystrokes it will silently drop.
	ReadOnly bool `json:"read_only,omitempty"`

	// Watching is who the observer is watching, for their own chrome.
	Watching string `json:"watching,omitempty"`
}

// Resize carries a window change. Coalesce to at most one per 100 ms: dragging a
// browser edge generates hundreds of events and the PTY needs only the last.
type Resize struct {
	Cols int `json:"cols"`
	Rows int `json:"rows"`
}

// Signal is the SSH signal channel request, and a browser's stop button. It is
// not interactive Ctrl-C — that is byte 0x03 inside DATA, interpreted by the
// device's line discipline.
type Signal struct {
	Signal string `json:"signal"` // INT TERM QUIT HUP KILL USR1 USR2 WINCH
}

// Exit reports how the process ended. The exec profile needs this to mean
// anything at all.
type Exit struct {
	Code   int     `json:"code"`
	Signal *string `json:"signal"`
}

// Close carries one close reason from the closed set in ARCHITECTURE § 6.
type Close struct {
	Reason string `json:"reason"`
}

// Throttle reports dropped bytes. Sent only for profiles whose policy is to
// drop. Never on a shell stream: shell backpressures instead, and a THROTTLE
// there is a gateway bug — a dropped chunk landing mid escape sequence leaves the
// terminal corrupt until a full redraw, and a marker cannot repair it.
type Throttle struct {
	DroppedBytes int64  `json:"dropped_bytes"`
	Profile      string `json:"profile,omitempty"`
}

// Observer is somebody watching a session read-only.
//
// Named, always. Anonymous observation is not offered at any level: an operator is
// entitled to know *who* is watching, not merely that somebody is, and a UI that could
// only say "1 watcher" would be a UI that had thrown the answer away.
type Observer struct {
	Principal string `json:"principal"`
	// Since is RFC 3339, so "watched since before I ran that" is answerable.
	Since string `json:"since,omitempty"`
}

// Observers is the current watcher list, sent to the operator being watched whenever it
// changes.
//
// The whole list rather than a join/leave delta: a client that missed one frame would
// otherwise show a watcher who has left, or miss one who arrived, and be wrong about the
// one fact this frame exists to convey. An empty list means nobody, and is sent — the
// indicator has to be able to go away.
type Observers struct {
	Observers []Observer `json:"observers"`
}

// Error carries a code from the closed set. Code is what a UI switches on;
// Message is for humans and logs and is never parsed.
type Error struct {
	Code      string `json:"code"`
	Message   string `json:"message,omitempty"`
	Retryable bool   `json:"retryable"`
}

// Hello opens the persistent handshake. Versions is a list and WELCOME names the
// single one chosen; an agent offering nothing the gateway knows is closed with
// version_unsupported, which beats a mysterious parse error six frames later.
//
// Caps is how a device says what it can actually do. An agent built without a
// PTY omits "shell", and the gateway then refuses at open time with a real
// reason instead of after a round trip.
type Hello struct {
	DeviceID string    `json:"device_id"`
	Versions []int     `json:"versions"`
	NonceC   string    `json:"nonce_c"`
	Caps     []string  `json:"caps,omitempty"`
	Agent    AgentInfo `json:"agent,omitzero"`
}

// Challenge is the gateway's half of the nonce. GatewayID is inside the signed
// blob so a signature captured by one gateway cannot be replayed to another.
type Challenge struct {
	NonceS    string `json:"nonce_s"`
	GatewayID string `json:"gateway_id"`
}

// Auth carries the signature over nonce_s ‖ nonce_c ‖ device_id ‖ gateway_id.
type Auth struct {
	Sig string `json:"sig"` // base64url
}

// Resume names live sessions the gateway is still holding for this device, so a
// reconnecting agent can dial back for each one instead of losing the operator's
// shell. A device on cellular loses its socket regularly, and a shell that dies
// with the radio is a shell nobody trusts with a long command.
//
// Without multiplexing, resuming is just dialling again: the agent receives one
// Invitation per session it should re-establish.
type Resume struct {
	Sessions []Invitation `json:"sessions,omitempty"`
}

// Welcome closes the control-channel handshake with the negotiated version and
// limits. There is no mux flag to negotiate: Oarlock does not multiplex (ADR-024).
type Welcome struct {
	Version   int     `json:"version"`
	GatewayID string  `json:"gateway_id,omitempty"`
	Limits    *Limits `json:"limits,omitempty"`
	Resume    *Resume `json:"resume,omitempty"`
}

// Invitation tells an agent to dial back for one session. It is the single shape
// both reachability modes deliver, which is the point of not multiplexing: in
// persistent mode it arrives as a DIAL frame down the control channel, and in
// dispatch mode a Dispatcher carries the identical payload over MQTT, a webhook or
// an exec. Downstream of arrival there is one code path.
//
// URL names a specific gateway node rather than a load balancer. That is what lets
// a multi-node deployment work without node-to-node forwarding: whichever node the
// operator is waiting on is the node named here.
//
// Principal is passed so the agent can log who is on it. It is not an
// authorisation input — the agent trusts the gateway completely and cannot check
// anything itself. Do not gate on it.
type Invitation struct {
	SessionID string   `json:"session_id"`
	Ticket    string   `json:"ticket"`
	URL       string   `json:"url"`
	Profile   string   `json:"profile"`
	PTY       *PTY     `json:"pty,omitempty"`
	Exec      []string `json:"exec,omitempty"`
	File      *FileOp  `json:"file,omitempty"`
	Principal string   `json:"principal,omitempty"`
	ExpiresAt string   `json:"expires_at,omitempty"` // RFC 3339
}

// FileOp is one file operation, for the `file` profile.
//
// The path travels in the invitation rather than in a request frame, for the same reason
// the exec argv does: the ticket is scoped to a profile *and* to what was authorised, so a
// session cannot be repurposed after it opens. One session is one file.
type FileOp struct {
	// Op is "read" or "write".
	Op string `json:"op"`
	// Path is relative to the device's configured root. Absolute paths and anything
	// escaping the root are refused by the device, which is the side that knows where
	// its root is.
	Path string `json:"path"`
	// Size is the exact byte count for a write.
	//
	// Known up front rather than signalled by an end-of-stream marker, because the
	// frame vocabulary has no operator-side "I am done" and CLOSE means the session is
	// over. A device that knows the size can also refuse before it starts, and a
	// transfer that delivers fewer bytes is detectably incomplete rather than silently
	// truncated.
	Size int64 `json:"size,omitempty"`
	// Mode is the permission bits for a created file. Zero means 0o600 — a file written
	// by a remote operator should not be world-readable because nobody said otherwise.
	Mode uint32 `json:"mode,omitempty"`
}

// Cancel withdraws an invitation. Without it a device that woke slowly would dial
// for a session nobody is waiting on any more, spend a ticket, and be told to go
// away — which looks like a bug from the device's side and costs a handshake.
type Cancel struct {
	SessionID string `json:"session_id"`
	Reason    string `json:"reason,omitempty"`
}

// GoAway announces the connection is going away. ReconnectAfterMS is jittered
// per agent during a drain: without it every agent in the fleet reconnects at the
// same instant and the replacement pod dies of the herd.
type GoAway struct {
	Reason           string `json:"reason"`
	ReconnectAfterMS int    `json:"reconnect_after_ms,omitempty"`
}

// Marshal builds a control frame. Use it for anything but DATA, DATA_ERR, PING
// and PONG, whose payloads are raw bytes.
func Marshal(t Type, v any) (Frame, error) {
	if t.IsRaw() {
		return Frame{}, fmt.Errorf("frame: %s carries raw bytes, not JSON", t)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return Frame{}, fmt.Errorf("frame: marshal %s: %w", t, err)
	}
	return Frame{Type: t, Payload: b}, nil
}

// Unmarshal decodes a control frame's payload into v.
func Unmarshal(f Frame, v any) error {
	if f.Type.IsRaw() {
		return fmt.Errorf("frame: %s carries raw bytes, not JSON", f.Type)
	}
	if len(f.Payload) == 0 {
		return fmt.Errorf("frame: %s has an empty payload", f.Type)
	}
	if err := json.Unmarshal(f.Payload, v); err != nil {
		return fmt.Errorf("frame: unmarshal %s: %w", f.Type, err)
	}
	return nil
}

// Stamp builds a PING or PONG. The payload is a monotonic timestamp in
// microseconds, echoed verbatim, which drives the latency readout, holds ingress
// idle timeouts off, and tells a peer that is gone from one that is merely quiet.
func Stamp(t Type, micros uint64) (Frame, error) {
	if t != TypePing && t != TypePong {
		return Frame{}, fmt.Errorf("frame: %s is not PING or PONG", t)
	}
	p := make([]byte, 8)
	binary.BigEndian.PutUint64(p, micros)
	return Frame{Type: t, Payload: p}, nil
}

// ReadStamp reads a PING or PONG payload. The fixed length is checked here
// rather than in Decode, which stays structural.
func ReadStamp(f Frame) (uint64, error) {
	if f.Type != TypePing && f.Type != TypePong {
		return 0, fmt.Errorf("frame: %s is not PING or PONG", f.Type)
	}
	if len(f.Payload) != 8 {
		return 0, fmt.Errorf("%w: %s has %d bytes, want 8", ErrPayloadLen, f.Type, len(f.Payload))
	}
	return binary.BigEndian.Uint64(f.Payload), nil
}

// Data builds a DATA frame aliasing b. It does not copy: the caller keeps
// ownership until the frame is written.
func Data(b []byte) Frame { return Frame{Type: TypeData, Payload: b} }

// DataErr builds a DATA_ERR frame aliasing b.
func DataErr(b []byte) Frame { return Frame{Type: TypeDataErr, Payload: b} }
