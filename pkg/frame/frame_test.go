package frame

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// allTypes is every type this build knows. The round-trip test walks it, so a new
// frame type added without a test is a visible omission rather than a silent one.
var allTypes = []Type{
	TypeData, TypeDataErr, TypeOpen, TypeReady, TypeResize, TypeSignal,
	TypeExit, TypeClose, TypeThrottle, TypeError, TypeObservers,
	TypeHello, TypeChallenge, TypeAuth, TypeWelcome, TypePing, TypePong,
	TypeDial, TypeCancel, TypeGoAway,
}

func TestTypeTableIsComplete(t *testing.T) {
	if len(allTypes) != len(names) {
		t.Fatalf("allTypes has %d entries, names has %d — a type was added without a test",
			len(allTypes), len(names))
	}
	for _, ty := range allTypes {
		if !ty.Known() {
			t.Errorf("%v is in allTypes but not in names", ty)
		}
		if ty.Scope() == ScopeUnknown {
			t.Errorf("%v has no scope", ty)
		}
	}
}

// TestNoMultiplexingRemains guards ADR-024. If a stream id ever comes back, the
// header grows, Decode's zero-allocation property comes under pressure, and the
// two reachability modes stop converging on one data path.
func TestNoMultiplexingRemains(t *testing.T) {
	if HeaderLen != 1 {
		t.Fatalf("HeaderLen is %d; the header is one type byte and nothing else", HeaderLen)
	}
	wire, err := Codec{}.Encode(nil, Data([]byte("x")))
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) != 2 {
		t.Fatalf("a one-byte payload encodes to %d bytes, want 2", len(wire))
	}
}

func TestRoundTrip(t *testing.T) {
	payload := []byte("logcat: something went wrong\r\n")
	c := Codec{}
	for _, ty := range allTypes {
		in := Frame{Type: ty, Payload: payload}
		wire, err := c.Encode(nil, in)
		if err != nil {
			t.Fatalf("%v: encode: %v", ty, err)
		}
		if got, want := len(wire), HeaderLen+len(payload); got != want {
			t.Errorf("%v: wire is %d bytes, want %d", ty, got, want)
		}
		out, err := c.Decode(wire)
		if err != nil {
			t.Fatalf("%v: decode: %v", ty, err)
		}
		if out.Type != in.Type || !bytes.Equal(out.Payload, in.Payload) {
			t.Errorf("round trip changed %v -> %v", in, out)
		}
	}
}

func TestEmptyPayloadRoundTrips(t *testing.T) {
	// A bare header is legal: a PING with no stamp, a CANCEL with no reason.
	c := Codec{}
	wire, err := c.Encode(nil, Frame{Type: TypeCancel})
	if err != nil {
		t.Fatal(err)
	}
	f, err := c.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Payload) != 0 {
		t.Errorf("payload is %d bytes, want 0", len(f.Payload))
	}
}

func TestDecodeRejects(t *testing.T) {
	tests := []struct {
		name string
		msg  []byte
		want error
	}{
		{"empty", nil, ErrEmpty},
		{"type 0x00", []byte{0x00, 'x'}, ErrBadType},
		{"over the ceiling", append([]byte{byte(TypeData)}, make([]byte, MaxFrame)...), ErrTooLarge},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := (Codec{}).Decode(tc.msg); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestEncodeRejects(t *testing.T) {
	if _, err := (Codec{}).Encode(nil, Frame{Type: 0}); !errors.Is(err, ErrBadType) {
		t.Errorf("type 0: got %v, want ErrBadType", err)
	}
	big := Frame{Type: TypeData, Payload: make([]byte, MaxFrame)}
	if _, err := (Codec{}).Encode(nil, big); !errors.Is(err, ErrTooLarge) {
		t.Errorf("oversize: got %v, want ErrTooLarge", err)
	}
	// A tighter per-connection ceiling must be honoured, so a peer that advertised
	// a smaller limit in WELCOME is not sent something it will drop.
	if _, err := (Codec{MaxFrameBytes: 4}).Encode(nil, Data([]byte("hello"))); !errors.Is(err, ErrTooLarge) {
		t.Errorf("negotiated ceiling ignored: %v", err)
	}
}

// TestExpectSeparatesTheTwoConnections is the acceptance criterion for the shape
// that replaced multiplexing: a connection is one session or the control channel,
// and a frame from the wrong family is a connection-level fault.
func TestExpectSeparatesTheTwoConnections(t *testing.T) {
	sessionFrame := Frame{Type: TypeData}
	controlFrame := Frame{Type: TypeDial}

	if err := Expect(ScopeSession, sessionFrame); err != nil {
		t.Errorf("DATA on a session connection: %v", err)
	}
	if err := Expect(ScopeConnection, controlFrame); err != nil {
		t.Errorf("DIAL on a control channel: %v", err)
	}
	if err := Expect(ScopeSession, controlFrame); !errors.Is(err, ErrWrongChan) {
		t.Errorf("DIAL down a session connection: got %v, want ErrWrongChan", err)
	}
	if err := Expect(ScopeConnection, sessionFrame); !errors.Is(err, ErrWrongChan) {
		t.Errorf("DATA up a control channel: got %v, want ErrWrongChan", err)
	}
	// Three frames are valid on either connection kind, and the common thread is
	// that they are about the connection rather than what it carries: ERROR explains
	// why one is ending, and PING/PONG establish that a peer is gone rather than
	// quiet. Both facts are needed on a control channel *and* on a session.
	universal := map[Type]bool{TypeError: true, TypePing: true, TypePong: true}
	for ty := range universal {
		if !ty.Universal() {
			t.Errorf("%v must be universal", ty)
		}
		for _, scope := range []Scope{ScopeSession, ScopeConnection} {
			if err := Expect(scope, Frame{Type: ty}); err != nil {
				t.Errorf("%v rejected on %v: %v", ty, scopeName(scope), err)
			}
		}
	}
	for _, ty := range allTypes {
		if !universal[ty] && ty.Universal() {
			t.Errorf("%v claims to be universal; only ERROR, PING and PONG may", ty)
		}
	}

	// The message must name both sides, because "wrong channel" without saying
	// which is a log line that costs an hour.
	err := Expect(ScopeSession, controlFrame)
	if !strings.Contains(err.Error(), "DIAL") || !strings.Contains(err.Error(), "session-scoped") {
		t.Errorf("unhelpful message: %v", err)
	}
}

// TestUnknownTypeDisposition is the acceptance criterion for forward
// compatibility: a session-scoped type we have never seen is skipped, and a
// connection-scoped one closes the connection.
func TestUnknownTypeDisposition(t *testing.T) {
	tests := []struct {
		ty   Type
		want Disposition
	}{
		{TypeData, Handle},
		{TypeWelcome, Handle},
		{TypeObservers, Handle},
		{0x0F, Ignore},
		// 0x0B was the stand-in for "an unknown session-scoped type" until OBSERVERS
		// took it. The property being tested is the taxonomy, not the number.
		{0x0E, Ignore},
		{0x19, CloseConnection}, // the retired WINDOW type is now simply unknown
		{0x1F, CloseConnection},
		{0x42, CloseConnection},
		{0xFF, CloseConnection},
	}
	for _, tc := range tests {
		if got := tc.ty.Disposition(); got != tc.want {
			t.Errorf("%v: disposition %v, want %v", tc.ty, got, tc.want)
		}
	}

	// An unknown type still decodes: refusing to would make the frame
	// undeliverable to the code that decides to ignore it.
	f, err := Codec{}.Decode([]byte{0x0F, 'h', 'i'})
	if err != nil {
		t.Fatalf("unknown session type failed to decode: %v", err)
	}
	if string(f.Payload) != "hi" {
		t.Errorf("unknown type decoded to %v", f)
	}
}

// TestDecodeDoesNotAllocate guards the property the whole framing exists for: no
// peer can make the decoder allocate. If this starts failing, something introduced
// a copy or a length-driven make() on the hot path.
func TestDecodeDoesNotAllocate(t *testing.T) {
	c := Codec{}
	wire, err := c.Encode(nil, Data(bytes.Repeat([]byte("x"), 4096)))
	if err != nil {
		t.Fatal(err)
	}
	allocs := testing.AllocsPerRun(200, func() {
		if _, err := c.Decode(wire); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 0 {
		t.Errorf("Decode allocated %.1f times per call, want 0", allocs)
	}
}

// TestDecodeAliases pins the documented contract that a payload points into the
// caller's buffer. It is why Decode does not allocate, and why anything outliving
// the read must Clone.
func TestDecodeAliases(t *testing.T) {
	c := Codec{}
	wire, err := c.Encode(nil, Data([]byte("abc")))
	if err != nil {
		t.Fatal(err)
	}
	f, err := c.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	if &f.Payload[0] != &wire[HeaderLen] {
		t.Fatal("payload was copied; Decode must alias its input")
	}
	wire[HeaderLen] = 'z'
	if string(f.Payload) != "zbc" {
		t.Errorf("payload %q does not track the buffer", f.Payload)
	}
	cl := f.Clone()
	wire[HeaderLen] = 'q'
	if string(cl.Payload) != "zbc" {
		t.Errorf("Clone %q still aliases the buffer", cl.Payload)
	}
}

func TestEncodeReusesBuffer(t *testing.T) {
	c := Codec{}
	buf := make([]byte, 0, 512)
	for i := range 4 {
		var err error
		buf, err = c.Encode(buf[:0], Data([]byte{byte('a' + i)}))
		if err != nil {
			t.Fatal(err)
		}
		if len(buf) != 2 {
			t.Fatalf("iteration %d: buffer is %d bytes, want 2", i, len(buf))
		}
	}
	if cap(buf) != 512 {
		t.Errorf("buffer was reallocated: cap %d, want 512", cap(buf))
	}
}

func TestMarshalUnmarshal(t *testing.T) {
	in := Welcome{
		Version:   0,
		GatewayID: "gw-a",
		Limits:    &Limits{Frame: MaxFrame, Batch: MaxBatch, Rate: 262144, PingInterval: 30},
		Resume: &Resume{Sessions: []Invitation{
			{SessionID: "sess_01J8Z", Ticket: "hK3", URL: "wss://gw-a/ws/session", Profile: "shell"},
		}},
	}
	f, err := Marshal(TypeWelcome, in)
	if err != nil {
		t.Fatal(err)
	}
	var out Welcome
	if err := Unmarshal(f, &out); err != nil {
		t.Fatal(err)
	}
	if out.GatewayID != in.GatewayID || out.Resume == nil || len(out.Resume.Sessions) != 1 {
		t.Fatalf("round trip changed %+v -> %+v", in, out)
	}
	if out.Resume.Sessions[0].SessionID != "sess_01J8Z" {
		t.Errorf("resume lost the session id: %+v", out.Resume.Sessions[0])
	}

	if _, err := Marshal(TypeData, in); err == nil {
		t.Error("Marshal accepted a raw type; DATA carries bytes, not JSON")
	}
	if err := Unmarshal(Frame{Type: TypeData}, &out); err == nil {
		t.Error("Unmarshal accepted a raw type")
	}
	if err := Unmarshal(Frame{Type: TypeWelcome}, &out); err == nil {
		t.Error("Unmarshal accepted an empty payload")
	}
}

// TestInvitationIsTheSharedShape covers what not multiplexing bought: one payload
// for both reachability modes, so downstream of arrival there is one code path.
func TestInvitationIsTheSharedShape(t *testing.T) {
	inv := Invitation{
		SessionID: "sess_1", Ticket: "hK3", URL: "wss://gw-a/ws/session",
		Profile: "shell", PTY: &PTY{Cols: 132, Rows: 38, Term: "xterm-256color"},
		Principal: "admin@mail.com", ExpiresAt: "2026-08-21T09:15:02Z",
	}
	// Down the control channel as DIAL...
	f, err := Marshal(TypeDial, inv)
	if err != nil {
		t.Fatal(err)
	}
	var viaDial Invitation
	if err := Unmarshal(f, &viaDial); err != nil {
		t.Fatal(err)
	}
	// ...and through a Dispatcher as JSON, which must produce the same thing.
	var viaDoorbell Invitation
	if err := Unmarshal(Frame{Type: TypeDial, Payload: f.Payload}, &viaDoorbell); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(viaDial, viaDoorbell) {
		t.Errorf("the two delivery paths produced different invitations:\n %+v\n %+v",
			viaDial, viaDoorbell)
	}
	if viaDial.URL != inv.URL {
		t.Errorf("URL must name a node, got %q", viaDial.URL)
	}
}

// TestUnknownJSONFieldsAreDropped is the other half of forward compatibility.
func TestUnknownJSONFieldsAreDropped(t *testing.T) {
	f := Frame{Type: TypeReady, Payload: []byte(
		`{"session_id":"s1","recording":true,"mode":"gateway","something_new":{"a":1}}`)}
	var r Ready
	if err := Unmarshal(f, &r); err != nil {
		t.Fatalf("an unknown field broke decoding: %v", err)
	}
	if r.SessionID != "s1" || !r.Recording {
		t.Errorf("decoded %+v", r)
	}
}

func TestStamp(t *testing.T) {
	f, err := Stamp(TypePing, 1787218725000123)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReadStamp(f)
	if err != nil || got != 1787218725000123 {
		t.Errorf("ReadStamp = %d, %v", got, err)
	}
	if _, err := Stamp(TypeData, 1); err == nil {
		t.Error("Stamp accepted a non-ping type")
	}
	if _, err := ReadStamp(Frame{Type: TypePong, Payload: []byte{1, 2, 3}}); !errors.Is(err, ErrPayloadLen) {
		t.Errorf("short stamp: got %v, want ErrPayloadLen", err)
	}
}

func TestErrorCodeMapping(t *testing.T) {
	if got := ErrorCode(ErrTooLarge); got != "frame_too_large" {
		t.Errorf("ErrTooLarge -> %q", got)
	}
	if got := ErrorCode(ErrWrongChan); got != "protocol_error" {
		t.Errorf("ErrWrongChan -> %q", got)
	}
	if got := ErrorCode(nil); got != "" {
		t.Errorf("nil -> %q", got)
	}
}

func TestTypeString(t *testing.T) {
	if got := TypeDial.String(); got != "DIAL" {
		t.Errorf("got %q", got)
	}
	if got := Type(0xAB).String(); !strings.Contains(got, "0xab") {
		t.Errorf("unknown type rendered as %q, want it to show the byte", got)
	}
}

func TestLimitsAreOneSet(t *testing.T) {
	if MaxBatch >= MaxFrame {
		t.Fatalf("MaxBatch (%d) must sit below MaxFrame (%d)", MaxBatch, MaxFrame)
	}
	if HeaderLen+MaxBatch >= MaxFrame {
		t.Fatalf("a full batch plus a header (%d) must fit under MaxFrame (%d)",
			HeaderLen+MaxBatch, MaxFrame)
	}
}
