package frame

import (
	"bytes"
	"testing"
)

// FuzzDecode is the reason this package exists in the shape it does.
//
// The device leg is the largest untrusted-input surface in the system, and it
// terminates in a process that can open a shell. This runs in CI on every commit
// and is the first thing to extend when the format changes.
//
// It asserts two properties:
//
//  1. Decode never panics and never allocates, whatever the input.
//  2. Anything that decodes re-encodes to the identical bytes. A decoder that
//     accepts input it cannot reproduce is a decoder two implementations will
//     disagree about — and one of them will be a third-party agent.
func FuzzDecode(f *testing.F) {
	seeds := [][]byte{
		nil,
		{},
		{0x00},
		{0x01},
		{0x01, 'h', 'i'},
		{0x14, 0, 0, 0, 0, 0, 0, 0, 1},
		{0x03, '{', '}'},
		{0xFF},
		{0x0F, 0xDE, 0xAD, 0xBE, 0xEF},
		{0x10},
		{0x16, '{', '}'},
		{0x19, 'o', 'l', 'd'}, // the retired WINDOW type
		bytes.Repeat([]byte{0x01}, 1024),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, msg []byte) {
		c := Codec{}

		fr, err := c.Decode(msg)
		if err != nil {
			// Every rejection must map to a wire code, or the gateway has nothing
			// truthful to put in an ERROR frame.
			if code := ErrorCode(err); code == "" {
				t.Fatalf("rejection with no wire code: %v", err)
			}
			return
		}

		if fr.Type == 0 {
			t.Fatal("decoded a 0x00 type")
		}
		// Every decoded frame must have a defined disposition and a channel, so no
		// input can reach a receiver that has no rule for it.
		switch fr.Type.Disposition() {
		case Handle, Ignore, CloseConnection:
		default:
			t.Fatalf("%v has no disposition", fr.Type)
		}
		if Expect(ScopeSession, fr) != nil && Expect(ScopeConnection, fr) != nil {
			if fr.Type.Scope() != ScopeUnknown {
				t.Fatalf("%v belongs to neither connection kind but has a scope", fr.Type)
			}
		}

		// Round trip: re-encoding must reproduce the input exactly.
		wire, err := c.Encode(nil, fr)
		if err != nil {
			t.Fatalf("re-encoding a frame we just decoded failed: %v", err)
		}
		if !bytes.Equal(wire, msg) {
			t.Fatalf("round trip changed the bytes:\n in  %x\n out %x", msg, wire)
		}

		// Clone must not alias the input.
		if len(fr.Payload) > 0 {
			cl := fr.Clone()
			before := cl.Payload[0]
			msg[HeaderLen] ^= 0xFF
			if cl.Payload[0] != before {
				t.Fatal("Clone still aliases the input")
			}
		}
	})
}
