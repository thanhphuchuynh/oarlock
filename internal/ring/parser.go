package ring

// A minimal VT parser, kept to the one question the ring needs answered: after this
// byte, could a terminal starting fresh be in the middle of something?
//
// It is deliberately not a terminal emulator. It does not interpret sequences, keep
// parameters, or care what they mean — it only tracks whether the stream is between
// sequences (ground) or inside one. Everything else is somebody else's problem, and
// keeping it that small is what makes it auditable against R-002.
//
// The shape follows Paul Williams' DEC parser, minus every state whose distinction only
// matters to something that acts on the sequence.
//
// # 8-bit C1 controls are not honoured, on purpose
//
// 0x80–0x9F are C1 controls in an 8-bit terminal — 0x9B is CSI, 0x9D is OSC. They are
// also UTF-8 continuation bytes, and this stream is UTF-8: a device printing "café"
// sends 0xC3 0xA9, and reading 0xA9 as a control would desynchronise the parser on
// ordinary text. Modern terminals in UTF-8 mode do not honour 8-bit C1 either.
type state uint8

const (
	ground state = iota
	escape
	escapeIntermediate
	csi
	str    // OSC, DCS, SOS, PM, APC — all terminated the same way
	strEsc // saw ESC inside a string; ESC \ is the terminator
)

type parser struct {
	state state
	// utf8 is how many continuation bytes are still owed. A replay may not begin in
	// the middle of a character either: it would cost the operator a replacement
	// glyph, which is a small thing that is free to avoid.
	utf8 uint8
}

const (
	bel = 0x07
	can = 0x18
	sub = 0x1a
	esc = 0x1b
)

// step consumes one byte and reports whether the parser is in the ground state
// afterwards — that is, whether a replay may begin at the *next* byte.
func (p *parser) step(b byte) bool {
	// CAN and SUB abort whatever is in progress, from any state. A device that sends
	// one is explicitly saying "forget the partial sequence", which is exactly the
	// resynchronisation point the ring is looking for.
	if b == can || b == sub {
		p.state = ground
		p.utf8 = 0
		return true
	}

	if p.utf8 > 0 {
		if b >= 0x80 && b < 0xC0 {
			p.utf8--
			return p.utf8 == 0 && p.state == ground
		}
		// Not a continuation byte: the character was truncated. Fall through and
		// interpret this byte normally, which is what a terminal does.
		p.utf8 = 0
	}

	switch p.state {
	case ground:
		switch {
		case b == esc:
			p.state = escape
			return false
		case b < 0x80:
			// C0 controls other than ESC execute in place; printable is printable.
			return true
		case b < 0xC0:
			// A continuation byte with no lead. Invalid UTF-8, which a terminal
			// resynchronises on rather than getting stuck in.
			return true
		default:
			p.utf8 = utf8Continuations(b)
			return p.utf8 == 0
		}

	case escape:
		switch {
		case b == esc:
			return false // ESC ESC: the second one starts over
		case b >= 0x20 && b <= 0x2F:
			p.state = escapeIntermediate
			return false
		case b == '[':
			p.state = csi
			return false
		case b == ']' || b == 'P' || b == 'X' || b == '^' || b == '_':
			p.state = str
			return false
		case b >= 0x30 && b <= 0x7E:
			p.state = ground
			return true // a complete two-byte sequence, e.g. ESC c
		default:
			return false // a C0 control inside an escape; still inside it
		}

	case escapeIntermediate:
		switch {
		case b >= 0x20 && b <= 0x2F:
			return false
		case b >= 0x30 && b <= 0x7E:
			p.state = ground
			return true // e.g. ESC ( B
		case b == esc:
			p.state = escape
			return false
		default:
			return false
		}

	case csi:
		switch {
		case b >= 0x40 && b <= 0x7E:
			p.state = ground
			return true // the final byte, e.g. the m of CSI 1;31 m
		case b == esc:
			p.state = escape
			return false
		default:
			return false // parameters, intermediates, and C0 controls
		}

	case str:
		switch b {
		case bel:
			p.state = ground
			return true // the OSC form: ESC ] ... BEL
		case esc:
			p.state = strEsc
			return false
		default:
			return false
		}

	case strEsc:
		switch b {
		case '\\':
			p.state = ground
			return true // ST: ESC ] ... ESC \
		case esc:
			return false
		default:
			p.state = str
			return false
		}
	}
	return false
}

// utf8Continuations is how many bytes follow this lead byte.
func utf8Continuations(lead byte) uint8 {
	switch {
	case lead >= 0xF0:
		return 3
	case lead >= 0xE0:
		return 2
	case lead >= 0xC0:
		return 1
	}
	return 0
}
