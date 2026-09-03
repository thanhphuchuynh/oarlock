package sshsrv

// Making the gateway's own words safe to print on an operator's terminal.
//
// # What this is not
//
// It is not about session output. A hostile device can emit any escape sequence it likes
// into a shell's output and always could — that is true of `ssh` generally and the threat
// model says so. The bytes between the prompts are the device's to write.
//
// This is about the lines the *gateway* writes: the banner, the closing disclosure, a
// refusal. Those are chrome, and an operator reads them as the gateway speaking. Several
// of them interpolate strings the gateway did not author — a device id from a registry
// file, a refusal sentence from an authorisation backend, a close reason that arrived on
// the wire — and a control byte in any of those lets somebody else finish the gateway's
// sentence.
//
// The closing disclosure is the one that matters. It says whether the session was
// recorded, and it is said twice precisely so that a deleted prefix cannot remove it. A
// `\r` and a few spaces in an interpolated field would let the party being disclosed
// *about* erase the line and write a different answer — which is a more direct defeat than
// the truncation attack the second disclosure exists to survive.
//
// # Why escaping rather than dropping
//
// A dropped byte is invisible. `\x1b` in the middle of a device id tells the operator that
// something put an escape sequence there, which is worth knowing and is exactly the sort of
// thing that should end up in a support ticket.

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxTerminalField bounds one interpolated field.
//
// A refusal sentence comes from an authorisation backend, and a backend having a bad day
// can return a megabyte. Truncating is not politeness: an operator's scrollback is a
// finite thing, and the disclosure they need to read is the line that would scroll away.
const maxTerminalField = 512

// safeText renders s for a terminal: printable runes survive, everything else becomes a
// visible escape, and the result is bounded.
//
// Invalid UTF-8 is escaped byte by byte rather than replaced, because a device id that is
// not valid UTF-8 is a fact about the registry worth seeing rather than smoothing over.
func safeText(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	n := 0
	for i, r := range s {
		if n >= maxTerminalField {
			b.WriteString("…")
			break
		}
		if r == utf8.RuneError {
			if _, size := utf8.DecodeRuneInString(s[i:]); size == 1 {
				// A raw byte that is not valid UTF-8.
				b.WriteString(`\x`)
				const hex = "0123456789abcdef"
				b.WriteByte(hex[s[i]>>4])
				b.WriteByte(hex[s[i]&0x0f])
				n++
				continue
			}
		}
		// Space is printable for our purposes; unicode.IsPrint says otherwise for it
		// alone among the characters a sentence needs.
		if r == ' ' || unicode.IsPrint(r) {
			b.WriteRune(r)
			n++
			continue
		}
		// strconv.QuoteRune gives \x1b, \n, ‎ and so on, with the surrounding
		// quotes this does not want.
		q := strconv.QuoteRune(r)
		b.WriteString(q[1 : len(q)-1])
		n++
	}
	return b.String()
}
