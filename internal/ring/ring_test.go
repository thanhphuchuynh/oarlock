package ring_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/oarlock/oarlock/internal/ring"
)

// A corpus of sequences a real shell session produces. Every one of these has been on
// somebody's screen: colours from ls, the prompt-repainting a shell does on every
// keystroke, the title-setting an OSC does, the alternate screen vim uses, a bracketed
// paste, a hyperlink from a modern ls.
var sequences = []struct {
	name string
	seq  string
}{
	{"sgr-reset", "\x1b[0m"},
	{"sgr-bold-red", "\x1b[1;31m"},
	{"sgr-256", "\x1b[38;5;196m"},
	{"sgr-truecolour", "\x1b[38;2;255;128;0m"},
	{"clear-screen", "\x1b[2J"},
	{"cursor-home", "\x1b[H"},
	{"cursor-position", "\x1b[24;80H"},
	{"erase-line", "\x1b[K"},
	{"scroll-region", "\x1b[1;24r"},
	{"alt-screen-on", "\x1b[?1049h"},
	{"alt-screen-off", "\x1b[?1049l"},
	{"bracketed-paste-on", "\x1b[?2004h"},
	{"cursor-hide", "\x1b[?25l"},
	{"osc-title-bel", "\x1b]0;phuc@treadmill-4821\x07"},
	{"osc-title-st", "\x1b]2;a title\x1b\\"},
	{"osc-hyperlink", "\x1b]8;;https://example.org\x1b\\link\x1b]8;;\x1b\\"},
	{"charset-ascii", "\x1b(B"},
	{"charset-graphics", "\x1b(0"},
	{"reset-terminal", "\x1bc"},
	{"save-cursor", "\x1b7"},
	{"restore-cursor", "\x1b8"},
	{"dcs", "\x1bP1$r0m\x1b\\"},
	{"apc", "\x1b_Gi=1,a=q;\x1b\\"},
	{"cr-lf", "\r\n"},
	{"tab", "\t"},
	{"backspace", "\b"},
	{"utf8-2byte", "café"},
	{"utf8-3byte", "日本語"},
	{"utf8-4byte", "🚣"},
	{"can-aborts", "\x1b[1;3\x18m"},
}

// TestReplayNeverStartsInsideASequence is R-002 as a property.
//
// For every sequence in the corpus and every ring size that forces a cut *inside* it,
// the replay must not begin in the middle. The check is not "the bytes look right" — it
// is that feeding the replay to a fresh parser leaves it in the ground state at the
// same points as feeding it the original stream, which is the property a terminal
// actually depends on.
func TestReplayNeverStartsInsideASequence(t *testing.T) {
	for _, tc := range sequences {
		t.Run(tc.name, func(t *testing.T) {
			// A recognisable prefix, then the sequence, then text. The ring is sized so
			// its window starts somewhere inside the sequence.
			stream := "BEFORE" + tc.seq + "AFTER"
			for size := 1; size <= len(stream); size++ {
				r := ring.New(size)
				if _, err := r.Write([]byte(stream)); err != nil {
					t.Fatal(err)
				}
				snap := r.Snapshot()

				// The replay must be a suffix of the stream — the ring cannot invent
				// bytes — and it must start at a position where a fresh terminal is
				// not inside anything.
				if len(snap.Replay) > 0 && !bytes.HasSuffix([]byte(stream), snap.Replay) {
					t.Fatalf("size %d: replay is not a suffix of the stream: %q", size, snap.Replay)
				}
				if got := startOffset(stream, snap); got >= 0 && !safeToStartAt(stream, got) {
					t.Errorf("size %d: replay starts at offset %d, inside a sequence: %q",
						size, got, snap.Replay)
				}

				// Nothing is silently lost: everything the operator will not see is
				// counted, so the UI can show a gap marker instead of a silence.
				accounted := int64(len(snap.Replay)) + snap.Lost()
				if accounted != int64(len(stream)) {
					t.Errorf("size %d: %d replayed + %d lost != %d written",
						size, len(snap.Replay), snap.Lost(), len(stream))
				}
			}
		})
	}
}

// startOffset finds where the replay begins in the original stream, or -1.
func startOffset(stream string, s ring.Snapshot) int {
	if len(s.Replay) == 0 {
		return -1
	}
	return len(stream) - len(s.Replay)
}

// safeToStartAt reports whether a terminal fed stream[at:] can be sure it is not
// resuming inside a sequence.
//
// Computed by running the parser over the prefix from scratch, which deliberately does
// *not* vouch for the parser's semantics — the corpus test and groundAfter do that. What
// it pins is everything between the parser and the replay: the bitmap, the wraparound,
// the offset arithmetic, and the mark of the byte that just fell out of the window.
// Those are where the ring's actual bugs were.
func safeToStartAt(stream string, at int) bool {
	marks := ring.GroundMarks([]byte(stream))
	return at >= 0 && at < len(marks) && marks[at]
}

// groundAfter is a second implementation of the one question the ring's parser answers:
// after consuming these bytes, is a terminal between sequences?
//
// Written from the sequence grammar rather than from the ring's state machine, so that
// two implementations have to agree. That is worth more than one confident one — and it
// has already paid for itself twice: the fuzzer found this checker wrong about invalid
// UTF-8, and wrong again about ESC cancelling a CSI. Both times the ring was right.
//
// "Naive" was the wrong word for it. An oracle has to be correct, not simple.
func groundAfter(s string) bool {
	i := 0
	for i < len(s) {
		b := s[i]

		// CAN and SUB abort anything in progress, from anywhere.
		if b == 0x18 || b == 0x1a {
			i++
			continue
		}

		if b != 0x1b {
			if b < 0xC0 {
				// A C0 control, printable ASCII, or a stray continuation byte, all of
				// which a terminal consumes in place.
				i++
				continue
			}
			// A UTF-8 lead owes continuations, and does not necessarily get them:
			// invalid UTF-8 is ordinary in a terminal stream, and a terminal emits
			// U+FFFD and resynchronises on the offending byte rather than sticking.
			need := 1
			switch {
			case b >= 0xF0:
				need = 3
			case b >= 0xE0:
				need = 2
			}
			j := i + 1
			for j < len(s) && need > 0 && s[j] >= 0x80 && s[j] < 0xC0 {
				j++
				need--
			}
			if need > 0 && j >= len(s) {
				return false // the string ends mid-character
			}
			i = j // satisfied, or stopped on a byte to reinterpret
			continue
		}

		// An escape sequence. Everywhere below, an ESC encountered *inside* one
		// cancels it and begins a new one — the behaviour the fuzzer caught this
		// checker getting wrong.
		j := i + 1
		if j >= len(s) {
			return false // a lone trailing ESC
		}
		// Each branch below has exactly one way to fail — running out of input while
		// still inside a sequence. Consuming a terminator that happens to be the last
		// byte is *completion*, not truncation, and conflating the two is the third
		// thing the fuzzer caught here.
		switch c := s[j]; {
		case c == '[': // CSI: parameters and intermediates, then one final byte
			for j++; ; j++ {
				if j >= len(s) {
					return false
				}
				d := s[j]
				if d == 0x18 || d == 0x1a { // aborted
					j++
					break
				}
				if d == 0x1b { // cancelled: reinterpret from this ESC
					break
				}
				if d >= 0x40 && d <= 0x7e { // the final byte
					j++
					break
				}
			}
			i = j

		case c == ']' || c == 'P' || c == 'X' || c == '^' || c == '_':
			// A string sequence: OSC, DCS, SOS, PM, APC. Terminated by BEL or ST.
			for j++; ; {
				if j >= len(s) {
					return false
				}
				d := s[j]
				if d == 0x07 || d == 0x18 || d == 0x1a {
					j++
					break
				}
				if d == 0x1b {
					if j+1 >= len(s) {
						return false // a trailing ESC inside a string
					}
					switch next := s[j+1]; {
					case next == '\\': // ST
						j += 2
					case next == 0x18 || next == 0x1a:
						// CAN and SUB abort from *any* state, including from inside a
						// string sequence. Consuming them as ordinary content is the
						// fourth thing the fuzzer caught in this checker.
						j += 2
					default:
						j += 2 // ignored inside the string; keep scanning
						continue
					}
					break
				}
				j++
			}
			i = j

		case c >= 0x20 && c <= 0x2f: // intermediates, then a final, e.g. ESC ( B
			for j++; j < len(s) && s[j] >= 0x20 && s[j] <= 0x2f; j++ {
			}
			if j >= len(s) {
				return false
			}
			if s[j] == 0x1b { // cancelled
				i = j
				continue
			}
			i = j + 1

		case c >= 0x30 && c <= 0x7e: // a complete two-byte sequence, e.g. ESC c
			i = j + 1

		default: // ESC followed by a control, including ESC ESC
			i = j
		}
	}
	return true
}

// TestTheParserAgreesWithTheGrammar cross-checks the state machine against a second
// implementation written from the sequence grammar, over input made of sequences that
// have actually been on somebody's screen. Two implementations that agree are worth more
// than one that is confident — and on realistic input the grammar version is
// trustworthy, which is what makes this the right place for it rather than the fuzzer.
func TestTheParserAgreesWithTheGrammar(t *testing.T) {
	var streams []string
	for _, a := range sequences {
		streams = append(streams, a.seq, "text"+a.seq, a.seq+"text")
		for _, b := range sequences {
			streams = append(streams, a.seq+b.seq)
		}
	}
	for _, s := range streams {
		marks := ring.GroundMarks([]byte(s))
		for at := range marks {
			if want := groundAfter(s[:at]); marks[at] != want {
				t.Errorf("%q at %d: parser says ground=%v, the grammar says %v",
					s, at, marks[at], want)
			}
		}
	}
}

func TestNothingDroppedMeansEverythingReplayed(t *testing.T) {
	stream := "\x1b[1;31mALERT\x1b[0m ready\r\n"
	r := ring.New(1024)
	r.Write([]byte(stream))
	snap := r.Snapshot()

	if string(snap.Replay) != stream {
		t.Errorf("replay %q, want the whole stream", snap.Replay)
	}
	if snap.Lost() != 0 {
		t.Errorf("lost %d bytes with room to spare", snap.Lost())
	}
	// A terminal at the start of a stream is in the ground state by definition, so a
	// ring that never wrapped must replay from byte zero — trimming here would throw
	// away the colour that makes the first line legible.
	if snap.SkippedForSafety != 0 {
		t.Errorf("skipped %d bytes without having dropped any", snap.SkippedForSafety)
	}
}

func TestTheGapIsReported(t *testing.T) {
	r := ring.New(16)
	r.Write([]byte(strings.Repeat("x", 100)))
	snap := r.Snapshot()

	if len(snap.Replay) != 16 {
		t.Errorf("replayed %d bytes from a 16-byte ring", len(snap.Replay))
	}
	if snap.Dropped != 84 {
		t.Errorf("dropped %d, want 84", snap.Dropped)
	}
	if snap.Written != 100 {
		t.Errorf("written %d, want 100", snap.Written)
	}
}

// TestAnUnterminatedSequenceLongerThanTheRing: a device that opens an OSC and never
// closes it fills the ring with bytes that can never be safely replayed. The operator
// gets a gap rather than a screen full of somebody else's title string.
func TestAnUnterminatedSequenceLongerThanTheRing(t *testing.T) {
	r := ring.New(64)
	r.Write([]byte("\x1b]0;" + strings.Repeat("A", 200)))
	snap := r.Snapshot()

	if len(snap.Replay) != 0 {
		t.Errorf("replayed %d bytes of an unterminated sequence: %q",
			len(snap.Replay), snap.Replay)
	}
	if snap.SkippedForSafety != 64 {
		t.Errorf("skipped %d, want the whole ring", snap.SkippedForSafety)
	}
	if snap.Lost() != 204 {
		t.Errorf("lost %d, want everything written", snap.Lost())
	}
}

// TestWriteBoundariesDoNotChangeTheAnswer: the pump writes whatever the socket handed
// it, so the same stream arrives in different chunkings on different runs. A ring whose
// answer depended on that would be a flake generator.
func TestWriteBoundariesDoNotChangeTheAnswer(t *testing.T) {
	stream := []byte("hello \x1b[1;31mred\x1b[0m and \x1b]0;title\x07 done\r\n")
	want := ring.New(24)
	want.Write(stream)
	reference := want.Snapshot()

	for chunk := 1; chunk <= len(stream); chunk++ {
		r := ring.New(24)
		for i := 0; i < len(stream); i += chunk {
			end := min(i+chunk, len(stream))
			r.Write(stream[i:end])
		}
		got := r.Snapshot()
		if !bytes.Equal(got.Replay, reference.Replay) {
			t.Fatalf("chunk %d: replay %q, want %q", chunk, got.Replay, reference.Replay)
		}
		if got.Lost() != reference.Lost() {
			t.Errorf("chunk %d: lost %d, want %d", chunk, got.Lost(), reference.Lost())
		}
	}
}

func TestSnapshotIsACopy(t *testing.T) {
	r := ring.New(32)
	r.Write([]byte("original"))
	snap := r.Snapshot()

	// The caller writes this to a socket while the device keeps producing. Handing out
	// a window onto a live ring would be handing out a data race.
	r.Write([]byte(strings.Repeat("later", 20)))
	if string(snap.Replay) != "original" {
		t.Errorf("the snapshot changed under the caller: %q", snap.Replay)
	}
}

func TestEmptyRing(t *testing.T) {
	r := ring.New(64)
	snap := r.Snapshot()
	if len(snap.Replay) != 0 || snap.Lost() != 0 || snap.Written != 0 {
		t.Errorf("a ring nobody wrote to is not empty: %+v", snap)
	}
	if n, err := r.Write(nil); n != 0 || err != nil {
		t.Errorf("Write(nil) = %d, %v", n, err)
	}
}

func TestDefaultSizeIsTheDocumentedLimit(t *testing.T) {
	// limits.scrollback, ARCHITECTURE § 9.3. A number that drifts from the table is a
	// number somebody will trust.
	if got := ring.New(0).Size(); got != 256<<10 {
		t.Errorf("default size %d, want 256 KiB", got)
	}
}

// TestReplayResumesCleanlyIntoLiveOutput: the operator gets the replay and then the
// live stream. Parsed end to end, that has to be a coherent stream.
func TestReplayResumesCleanlyIntoLiveOutput(t *testing.T) {
	r := ring.New(20)
	r.Write([]byte("\x1b[1;31mred text that overflows the ring\x1b[0m"))
	snap := r.Snapshot()
	live := []byte("\x1b[32mgreen\x1b[0m\r\n")

	combined := append(append([]byte{}, snap.Replay...), live...)
	if !groundAfter(string(combined)) {
		t.Errorf("replay + live output does not end at rest: %q", combined)
	}
}

func FuzzRingNeverReplaysMidSequence(f *testing.F) {
	f.Add([]byte("\x1b[1;31mhello\x1b[0m"), 8)
	f.Add([]byte("\x1b]0;title\x07text"), 4)
	f.Add([]byte("café 日本語 🚣"), 6)
	f.Add([]byte{0x1b, 0x1b, 0x1b, '['}, 2)

	f.Fuzz(func(t *testing.T, stream []byte, size int) {
		if size <= 0 || size > 4096 {
			t.Skip()
		}
		r := ring.New(size)
		r.Write(stream)
		snap := r.Snapshot()

		if len(snap.Replay) > 0 {
			if !bytes.HasSuffix(stream, snap.Replay) {
				t.Fatalf("replay is not a suffix of the input")
			}
			at := len(stream) - len(snap.Replay)
			if !safeToStartAt(string(stream), at) {
				t.Fatalf("replay starts inside a sequence at %d", at)
			}
		}
		if accounted := int64(len(snap.Replay)) + snap.Lost(); accounted != int64(len(stream)) {
			t.Fatalf("%d accounted for, %d written", accounted, len(stream))
		}
	})
}

// ExampleRing shows the case the ring exists for: a window that opens inside a colour
// sequence. Replaying from the window's first byte would print ";196mred" as text; the
// ring skips forward to the sequence's end instead, and says how much it skipped so the
// operator can be shown a gap rather than a silence.
func ExampleRing() {
	r := ring.New(12)
	r.Write([]byte("\x1b[38;5;196mred\x1b[0m"))
	snap := r.Snapshot()
	fmt.Printf("replay=%q skipped=%d dropped=%d\n",
		snap.Replay, snap.SkippedForSafety, snap.Dropped)
	// Output: replay="red\x1b[0m" skipped=5 dropped=6
}
