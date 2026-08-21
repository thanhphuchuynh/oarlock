package ring

// Exported for the tests in ring_test.go.
//
// The ring has two separable concerns and they want different kinds of test:
//
//   - **Parser semantics** — does the state machine know where a sequence ends? Best
//     tested against a corpus of sequences that have actually been on somebody's
//     screen, cross-checked with a second implementation written from the grammar.
//     Realistic input, where an independent implementation is trustworthy.
//
//   - **Bookkeeping** — the bitmap, the wraparound, the offset arithmetic, the mark of
//     the byte that just fell out of the window. This is where the ring's real bugs
//     were, and it wants adversarial input.
//
// Fuzzing the second with a hand-written grammar oracle turned out to test the oracle:
// four consecutive findings were all the checker being wrong about invalid UTF-8, about
// ESC cancelling a CSI, about a terminator landing on the last byte, and about SUB
// aborting from inside a string. So the fuzz oracle is the parser itself, run from
// scratch over the prefix — which cannot vouch for the semantics, but pins every piece
// of arithmetic between the parser and the replay.

// GroundMarks reports, for each position i in b, whether a replay may begin at i.
//
// Position 0 is always startable — a terminal at the start of a stream is in the ground
// state by definition — so the result has len(b)+1 entries.
func GroundMarks(b []byte) []bool {
	out := make([]bool, len(b)+1)
	out[0] = true
	var p parser
	for i, c := range b {
		out[i+1] = p.step(c)
	}
	return out
}
