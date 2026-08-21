// Package ring is the scrollback a reattaching operator gets replayed.
//
// # Why a ring and not a buffer
//
// A dropped operator socket is not a close (ARCHITECTURE § 6): the session stays
// attached and the device keeps producing. Operators lose wifi constantly, and a shell
// that dies with it is a shell nobody trusts with a long command. So somebody has to
// hold what the device said while nobody was listening, and it has to be bounded —
// `limits.scrollback`, 256 KiB — because a detached session watching `tail -f` would
// otherwise be an unbounded allocation with no operator to notice.
//
// # The part that is not obvious: where a replay may start
//
// A ring drops its oldest bytes, and the byte it drops may be the ESC that opened a
// sequence whose remaining bytes are still in the buffer. Replaying from the ring's
// start then feeds a terminal the tail of a sequence it never saw the head of —
// `[38;5;196m` arrives as text, or worse, `2J` clears the screen. The operator sees a
// mangled screen and has no way to know it is an artefact of reconnecting rather than
// what the device actually printed. That is R-002, and it cannot be fixed at replay
// time by guessing, because a parameter byte and a printable byte are the same byte:
// from the middle of a stream there is no way to tell `1;2` inside a CSI from the text
// "1;2".
//
// So the ring tracks it on the way *in*. A minimal VT parser runs over every byte as it
// is written and marks the positions where it is in the ground state — positions where a
// terminal starting fresh cannot be inside anything. Replay starts at the oldest
// surviving mark, and the bytes skipped to reach it are reported so the operator can be
// shown a gap rather than a silence.
package ring

import "sync"

// DefaultSize is `limits.scrollback` from ARCHITECTURE § 9.3.
const DefaultSize = 256 << 10

// Ring is a bounded byte ring that knows where a terminal may safely resume.
//
// Safe for concurrent use: the pump writes from its output path while an attaching
// operator snapshots.
type Ring struct {
	mu   sync.Mutex
	buf  []byte
	safe []byte // bitset, one bit per byte of buf: "a replay may start here"
	// start is the index of the oldest byte; n is how many bytes are live.
	start int
	n     int
	// dropped counts bytes the ring has overwritten, for the record.
	dropped int64
	// startSafe remembers the mark of the byte most recently dropped, which is what
	// says whether the window's own first byte is a legal resume point. Without it the
	// ring skips one byte of every replay — harmless-looking, and wrong: for a stream
	// of plain text every position is safe and none should be skipped.
	startSafe bool
	// written counts everything ever written, which is what makes "dropped" legible.
	written int64

	p parser
}

// New returns a ring holding at most size bytes. Size <= 0 means DefaultSize.
func New(size int) *Ring {
	if size <= 0 {
		size = DefaultSize
	}
	return &Ring{
		buf:  make([]byte, size),
		safe: make([]byte, (size+7)/8),
	}
}

// Size is the ring's capacity in bytes.
func (r *Ring) Size() int { return len(r.buf) }

// Write appends bytes, overwriting the oldest when full. It never fails and never
// blocks on anything but the mutex: the ring is a best-effort convenience for the
// operator, and it must not be able to stall the device.
func (r *Ring) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	size := len(r.buf)
	for _, b := range p {
		idx := (r.start + r.n) % size
		r.buf[idx] = b
		// The mark belongs to the position *after* this byte: if consuming it returns
		// the parser to ground, then a replay may begin at the next byte.
		ground := r.p.step(b)
		if r.n == size {
			// Full: this write overwrote the oldest byte, so the window slides. Read
			// the departing byte's mark before it goes.
			r.startSafe = r.isSafe(r.start)
			r.start = (r.start + 1) % size
			r.dropped++
		} else {
			r.n++
		}
		r.setSafe(idx, ground)
	}
	r.written += int64(len(p))
	return len(p), nil
}

// Snapshot is what a reattaching operator gets.
//
// Replay is the bytes from the oldest position a terminal may safely resume at.
// SkippedForSafety is how many surviving bytes were left out to reach it — the tail of
// a sequence whose head the ring had already dropped. Dropped is how many bytes the
// ring overwrote over the session's life.
type Snapshot struct {
	Replay           []byte
	SkippedForSafety int
	Dropped          int64
	Written          int64
}

// Lost is everything the operator will not see: bytes the ring overwrote, plus the
// unsafe fragment it had to skip.
func (s Snapshot) Lost() int64 { return s.Dropped + int64(s.SkippedForSafety) }

// Snapshot copies out the replayable scrollback.
//
// A copy, not a view: the caller writes it to a socket while the device keeps producing,
// and handing out a window onto a live ring would be handing out a data race.
func (r *Ring) Snapshot() Snapshot {
	r.mu.Lock()
	defer r.mu.Unlock()

	s := Snapshot{Dropped: r.dropped, Written: r.written}
	if r.n == 0 {
		return s
	}

	// Nothing has been dropped, so the ring starts where the stream started, and a
	// terminal at the start of a stream is by definition in the ground state.
	from := 0
	if r.dropped > 0 {
		from = r.firstSafeLocked()
		if from < 0 {
			// Every surviving byte is inside one unterminated sequence. Replaying any
			// of it would corrupt the screen, so the operator gets the gap and
			// nothing else. This is what an OSC longer than the whole ring looks
			// like, which is a hostile device rather than a shell.
			s.SkippedForSafety = r.n
			return s
		}
	}

	s.SkippedForSafety = from
	out := make([]byte, r.n-from)
	size := len(r.buf)
	for i := range out {
		out[i] = r.buf[(r.start+from+i)%size]
	}
	s.Replay = out
	return s
}

// firstSafeLocked returns the offset from start of the oldest position a replay may
// begin at, or -1 if there is none.
//
// The mark on a byte means "a replay may begin *after* this byte", so offset i is
// startable when the byte before it is marked. For offset 0 that byte has already been
// dropped, which is what startSafe remembers.
func (r *Ring) firstSafeLocked() int {
	if r.startSafe {
		return 0
	}
	size := len(r.buf)
	for i := 1; i < r.n; i++ {
		if r.isSafe((r.start + i - 1) % size) {
			return i
		}
	}
	return -1
}

func (r *Ring) setSafe(idx int, ok bool) {
	if ok {
		r.safe[idx/8] |= 1 << (idx % 8)
		return
	}
	r.safe[idx/8] &^= 1 << (idx % 8)
}

func (r *Ring) isSafe(idx int) bool {
	return r.safe[idx/8]&(1<<(idx%8)) != 0
}
