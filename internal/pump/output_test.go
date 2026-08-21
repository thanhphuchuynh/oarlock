package pump_test

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/pump"
)

// sink records what the operator would have received.
type sink struct {
	mu        sync.Mutex
	batches   [][]byte
	throttles []int64
	sendErr   error
}

func (s *sink) SendData(_ context.Context, b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sendErr != nil {
		return s.sendErr
	}
	s.batches = append(s.batches, append([]byte(nil), b...))
	return nil
}

func (s *sink) SendThrottle(_ context.Context, dropped int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.throttles = append(s.throttles, dropped)
	return nil
}

func (s *sink) bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Join(s.batches, nil)
}
func (s *sink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.batches)
}
func (s *sink) droppedTotal() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for _, d := range s.throttles {
		n += d
	}
	return n
}
func (s *sink) throttleCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.throttles)
}

func run(t *testing.T, o *pump.Output) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = o.Run(ctx) }()
	return func() {
		o.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			cancel()
			<-done
			t.Fatal("Run did not return after Close")
		}
		cancel()
	}
}

// ── coalescing ──────────────────────────────────────────────────────────────────

// TestManySmallWritesBecomeOneBatch is why coalescing is always on: a chatty PTY
// writes thousands of times a second, and one frame per write is a syscall storm
// plus a WebSocket header per byte.
func TestManySmallWritesBecomeOneBatch(t *testing.T) {
	s := &sink{}
	o := pump.NewOutput(pump.Options{
		Sink: s, Policy: pump.Backpressure,
		Limits: pump.Limits{Batch: 64 << 10, Window: 50 * time.Millisecond, Rate: 0},
	})
	stop := run(t, o)

	var want []byte
	for i := range 500 {
		b := []byte{byte('a' + i%26)}
		if _, err := o.Write(b); err != nil {
			t.Fatal(err)
		}
		want = append(want, b...)
	}
	stop()

	if got := s.bytes(); !bytes.Equal(got, want) {
		t.Fatalf("coalescing changed the bytes: %d in, %d out", len(want), len(got))
	}
	if n := s.count(); n > 5 {
		t.Errorf("500 one-byte writes produced %d batches; coalescing is not working", n)
	}
}

func TestBatchCapSplitsLargeOutput(t *testing.T) {
	s := &sink{}
	const batch = 4096
	o := pump.NewOutput(pump.Options{
		Sink: s, Policy: pump.Backpressure,
		Limits: pump.Limits{Batch: batch, Window: 10 * time.Millisecond,
			HighWater: 1 << 20, LowWater: 1 << 16},
	})
	stop := run(t, o)

	want := bytes.Repeat([]byte("x"), batch*10+7)
	if _, err := o.Write(want); err != nil {
		t.Fatal(err)
	}
	stop()

	s.mu.Lock()
	for i, b := range s.batches {
		if len(b) > batch {
			t.Errorf("batch %d is %d bytes, over the %d cap", i, len(b), batch)
		}
	}
	s.mu.Unlock()
	if got := s.bytes(); !bytes.Equal(got, want) {
		t.Errorf("splitting lost bytes: %d in, %d out", len(want), len(got))
	}
}

func TestSingleWriteIsFlushedWithinTheWindow(t *testing.T) {
	s := &sink{}
	o := pump.NewOutput(pump.Options{
		Sink: s, Policy: pump.Backpressure,
		Limits: pump.Limits{Batch: 1 << 20, Window: 25 * time.Millisecond},
	})
	stop := run(t, o)
	defer stop()

	start := time.Now()
	if _, err := o.Write([]byte("$ ")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && s.count() == 0 {
		time.Sleep(time.Millisecond)
	}
	if s.count() == 0 {
		t.Fatal("a prompt was never flushed; batching must not hold output indefinitely")
	}
	// A human is waiting on the echo, so the window is a ceiling, not a target.
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("took %v to flush a two-byte prompt", elapsed)
	}
}

// ── the property a shell depends on ─────────────────────────────────────────────

// TestBackpressureIsLossless is the acceptance criterion that matters most. A
// dropped chunk lands in the middle of an escape sequence and leaves the terminal
// corrupt until a full redraw; no marker can repair that.
func TestBackpressureIsLossless(t *testing.T) {
	s := &sink{}
	o := pump.NewOutput(pump.Options{
		Sink: s, Policy: pump.Backpressure,
		// A deliberately tiny buffer, so the writer stalls constantly.
		Limits: pump.Limits{Batch: 1024, Window: time.Millisecond,
			HighWater: 4096, LowWater: 512},
	})
	stop := run(t, o)

	var want []byte
	chunk := bytes.Repeat([]byte("0123456789"), 100) // 1 KiB
	for range 1000 {                                 // ~1 MiB through a 4 KiB buffer
		if _, err := o.Write(chunk); err != nil {
			t.Fatal(err)
		}
		want = append(want, chunk...)
	}
	stop()

	got := s.bytes()
	if !bytes.Equal(got, want) {
		t.Fatalf("backpressure lost or reordered bytes: sent %d, received %d", len(want), len(got))
	}
	st := o.Stats()
	if st.BytesDropped != 0 {
		t.Errorf("dropped %d bytes under backpressure", st.BytesDropped)
	}
	if st.Stalls == 0 {
		t.Error("the writer never stalled, so this test proved nothing")
	}
	// The rule, stated as a test: a shell stream never announces a drop, because it
	// never has one to announce.
	if s.throttleCount() != 0 {
		t.Errorf("THROTTLE was sent on a backpressure stream %d times", s.throttleCount())
	}
}

// TestEscapeSequencesSurviveIntact is the vi-shaped property, without needing a PTY
// yet: a full-screen program's control bytes must arrive byte-exact and in order.
// The real vi-under-flood test lands with E1.S6.
func TestEscapeSequencesSurviveIntact(t *testing.T) {
	s := &sink{}
	o := pump.NewOutput(pump.Options{
		Sink: s, Policy: pump.Backpressure,
		Limits: pump.Limits{Batch: 37, Window: time.Millisecond, // odd size, to split sequences
			HighWater: 256, LowWater: 64},
	})
	stop := run(t, o)

	var want bytes.Buffer
	for i := range 2000 {
		// Cursor moves, colours, erase-to-end — the sequences that corrupt a screen
		// if a byte goes missing from the middle of one.
		want.WriteString("\x1b[2J\x1b[H\x1b[1;32m")
		want.WriteString(strings.Repeat("▓", i%7))
		want.WriteString("\x1b[0m\x1b[K\r\n")
	}
	if _, err := o.Write(want.Bytes()); err != nil {
		t.Fatal(err)
	}
	stop()

	if got := s.bytes(); !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("escape sequences were corrupted: %d in, %d out", want.Len(), len(got))
	}
}

// ── the other policy ────────────────────────────────────────────────────────────

// TestDropAnnouncesExactly: a log firehose loses a line, the marker names the byte
// count, and the reader is no worse off — but only if the count is truthful.
func TestDropAnnouncesExactly(t *testing.T) {
	s := &sink{sendErr: nil}
	o := pump.NewOutput(pump.Options{
		Sink: s, Policy: pump.Drop,
		Limits: pump.Limits{Batch: 512, Window: time.Hour, // never flush on time
			HighWater: 1024, LowWater: 256},
	})
	// Deliberately not running the sender yet, so the buffer fills and drops start.
	var sent int64
	chunk := bytes.Repeat([]byte("l"), 256)
	for range 40 {
		n, err := o.Write(chunk)
		if err != nil {
			t.Fatal(err)
		}
		sent += int64(n)
	}
	st := o.Stats()
	if st.BytesDropped == 0 {
		t.Fatal("a full buffer under Drop dropped nothing")
	}
	if st.BytesIn != sent {
		t.Errorf("accounted %d bytes in, sent %d", st.BytesIn, sent)
	}
	// Nothing is lost from the accounting: what got buffered plus what got dropped
	// is everything that came in.
	stop := run(t, o)
	stop()
	after := o.Stats()
	if after.BytesOut+after.BytesDropped != after.BytesIn {
		t.Errorf("accounting does not balance: in=%d out=%d dropped=%d",
			after.BytesIn, after.BytesOut, after.BytesDropped)
	}
	if s.throttleCount() == 0 {
		t.Error("bytes were dropped and no THROTTLE was sent")
	}
	if s.droppedTotal() != after.BytesDropped {
		t.Errorf("announced %d dropped, actually dropped %d",
			s.droppedTotal(), after.BytesDropped)
	}
}

func TestDropNeverBlocksTheWriter(t *testing.T) {
	s := &sink{}
	o := pump.NewOutput(pump.Options{
		Sink: s, Policy: pump.Drop,
		Limits: pump.Limits{Batch: 128, Window: time.Hour, HighWater: 256, LowWater: 64},
	})
	// No sender at all: every write must still return promptly. A log stream that
	// blocks the device is worse than a log stream with a gap.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 1000 {
			_, _ = o.Write(bytes.Repeat([]byte("x"), 100))
		}
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Drop policy blocked the writer")
	}
}

// ── rate limiting ───────────────────────────────────────────────────────────────

func TestBurstIsAllowedThenRateApplies(t *testing.T) {
	s := &sink{}
	now := time.Now()
	clock := func() time.Time { return now }
	var slept time.Duration

	o := pump.NewOutput(pump.Options{
		Sink: s, Policy: pump.Backpressure,
		Limits: pump.Limits{Batch: 1024, Window: time.Millisecond,
			Rate: 10 << 10 /* 10 KiB/s */, Burst: 4 << 10,
			HighWater: 1 << 20, LowWater: 1 << 16},
		Now: clock,
		Sleep: func(_ context.Context, d time.Duration) error {
			// Advance the fake clock instead of really sleeping, so the bucket
			// refills deterministically.
			slept += d
			now = now.Add(d)
			return nil
		},
	})
	stop := run(t, o)

	// The first 4 KiB is the burst and must go straight out — a full-screen redraw
	// should not be throttled.
	if _, err := o.Write(bytes.Repeat([]byte("b"), 4<<10)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && o.Stats().BytesOut < 4<<10 {
		time.Sleep(time.Millisecond)
	}
	if slept != 0 {
		t.Errorf("the burst was throttled: slept %v", slept)
	}

	// The next 20 KiB has no tokens behind it, so the sender must wait roughly
	// 20 KiB / 10 KiB per second = 2 s of simulated time.
	if _, err := o.Write(bytes.Repeat([]byte("c"), 20<<10)); err != nil {
		t.Fatal(err)
	}
	stop()
	if slept < time.Second {
		t.Errorf("only slept %v for 20 KiB at 10 KiB/s", slept)
	}
	if got, want := o.Stats().BytesOut, int64(24<<10); got != want {
		t.Errorf("sent %d bytes, want %d — rate limiting must delay, not drop", got, want)
	}
}

func TestRateZeroDisablesLimiting(t *testing.T) {
	s := &sink{}
	o := pump.NewOutput(pump.Options{
		Sink: s, Policy: pump.Backpressure,
		Limits: pump.Limits{Batch: 4096, Window: time.Millisecond, Rate: 0,
			HighWater: 1 << 20, LowWater: 1 << 16},
		Sleep: func(context.Context, time.Duration) error {
			t.Fatal("slept with rate limiting disabled")
			return nil
		},
	})
	stop := run(t, o)
	if _, err := o.Write(bytes.Repeat([]byte("z"), 100<<10)); err != nil {
		t.Fatal(err)
	}
	stop()
	if got := o.Stats().BytesOut; got != 100<<10 {
		t.Errorf("sent %d of 102400", got)
	}
}

// ── policy table ────────────────────────────────────────────────────────────────

func TestPolicyForProfile(t *testing.T) {
	drop := []string{"log", "exec"}
	backpressure := []string{"shell", "sshpass", "file", "tcp", "", "something-new"}

	for _, p := range drop {
		if got := pump.PolicyFor(p); got != pump.Drop {
			t.Errorf("%q: got %v, want drop", p, got)
		}
	}
	for _, p := range backpressure {
		if got := pump.PolicyFor(p); got != pump.Backpressure {
			// Unknown profiles fail safe: slow rather than corrupt. A new profile
			// added without touching the table must not silently start losing bytes.
			t.Errorf("%q: got %v, want backpressure", p, got)
		}
	}
}

func TestTeeSeesEverythingIncludingDrops(t *testing.T) {
	// The recording says what the *device* produced, not what a slow operator
	// happened to see. A THROTTLE marker tells the operator their view had a gap;
	// the recording has none, so an auditor asking what a command printed gets the
	// real answer.
	s := &sink{}
	var teed []byte
	var mu sync.Mutex
	o := pump.NewOutput(pump.Options{
		Sink: s, Policy: pump.Drop,
		Limits: pump.Limits{Batch: 128, Window: time.Hour, HighWater: 256, LowWater: 64},
		Tee: func(b []byte) {
			mu.Lock()
			teed = append(teed, b...)
			mu.Unlock()
		},
	})
	var sent int
	for range 100 {
		n, _ := o.Write(bytes.Repeat([]byte("t"), 64))
		sent += n
	}
	mu.Lock()
	got := len(teed)
	mu.Unlock()
	if got != sent {
		t.Errorf("tee saw %d of %d bytes", got, sent)
	}
	if o.Stats().BytesDropped == 0 {
		t.Fatal("nothing was dropped, so this test proved nothing")
	}
}

func TestSinkErrorEndsTheRun(t *testing.T) {
	s := &sink{sendErr: context.Canceled}
	o := pump.NewOutput(pump.Options{
		Sink: s, Policy: pump.Backpressure,
		Limits: pump.Limits{Batch: 16, Window: time.Millisecond,
			HighWater: 1024, LowWater: 256},
	})
	errc := make(chan error, 1)
	go func() { errc <- o.Run(context.Background()) }()
	_, _ = o.Write([]byte("hello"))
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("Run returned nil after the sink failed")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run ignored a sink failure")
	}
}

func TestWriteAfterCloseFails(t *testing.T) {
	s := &sink{}
	o := pump.NewOutput(pump.Options{Sink: s, Policy: pump.Backpressure,
		Limits: pump.DefaultLimits()})
	stop := run(t, o)
	stop()
	if _, err := o.Write([]byte("x")); err == nil {
		t.Error("a write after Close succeeded")
	}
}
