package backoff_test

import (
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/backoff"
)

// fixed returns a deterministic rnd, so the jitter can be pinned. A schedule whose
// randomness cannot be pinned is a schedule nobody verifies.
func fixed(v float64) func() float64 { return func() float64 { return v } }

func TestGrowsAndCaps(t *testing.T) {
	p := backoff.Policy{Base: time.Second, Cap: time.Minute, Factor: 1.6, Jitter: 0}
	want := []time.Duration{
		1000 * time.Millisecond,
		1600 * time.Millisecond,
		2560 * time.Millisecond,
		4096 * time.Millisecond,
	}
	for i, w := range want {
		if got := p.Delay(i, fixed(0.5)); got != w {
			t.Errorf("attempt %d: got %v, want %v", i, got, w)
		}
	}
	// The cap must hold however far the exponent runs — including where the naive
	// float would overflow to +Inf.
	for _, attempt := range []int{20, 100, 10000} {
		if got := p.Delay(attempt, fixed(0.5)); got != time.Minute {
			t.Errorf("attempt %d: got %v, want the cap %v", attempt, got, time.Minute)
		}
	}
}

func TestJitterStaysInBand(t *testing.T) {
	p := backoff.Default
	for _, attempt := range []int{0, 1, 5, 50} {
		lo := p.Delay(attempt, fixed(0))   // -25 %
		mid := p.Delay(attempt, fixed(.5)) // centre
		hi := p.Delay(attempt, fixed(1))   // +25 %
		if lo >= mid || mid >= hi {
			t.Errorf("attempt %d: jitter is not ordered: %v %v %v", attempt, lo, mid, hi)
		}
		if got, want := float64(lo)/float64(mid), 0.75; !approx(got, want) {
			t.Errorf("attempt %d: low end is %.3f of centre, want %.2f", attempt, got, want)
		}
		if got, want := float64(hi)/float64(mid), 1.25; !approx(got, want) {
			t.Errorf("attempt %d: high end is %.3f of centre, want %.2f", attempt, got, want)
		}
	}
}

// TestJitterDispersesTheHerd is the property the jitter exists for. Every agent in
// a persistent fleet loses its channel at the same instant when a replica goes
// away; without spread they all come back at the same instant and the replacement
// meets the whole fleet at once.
func TestJitterDispersesTheHerd(t *testing.T) {
	p := backoff.Default
	seen := map[time.Duration]int{}
	const fleet = 500
	for i := range fleet {
		// A distinct stream per agent, as each device's own PRNG would give.
		v := float64(i) / float64(fleet)
		seen[p.Delay(3, fixed(v))]++
	}
	if len(seen) < fleet/2 {
		t.Fatalf("500 agents produced only %d distinct delays", len(seen))
	}
	var lo, hi time.Duration = 1 << 62, 0
	for d := range seen {
		lo = min(lo, d)
		hi = max(hi, d)
	}
	// Half a second of spread at attempt 3 is the difference between a spike and a
	// ramp.
	if hi-lo < 500*time.Millisecond {
		t.Errorf("spread is only %v", hi-lo)
	}
}

func TestZeroJitterIsDeterministic(t *testing.T) {
	p := backoff.Policy{Base: time.Second, Cap: time.Minute, Factor: 2, Jitter: 0}
	if p.Delay(2, fixed(0)) != p.Delay(2, fixed(1)) {
		t.Error("jitter 0 still varied with rnd")
	}
}

func TestDefaultsFillIn(t *testing.T) {
	// The zero Policy must be usable, so a Config that never mentions backoff still
	// reconnects sanely instead of hot-looping.
	var p backoff.Policy
	d := p.Delay(0, fixed(0.5))
	if d != backoff.Default.Base {
		t.Errorf("zero policy: attempt 0 is %v, want %v", d, backoff.Default.Base)
	}
	if got := p.Delay(100, fixed(0.5)); got != backoff.Default.Cap {
		t.Errorf("zero policy: capped at %v, want %v", got, backoff.Default.Cap)
	}
	// A negative attempt must not produce a negative or absurd delay.
	if got := p.Delay(-5, fixed(0.5)); got != backoff.Default.Base {
		t.Errorf("negative attempt: %v", got)
	}
	// Nil rnd must work.
	if got := p.Delay(1, nil); got <= 0 {
		t.Errorf("nil rnd produced %v", got)
	}
}

func TestJitterClampedToUnitRange(t *testing.T) {
	// A misconfigured jitter must not produce a negative delay, which would become
	// a hot reconnect loop.
	p := backoff.Policy{Base: time.Second, Cap: time.Minute, Factor: 2, Jitter: 5}
	for _, v := range []float64{0, 0.5, 1} {
		if d := p.Delay(0, fixed(v)); d < 0 {
			t.Errorf("jitter 5 produced %v", d)
		}
	}
}

func TestSleeperResetsOnSuccess(t *testing.T) {
	s := &backoff.Sleeper{Policy: backoff.Policy{Base: time.Second, Cap: time.Minute,
		Factor: 2, Jitter: 0}, Rand: fixed(0.5)}

	first := s.Next()
	second := s.Next()
	if second <= first {
		t.Fatalf("not growing: %v then %v", first, second)
	}
	if s.Attempt() != 2 {
		t.Errorf("attempt is %d, want 2", s.Attempt())
	}

	// Reset belongs after a successful *handshake*, not a successful dial: a gateway
	// that accepts connections and rejects every handshake would otherwise be
	// hammered at the base interval forever.
	s.Reset()
	if s.Attempt() != 0 {
		t.Errorf("attempt is %d after Reset, want 0", s.Attempt())
	}
	if again := s.Next(); again != first {
		t.Errorf("after Reset got %v, want %v", again, first)
	}
}

func approx(a, b float64) bool { return a > b-0.01 && a < b+0.01 }
