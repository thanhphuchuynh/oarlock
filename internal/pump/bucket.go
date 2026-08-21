package pump

import (
	"context"
	"time"
)

// bucket is a token bucket over bytes.
//
// Sustained rate with a burst allowance, because terminal output is bursty by
// nature: a full-screen redraw is 20 KiB in one instant and then nothing for a
// second. A flat per-interval cap would either throttle every redraw or have to be
// set so high it stops being a cap.
type bucket struct {
	rate   float64 // bytes per second; 0 disables
	burst  float64
	tokens float64
	last   time.Time
	now    func() time.Time
}

func newBucket(rate, burst int, now func() time.Time) *bucket {
	if now == nil {
		now = time.Now
	}
	return &bucket{
		rate:   float64(rate),
		burst:  float64(burst),
		tokens: float64(burst), // start full: the first redraw should not be throttled
		last:   now(),
		now:    now,
	}
}

func (b *bucket) refill() {
	if b.rate <= 0 {
		return
	}
	t := b.now()
	if elapsed := t.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.last = t
	}
}

// take removes up to n tokens and reports how many were available. Never blocks.
func (b *bucket) take(n int) int {
	if b.rate <= 0 {
		return n
	}
	b.refill()
	if b.tokens <= 0 {
		return 0
	}
	if float64(n) <= b.tokens {
		b.tokens -= float64(n)
		return n
	}
	got := int(b.tokens)
	b.tokens -= float64(got)
	return got
}

// wait blocks until n tokens are available, or ctx ends. Used by the backpressure
// policy: the excess travels back to the producer rather than into the bit bucket.
func (b *bucket) wait(ctx context.Context, n int, sleep func(context.Context, time.Duration) error) error {
	if b.rate <= 0 {
		return nil
	}
	if float64(n) > b.burst {
		// A single frame larger than the whole bucket would wait forever. Batch is
		// configured below Burst so this cannot happen in practice; clamp rather
		// than deadlock if someone reconfigures it.
		n = int(b.burst)
	}
	for {
		b.refill()
		if float64(n) <= b.tokens {
			b.tokens -= float64(n)
			return nil
		}
		need := (float64(n) - b.tokens) / b.rate
		d := time.Duration(need * float64(time.Second))
		if d < time.Millisecond {
			d = time.Millisecond
		}
		if err := sleep(ctx, d); err != nil {
			return err
		}
	}
}
