package pump

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// Sink is where shaped output goes — the operator connection, in production.
type Sink interface {
	// SendData sends one DATA batch. It must not retain b.
	SendData(ctx context.Context, b []byte) error
	// SendThrottle announces dropped bytes. Only ever called under Policy Drop.
	SendThrottle(ctx context.Context, dropped int64) error
}

// Options configure an Output.
type Options struct {
	Sink    Sink
	Policy  Policy
	Limits  Limits
	Profile string

	// Tee receives every byte accepted into the pump, including bytes the live view
	// drops. The Session wires this to the recorder.
	//
	// That asymmetry is deliberate: the recording should say what the *device*
	// produced, not what a slow operator happened to see. A THROTTLE marker tells
	// the operator their view was incomplete; the recording has no such gap, and an
	// auditor asking "what did that command print" gets the real answer. The cost is
	// that a flood pushes into the recorder's spool instead of the bit bucket, which
	// is bounded there (E2.S2) rather than here.
	Tee func(b []byte)

	// Now is injectable for tests.
	Now func() time.Time
	// Sleep is injectable for tests. Defaults to a context-aware timer.
	Sleep func(context.Context, time.Duration) error
}

// Stats is what an operator or a metric wants to know.
type Stats struct {
	BytesIn      int64
	BytesOut     int64
	BytesDropped int64
	Batches      int64
	Throttles    int64
	Stalls       int64 // times backpressure engaged
}

// Output shapes device→operator bytes: coalesce, rate-limit, then apply the
// profile's policy when the operator cannot keep up.
type Output struct {
	o      Options
	lim    Limits
	bucket *bucket

	mu       sync.Mutex
	cond     *sync.Cond
	buf      []byte
	since    time.Time // when the oldest buffered byte arrived
	closed   bool
	stalling bool

	// dropped is the queue of *unannounced* drops: Run swaps it to zero when it
	// emits a THROTTLE. droppedTotal is the running total, which is what a metric
	// wants. Conflating the two was a bug in the first draft of this file.
	dropped      atomic.Int64
	droppedTotal atomic.Int64

	stats struct {
		in, out, batches, throttles, stalls atomic.Int64
	}

	done chan struct{}
	err  atomic.Pointer[error]
}

var ErrOutputClosed = errors.New("pump: output closed")

// NewOutput returns an Output. Run must be called for anything to be sent.
func NewOutput(o Options) *Output {
	lim := o.Limits.withDefaults()
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Sleep == nil {
		o.Sleep = sleepCtx
	}
	out := &Output{
		o:      o,
		lim:    lim,
		bucket: newBucket(lim.Rate, lim.Burst, o.Now),
		done:   make(chan struct{}),
	}
	out.cond = sync.NewCond(&out.mu)
	return out
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Write accepts device output.
//
// Under Backpressure it **blocks** once the buffer passes HighWater, and that is
// the whole mechanism: the caller is the goroutine reading the device connection,
// so blocking here stops reading, which stalls the agent's own PTY write. Under
// Drop it discards and counts instead.
func (o *Output) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	o.stats.in.Add(int64(len(p)))
	if o.o.Tee != nil {
		o.o.Tee(p)
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	if o.o.Policy == Drop {
		if len(o.buf)+len(p) > o.lim.HighWater {
			// Drop the incoming chunk rather than evicting what is already queued.
			// The reader then sees a contiguous run followed by a marker, instead of
			// a hole in the middle of what they were reading. The alternative —
			// dropping the oldest to stay current — suits a live tail better, and is
			// worth revisiting when there is a log viewer to have an opinion.
			o.dropped.Add(int64(len(p)))
			o.droppedTotal.Add(int64(len(p)))
			o.cond.Broadcast()
			return len(p), nil
		}
	} else {
		for !o.closed && len(o.buf) >= o.lim.HighWater {
			if !o.stalling {
				o.stalling = true
				o.stats.stalls.Add(1)
			}
			o.cond.Wait()
		}
	}
	if o.closed {
		return 0, ErrOutputClosed
	}

	if len(o.buf) == 0 {
		o.since = o.o.Now()
	}
	o.buf = append(o.buf, p...)
	o.cond.Broadcast()
	return len(p), nil
}

// Run sends batches until ctx ends or Close is called.
func (o *Output) Run(ctx context.Context) error {
	defer close(o.done)
	for {
		batch, drops, closed := o.next(ctx)
		if drops > 0 {
			o.stats.throttles.Add(1)
			if err := o.o.Sink.SendThrottle(ctx, drops); err != nil {
				return o.fail(err)
			}
		}
		if len(batch) > 0 {
			if err := o.emit(ctx, batch); err != nil {
				return o.fail(err)
			}
		}
		if closed && len(batch) == 0 && drops == 0 {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

// next waits for a batch worth sending: either the buffer reached Batch, or the
// coalescing window elapsed since the oldest byte arrived.
func (o *Output) next(ctx context.Context) (batch []byte, drops int64, closed bool) {
	o.mu.Lock()
	defer o.mu.Unlock()

	for {
		if d := o.dropped.Swap(0); d > 0 {
			return nil, d, o.closed
		}
		if len(o.buf) >= o.lim.Batch {
			return o.takeLocked(), 0, o.closed
		}
		if len(o.buf) > 0 {
			waited := o.o.Now().Sub(o.since)
			if waited >= o.lim.Window {
				return o.takeLocked(), 0, o.closed
			}
			// Wait out the remainder of the window, but wake early if the buffer
			// fills or the stream closes.
			o.waitFor(ctx, o.lim.Window-waited)
			continue
		}
		if o.closed {
			return nil, 0, true
		}
		o.waitFor(ctx, 0)
		if ctx.Err() != nil {
			return nil, 0, true
		}
	}
}

// waitFor releases the lock and waits for a signal, a timeout, or ctx. sync.Cond
// has no timed wait, so a timer goroutine broadcasts.
func (o *Output) waitFor(ctx context.Context, d time.Duration) {
	stop := make(chan struct{})
	if d > 0 {
		t := time.AfterFunc(d, func() {
			o.mu.Lock()
			o.cond.Broadcast()
			o.mu.Unlock()
		})
		defer t.Stop()
	}
	go func() {
		select {
		case <-ctx.Done():
			o.mu.Lock()
			o.cond.Broadcast()
			o.mu.Unlock()
		case <-stop:
		}
	}()
	o.cond.Wait()
	close(stop)
}

func (o *Output) takeLocked() []byte {
	n := min(len(o.buf), o.lim.Batch)
	batch := make([]byte, n)
	copy(batch, o.buf[:n])
	o.buf = o.buf[:copy(o.buf, o.buf[n:])]
	if len(o.buf) == 0 {
		o.since = time.Time{}
	} else {
		o.since = o.o.Now()
	}
	// Release a stalled writer once the buffer has drained past the low-water mark.
	// Hysteresis, not the same mark: releasing where it engaged makes the reader
	// oscillate one byte at a time.
	if o.stalling && len(o.buf) <= o.lim.LowWater {
		o.stalling = false
		o.cond.Broadcast()
	}
	return batch
}

func (o *Output) emit(ctx context.Context, batch []byte) error {
	switch o.o.Policy {
	case Backpressure:
		// Wait for tokens. The excess travels back to the producer rather than into
		// the bit bucket, which is what "a shell never drops" means in practice.
		if err := o.bucket.wait(ctx, len(batch), o.o.Sleep); err != nil {
			return err
		}
	case Drop:
		if got := o.bucket.take(len(batch)); got < len(batch) {
			o.dropped.Add(int64(len(batch) - got))
			o.droppedTotal.Add(int64(len(batch) - got))
			batch = batch[:got]
			if len(batch) == 0 {
				return nil
			}
		}
	}
	if err := o.o.Sink.SendData(ctx, batch); err != nil {
		return err
	}
	o.stats.out.Add(int64(len(batch)))
	o.stats.batches.Add(1)
	return nil
}

func (o *Output) fail(err error) error {
	o.err.CompareAndSwap(nil, &err)
	return err
}

// Close stops accepting writes and lets Run drain what is buffered.
func (o *Output) Close() {
	o.mu.Lock()
	o.closed = true
	o.cond.Broadcast()
	o.mu.Unlock()
}

// Wait blocks until Run has returned.
func (o *Output) Wait() { <-o.done }

// Stats returns a snapshot.
func (o *Output) Stats() Stats {
	return Stats{
		BytesIn:      o.stats.in.Load(),
		BytesOut:     o.stats.out.Load(),
		BytesDropped: o.droppedTotal.Load(),
		Batches:      o.stats.batches.Load(),
		Throttles:    o.stats.throttles.Load(),
		Stalls:       o.stats.stalls.Load(),
	}
}
