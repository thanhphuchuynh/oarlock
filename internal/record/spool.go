package record

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Spool defaults.
//
// The pair of them is the tolerance band, and the band is the whole point: without
// one, "the recording must be written" means object storage's bad minute closes
// every session in the fleet — during the incident that put operators on the
// devices in the first place.
const (
	DefaultSpoolBytes    = 64 << 20 // 64 MiB per session
	DefaultFlushDeadline = 60 * time.Second
)

// SpoolConfig configures the buffer between the encoder and the store.
type SpoolConfig struct {
	// MaxBytes is how much unflushed recording may accumulate. Zero means
	// DefaultSpoolBytes. Negative disables spooling entirely, so a write error is
	// immediately terminal.
	MaxBytes int64
	// FlushDeadline is how long the store may be failing before the session is
	// given up on. Zero means DefaultFlushDeadline.
	FlushDeadline time.Duration
	// Dir is where an exhausted spool is dumped. Empty means the fragment is lost,
	// which is worth a warning: the point of the dump is that the part of the
	// recording that never reached storage is still recoverable.
	Dir string

	// RetryEvery is how often a failing store is retried.
	RetryEvery time.Duration
	// Audit receives degraded, recovered and failed events. Recording failures are
	// exactly what an operator wants alerting on.
	Audit func(Event)
	Log   *slog.Logger
	Now   func() time.Time
}

// EventKind names a spool event.
type EventKind string

const (
	// Degraded: the store started failing. The operator notices nothing.
	Degraded EventKind = "recorder.degraded"
	// Recovered: it came back inside the tolerance band.
	Recovered EventKind = "recorder.recovered"
	// Failed: the band is exhausted and the session is being closed.
	Failed EventKind = "recorder.failed"
	// Dumped: the unflushed remainder was written to Dir.
	Dumped EventKind = "recorder.spool_dumped"
)

// Event is what Audit receives.
type Event struct {
	Kind      EventKind
	SessionID string
	// Buffered is unflushed bytes at the time of the event.
	Buffered int64
	// Flushed is how much reached the store, which is also the offset a dumped
	// fragment belongs at.
	Flushed int64
	// DegradedFor is how long the store had been failing.
	DegradedFor time.Duration
	Path        string // for Dumped
	Err         error
}

// ErrSpoolExhausted is returned once the tolerance band is spent. It reaches the
// pump through the recording writer and closes the session as recorder_failed.
var ErrSpoolExhausted = errors.New("record: spool exhausted")

// spool is a bounded, retrying io.WriteCloser in front of a store.
//
// Writes never block on the store: they land in a buffer and a drainer forwards
// them. That is what makes a failing backend invisible to the operator — the
// alternative is a keystroke waiting on S3.
type spool struct {
	sink      io.WriteCloser
	cfg       SpoolConfig
	sessionID string
	log       *slog.Logger

	mu       sync.Mutex
	cond     *sync.Cond
	buf      []byte
	flushed  int64
	degraded time.Time // zero when healthy
	fatal    error
	closing  bool
	closed   bool

	done chan struct{}
}

func newSpool(sink io.WriteCloser, sessionID string, cfg SpoolConfig) *spool {
	if cfg.MaxBytes == 0 {
		cfg.MaxBytes = DefaultSpoolBytes
	}
	if cfg.FlushDeadline <= 0 {
		cfg.FlushDeadline = DefaultFlushDeadline
	}
	if cfg.RetryEvery <= 0 {
		cfg.RetryEvery = 250 * time.Millisecond
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	s := &spool{
		sink: sink, cfg: cfg, sessionID: sessionID,
		log:  cfg.Log.With("session", sessionID),
		done: make(chan struct{}),
	}
	s.cond = sync.NewCond(&s.mu)
	go s.drain()
	return s
}

// Write buffers. It returns an error only once the tolerance band is spent, which
// is the one case the session must not survive.
func (s *spool) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.fatal != nil {
		return 0, s.fatal
	}
	if s.closed {
		return 0, errors.New("record: spool is closed")
	}
	if s.cfg.MaxBytes < 0 {
		// Spooling disabled: hand it to the store now, so a failure is immediate.
		// Written under the lock rather than releasing and re-acquiring it — that
		// dance around a deferred unlock is exactly how a double-unlock gets
		// introduced by the next edit.
		n, err := s.sink.Write(p)
		if err != nil {
			s.fail(err)
			return n, s.fatal
		}
		s.flushed += int64(n)
		return n, nil
	}

	if int64(len(s.buf))+int64(len(p)) > s.cfg.MaxBytes {
		s.fail(fmt.Errorf("%w: %d buffered bytes exceeds %d",
			ErrSpoolExhausted, int64(len(s.buf))+int64(len(p)), s.cfg.MaxBytes))
		return 0, s.fatal
	}
	s.buf = append(s.buf, p...)
	s.cond.Broadcast()
	return len(p), nil
}

// drain forwards buffered bytes to the store, retrying while it is failing.
func (s *spool) drain() {
	defer close(s.done)
	for {
		s.mu.Lock()
		for len(s.buf) == 0 && !s.closing && s.fatal == nil {
			s.cond.Wait()
		}
		if s.fatal != nil || (s.closing && len(s.buf) == 0) {
			s.mu.Unlock()
			return
		}
		chunk := s.buf
		s.buf = nil
		s.mu.Unlock()

		n, err := s.sink.Write(chunk)

		s.mu.Lock()
		s.flushed += int64(n)
		switch {
		case err == nil:
			if !s.degraded.IsZero() {
				for_ := s.cfg.Now().Sub(s.degraded)
				s.degraded = time.Time{}
				s.log.Info("recording store recovered", "degraded_for", for_)
				s.emit(Event{Kind: Recovered, Flushed: s.flushed, DegradedFor: for_})
			}
			s.cond.Broadcast()
			s.mu.Unlock()

		default:
			// Put back whatever did not land, in order, ahead of anything new.
			s.buf = append(chunk[n:], s.buf...)
			if s.degraded.IsZero() {
				s.degraded = s.cfg.Now()
				s.log.Warn("recording store is failing; buffering",
					"error", err, "buffered", len(s.buf))
				s.emit(Event{Kind: Degraded, Buffered: int64(len(s.buf)),
					Flushed: s.flushed, Err: err})
			}
			// The deadline is measured from when the store *started* failing, not
			// from the last attempt: a store that fails, briefly succeeds, and fails
			// again should not reset the clock forever.
			if degradedFor := s.cfg.Now().Sub(s.degraded); degradedFor > s.cfg.FlushDeadline {
				s.fail(fmt.Errorf("%w: store failing for %v: %w",
					ErrSpoolExhausted, degradedFor.Round(time.Millisecond), err))
				s.mu.Unlock()
				return
			}
			retry := s.cfg.RetryEvery
			s.mu.Unlock()
			time.Sleep(retry)
		}
	}
}

// fail marks the spool spent and dumps the unflushed remainder. Callers hold the
// lock.
func (s *spool) fail(err error) {
	if s.fatal != nil {
		return
	}
	s.fatal = err
	degradedFor := time.Duration(0)
	if !s.degraded.IsZero() {
		degradedFor = s.cfg.Now().Sub(s.degraded)
	}
	s.log.Error("recording failed; the session will be closed",
		"error", err, "buffered", len(s.buf), "flushed", s.flushed)
	s.emit(Event{Kind: Failed, Buffered: int64(len(s.buf)), Flushed: s.flushed,
		DegradedFor: degradedFor, Err: err})
	s.dumpLocked()
	s.cond.Broadcast()
}

// dumpLocked writes the unflushed remainder where it can be recovered from.
//
// The filename carries the offset it belongs at, because that is the only thing
// that makes recovery mechanical: append this fragment to whatever reached the store
// at exactly that byte position and the chain verifies again.
func (s *spool) dumpLocked() {
	if len(s.buf) == 0 {
		return
	}
	if s.cfg.Dir == "" {
		s.log.Warn("no spool dir configured; the unflushed remainder is lost",
			"bytes", len(s.buf))
		return
	}
	if err := os.MkdirAll(s.cfg.Dir, 0o700); err != nil {
		s.log.Error("could not create the spool dir", "dir", s.cfg.Dir, "error", err)
		return
	}
	name := fmt.Sprintf("%s.offset-%d.castfragment", s.sessionID, s.flushed)
	path := filepath.Join(s.cfg.Dir, name)
	if err := os.WriteFile(path, s.buf, 0o600); err != nil {
		s.log.Error("could not dump the spool", "path", path, "error", err)
		return
	}
	s.log.Warn("dumped the unflushed recording", "path", path, "bytes", len(s.buf))
	s.emit(Event{Kind: Dumped, Buffered: int64(len(s.buf)), Flushed: s.flushed, Path: path})
}

func (s *spool) emit(e Event) {
	if s.cfg.Audit == nil {
		return
	}
	e.SessionID = s.sessionID
	// Called with the lock held, so the callback must not re-enter. Documented on
	// SpoolConfig.Audit; keep it to a metric or a queue push.
	s.cfg.Audit(e)
}

// Close drains what is left, then closes the store's writer.
func (s *spool) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closing = true
	s.cond.Broadcast()
	s.mu.Unlock()

	// Bounded wait: a store that is failing at close time must not hold the session
	// teardown open indefinitely.
	select {
	case <-s.done:
	case <-time.After(s.cfg.FlushDeadline):
	}

	s.mu.Lock()
	s.closed = true
	fatal := s.fatal
	if fatal == nil && len(s.buf) > 0 {
		// Never flushed and no fatal error: the drainer ran out of time. Dump it —
		// silently dropping the tail of a recording is the failure this whole
		// mechanism exists to prevent.
		s.fail(fmt.Errorf("%w: %d bytes unflushed at close", ErrSpoolExhausted, len(s.buf)))
		fatal = s.fatal
	}
	s.mu.Unlock()

	return errors.Join(fatal, s.sink.Close())
}

// Err returns the fatal error, if any.
func (s *spool) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fatal
}

// Buffered is the unflushed byte count, for metrics.
func (s *spool) Buffered() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return int64(len(s.buf))
}
