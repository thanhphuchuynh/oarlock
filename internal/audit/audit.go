// Package audit contains built-in AuditSink implementations.
package audit

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oarlock/oarlock/pkg/plugin"
)

// Async is a bounded, non-blocking audit sink wrapper.
type Async struct {
	next plugin.AuditSink
	log  *slog.Logger

	ch      chan plugin.AuditEvent
	done    chan struct{}
	once    sync.Once
	dropped atomic.Int64
}

var _ plugin.AuditSink = (*Async)(nil)

// NewAsync wraps next in a bounded queue. buffer <= 0 uses a small default.
func NewAsync(next plugin.AuditSink, buffer int, log *slog.Logger) *Async {
	if next == nil {
		next = Discard{}
	}
	if buffer <= 0 {
		buffer = 1024
	}
	if log == nil {
		log = slog.Default()
	}
	a := &Async{
		next: next, log: log, ch: make(chan plugin.AuditEvent, buffer),
		done: make(chan struct{}),
	}
	go a.run()
	return a
}

// Emit never blocks the caller. A full queue increments Dropped.
func (a *Async) Emit(ctx context.Context, e plugin.AuditEvent) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	select {
	case a.ch <- e:
	case <-ctx.Done():
		a.dropped.Add(1)
	default:
		n := a.dropped.Add(1)
		if n == 1 || n&(n-1) == 0 {
			a.log.Warn("audit queue dropped events", "dropped", n)
		}
	}
}

// Dropped reports how many events could not be queued.
func (a *Async) Dropped() int64 { return a.dropped.Load() }

// Close drains queued events and stops the worker.
func (a *Async) Close() error {
	a.once.Do(func() {
		close(a.ch)
		<-a.done
	})
	return nil
}

func (a *Async) run() {
	defer close(a.done)
	for e := range a.ch {
		a.next.Emit(context.Background(), e)
	}
}

// Discard drops every event. Useful for tests and disabled audit.
type Discard struct{}

func (Discard) Emit(context.Context, plugin.AuditEvent) {}

// JSONL writes one JSON object per event.
type JSONL struct {
	mu sync.Mutex
	w  io.Writer
}

var _ plugin.AuditSink = (*JSONL)(nil)

func NewJSONL(w io.Writer) *JSONL { return &JSONL{w: w} }

func (j *JSONL) Emit(_ context.Context, e plugin.AuditEvent) {
	if j == nil || j.w == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	_ = json.NewEncoder(j.w).Encode(e)
}

// Memory records events for tests.
type Memory struct {
	mu     sync.Mutex
	Events []plugin.AuditEvent
}

var _ plugin.AuditSink = (*Memory)(nil)

func (m *Memory) Emit(_ context.Context, e plugin.AuditEvent) {
	m.mu.Lock()
	m.Events = append(m.Events, e)
	m.mu.Unlock()
}

func (m *Memory) Snapshot() []plugin.AuditEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]plugin.AuditEvent, len(m.Events))
	copy(out, m.Events)
	return out
}
