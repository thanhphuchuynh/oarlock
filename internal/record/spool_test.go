package record_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/record"
	"github.com/oarlock/oarlock/pkg/plugin"
)

// flakyStore is a Store whose writes can be turned off and on, standing in for
// object storage having a bad minute.
type flakyStore struct {
	mu       sync.Mutex
	body     bytes.Buffer
	manifest []byte
	failing  bool
	failures int
}

func (s *flakyStore) setFailing(v bool) {
	s.mu.Lock()
	s.failing = v
	s.mu.Unlock()
}

func (s *flakyStore) failureCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failures
}

func (s *flakyStore) stored() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.body.String()
}

func (s *flakyStore) Create(context.Context, *plugin.SessionMeta) (io.WriteCloser, error) {
	return &flakyWriter{s: s}, nil
}
func (s *flakyStore) PutManifest(_ context.Context, _ string, b []byte) error {
	s.mu.Lock()
	s.manifest = append([]byte(nil), b...)
	s.mu.Unlock()
	return nil
}
func (s *flakyStore) Get(context.Context, string) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader(s.stored())), nil
}
func (s *flakyStore) GetManifest(context.Context, string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.manifest == nil {
		return nil, record.ErrNotFound
	}
	return s.manifest, nil
}
func (s *flakyStore) URL(context.Context, string, time.Duration) (string, error) {
	return "", plugin.ErrUnsupported
}

type flakyWriter struct{ s *flakyStore }

func (w *flakyWriter) Write(p []byte) (int, error) {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	if w.s.failing {
		w.s.failures++
		// What object storage actually gives you.
		return 0, errors.New("503 Service Unavailable")
	}
	return w.s.body.Write(p)
}
func (w *flakyWriter) Close() error { return nil }

type auditLog struct {
	mu     sync.Mutex
	events []record.Event
}

func (a *auditLog) record(e record.Event) {
	a.mu.Lock()
	a.events = append(a.events, e)
	a.mu.Unlock()
}
func (a *auditLog) kinds() []record.EventKind {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]record.EventKind, len(a.events))
	for i, e := range a.events {
		out[i] = e.Kind
	}
	return out
}
func (a *auditLog) find(k record.EventKind) (record.Event, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.events {
		if e.Kind == k {
			return e, true
		}
	}
	return record.Event{}, false
}

// TestBackendOutageClosesZeroSessions is the acceptance criterion, and the reason
// the spool exists.
//
// Before it, "the recording must be written" meant a 503 from object storage closed
// every live session in the fleet — during the incident that put operators on the
// devices in the first place. The ratio here matches the shipped configuration: the
// store fails for a quarter of the deadline.
func TestBackendOutageClosesZeroSessions(t *testing.T) {
	ctx := context.Background()
	s, pub := signer(t)
	store := &flakyStore{}
	audit := &auditLog{}

	rec, err := record.New(record.Options{
		Store: store, Signer: s, Log: quietLog(),
		Spool: record.SpoolConfig{
			FlushDeadline: 2 * time.Second,
			RetryEvery:    20 * time.Millisecond,
			Audit:         audit.record,
			Log:           quietLog(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	w, err := rec.Open(ctx, meta())
	if err != nil {
		t.Fatal(err)
	}

	// Healthy, then a bad half-second, then healthy again — with output flowing the
	// whole time.
	write := func(from, to int) {
		for i := from; i < to; i++ {
			if err := w.Output(time.Duration(i)*time.Millisecond,
				[]byte(fmt.Sprintf("row %04d\r\n", i))); err != nil {
				t.Fatalf("event %d was refused during a store outage: %v", i, err)
			}
			time.Sleep(time.Millisecond)
		}
	}
	write(0, 50)
	store.setFailing(true)
	write(50, 300) // ~250 ms of writes with the store down
	time.Sleep(250 * time.Millisecond)
	store.setFailing(false)
	write(300, 400)

	code := 0
	if err := w.Close(ctx, plugin.RecordingResult{
		CloseReason: "device_close", ExitCode: &code, ClosedAt: time.Now()}); err != nil {
		t.Fatalf("Close reported a failure after a recovered outage: %v", err)
	}

	if store.failureCount() == 0 {
		t.Fatal("the store never actually failed; this test proved nothing")
	}
	// The operator noticed nothing, and the recording is complete.
	v, err := rec.Verify(ctx, meta().SessionID, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !v.OK {
		t.Fatalf("the recording did not verify after an outage: %s (%s)", v.Status, v.Detail)
	}
	if v.EventsFound != 400 {
		t.Errorf("%d of 400 events survived the outage", v.EventsFound)
	}

	// One degraded event, one recovered — not one per failed write.
	kinds := audit.kinds()
	if countKind(kinds, record.Degraded) != 1 {
		t.Errorf("degraded events: %v", kinds)
	}
	if countKind(kinds, record.Recovered) != 1 {
		t.Errorf("recovered events: %v", kinds)
	}
	if countKind(kinds, record.Failed) != 0 {
		t.Errorf("a recovered outage emitted a failure: %v", kinds)
	}
	if e, ok := audit.find(record.Degraded); ok && e.SessionID != meta().SessionID {
		t.Errorf("degraded event has session %q", e.SessionID)
	}
}

// TestDeadlineExhaustionClosesTheSession: the band is a tolerance, not a promise.
// Past it, the session must end rather than continue unrecorded.
func TestDeadlineExhaustionClosesTheSession(t *testing.T) {
	ctx := context.Background()
	s, _ := signer(t)
	store := &flakyStore{}
	audit := &auditLog{}
	dumpDir := t.TempDir()

	rec, err := record.New(record.Options{
		Store: store, Signer: s, Log: quietLog(),
		Spool: record.SpoolConfig{
			FlushDeadline: 150 * time.Millisecond,
			RetryEvery:    10 * time.Millisecond,
			Dir:           dumpDir,
			Audit:         audit.record,
			Log:           quietLog(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	w, err := rec.Open(ctx, meta())
	if err != nil {
		t.Fatal(err)
	}
	// Let the header reach the store, so the dumped fragment has a real offset.
	if err := w.Output(0, []byte("before the outage\r\n")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	store.setFailing(true)

	var last error
	deadline := time.Now().Add(5 * time.Second)
	for i := 1; time.Now().Before(deadline); i++ {
		last = w.Output(time.Duration(i)*time.Millisecond, []byte("during the outage\r\n"))
		if last != nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if last == nil {
		t.Fatal("the spool never gave up; the deadline is not being enforced")
	}
	if !errors.Is(last, record.ErrSpoolExhausted) {
		t.Fatalf("got %v, want ErrSpoolExhausted", last)
	}

	if _, ok := audit.find(record.Failed); !ok {
		t.Errorf("no failure event: %v", audit.kinds())
	}
	// The unflushed remainder is on disk, named with the offset it belongs at —
	// which is the only thing that makes recovery mechanical.
	dumped, ok := audit.find(record.Dumped)
	if !ok {
		t.Fatalf("nothing was dumped: %v", audit.kinds())
	}
	if _, err := os.Stat(dumped.Path); err != nil {
		t.Fatalf("the dumped fragment is not on disk: %v", err)
	}
	if !strings.Contains(filepath.Base(dumped.Path), fmt.Sprintf("offset-%d", dumped.Flushed)) {
		t.Errorf("fragment name %q does not carry its offset", filepath.Base(dumped.Path))
	}
}

// TestDumpedFragmentIsRecoverable proves the dump is worth writing: the prefix that
// reached the store plus the fragment appended at its offset is the original stream,
// and it verifies.
func TestDumpedFragmentIsRecoverable(t *testing.T) {
	ctx := context.Background()
	s, pub := signer(t)
	store := &flakyStore{}
	audit := &auditLog{}
	dumpDir := t.TempDir()

	rec, err := record.New(record.Options{
		Store: store, Signer: s, Log: quietLog(),
		Spool: record.SpoolConfig{
			FlushDeadline: 120 * time.Millisecond,
			RetryEvery:    10 * time.Millisecond,
			Dir:           dumpDir, Audit: audit.record, Log: quietLog(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	w, err := rec.Open(ctx, meta())
	if err != nil {
		t.Fatal(err)
	}
	for i := range 40 {
		if err := w.Output(time.Duration(i)*time.Millisecond,
			[]byte(fmt.Sprintf("pre %02d\r\n", i))); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(50 * time.Millisecond) // let it all land
	store.setFailing(true)
	for i := 40; i < 200; i++ {
		if err := w.Output(time.Duration(i)*time.Millisecond,
			[]byte(fmt.Sprintf("post %03d\r\n", i))); err != nil {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	// Close finalises the manifest even though the recording failed, because a
	// manifest for a partial recording is what makes the partial recording useful.
	_ = w.Close(ctx, plugin.RecordingResult{CloseReason: "recorder_failed", ClosedAt: time.Now()})

	dumped, ok := audit.find(record.Dumped)
	if !ok {
		t.Fatalf("nothing was dumped: %v", audit.kinds())
	}
	fragment, err := os.ReadFile(dumped.Path)
	if err != nil {
		t.Fatal(err)
	}
	prefix := store.stored()
	if int64(len(prefix)) != dumped.Flushed {
		t.Fatalf("the store holds %d bytes but the fragment claims offset %d",
			len(prefix), dumped.Flushed)
	}

	// Recovery, mechanically: prefix ‖ fragment.
	recovered := prefix + string(fragment)
	man, err := rec.Manifest(ctx, meta().SessionID)
	if err != nil {
		t.Fatal(err)
	}
	v, err := record.Verify(strings.NewReader(recovered), man, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !v.OK {
		t.Fatalf("the recovered recording did not verify: %s (%s)\nstore=%d fragment=%d",
			v.Status, v.Detail, len(prefix), len(fragment))
	}
	// And the store's own copy, without the fragment, reads as truncated rather
	// than as altered — which is the true description of what happened.
	vPartial, _ := record.Verify(strings.NewReader(prefix), man, pub)
	if vPartial.Status != record.StatusTruncated {
		t.Errorf("the partial recording reads as %s, want truncated", vPartial.Status)
	}
}

func TestSpoolByteCeilingIsEnforced(t *testing.T) {
	ctx := context.Background()
	s, _ := signer(t)
	store := &flakyStore{}
	audit := &auditLog{}
	rec, err := record.New(record.Options{
		Store: store, Signer: s, Log: quietLog(),
		Spool: record.SpoolConfig{
			MaxBytes:      4 << 10, // tiny, so the ceiling binds before the deadline
			FlushDeadline: time.Hour,
			RetryEvery:    time.Hour,
			Dir:           t.TempDir(), Audit: audit.record, Log: quietLog(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	w, err := rec.Open(ctx, meta())
	if err != nil {
		t.Fatal(err)
	}
	store.setFailing(true)

	var last error
	for i := range 2000 {
		last = w.Output(time.Duration(i)*time.Microsecond, bytes.Repeat([]byte("x"), 256))
		if last != nil {
			break
		}
	}
	if !errors.Is(last, record.ErrSpoolExhausted) {
		t.Fatalf("got %v, want ErrSpoolExhausted", last)
	}
	// Memory is bounded: the point of a ceiling is that a flood during an outage
	// cannot take the pod with it.
	if e, ok := audit.find(record.Failed); ok && e.Buffered > 8<<10 {
		t.Errorf("buffered %d bytes against a 4 KiB ceiling", e.Buffered)
	}
}

func TestSpoolingCanBeDisabled(t *testing.T) {
	ctx := context.Background()
	s, _ := signer(t)
	store := &flakyStore{}
	rec, err := record.New(record.Options{
		Store: store, Signer: s, Log: quietLog(),
		Spool: record.SpoolConfig{MaxBytes: -1, Log: quietLog()},
	})
	if err != nil {
		t.Fatal(err)
	}
	w, err := rec.Open(ctx, meta())
	if err != nil {
		t.Fatal(err)
	}
	store.setFailing(true)
	// No tolerance band: the first failed write is terminal. For anyone who would
	// rather a session end than run on a buffer.
	if err := w.Output(0, []byte("x")); err == nil {
		t.Fatal("a write succeeded with spooling disabled and the store failing")
	}
}

// TestOpenFailureRefusesTheSession: there is no silent unrecorded session.
func TestOpenFailureRefusesTheSession(t *testing.T) {
	ctx := context.Background()
	s, _ := signer(t)
	rec, err := record.New(record.Options{
		Store: &brokenStore{}, Signer: s, Log: quietLog()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rec.Open(ctx, meta()); err == nil {
		t.Fatal("Open succeeded against a store that cannot create anything")
	}
}

type brokenStore struct{ flakyStore }

func (b *brokenStore) Create(context.Context, *plugin.SessionMeta) (io.WriteCloser, error) {
	return nil, errors.New("bucket does not exist")
}

func TestNewValidates(t *testing.T) {
	s, _ := signer(t)
	if _, err := record.New(record.Options{Signer: s}); err == nil {
		t.Error("a recorder with no store was created")
	}
	if _, err := record.New(record.Options{Store: &flakyStore{}}); err == nil {
		t.Error("a recorder with no signer was created")
	}
}

func countKind(kinds []record.EventKind, want record.EventKind) int {
	n := 0
	for _, k := range kinds {
		if k == want {
			n++
		}
	}
	return n
}

func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}
