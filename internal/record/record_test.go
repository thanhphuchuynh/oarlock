package record_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/record"
	"github.com/oarlock/oarlock/pkg/plugin"
)

func signer(t *testing.T) (*record.KeySigner, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &record.KeySigner{Key: priv, ID: "recording-key-1"}, pub
}

func meta() *plugin.SessionMeta {
	return &plugin.SessionMeta{
		SessionID: "sess_test", DeviceID: "treadmill-4821", Profile: "shell",
		Mode: "gateway", Principal: "admin@mail.com",
		Term: "xterm-256color", Cols: 132, Rows: 38,
		StartedAt: time.Unix(1787218725, 0).UTC(),
	}
}

type recording struct {
	cast     *bytes.Buffer
	manifest record.Manifest
	writer   *record.Writer
}

func newRecording(t *testing.T, s record.Signer, m *plugin.SessionMeta) *recording {
	t.Helper()
	r := &recording{cast: &bytes.Buffer{}}
	w, err := record.NewWriter(record.WriterOptions{
		Out: r.cast, Meta: m, Signer: s,
		OnClose: func(_ context.Context, man record.Manifest) error {
			r.manifest = man
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	r.writer = w
	return r
}

// ── the format ──────────────────────────────────────────────────────────────────

// TestHeaderMatchesTheV3Spec pins the shape of the first line. A durable file format
// is not somewhere to be approximately right.
func TestHeaderMatchesTheV3Spec(t *testing.T) {
	s, _ := signer(t)
	r := newRecording(t, s, meta())
	if err := r.writer.Close(context.Background(), plugin.RecordingResult{}); err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimRight(r.cast.String(), "\n"), "\n")
	var h struct {
		Version int `json:"version"`
		Term    struct {
			Cols int    `json:"cols"`
			Rows int    `json:"rows"`
			Type string `json:"type"`
		} `json:"term"`
		Timestamp int64  `json:"timestamp"`
		Title     string `json:"title"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &h); err != nil {
		t.Fatalf("header is not JSON: %v\n%s", err, lines[0])
	}
	if h.Version != 3 {
		t.Errorf("version %d, want 3", h.Version)
	}
	if h.Term.Cols != 132 || h.Term.Rows != 38 || h.Term.Type != "xterm-256color" {
		t.Errorf("term %+v", h.Term)
	}
	if h.Timestamp != 1787218725 {
		t.Errorf("timestamp %d", h.Timestamp)
	}
	// The .cast may travel further than its sidecar, so it carries enough to be
	// identified — but not the name of the person recorded.
	if !strings.Contains(h.Title, "treadmill-4821") {
		t.Errorf("title %q", h.Title)
	}
	if strings.Contains(r.cast.String(), "admin@mail.com") {
		t.Error("the principal was written into the .cast")
	}
}

// TestEventsAreIntervalsNotOffsets is why v3: an interval-encoded stream can be
// resumed mid-session without rewriting what was already flushed, which is exactly
// what a spooling recorder does when its backend comes back.
func TestEventsAreIntervalsNotOffsets(t *testing.T) {
	s, _ := signer(t)
	r := newRecording(t, s, meta())

	_ = r.writer.Output(1*time.Second, []byte("one"))
	_ = r.writer.Output(3*time.Second, []byte("two"))
	_ = r.writer.Output(3500*time.Millisecond, []byte("three"))
	_ = r.writer.Close(context.Background(), plugin.RecordingResult{})

	events := eventsOf(t, r.cast.String())
	want := []struct {
		interval float64
		code     string
		data     string
	}{
		{1.0, "o", "one"},
		{2.0, "o", "two"},   // 3s - 1s
		{0.5, "o", "three"}, // 3.5s - 3s
	}
	if len(events) != len(want) {
		t.Fatalf("%d events, want %d", len(events), len(want))
	}
	for i, w := range want {
		if events[i].interval != w.interval || events[i].code != w.code || events[i].data != w.data {
			t.Errorf("event %d: %+v, want %+v", i, events[i], w)
		}
	}
}

func TestResizeAndExitEvents(t *testing.T) {
	s, _ := signer(t)
	r := newRecording(t, s, meta())
	_ = r.writer.Output(0, []byte("$ "))
	_ = r.writer.Resize(time.Second, 90, 30)
	_ = r.writer.Exit(2*time.Second, 7)
	_ = r.writer.Close(context.Background(), plugin.RecordingResult{})

	events := eventsOf(t, r.cast.String())
	// The v3 spec is specific about these: resize is "COLSxROWS", exit is the code
	// as a string.
	found := map[string]string{}
	for _, e := range events {
		found[e.code] = e.data
	}
	if found["r"] != "90x30" {
		t.Errorf("resize data %q, want 90x30", found["r"])
	}
	if found["x"] != "7" {
		t.Errorf("exit data %q, want \"7\"", found["x"])
	}
}

// TestInputIsOmittedUnlessPolicyAllowsIt: keystroke capture makes a recording a
// credential store, so the writer refuses to do it unless it was asked.
func TestInputIsOmittedUnlessPolicyAllowsIt(t *testing.T) {
	s, _ := signer(t)

	off := newRecording(t, s, meta())
	_ = off.writer.Input(time.Second, []byte("sudo -S\nhunter2\n"))
	_ = off.writer.Output(2*time.Second, []byte("ok"))
	_ = off.writer.Close(context.Background(), plugin.RecordingResult{})
	if strings.Contains(off.cast.String(), "hunter2") {
		t.Fatal("input was recorded with record_input off")
	}
	if off.manifest.Counts.InputBytes != 0 {
		t.Errorf("input bytes %d", off.manifest.Counts.InputBytes)
	}

	m := meta()
	m.RecordInput = true
	on := newRecording(t, s, m)
	_ = on.writer.Input(time.Second, []byte("whoami\n"))
	_ = on.writer.Close(context.Background(), plugin.RecordingResult{})
	if !strings.Contains(on.cast.String(), "whoami") {
		t.Fatal("input was not recorded with record_input on")
	}
	if !on.manifest.RecordInput {
		t.Error("the manifest does not record that input was captured")
	}
}

// TestTruncatedFileStillPlays is the reason the writer flushes per event rather than
// buffering: a gateway killed mid-session must leave a file that plays up to the
// last event.
func TestTruncatedFileStillPlays(t *testing.T) {
	s, _ := signer(t)
	r := newRecording(t, s, meta())
	for i := range 20 {
		if err := r.writer.Output(time.Duration(i)*time.Second,
			[]byte(fmt.Sprintf("line %d\r\n", i))); err != nil {
			t.Fatal(err)
		}
	}
	// No Close: simulate the process dying. Every event written so far must already
	// be on the other side of the buffer.
	full := r.cast.String()
	lines := strings.Split(strings.TrimRight(full, "\n"), "\n")
	if len(lines) < 21 {
		t.Fatalf("only %d lines survived without a Close; events are not being flushed", len(lines))
	}
	// Cut mid-file and confirm every remaining line is parseable.
	cut := strings.Join(lines[:12], "\n") + "\n"
	if got := len(eventsOf(t, cut)); got == 0 {
		t.Fatal("a truncated file yielded no events")
	}
}

// ── the chain ───────────────────────────────────────────────────────────────────

func TestValidRecordingVerifies(t *testing.T) {
	s, pub := signer(t)
	r := newRecording(t, s, meta())
	for i := range 300 {
		_ = r.writer.Output(time.Duration(i)*time.Millisecond, []byte(fmt.Sprintf("l%d\r\n", i)))
	}
	_ = r.writer.Resize(time.Second, 90, 30)
	_ = r.writer.Exit(2*time.Second, 0)
	if err := r.writer.Close(context.Background(), plugin.RecordingResult{
		CloseReason: "device_close", ClosedAt: time.Unix(1787218800, 0)}); err != nil {
		t.Fatal(err)
	}

	v, err := record.Verify(strings.NewReader(r.cast.String()), r.manifest, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !v.OK || v.Status != record.StatusValid {
		t.Fatalf("verdict: %s (%s)", v.Status, v.Detail)
	}
	if v.EventsFound != 302 || v.EventsFound != v.EventsExpected {
		t.Errorf("events found %d, expected %d", v.EventsFound, v.EventsExpected)
	}
	if r.manifest.Counts.OutputBytes == 0 || r.manifest.Counts.Resizes != 1 {
		t.Errorf("counts: %+v", r.manifest.Counts)
	}
	if r.manifest.CloseReason != "device_close" {
		t.Errorf("close reason %q", r.manifest.CloseReason)
	}
}

// TestAlteredByteIsDetected — the PCI requirement in one test.
func TestAlteredByteIsDetected(t *testing.T) {
	s, pub := signer(t)
	r := newRecording(t, s, meta())
	for i := range 50 {
		_ = r.writer.Output(time.Duration(i)*time.Millisecond, []byte(fmt.Sprintf("l%d\r\n", i)))
	}
	_ = r.writer.Close(context.Background(), plugin.RecordingResult{})

	tampered := strings.Replace(r.cast.String(), "l7\\r\\n", "l9\\r\\n", 1)
	if tampered == r.cast.String() {
		t.Fatal("the test did not actually change anything")
	}
	v, err := record.Verify(strings.NewReader(tampered), r.manifest, pub)
	if err != nil {
		t.Fatal(err)
	}
	if v.OK || v.Status != record.StatusAltered {
		t.Fatalf("an altered recording verified as %s", v.Status)
	}
}

// TestTruncationIsDistinguishedFromAlteration is E9.S1's acceptance criterion, and
// the reason checkpoints exist: "this file stops early" and "somebody edited this
// file" lead somewhere completely different.
func TestTruncationIsDistinguishedFromAlteration(t *testing.T) {
	s, pub := signer(t)
	r := newRecording(t, s, meta())
	for i := range 400 {
		_ = r.writer.Output(time.Duration(i)*time.Millisecond, []byte(fmt.Sprintf("l%03d\r\n", i)))
	}
	_ = r.writer.Close(context.Background(), plugin.RecordingResult{})

	full := r.cast.String()
	lines := strings.Split(strings.TrimRight(full, "\n"), "\n")

	t.Run("truncated", func(t *testing.T) {
		cut := strings.Join(lines[:200], "\n") + "\n"
		v, err := record.Verify(strings.NewReader(cut), r.manifest, pub)
		if err != nil {
			t.Fatal(err)
		}
		if v.Status != record.StatusTruncated {
			t.Fatalf("verdict %s (%s), want truncated", v.Status, v.Detail)
		}
		if v.LastGoodCheckpoint == 0 {
			t.Error("no checkpoint verified, so the report cannot say where it stopped")
		}
		if v.EventsFound >= v.EventsExpected {
			t.Errorf("found %d of %d", v.EventsFound, v.EventsExpected)
		}
	})

	t.Run("removed from the middle", func(t *testing.T) {
		// Same event count as truncation would give, but the content is wrong — so
		// the verdict has to be different.
		spliced := append([]string{}, lines[:50]...)
		spliced = append(spliced, lines[60:]...)
		v, err := record.Verify(strings.NewReader(strings.Join(spliced, "\n")+"\n"),
			r.manifest, pub)
		if err != nil {
			t.Fatal(err)
		}
		if v.Status != record.StatusAltered {
			t.Fatalf("verdict %s (%s), want altered", v.Status, v.Detail)
		}
	})

	t.Run("reordered", func(t *testing.T) {
		swapped := append([]string{}, lines...)
		swapped[10], swapped[11] = swapped[11], swapped[10]
		v, err := record.Verify(strings.NewReader(strings.Join(swapped, "\n")+"\n"),
			r.manifest, pub)
		if err != nil {
			t.Fatal(err)
		}
		if v.Status != record.StatusAltered {
			t.Fatalf("reordering was not detected: %s", v.Status)
		}
	})
}

// TestSignatureIsCheckedFirst: if the manifest is not ours, its head and counts are
// attacker-chosen, and comparing the file against them proves nothing.
func TestSignatureIsCheckedFirst(t *testing.T) {
	s, pub := signer(t)
	r := newRecording(t, s, meta())
	_ = r.writer.Output(0, []byte("hello"))
	_ = r.writer.Close(context.Background(), plugin.RecordingResult{})

	t.Run("wrong key", func(t *testing.T) {
		otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
		v, _ := record.Verify(strings.NewReader(r.cast.String()), r.manifest, otherPub)
		if v.Status != record.StatusBadSignature {
			t.Fatalf("verdict %s", v.Status)
		}
	})

	t.Run("forged manifest", func(t *testing.T) {
		// An attacker rewrites the recording *and* the sidecar to match. Without the
		// key the signature cannot be reproduced, so the forgery is caught before
		// the chain is even walked.
		forged := r.manifest
		forged.Chain.Head = strings.Repeat("ab", 32)
		forged.Chain.Events = 1
		v, _ := record.Verify(strings.NewReader("{\"version\":3}\n[0,\"o\",\"lies\"]\n"),
			forged, pub)
		if v.Status != record.StatusBadSignature {
			t.Fatalf("a forged manifest produced %s, not bad_signature", v.Status)
		}
	})

	t.Run("unsigned", func(t *testing.T) {
		unsigned := r.manifest
		unsigned.Signature = nil
		v, _ := record.Verify(strings.NewReader(r.cast.String()), unsigned, pub)
		if v.Status != record.StatusBadSignature {
			t.Fatalf("verdict %s", v.Status)
		}
	})
}

func TestManifestRoundTrips(t *testing.T) {
	s, pub := signer(t)
	r := newRecording(t, s, meta())
	_ = r.writer.Output(0, []byte("x"))
	code := 3
	_ = r.writer.Close(context.Background(), plugin.RecordingResult{
		CloseReason: "operator_close", ExitCode: &code, BytesDropped: 12})

	b, err := record.EncodeManifest(r.manifest)
	if err != nil {
		t.Fatal(err)
	}
	back, err := record.DecodeManifest(b)
	if err != nil {
		t.Fatal(err)
	}
	// The signature must survive an encode/decode cycle, or a manifest read from
	// disk verifies as forged.
	if err := back.VerifySignature(pub); err != nil {
		t.Fatalf("a round-tripped manifest failed to verify: %v", err)
	}
	if back.ExitCode == nil || *back.ExitCode != 3 || back.BytesDropped != 12 {
		t.Errorf("fields lost: %+v", back)
	}
	if back.Signature.KeyID != "recording-key-1" {
		t.Errorf("key id %q — a signature nobody can attribute to a key is one nobody can check",
			back.Signature.KeyID)
	}
	if _, err := record.DecodeManifest([]byte(`{"oarlock_manifest":99}`)); err == nil {
		t.Error("a future manifest version was accepted")
	}
}

func TestWriterRequiresASigner(t *testing.T) {
	// An unsigned manifest is a chain anyone with write access can recompute, which
	// is not integrity — so this is a hard requirement, not a default.
	_, err := record.NewWriter(record.WriterOptions{
		Out: &bytes.Buffer{}, Meta: meta(), Signer: nil})
	if err == nil {
		t.Fatal("a writer with no signer was created")
	}
	if !strings.Contains(err.Error(), "Signer is required") {
		t.Errorf("unhelpful error: %v", err)
	}
}

func TestWriteAfterCloseFails(t *testing.T) {
	s, _ := signer(t)
	r := newRecording(t, s, meta())
	_ = r.writer.Close(context.Background(), plugin.RecordingResult{})
	if err := r.writer.Output(time.Second, []byte("late")); err == nil {
		t.Error("a write after Close succeeded")
	}
	// Close twice is a no-op, because it runs from a defer that may also have run
	// on the error path.
	if err := r.writer.Close(context.Background(), plugin.RecordingResult{}); err != nil {
		t.Errorf("second Close returned %v", err)
	}
}

func TestNonMonotonicTimeDoesNotProduceNegativeIntervals(t *testing.T) {
	s, pub := signer(t)
	r := newRecording(t, s, meta())
	_ = r.writer.Output(5*time.Second, []byte("later"))
	_ = r.writer.Output(2*time.Second, []byte("earlier")) // clock went backwards
	_ = r.writer.Close(context.Background(), plugin.RecordingResult{})

	for _, e := range eventsOf(t, r.cast.String()) {
		if e.interval < 0 {
			t.Fatalf("negative interval %v; no player handles that sensibly", e.interval)
		}
	}
	v, _ := record.Verify(strings.NewReader(r.cast.String()), r.manifest, pub)
	if !v.OK {
		t.Errorf("verdict %s", v.Status)
	}
}

// ── the file backend ────────────────────────────────────────────────────────────

func TestFileRecorderEndToEnd(t *testing.T) {
	ctx := context.Background()
	s, pub := signer(t)
	dir := t.TempDir()
	rec, err := record.NewFileRecorder(dir, s)
	if err != nil {
		t.Fatal(err)
	}

	m := meta()
	w, err := rec.Open(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 200 {
		if err := w.Output(time.Duration(i)*time.Millisecond,
			[]byte(fmt.Sprintf("\x1b[1;32mrow %03d\x1b[0m\r\n", i))); err != nil {
			t.Fatal(err)
		}
	}
	code := 0
	if err := w.Close(ctx, plugin.RecordingResult{
		CloseReason: "device_close", ExitCode: &code, ClosedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	v, err := rec.Verify(ctx, m.SessionID, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !v.OK {
		t.Fatalf("verdict %s (%s)", v.Status, v.Detail)
	}

	// Both halves are on disk, under a dated directory.
	day := m.StartedAt.UTC().Format("2006-01-02")
	for _, ext := range []string{".cast", ".json"} {
		p := filepath.Join(dir, day, m.SessionID+ext)
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s missing: %v", p, err)
		}
	}
	// No leftover temp file: a half-written sidecar is worse than none.
	if entries, _ := filepath.Glob(filepath.Join(dir, day, "*.tmp")); len(entries) != 0 {
		t.Errorf("temp files left behind: %v", entries)
	}

	rc, err := rec.Get(ctx, m.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	first, _ := bufio.NewReader(rc).ReadString('\n')
	if !strings.Contains(first, `"version":3`) {
		t.Errorf("first line: %q", first)
	}
}

func TestFileRecorderRefusesDuplicateSession(t *testing.T) {
	ctx := context.Background()
	s, _ := signer(t)
	rec, _ := record.NewFileRecorder(t.TempDir(), s)
	m := meta()
	if _, err := rec.Open(ctx, m); err != nil {
		t.Fatal(err)
	}
	// Two writers for one session id would interleave into a file that verifies as
	// neither.
	if _, err := rec.Open(ctx, m); err == nil {
		t.Fatal("a second writer for the same session was allowed")
	}
}

func TestFileRecorderRejectsUnsafeSessionID(t *testing.T) {
	ctx := context.Background()
	s, _ := signer(t)
	rec, _ := record.NewFileRecorder(t.TempDir(), s)
	for _, id := range []string{"../escape", "a/b", ""} {
		if _, err := rec.Get(ctx, id); err == nil {
			t.Errorf("Get accepted %q", id)
		}
	}
}

func TestFileRecorderNotFoundAndURL(t *testing.T) {
	ctx := context.Background()
	s, _ := signer(t)
	rec, _ := record.NewFileRecorder(t.TempDir(), s)
	if _, err := rec.Get(ctx, "sess_missing"); err == nil {
		t.Error("Get found a recording that does not exist")
	}
	if _, err := rec.URL(ctx, "sess_missing", time.Minute); err == nil {
		t.Error("URL invented a link for a local directory")
	}
}

func TestNewFileRecorderValidates(t *testing.T) {
	s, _ := signer(t)
	if _, err := record.NewFileRecorder("", s); err == nil {
		t.Error("an empty dir was accepted")
	}
	if _, err := record.NewFileRecorder(t.TempDir(), nil); err == nil {
		t.Error("a recorder with no signer was created")
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────────

type event struct {
	interval float64
	code     string
	data     string
}

// eventsOf parses the event lines, skipping comments the way the v3 spec says a
// reader must.
func eventsOf(t *testing.T, cast string) []event {
	t.Helper()
	var out []event
	for i, line := range strings.Split(strings.TrimRight(cast, "\n"), "\n") {
		if i == 0 || line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var raw []any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			t.Fatalf("event line %d is not JSON: %v\n%s", i, err, line)
		}
		if len(raw) != 3 {
			t.Fatalf("event line %d has %d elements, want 3", i, len(raw))
		}
		iv, ok := raw[0].(float64)
		if !ok {
			t.Fatalf("event line %d: interval is %T", i, raw[0])
		}
		out = append(out, event{iv, raw[1].(string), raw[2].(string)})
	}
	return out
}

// ── immutability (E9.S4) ────────────────────────────────────────────────────────

// TestFileStoreReportsItselfMutable: a directory cannot promise anything, and saying
// so honestly is what makes the warning meaningful when a store *can*.
func TestFileStoreReportsItselfMutable(t *testing.T) {
	store, err := record.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	im, err := store.Immutability(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if im.Mode != record.ModeMutable {
		t.Errorf("mode %q, want mutable", im.Mode)
	}
	if im.Mode.Protected() {
		t.Error("a plain directory reported itself protected")
	}
	if im.Kind != "file" || im.Detail == "" {
		t.Errorf("report is not useful to a human: %+v", im)
	}
}

// TestDeclaredProtectionIsRecordedAsDeclared: an operator saying the directory is
// append-only is worth recording and must never be recorded as a lock.
func TestDeclaredProtectionIsRecordedAsDeclared(t *testing.T) {
	store, err := record.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.Declared = true
	store.DeclaredWhat = "chattr +a, verified by the platform team"
	store.DeclaredFor = 90 * 24 * time.Hour

	im, err := store.Immutability(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if im.Mode != record.ModeDeclared {
		t.Fatalf("mode %q, want declared", im.Mode)
	}
	// Declared counts as protected — it is better than nothing — but it is never
	// reported as governance or compliance, because nothing checked it.
	if !im.Mode.Protected() {
		t.Error("a declaration should count as protection")
	}
	for _, lock := range []record.Mode{record.ModeGovernance, record.ModeCompliance} {
		if im.Mode == lock {
			t.Errorf("an unverified declaration was reported as %q", lock)
		}
	}
	if im.RetainFor == 0 || im.Detail == "" {
		t.Errorf("the declaration lost its detail: %+v", im)
	}
}

// TestManifestRecordsTheStorageGuarantee is the point of E9.S4: a chain proves the
// bytes have not changed, and this says what stood between them and a change. An
// auditor two years later should not have to guess whether the bucket had object lock
// on in 2026.
func TestManifestRecordsTheStorageGuarantee(t *testing.T) {
	ctx := context.Background()
	s, pub := signer(t)
	store, err := record.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.Declared = true
	store.DeclaredWhat = "WORM appliance over NFS"

	rec, err := record.New(record.Options{Store: store, Signer: s, Log: quietLog()})
	if err != nil {
		t.Fatal(err)
	}
	if !rec.Immutability().Mode.Protected() {
		t.Fatalf("recorder reported %q", rec.Immutability().Mode)
	}

	m := meta()
	w, err := rec.Open(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Output(0, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(ctx, plugin.RecordingResult{CloseReason: "device_close"}); err != nil {
		t.Fatal(err)
	}

	man, err := rec.Manifest(ctx, m.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if man.Storage.Mode != record.ModeDeclared {
		t.Errorf("manifest storage mode %q", man.Storage.Mode)
	}
	if man.Storage.Detail != "WORM appliance over NFS" {
		t.Errorf("manifest storage detail %q", man.Storage.Detail)
	}
	// And it is inside the signed bytes, so the claim cannot be edited afterwards
	// without breaking the signature.
	if err := man.VerifySignature(pub); err != nil {
		t.Fatal(err)
	}
	tampered := man
	tampered.Storage.Mode = record.ModeCompliance
	if err := tampered.VerifySignature(pub); err == nil {
		t.Fatal("the storage guarantee can be upgraded after the fact without " +
			"breaking the signature")
	}
}

// TestUnreportingStoreIsTreatedAsMutable: silence is not a guarantee.
func TestUnreportingStoreIsTreatedAsMutable(t *testing.T) {
	ctx := context.Background()
	s, _ := signer(t)
	rec, err := record.New(record.Options{
		Store: &flakyStore{}, Signer: s, Log: quietLog()}) // implements no reporter
	if err != nil {
		t.Fatal(err)
	}
	im := rec.Immutability()
	if im.Mode != record.ModeUnknown {
		t.Errorf("mode %q, want unknown", im.Mode)
	}
	if im.Mode.Protected() {
		t.Error("a store that reports nothing was treated as protected")
	}
	_ = ctx
}
