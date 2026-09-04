package record_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/record"
	"github.com/oarlock/oarlock/pkg/plugin"
)

var updateFixtures = flag.Bool("update-fixtures", false,
	"rewrite the shared recording fixtures")

// The fixtures are shared with the browser's replay component, which has to render an
// integrity verdict above every recording it plays. Testing that with a hand-written
// "tampered" file would test the hand-writing: the interesting cases are what an *actual*
// truncation and an *actual* edit produce, including how the hash chain and the
// checkpoints respond to them.
//
// So they are produced here, by the real recorder, and then damaged in the specific ways
// the verifier distinguishes.
const fixtureDir = "../../tests/fixtures/recordings"

type recordingFixture struct {
	Name string `json:"name"`
	// What Verify says about it. The component renders from these fields.
	Status             string `json:"status"`
	OK                 bool   `json:"ok"`
	EventsFound        int    `json:"events_found"`
	EventsExpected     int    `json:"events_expected"`
	LastGoodCheckpoint int    `json:"last_good_checkpoint"`
	// Cast and Manifest are the files themselves, base64, so one fixture file carries
	// everything the component needs to play and verify.
	Cast     string `json:"cast"`
	Manifest string `json:"manifest"`
	// PublicKey is the key the manifest should verify against.
	PublicKey string `json:"public_key"`
	// Note says what was done to it, for whoever reads the fixture later.
	Note string `json:"note"`
}

// buildLongRecording makes a recording that crosses a checkpoint, so the fixtures cover
// the field that turns "this file is wrong" into "intact up to event 128 and then stops".
// A five-event session never reaches one.
func buildLongRecording(t *testing.T) (cast []byte, manifest []byte, pub ed25519.PublicKey) {
	t.Helper()
	pub, priv := fixtureKey(0x22)
	rec, err := record.NewFileRecorder(t.TempDir(),
		&record.KeySigner{Key: priv, ID: "fixture-key"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	started := time.Date(2026, 8, 21, 11, 0, 0, 0, time.UTC)
	w, err := rec.Open(ctx, &plugin.SessionMeta{
		SessionID: "sess_long", DeviceID: "treadmill-4821", Profile: "shell",
		Mode: "gateway", Principal: "admin@mail.com",
		Term: "xterm-256color", Cols: 80, Rows: 24, StartedAt: started,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Comfortably past one checkpoint, so a truncation after it leaves a verifiable
	// prefix behind.
	for i := range record.CheckpointEvery + 40 {
		at := time.Duration(i) * 50 * time.Millisecond
		if err := w.Output(at, []byte(fmt.Sprintf("line %03d of a long session\r\n", i))); err != nil {
			t.Fatal(err)
		}
	}
	code := 0
	if err := w.Close(ctx, plugin.RecordingResult{
		CloseReason: "operator_close", ExitCode: &code,
		ClosedAt: started.Add(10 * time.Second),
	}); err != nil {
		t.Fatal(err)
	}

	rc, err := rec.Get(ctx, "sess_long")
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if cast, err = io.ReadAll(rc); err != nil {
		t.Fatal(err)
	}
	m, err := rec.Manifest(ctx, "sess_long")
	if err != nil {
		t.Fatal(err)
	}
	if manifest, err = json.Marshal(m); err != nil {
		t.Fatal(err)
	}
	return cast, manifest, pub
}

// fixtureKey is a deterministic signing key.
//
// Random keys make the fixture unreproducible: every regeneration produces a different
// signature and a different public key, so the staleness check can never pass and the
// generated file churns on every run. A fixed seed makes the fixture a *fixture*.
//
// Obviously not a key for anything real. It exists so that a signature over known bytes
// is itself known.
func fixtureKey(seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed + byte(i)
	}
	priv := ed25519.NewKeyFromSeed(s)
	return priv.Public().(ed25519.PublicKey), priv
}

// build makes one real recording and returns both halves.
func buildRecording(t *testing.T) (cast []byte, manifest []byte, pub ed25519.PublicKey) {
	t.Helper()
	pub, priv := fixtureKey(0x11)
	dir := t.TempDir()
	rec, err := record.NewFileRecorder(dir, &record.KeySigner{Key: priv, ID: "fixture-key"})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	started := time.Date(2026, 8, 21, 10, 14, 2, 0, time.UTC)
	w, err := rec.Open(ctx, &plugin.SessionMeta{
		SessionID: "sess_fixture", DeviceID: "treadmill-4821", Profile: "shell",
		Mode: "gateway", Principal: "admin@mail.com",
		Term: "xterm-256color", Cols: 80, Rows: 24, StartedAt: started,
	})
	if err != nil {
		t.Fatal(err)
	}

	// A short but realistic session: a prompt, a command, colourful output, an exit.
	at := time.Duration(0)
	write := func(after time.Duration, s string) {
		at += after
		if err := w.Output(at, []byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	write(120*time.Millisecond, "\x1b[1;32mphuc@treadmill-4821\x1b[0m:~$ ")
	write(900*time.Millisecond, "uptime\r\n")
	write(80*time.Millisecond, " 10:14:03 up 6 days,  3:22,  1 user,  load average: 0.14\r\n")
	write(40*time.Millisecond, "\x1b[1;32mphuc@treadmill-4821\x1b[0m:~$ ")
	write(1200*time.Millisecond, "exit\r\n")

	code := 0
	if err := w.Close(ctx, plugin.RecordingResult{
		CloseReason: "operator_close", ExitCode: &code,
		ClosedAt: started.Add(3 * time.Second),
	}); err != nil {
		t.Fatal(err)
	}

	rc, err := rec.Get(ctx, "sess_fixture")
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	cast, err = io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	m, err := rec.Manifest(ctx, "sess_fixture")
	if err != nil {
		t.Fatal(err)
	}
	manifest, err = json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return cast, manifest, pub
}

// TestRecordingFixturesAreCurrent generates the recordings the browser's replay tests
// read, and fails when they are stale.
//
// Regenerate with: go test ./internal/record/ -run TestRecordingFixtures -update-fixtures
func TestRecordingFixturesAreCurrent(t *testing.T) {
	cast, manifest, pub := buildRecording(t)
	longCast, longManifest, longPub := buildLongRecording(t)

	fixtures := []recordingFixture{
		mk(t, "valid", cast, manifest, pub,
			"Untouched. The chain reaches the signed head with the expected count."),

		// A truncation: the process died mid-write. Everything present is intact, which
		// is exactly what makes it different from an edit — and what lets the UI say
		// "intact up to here" rather than "this file is wrong".
		mk(t, "truncated", truncateEvents(cast, 2), manifest, pub,
			"The last events are missing, as though the gateway was killed mid-session."),

		// An edit: somebody changed what the command printed. The count still matches,
		// so only the chain catches it.
		mk(t, "altered", alterOutput(t, cast, "load average: 0.14", "load average: 9.99"),
			manifest, pub,
			"One line of output was edited, leaving the event count unchanged."),

		// A whole event removed from the middle: the count is short *and* the chain
		// breaks, which is a different signature from a clean truncation.
		mk(t, "altered-middle", dropEvent(cast, 3), manifest, pub,
			"An event was removed from the middle of the file."),

		// The manifest is real but signed by somebody else's key.
		mk(t, "bad-signature", cast, manifest, otherKey(t),
			"Verified against a different public key, as though the manifest were not ours."),

		mk(t, "malformed", []byte("this is not an asciicast\n{{{\n"), manifest, pub,
			"Not a readable asciicast at all."),

		// Long enough to have crossed a checkpoint before being cut. This is the case
		// that lets a UI say "intact up to event 128" rather than only "wrong", and a
		// five-event recording cannot produce it.
		mk(t, "truncated-after-checkpoint", truncateEvents(longCast, 30), longManifest, longPub,
			"Cut after a checkpoint, so a verifiable prefix survives."),
		mk(t, "valid-long", longCast, longManifest, longPub,
			"A longer untouched recording, past one checkpoint."),
	}

	out, err := json.MarshalIndent(map[string]any{
		"$comment": "GENERATED by internal/record/fixtures_test.go -update-fixtures. " +
			"Real recordings, damaged in the specific ways internal/record/verify.go " +
			"distinguishes. Shared with the browser's replay component.",
		"recordings": fixtures,
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')

	path := filepath.Join(fixtureDir, "verdicts.json")
	if *updateFixtures {
		if err := os.MkdirAll(fixtureDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, out, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", path)
		return
	}
	have, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v\n\nRegenerate with: go test ./internal/record/ "+
			"-run TestRecordingFixtures -update-fixtures", err)
	}
	if string(have) != string(out) {
		t.Errorf("%s is stale — the recorder or the verifier changed and the fixtures "+
			"did not.\nThe browser's replay tests read this file, so leaving it stale "+
			"means the component is being tested against a format the gateway no longer "+
			"produces.\n\nRegenerate with: go test ./internal/record/ "+
			"-run TestRecordingFixtures -update-fixtures", path)
	}
}

// mk verifies a damaged recording and records what the verifier said about it.
//
// The expected verdict is *computed*, not asserted: the fixture's job is to carry the
// truth to another language, and writing the expectations by hand here would mean the
// browser was being tested against my beliefs rather than against the verifier.
func mk(t *testing.T, name string, cast, manifest []byte, pub ed25519.PublicKey,
	note string) recordingFixture {
	t.Helper()
	m, err := record.DecodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	v, err := record.Verify(strings.NewReader(string(cast)), m, pub)
	if err != nil && v.Status == "" {
		t.Fatalf("%s: %v", name, err)
	}
	return recordingFixture{
		Name: name, Status: string(v.Status), OK: v.OK,
		EventsFound: v.EventsFound, EventsExpected: v.EventsExpected,
		LastGoodCheckpoint: v.LastGoodCheckpoint,
		Cast:               base64.StdEncoding.EncodeToString(cast),
		Manifest:           base64.StdEncoding.EncodeToString(manifest),
		PublicKey:          base64.StdEncoding.EncodeToString(pub),
		Note:               note,
	}
}

// truncateEvents drops the last n event lines, keeping the header.
func truncateEvents(cast []byte, n int) []byte {
	lines := strings.Split(strings.TrimRight(string(cast), "\n"), "\n")
	if len(lines) <= n+1 {
		return cast
	}
	return []byte(strings.Join(lines[:len(lines)-n], "\n") + "\n")
}

// dropEvent removes one event line from the middle.
func dropEvent(cast []byte, at int) []byte {
	lines := strings.Split(strings.TrimRight(string(cast), "\n"), "\n")
	if at <= 0 || at >= len(lines) {
		return cast
	}
	out := append([]string{}, lines[:at]...)
	out = append(out, lines[at+1:]...)
	return []byte(strings.Join(out, "\n") + "\n")
}

// alterOutput edits the content of an event without changing the event count.
func alterOutput(t *testing.T, cast []byte, from, to string) []byte {
	t.Helper()
	// The cast holds JSON-escaped strings, so the substitution has to survive encoding.
	enc := func(s string) string {
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Trim(string(b), `"`)
	}
	out := strings.Replace(string(cast), enc(from), enc(to), 1)
	if out == string(cast) {
		t.Fatalf("alterOutput changed nothing: %q is not in the cast", from)
	}
	if len(out) != len(cast) {
		// Length-preserving on purpose: a different length would also change the
		// event's own bytes in a way that muddies which check caught it.
		t.Fatalf("the substitution changed the file length (%d → %d)", len(cast), len(out))
	}
	return []byte(out)
}

func otherKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _ := fixtureKey(0x33)
	return pub
}
