package agent_test

// The device's half of the `log` profile.
//
// The allow-list is the feature. Everything else here is a tailer, and a tailer is only
// interesting where it is wrong in a way nobody notices: a rotated file that goes silent, a
// line long enough to buffer the device out of memory, a history read that scans a log
// nobody wanted.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oarlock/oarlock/agent"
)

// collector is an io.Writer a test can read while the tailer is still writing.
type collector struct {
	mu sync.Mutex
	b  strings.Builder
}

func (c *collector) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.b.Write(p)
}

func (c *collector) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.b.String()
}

func writeLog(t *testing.T, path string, lines ...string) {
	t.Helper()
	body := ""
	for _, l := range lines {
		body += l + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func appendLog(t *testing.T, path string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, l := range lines {
		if _, err := f.WriteString(l + "\n"); err != nil {
			t.Fatal(err)
		}
	}
}

func eventually(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(msg)
}

// ── the allow-list ──────────────────────────────────────────────────────────────

// TestOnlyPublishedSourcesCanBeRead.
//
// The gateway names a source, not a path, and this map is the whole set. A gateway that
// could name a path would have an arbitrary-file-read on every device in the fleet — which
// is the one thing this profile is designed not to be.
func TestOnlyPublishedSourcesCanBeRead(t *testing.T) {
	dir := t.TempDir()
	published := filepath.Join(dir, "app.log")
	secret := filepath.Join(dir, "secrets.env")
	writeLog(t, published, "hello")
	writeLog(t, secret, "AWS_SECRET_ACCESS_KEY=hunter2")

	tail := agent.Logs(map[string]string{"app": published})

	var out collector
	if err := tail(context.Background(), agent.LogRequest{Source: "app"}, &out); err != nil {
		t.Fatalf("a published source was refused: %v", err)
	}
	if !strings.Contains(out.String(), "hello") {
		t.Fatalf("the published source was not read: %q", out.String())
	}

	// Every way of asking for something else.
	for _, name := range []string{
		"secrets.env",
		secret,
		"../secrets.env",
		filepath.Join(dir, "secrets.env"),
		"/etc/passwd",
		"app/../secrets.env",
	} {
		var got collector
		err := tail(context.Background(), agent.LogRequest{Source: name}, &got)
		if err == nil {
			t.Fatalf("source %q was served: %q", name, got.String())
		}
		if !errors.Is(err, agent.ErrNoSuchSource) {
			t.Fatalf("source %q was refused with %v, want ErrNoSuchSource", name, err)
		}
		if got.String() != "" {
			t.Fatalf("source %q was refused but still wrote %q", name, got.String())
		}
	}
}

// TestARefusalDoesNotSayWhy.
//
// A name that is not published and a name that does not exist get the same error. Telling
// them apart would let a gateway walk the device's filesystem one guess at a time — and
// the gateway is the party this allow-list exists to constrain.
func TestARefusalDoesNotSayWhy(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.log")
	writeLog(t, real, "x")

	// `hidden` exists on disk and is not published; `imaginary` does not exist at all.
	if err := os.WriteFile(filepath.Join(dir, "hidden.log"), []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}
	tail := agent.Logs(map[string]string{"real": real})

	var a, b collector
	errHidden := tail(context.Background(), agent.LogRequest{Source: "hidden"}, &a)
	errNothing := tail(context.Background(), agent.LogRequest{Source: "imaginary"}, &b)

	if errHidden == nil || errNothing == nil {
		t.Fatal("an unpublished source was served")
	}
	if errHidden.Error() == errNothing.Error() {
		return // identical, which is the point
	}
	// They differ only in the name echoed back, which the caller already knew.
	if strings.Replace(errHidden.Error(), "hidden", "X", 1) !=
		strings.Replace(errNothing.Error(), "imaginary", "X", 1) {
		t.Fatalf("a caller can tell these apart:\n  %v\n  %v", errHidden, errNothing)
	}
}

// TestNoSourcesMeansNoLogFunc. How a build says it has nothing worth exposing — and then
// leaves "log" out of Caps, so the gateway refuses at open time rather than after a round
// trip.
func TestNoSourcesMeansNoLogFunc(t *testing.T) {
	if agent.Logs(nil) != nil {
		t.Fatal("a nil map produced a tailer")
	}
	if agent.Logs(map[string]string{}) != nil {
		t.Fatal("an empty map produced a tailer")
	}
	// A map holding only nonsense is an empty allow-list, not a working one.
	if agent.Logs(map[string]string{"": "/var/log/x", "y": ""}) != nil {
		t.Fatal("a map of empty entries produced a tailer")
	}
}

// TestTheAllowListIsFixedAtConstruction. A caller that kept its map and edited it later
// would be changing what the device serves at runtime, from outside the agent.
func TestTheAllowListIsFixedAtConstruction(t *testing.T) {
	dir := t.TempDir()
	published := filepath.Join(dir, "app.log")
	secret := filepath.Join(dir, "secrets.env")
	writeLog(t, published, "hello")
	writeLog(t, secret, "secret")

	sources := map[string]string{"app": published}
	tail := agent.Logs(sources)
	sources["secrets"] = secret // too late

	var out collector
	if err := tail(context.Background(), agent.LogRequest{Source: "secrets"}, &out); err == nil {
		t.Fatal("a source added after construction was served")
	}
}

// ── the tailer ──────────────────────────────────────────────────────────────────

// TestHistoryIsBoundedToWhatWasAsked. A device's log can be large and the device was chosen
// for being cheap; sending all of it because nobody said a number is how an agent gets
// killed by the OOM reaper.
func TestHistoryIsBoundedToWhatWasAsked(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	var lines []string
	for i := range 500 {
		lines = append(lines, "line-"+strconv.Itoa(i))
	}
	writeLog(t, path, lines...)

	tail := agent.Logs(map[string]string{"app": path})
	var out collector
	if err := tail(context.Background(), agent.LogRequest{Source: "app", Lines: 10}, &out); err != nil {
		t.Fatal(err)
	}

	got := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(got) != 10 {
		t.Fatalf("sent %d lines, want 10", len(got))
	}
	// The *last* ten, because a log reader wants what just happened.
	if got[0] != "line-490" || got[9] != "line-499" {
		t.Fatalf("sent %q … %q, want the last ten", got[0], got[9])
	}
}

// TestNegativeLinesSendsOnlyWhatHappensNext. How to ask for a tail with no history, which
// is what a script watching for an event wants.
func TestNegativeLinesSendsOnlyWhatHappensNext(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	writeLog(t, path, "old-1", "old-2")

	tail := agent.Logs(map[string]string{"app": path},
		agent.LogPollInterval(10*time.Millisecond))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out collector
	done := make(chan error, 1)
	go func() {
		done <- tail(ctx, agent.LogRequest{Source: "app", Lines: -1, Follow: true}, &out)
	}()

	// Wait for the tailer to be following before appending. `Lines: -1` seeks to the end
	// and sends nothing, so there is no output to synchronise on — and a line written
	// before that seek is genuinely missed, which is what "only what happens next"
	// means. Appending immediately would be racing the seek and testing the race.
	time.Sleep(200 * time.Millisecond)

	appendLog(t, path, "new-1")
	eventually(t, func() bool { return strings.Contains(out.String(), "new-1") },
		"the new line never arrived")
	if strings.Contains(out.String(), "old-") {
		t.Fatalf("history was sent despite Lines: -1: %q", out.String())
	}
	cancel()
	<-done
}

// TestFollowStreamsNewLines. The default from the SSH surface, and the reason the profile
// exists rather than being a `file:read`.
func TestFollowStreamsNewLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	writeLog(t, path, "first")

	tail := agent.Logs(map[string]string{"app": path},
		agent.LogPollInterval(10*time.Millisecond))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out collector
	go func() { _ = tail(ctx, agent.LogRequest{Source: "app", Follow: true}, &out) }()

	eventually(t, func() bool { return strings.Contains(out.String(), "first") },
		"the history never arrived")
	appendLog(t, path, "second", "third")
	eventually(t, func() bool { return strings.Contains(out.String(), "third") },
		"appended lines never arrived")
}

// TestARotatedLogDoesNotGoSilent.
//
// Rotation is the normal case for a log, not an edge one. A tailer that kept reading at its
// old offset would produce nothing until the new file grew past it — which looks exactly
// like a device that has stopped logging, at the moment somebody is watching to find out
// whether it has.
func TestARotatedLogDoesNotGoSilent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	writeLog(t, path, strings.Repeat("padding-so-the-file-is-long ", 200))

	tail := agent.Logs(map[string]string{"app": path},
		agent.LogPollInterval(10*time.Millisecond))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out collector
	go func() { _ = tail(ctx, agent.LogRequest{Source: "app", Follow: true}, &out) }()

	eventually(t, func() bool { return strings.Contains(out.String(), "padding") },
		"the history never arrived")

	// Rotated: truncated and restarted, shorter than the old offset.
	writeLog(t, path, "after-rotation")

	eventually(t, func() bool { return strings.Contains(out.String(), "after-rotation") },
		"nothing arrived after the log rotated; the tail went silent")
	if !strings.Contains(out.String(), "log rotated") {
		t.Fatalf("the reader was not told the log rotated: %q", out.String())
	}
}

// TestAnEnormousLineIsReportedRatherThanBuffered.
//
// A log file with no newline in it is a file. Reading it as one "line" means holding the
// whole thing in the agent's memory, on hardware chosen for being cheap — so the limit is
// a refusal rather than an allocation.
func TestAnEnormousLineIsReportedRatherThanBuffered(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("a", agent.MaxLogLineBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}

	tail := agent.Logs(map[string]string{"app": path})
	var out collector
	err := tail(context.Background(), agent.LogRequest{Source: "app"}, &out)
	if err == nil {
		t.Fatal("a line over the limit was read anyway")
	}
	if !strings.Contains(err.Error(), "reading the log source") {
		t.Fatalf("the error does not say what happened: %v", err)
	}
}

// TestAMissingFileIsReported. The path is this device's own configuration, so naming it is
// not a leak — and "the source is configured but the file is gone" is a different problem
// from "no such source" and sends somebody somewhere different.
func TestAMissingFileIsReported(t *testing.T) {
	tail := agent.Logs(map[string]string{"app": "/nonexistent/nope.log"})
	var out collector
	err := tail(context.Background(), agent.LogRequest{Source: "app"}, &out)
	if err == nil {
		t.Fatal("a missing file was read")
	}
	if errors.Is(err, agent.ErrNoSuchSource) {
		t.Fatal("a configured-but-missing file was reported as an unknown source; those " +
			"are different problems with different fixes")
	}
}

// TestFollowStopsWhenTheContextEnds. An operator pressing Ctrl-C must not leave a goroutine
// reading a file on the device forever.
func TestFollowStopsWhenTheContextEnds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	writeLog(t, path, "x")

	tail := agent.Logs(map[string]string{"app": path},
		agent.LogPollInterval(10*time.Millisecond))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	var out collector
	go func() { done <- tail(ctx, agent.LogRequest{Source: "app", Follow: true}, &out) }()

	eventually(t, func() bool { return out.String() != "" }, "nothing was read")
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a cancelled follow returned %v; giving up is not an error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the tailer kept reading after its context ended")
	}
}

// TestLogSourcesListsWhatIsPublished, for a build that wants to say so at startup.
func TestLogSourcesListsWhatIsPublished(t *testing.T) {
	got := agent.LogSources(map[string]string{"b": "/b", "a": "/a"})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("LogSources = %v, want [a b] sorted", got)
	}
}
