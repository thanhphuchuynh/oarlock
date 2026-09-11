package main

// The CLI's own tests.
//
// Most of it is a client, and a client's tests are mostly "did we send what we said". Two
// things here are worth more than that: the token is not sent somewhere it could leak, and
// `recordings verify` reaches a different answer from the gateway when the gateway is
// lying — which is the entire reason that command exists.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/record"
	"github.com/oarlock/oarlock/pkg/plugin"
)

// ── the token ───────────────────────────────────────────────────────────────────

// TestPlainHTTPToARemoteHostIsRefused.
//
// The CLI is where a bearer token is easiest to leak by accident: one `--url http://…`
// against a staging box and it is on the wire. Refused rather than warned, because the fix
// is one character and a warning on a tool people run all day is a warning nobody reads.
func TestPlainHTTPToARemoteHostIsRefused(t *testing.T) {
	if _, err := newClient("http://gateway.example.org", "tok"); err == nil {
		t.Fatal("plain http to a remote host was accepted")
	}
	// Loopback is fine: a development gateway is the thing this tool is most often
	// pointed at first, and refusing it would make the tool untryable.
	for _, u := range []string{"http://127.0.0.1:8443", "http://localhost:8443"} {
		if _, err := newClient(u, "tok"); err != nil {
			t.Errorf("%s was refused: %v", u, err)
		}
	}
	if _, err := newClient("https://gateway.example.org", "tok"); err != nil {
		t.Errorf("https was refused: %v", err)
	}
}

// TestTheTokenTravelsAsABearerHeader, and nowhere else — not in the URL, where it would
// land in the gateway's access log.
func TestTheTokenTravelsAsABearerHeader(t *testing.T) {
	var gotAuth, gotURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotURL = r.Header.Get("Authorization"), r.URL.String()
		_, _ = w.Write([]byte(`{"sessions":[]}`))
	}))
	defer srv.Close()

	c, err := newClient(srv.URL, "secret-token")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.listSessions(context.Background(), nil, 0); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer secret-token" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	if strings.Contains(gotURL, "secret-token") {
		t.Fatalf("the token appeared in the URL: %s", gotURL)
	}
}

// TestAWorldReadableConfigIsRefused. A file holding a bearer token that anybody on the
// machine can read is a credential nobody is treating as one.
func TestAWorldReadableConfigIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("url: https://gw\ntoken: t\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OARLOCK_CONFIG", path)

	_, _, err := readFileConfig()
	if err == nil {
		t.Fatal("a world-readable config was accepted")
	}
	if !strings.Contains(err.Error(), "chmod") {
		t.Fatalf("the error does not say how to fix it: %v", err)
	}

	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	fc, _, err := readFileConfig()
	if err != nil {
		t.Fatalf("a 0600 config was refused: %v", err)
	}
	if fc.URL != "https://gw" || fc.Token != "t" {
		t.Fatalf("config = %+v", fc)
	}
}

// TestConfigPrecedence. Flags beat the environment beats the file, and the reason to pin it
// is that an operator debugging "why is it talking to prod" needs the order to be the one
// documented.
func TestConfigPrecedence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("url: https://from-file\ntoken: file-tok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OARLOCK_CONFIG", path)

	// File only.
	g, err := globals{}.resolve()
	if err != nil {
		t.Fatal(err)
	}
	if g.url != "https://from-file" || g.token != "file-tok" {
		t.Fatalf("file: %+v", g)
	}

	// Environment beats it.
	t.Setenv("OARLOCK_URL", "https://from-env")
	t.Setenv("OARLOCK_TOKEN", "env-tok")
	g, err = globals{}.resolve()
	if err != nil {
		t.Fatal(err)
	}
	if g.url != "https://from-env" || g.token != "env-tok" {
		t.Fatalf("env: %+v", g)
	}

	// Flags beat both.
	g, err = globals{url: "https://from-flag", token: "flag-tok"}.resolve()
	if err != nil {
		t.Fatal(err)
	}
	if g.url != "https://from-flag" || g.token != "flag-tok" {
		t.Fatalf("flags: %+v", g)
	}
}

// TestNoURLSaysWhereToPutOne. The first thing anybody hits, so the message has to name all
// three places rather than "missing configuration".
func TestNoURLSaysWhereToPutOne(t *testing.T) {
	t.Setenv("OARLOCK_CONFIG", filepath.Join(t.TempDir(), "absent.yaml"))
	_, err := globals{}.resolve()
	if err == nil {
		t.Fatal("no URL was accepted")
	}
	// The three places, by name. The file's path comes from the environment here, so the
	// assertion is on the flag and the variable plus the fact that a path is shown.
	for _, want := range []string{"--url", "OARLOCK_URL", "absent.yaml"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q: %v", want, err)
		}
	}
}

// ── verification that does not trust the gateway ────────────────────────────────

// castAndManifest builds a real signed recording, then returns it with the key.
func castAndManifest(t *testing.T) (cast []byte, manifest []byte, pub ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	store, err := record.NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := record.New(record.Options{
		Store:  store,
		Signer: &record.KeySigner{Key: priv, ID: "test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	w, err := rec.Open(context.Background(), &plugin.SessionMeta{
		SessionID: "sess-1", DeviceID: "treadmill-4821", Profile: "shell",
		Mode: "gateway", Principal: "admin@mail.com",
		Term: "xterm-256color", Cols: 80, Rows: 24, StartedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Output(0, []byte("hello from the device\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(context.Background(), plugin.RecordingResult{CloseReason: "operator_close", ClosedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	rc, err := rec.Get(context.Background(), "sess-1")
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	cast, err = io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err = rec.RawManifest(context.Background(), "sess-1")
	if err != nil {
		t.Fatal(err)
	}
	return cast, manifest, pub
}

// TestVerificationUsesTheOperatorsKeyAndNotTheGatewaysWord.
//
// The command exists for one case: a gateway that says a recording is fine when it is not.
// Every other check on offer is the gateway's opinion of its own file, which is asking the
// party that might have altered something whether it was altered.
//
// So the server here reports `ok` and serves a tampered cast. A CLI that believed the
// verdict would print success.
func TestVerificationUsesTheOperatorsKeyAndNotTheGatewaysWord(t *testing.T) {
	cast, manifest, pub := castAndManifest(t)

	// The gateway lies: altered bytes, and a verdict saying all is well.
	tampered := strings.Replace(string(cast), "hello from the device", "nothing happened", 1)
	if tampered == string(cast) {
		t.Fatal("the test did not manage to alter the cast")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"cast":     tampered,
			"manifest": manifest,
			"verdict":  map[string]any{"status": "ok", "ok": true},
		})
	}))
	defer srv.Close()

	c, err := newClient(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := fetchRecording(context.Background(), c, "sess-1")
	if err != nil {
		t.Fatal(err)
	}
	if !rec.Verdict.OK {
		t.Fatal("the fake gateway did not claim the recording was fine")
	}

	m, err := record.DecodeManifest(rec.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := record.Verify(strings.NewReader(rec.Cast), m, pub)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.OK {
		t.Fatal("a tampered recording verified against the operator's key, so the local " +
			"check adds nothing over believing the gateway")
	}
}

// TestAnUntamperedRecordingVerifies, so the test above is not passing because verification
// always fails.
func TestAnUntamperedRecordingVerifies(t *testing.T) {
	cast, manifest, pub := castAndManifest(t)
	m, err := record.DecodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := record.Verify(strings.NewReader(string(cast)), m, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !verdict.OK {
		t.Fatalf("a good recording did not verify: %s %s", verdict.Status, verdict.Detail)
	}
}

// TestVerifyRefusesWithoutAKey. Verifying against a key the gateway supplied would only
// prove the gateway agrees with itself, so there is no default.
func TestVerifyRefusesWithoutAKey(t *testing.T) {
	err := cmdRecordingsVerify(context.Background(), globals{url: "https://gw", token: "t"},
		[]string{"sess-1"})
	if err == nil {
		t.Fatal("verify ran with no key")
	}
	if !strings.Contains(err.Error(), "--key is required") {
		t.Fatalf("the error does not say what is missing: %v", err)
	}
}

// ── errors an operator has to act on ────────────────────────────────────────────

// TestAProblemDocumentBecomesAReadableError, with the correlation id, because quoting it
// is how somebody gets help.
func TestAProblemDocumentBecomesAReadableError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type":  "https://oarlock.dev/problems/not_authorized",
			"title": "Not authorized", "detail": "not in the on-call group",
			"request": "req_abc123",
		})
	}))
	defer srv.Close()

	c, _ := newClient(srv.URL, "tok")
	err := c.do(context.Background(), http.MethodGet, "/api/v1/sessions", nil, nil)
	if err == nil {
		t.Fatal("a 403 was not an error")
	}
	for _, want := range []string{"Not authorized", "not in the on-call group", "req_abc123"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error is missing %q: %v", want, err)
		}
	}
}

// TestSomethingThatIsNotTheGatewayIsSaidSo. A proxy answering with an HTML error page is
// the common case, and "unexpected end of JSON input" sends somebody to the wrong place.
func TestSomethingThatIsNotTheGatewayIsSaidSo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html><body>502 Bad Gateway</body></html>"))
	}))
	defer srv.Close()

	c, _ := newClient(srv.URL, "tok")
	err := c.do(context.Background(), http.MethodGet, "/api/v1/sessions", nil, nil)
	if err == nil {
		t.Fatal("a 502 was not an error")
	}
	if !strings.Contains(err.Error(), "502") || !strings.Contains(err.Error(), "Bad Gateway") {
		t.Fatalf("the error does not show what arrived: %v", err)
	}
}

// TestListFollowsTheCursor. A `list` that returned the first page would be a list whose
// output an operator cannot count, and counting is most of what a list is for.
func TestListFollowsTheCursor(t *testing.T) {
	pages := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pages++
		if r.URL.Query().Get("cursor") == "" {
			// `next_cursor`, which is the field the API actually sends. This test used to
			// say `next` — the same mistake the client made — so it passed while paging
			// was broken. A fake server built from the same wrong assumption as the code
			// tests nothing.
			_, _ = w.Write([]byte(`{"sessions":[{"id":"a"},{"id":"b"}],"next_cursor":"c2"}`))
			return
		}
		_, _ = w.Write([]byte(`{"sessions":[{"id":"c"}]}`))
	}))
	defer srv.Close()

	c, _ := newClient(srv.URL, "tok")
	rows, err := c.listSessions(context.Background(), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || pages != 2 {
		t.Fatalf("got %d rows over %d pages, want 3 over 2", len(rows), pages)
	}
}

// TestUnknownCommandsAreNamed rather than printing usage and leaving somebody to spot the
// typo.
func TestVersionPrintsTheBuild(t *testing.T) {
	out, err := captureStdout(t, func() error { return run([]string{"--version"}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "oarlockctl ") {
		t.Fatalf("got %q", out)
	}
}

func TestUnknownCommandsAreNamed(t *testing.T) {
	t.Setenv("OARLOCK_CONFIG", filepath.Join(t.TempDir(), "absent.yaml"))
	err := run([]string{"sessions", "delete", "x"})
	if err == nil {
		t.Fatal("an unknown verb was accepted")
	}
	if !strings.Contains(err.Error(), "sessions delete") {
		t.Fatalf("the error does not name the command: %v", err)
	}
	if err := run([]string{"sessions"}); err == nil ||
		!strings.Contains(err.Error(), "needs a verb") {
		t.Fatalf("a group with no verb gave %v", err)
	}
}

// ── end to end, through run() ───────────────────────────────────────────────────

// captureStdout runs f with os.Stdout redirected and returns what it wrote.
func captureStdout(t *testing.T, f func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	ferr := f()
	_ = w.Close()
	os.Stdout = old
	return <-done, ferr
}

// TestSessionsListEndToEnd drives the whole path an operator uses: dispatch, config, the
// client, paging and the table. The pieces are tested apart; this is the wiring.
func TestSessionsListEndToEnd(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"sessions":[
			{"id":"sess_1","device_id":"treadmill-4821","profile":"shell",
			 "principal":"admin@mail.com","state":"closed","recording_state":"recorded",
			 "close_reason":"operator_close"}]}`))
	}))
	defer srv.Close()
	t.Setenv("OARLOCK_CONFIG", filepath.Join(t.TempDir(), "absent.yaml"))
	t.Setenv("OARLOCK_URL", srv.URL)
	t.Setenv("OARLOCK_TOKEN", "tok")

	out, err := captureStdout(t, func() error {
		return run([]string{"sessions", "list", "--device", "treadmill-4821"})
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(gotQuery, "device=treadmill-4821") {
		t.Errorf("the filter did not reach the gateway: %q", gotQuery)
	}
	for _, want := range []string{"SESSION", "sess_1", "treadmill-4821", "operator_close"} {
		if !strings.Contains(out, want) {
			t.Errorf("the table is missing %q:\n%s", want, out)
		}
	}
}

// TestJSONOutputIsMachineReadable, because the reason to have a CLI at all is that the
// next thing after reading it by eye is putting it in a script.
func TestJSONOutputIsMachineReadable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"sessions":[{"id":"sess_1","state":"closed"}]}`))
	}))
	defer srv.Close()
	t.Setenv("OARLOCK_CONFIG", filepath.Join(t.TempDir(), "absent.yaml"))
	t.Setenv("OARLOCK_URL", srv.URL)
	t.Setenv("OARLOCK_TOKEN", "tok")

	out, err := captureStdout(t, func() error {
		return run([]string{"--json", "sessions", "list"})
	})
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("--json did not produce JSON: %v\n%s", err, out)
	}
	if len(rows) != 1 || rows[0]["id"] != "sess_1" {
		t.Fatalf("rows = %v", rows)
	}
}

// TestKillSaysWhatItDid, and sends the reason. An operator ending somebody else's session
// should see it confirmed rather than silence.
func TestKillSaysWhatItDid(t *testing.T) {
	var gotMethod, gotPath, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotQuery = r.Method, r.URL.Path, r.URL.RawQuery
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	t.Setenv("OARLOCK_CONFIG", filepath.Join(t.TempDir(), "absent.yaml"))
	t.Setenv("OARLOCK_URL", srv.URL)
	t.Setenv("OARLOCK_TOKEN", "tok")

	out, err := captureStdout(t, func() error {
		return run([]string{"sessions", "kill", "sess_1", "--reason", "wrong box"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodDelete || gotPath != "/api/v1/sessions/sess_1" {
		t.Fatalf("sent %s %s", gotMethod, gotPath)
	}
	if !strings.Contains(gotQuery, "wrong+box") && !strings.Contains(gotQuery, "wrong%20box") {
		t.Errorf("the reason did not reach the gateway: %q", gotQuery)
	}
	if !strings.Contains(out, "killed sess_1") {
		t.Errorf("nothing confirmed the kill: %q", out)
	}
}
