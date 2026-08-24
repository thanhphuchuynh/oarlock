package app_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	xssh "golang.org/x/crypto/ssh"

	"github.com/oarlock/oarlock/agent"
	"github.com/oarlock/oarlock/cmd/oarlockd/app"
	"github.com/oarlock/oarlock/internal/config"
	"github.com/oarlock/oarlock/internal/sessions"
	"github.com/oarlock/oarlock/internal/sessions/sqlitestore"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/transport/websocket"
)

// The smoke test for the daemon: a real gateway built from a real configuration file, a
// real agent, and a real SSH client. Everything below the daemon has its own tests; what
// this covers is the part that had none — that the pieces can actually be *started* in an
// order a process can boot, which a test harness arranging components by hand never proved.

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

func loud(t *testing.T) *slog.Logger {
	return slog.New(slog.NewTextHandler(&testWriter{t}, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

type testWriter struct{ t *testing.T }

func (w *testWriter) Write(b []byte) (int, error) {
	w.t.Log(strings.TrimRight(string(b), "\n"))
	return len(b), nil
}

type deployment struct {
	dir      string
	cfg      *config.Config
	gw       *app.Gateway
	sshAddr  string
	httpAddr string
	opSigner xssh.Signer
	devKey   ed25519.PrivateKey
}

// deploy writes a working configuration and builds the gateway from it.
func deploy(t *testing.T, log *slog.Logger) *deployment {
	t.Helper()
	dir := t.TempDir()

	// The device's key, and the public half in the form the registry parses.
	devPub, devPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	devSSH, err := xssh.NewPublicKey(devPub)
	if err != nil {
		t.Fatal(err)
	}

	// The operator's key, in an authorized_keys file.
	opPub, opPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	opSSH, err := xssh.NewPublicKey(opPub)
	if err != nil {
		t.Fatal(err)
	}
	opSigner, err := xssh.NewSignerFromKey(opPriv)
	if err != nil {
		t.Fatal(err)
	}
	akLine := strings.TrimRight(string(xssh.MarshalAuthorizedKey(opSSH)), "\n")
	write(t, filepath.Join(dir, "authorized_keys"), akLine+" phuc@example.com\n")

	write(t, filepath.Join(dir, "devices.yaml"), fmt.Sprintf(`devices:
  - id: treadmill-4821
    platform: linux
    keys:
      - %q
    profiles: [shell, exec]
`, strings.TrimRight(string(xssh.MarshalAuthorizedKey(devSSH)), "\n")))

	write(t, filepath.Join(dir, "rules.yaml"), `rules:
  - principals: ["phuc@example.com"]
    devices: ["treadmill-*"]
    actions: ["shell", "exec", "replay", "observe"]
`)

	// The ports are chosen here rather than with :0 because `url` has to be the address
	// agents dial back on (ADR-025), and it is written into the configuration file — a
	// production deployment knows its own hostname, and a test that used :0 would need a
	// method on the gateway to rewrite the URL afterwards, which is a test-only seam in
	// production code.
	sshPort, httpPort := freePort(t), freePort(t)

	write(t, filepath.Join(dir, "oarlock.yaml"), fmt.Sprintf(`env: dev
url: ws://127.0.0.1:%d
listen:
  ssh: "127.0.0.1:%d"
  http: "127.0.0.1:%d"
ssh:
  host_key: %s
  generate_host_key: true
  authorized_keys: %s
devices: %s
authorizer:
  kind: rules
  path: %s
  recheck_interval: 1s
recorder:
  dir: %s
  signing_key: %s
  generate_signing_key: true
api:
  tokens:
    smoke-token-long-enough-for-checks: phuc@example.com
`,
		httpPort, sshPort, httpPort,
		filepath.Join(dir, "hostkey"),
		filepath.Join(dir, "authorized_keys"),
		filepath.Join(dir, "devices.yaml"),
		filepath.Join(dir, "rules.yaml"),
		filepath.Join(dir, "recordings"),
		filepath.Join(dir, "recording.key")))

	cfg, err := config.Load(filepath.Join(dir, "oarlock.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	gw, err := app.Build(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gw.Close)
	if err := gw.Listen(); err != nil {
		t.Fatal(err)
	}
	sshAddr, httpAddr := gw.Addrs()

	return &deployment{
		dir: dir, cfg: cfg, gw: gw,
		sshAddr: sshAddr, httpAddr: httpAddr,
		opSigner: opSigner, devKey: devPriv,
	}
}

// freePort binds a port, reads it, and lets it go. A small window, and the alternative is
// a test-only method on the gateway for rewriting its own URL.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// serve runs the gateway until the test ends.
func (d *deployment) serve(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := d.gw.Serve(ctx); err != nil {
			t.Errorf("Serve: %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Error("the gateway did not stop")
		}
	})
	waitForPort(t, d.sshAddr)
}

// startAgent runs a real agent against the deployment.
func (d *deployment) startAgent(t *testing.T, log *slog.Logger) *agent.Control {
	t.Helper()
	control, err := agent.NewControl(agent.Config{
		Gateway:   "ws://" + d.httpAddr + "/ws/control",
		DeviceID:  "treadmill-4821",
		Signer:    d.devKey,
		Dialer:    websocket.Dialer{},
		PinSHA256: []string{"smoke-test-does-not-pin"},
		Caps:      []string{"shell", "exec"},
		Info:      frame.AgentInfo{Version: "smoke", Platform: "test"},
		Shell:     agent.Forkpty([]string{"/bin/sh"}),
		// The device's own allow-list. Exact argvs — the gateway authorises the action,
		// the device decides what may actually run on it.
		Exec: agent.Exec([][]string{
			{"/bin/echo", "hello"},
			{"/bin/sh", "-c", "printf out; printf err >&2; exit 3"},
			{"/usr/bin/yes"},
		}, agent.ExecTimeout(2*time.Second)),
		Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = control.Run(ctx) }()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if control.Up() {
			return control
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the agent never established a control channel")
	return nil
}

func waitForPort(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("nothing listening on %s", addr)
}

// TestTheDaemonGivesAnOperatorAShell is the whole point: a configured gateway, a running
// agent, and `ssh` producing a prompt on the device.
func TestTheDaemonGivesAnOperatorAShell(t *testing.T) {
	d := deploy(t, loud(t))
	d.serve(t)
	d.startAgent(t, loud(t))

	client, err := xssh.Dial("tcp", d.sshAddr, &xssh.ClientConfig{
		User:            "treadmill-4821",
		Auth:            []xssh.AuthMethod{xssh.PublicKeys(d.opSigner)},
		HostKeyCallback: xssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.RequestPty("xterm", 24, 80, xssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out := &syncBuf{}
	sess.Stdout, sess.Stderr = out, out
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}

	if _, err := stdin.Write([]byte("printf 'SMOKE%s\\n' '-OK'\n")); err != nil {
		t.Fatal(err)
	}
	if got := waitFor(t, out, "SMOKE-OK", 20*time.Second); !strings.Contains(got, "SMOKE-OK") {
		t.Fatalf("never got a shell on the device:\n%s", got)
	}
	// The disclosure an operator reads before the prompt.
	if !strings.Contains(out.String(), "recorded") {
		t.Errorf("the session did not disclose that it is recorded:\n%s", out.String())
	}

	_, _ = stdin.Write([]byte("exit\n"))
	_ = sess.Wait()
}

type syncBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func waitFor(t *testing.T, buf *syncBuf, want string, within time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), want) {
			return buf.String()
		}
		time.Sleep(10 * time.Millisecond)
	}
	return buf.String()
}

// TestPipedInputStillProducesOutput is what `ssh host < script` does, and it was the first
// thing to fail when the daemon was run by hand rather than from a test: the client sends
// its input and immediately closes the channel's write side.
func TestPipedInputStillProducesOutput(t *testing.T) {
	d := deploy(t, loud(t))
	d.serve(t)
	d.startAgent(t, loud(t))

	client, err := xssh.Dial("tcp", d.sshAddr, &xssh.ClientConfig{
		User:            "treadmill-4821",
		Auth:            []xssh.AuthMethod{xssh.PublicKeys(d.opSigner)},
		HostKeyCallback: xssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.RequestPty("xterm", 24, 80, xssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out := &syncBuf{}
	sess.Stdout, sess.Stderr = out, out
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}

	// Everything at once, then EOF — a pipe, not a keyboard.
	if _, err := stdin.Write([]byte("printf 'PIPED%s\\n' '-OK'\nexit\n")); err != nil {
		t.Fatal(err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}

	if got := waitFor(t, out, "PIPED-OK", 20*time.Second); !strings.Contains(got, "PIPED-OK") {
		t.Fatalf("piped input produced no output:\n%s", got)
	}
	_ = sess.Wait()
}

// TestAWindowChangeBeforeAnyOutput is what OpenSSH does and the Go client does not: it
// sends a window-change immediately after requesting the PTY, before the device has
// produced a byte.
//
// It was the difference between "works from a test" and "does not work from a terminal",
// which is the kind of gap only running the thing finds.
func TestAWindowChangeBeforeAnyOutput(t *testing.T) {
	d := deploy(t, loud(t))
	d.serve(t)
	d.startAgent(t, loud(t))

	client, err := xssh.Dial("tcp", d.sshAddr, &xssh.ClientConfig{
		User:            "treadmill-4821",
		Auth:            []xssh.AuthMethod{xssh.PublicKeys(d.opSigner)},
		HostKeyCallback: xssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.RequestPty("xterm", 24, 80, xssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out := &syncBuf{}
	sess.Stdout, sess.Stderr = out, out
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}

	// Straight after the shell request, before anything has come back.
	if err := sess.WindowChange(40, 132); err != nil {
		t.Fatal(err)
	}

	if _, err := stdin.Write([]byte("printf 'RESIZED%s\\n' '-OK'\n")); err != nil {
		t.Fatal(err)
	}
	if got := waitFor(t, out, "RESIZED-OK", 20*time.Second); !strings.Contains(got, "RESIZED-OK") {
		t.Fatalf("a window change before any output killed the session:\n%s", got)
	}
	_, _ = stdin.Write([]byte("exit\n"))
	_ = sess.Wait()
}

// TestAPtyWithNoTerminalSizeStillWorks is the bug running the daemon by hand found.
//
// `ssh -tt host < script` asks for a PTY while stdin is not a terminal, so OpenSSH has no
// size to report and sends 0×0. The recorder refuses a zero-sized resize, a recording
// failure cancels the session, and the operator got a disclosure banner followed by
// `transport_error` and none of their output — with nothing in the logs to say why,
// because a recording failure cancelled the session silently.
func TestAPtyWithNoTerminalSizeStillWorks(t *testing.T) {
	d := deploy(t, loud(t))
	d.serve(t)
	d.startAgent(t, loud(t))

	client, err := xssh.Dial("tcp", d.sshAddr, &xssh.ClientConfig{
		User:            "treadmill-4821",
		Auth:            []xssh.AuthMethod{xssh.PublicKeys(d.opSigner)},
		HostKeyCallback: xssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	// A PTY with no size, exactly as a client with a pipe for stdin requests one.
	if err := sess.RequestPty("xterm", 0, 0, xssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out := &syncBuf{}
	sess.Stdout, sess.Stderr = out, out
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	// And a window-change with no size either, which is what follows.
	_ = sess.WindowChange(0, 0)

	if _, err := stdin.Write([]byte("printf 'NOSIZE%s\\n' '-OK'\n")); err != nil {
		t.Fatal(err)
	}
	if got := waitFor(t, out, "NOSIZE-OK", 20*time.Second); !strings.Contains(got, "NOSIZE-OK") {
		t.Fatalf("a PTY with no reported size killed the session:\n%s", got)
	}
	_, _ = stdin.Write([]byte("exit\n"))
	_ = sess.Wait()
}

// TestADrainRecordsWhyInTheLedger is the second bug draining a running gateway found: the
// finalisation ran on the context that had just been cancelled, so the log said
// `gateway_shutdown` and the ledger said nothing — and the ledger is what somebody reads
// afterwards to find out what a deploy did to people's sessions.
func TestADrainRecordsWhyInTheLedger(t *testing.T) {
	d := deploy(t, quiet())
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() {
		defer close(served)
		if err := d.gw.Serve(ctx); err != nil {
			t.Errorf("Serve: %v", err)
		}
	}()
	waitForPort(t, d.sshAddr)
	d.startAgent(t, quiet())

	client, err := xssh.Dial("tcp", d.sshAddr, &xssh.ClientConfig{
		User:            "treadmill-4821",
		Auth:            []xssh.AuthMethod{xssh.PublicKeys(d.opSigner)},
		HostKeyCallback: xssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.RequestPty("xterm", 24, 80, xssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out := &syncBuf{}
	sess.Stdout, sess.Stderr = out, out
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	// A session doing something, so the drain has work in progress to end.
	if _, err := stdin.Write([]byte("printf 'LIVE%s\\n' '-NOW'\n")); err != nil {
		t.Fatal(err)
	}
	if got := waitFor(t, out, "LIVE-NOW", 20*time.Second); !strings.Contains(got, "LIVE-NOW") {
		t.Fatalf("the session never became live:\n%s", got)
	}

	// SIGTERM, in effect.
	cancel()
	select {
	case <-served:
	case <-time.After(20 * time.Second):
		t.Fatal("the gateway did not drain")
	}

	// The row says why. Read through a fresh store, because the daemon's own is closed —
	// which is also the point: this has to be durable, not a log line.
	rows := readLedger(t, d)
	if len(rows) == 0 {
		t.Fatal("no session rows survived the drain")
	}
	var found bool
	for _, r := range rows {
		if r.reason == "gateway_shutdown" {
			found = true
		}
		if r.state != "closed" {
			t.Errorf("session %s is still %q after a drain", r.id, r.state)
		}
	}
	if !found {
		t.Errorf("no session recorded gateway_shutdown; got %+v.\n\n"+
			"A drain that does not reach the ledger leaves an operator's session ending "+
			"for no recorded reason, which is the row somebody reads to find out what "+
			"the deploy did.", rows)
	}
}

func TestConfiguredHostKeyIsServed(t *testing.T) {
	d := deploy(t, quiet())
	d.serve(t)

	b, err := os.ReadFile(d.cfg.SSH.HostKey)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := xssh.ParsePrivateKey(b)
	if err != nil {
		t.Fatal(err)
	}
	client, err := xssh.Dial("tcp", d.sshAddr, &xssh.ClientConfig{
		User:            "treadmill-4821",
		Auth:            []xssh.AuthMethod{xssh.PublicKeys(d.opSigner)},
		HostKeyCallback: xssh.FixedHostKey(signer.PublicKey()),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial with configured host key: %v", err)
	}
	_ = client.Close()
}

func TestGeneratedHostKeyIsNotLogged(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	d := deploy(t, log)

	key, err := os.ReadFile(d.cfg.SSH.HostKey)
	if err != nil {
		t.Fatal(err)
	}
	out := logs.String()
	if bytes.Contains([]byte(out), key) {
		t.Fatal("startup logs contain the private host key file")
	}
	for _, marker := range []string{"BEGIN OPENSSH PRIVATE KEY", "PRIVATE KEY-----"} {
		if strings.Contains(out, marker) {
			t.Fatalf("startup logs contain private key material marker %q:\n%s", marker, out)
		}
	}
}

type ledgerRow struct {
	id     string
	state  string
	reason string
}

func readLedger(t *testing.T, d *deployment) []ledgerRow {
	t.Helper()
	store, err := sqlitestore.Open(filepath.Join(d.dir, "recordings", "sessions.db"),
		sessions.Limits{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Shutdown()

	list, _, err := store.List(context.Background(), sessions.Query{})
	if err != nil {
		t.Fatal(err)
	}
	out := make([]ledgerRow, 0, len(list))
	for _, s := range list {
		out = append(out, ledgerRow{id: s.ID, state: string(s.State), reason: s.CloseReason})
	}
	return out
}

// ── the exec profile, through the assembled daemon ──────────────────────────────

// execViaAPI posts one command and returns the decoded response.
func execViaAPI(t *testing.T, d *deployment, body string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost,
		"http://"+d.httpAddr+"/api/v1/devices/treadmill-4821/exec",
		strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer smoke-token-long-enough-for-checks")
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// TestExecOverTheAPIReturnsOutputAndAnExitCode is the story's headline: one allow-listed
// command, no terminal, no attach, and stdout, stderr and a status in the response.
func TestExecOverTheAPIReturnsOutputAndAnExitCode(t *testing.T) {
	log := quiet()
	d := deploy(t, log)
	d.serve(t)
	d.startAgent(t, log)

	status, out := execViaAPI(t, d, `{"argv":["/bin/echo","hello"],"reason":"SUP-1"}`)
	if status != http.StatusOK {
		t.Fatalf("status %d: %v", status, out)
	}
	if got := strings.TrimSpace(out["stdout"].(string)); got != "hello" {
		t.Fatalf("stdout = %q", got)
	}
	if code, _ := out["exit_code"].(float64); code != 0 {
		t.Fatalf("exit_code = %v", out["exit_code"])
	}
	// A real session, with a row and a recording: exec being convenient must not make it
	// invisible.
	if out["session_id"] == "" {
		t.Fatal("no session id in the response")
	}
	if recorded, _ := out["recorded"].(bool); !recorded {
		t.Fatalf("recorded = %v; an exec session is recorded like any other", out["recorded"])
	}
}

// TestExecSeparatesStderrAndReportsTheStatus. Merging the streams is what a terminal
// does; a caller collecting output should not have to grep an error out of it.
func TestExecSeparatesStderrAndReportsTheStatus(t *testing.T) {
	log := quiet()
	d := deploy(t, log)
	d.serve(t)
	d.startAgent(t, log)

	status, out := execViaAPI(t, d,
		`{"argv":["/bin/sh","-c","printf out; printf err >&2; exit 3"]}`)
	if status != http.StatusOK {
		t.Fatalf("status %d: %v", status, out)
	}
	if out["stdout"] != "out" {
		t.Fatalf("stdout = %q", out["stdout"])
	}
	if out["stderr"] != "err" {
		t.Fatalf("stderr = %q", out["stderr"])
	}
	if code, _ := out["exit_code"].(float64); code != 3 {
		t.Fatalf("exit_code = %v, want 3", out["exit_code"])
	}
}

// TestExecRefusedByTheDeviceIsNotASuccess.
//
// The device holds the allow-list, so the gateway can authorise `exec` and still be told
// no. What must not happen is that refusal arriving as exit 0 — anything checking a
// status would read it as "the command ran and was happy".
func TestExecRefusedByTheDeviceIsNotASuccess(t *testing.T) {
	log := quiet()
	d := deploy(t, log)
	d.serve(t)
	d.startAgent(t, log)

	status, out := execViaAPI(t, d, `{"argv":["/bin/cat","/etc/passwd"]}`)
	if status != http.StatusOK {
		// The HTTP call itself succeeded; the command did not.
		t.Fatalf("status %d: %v", status, out)
	}
	if code, _ := out["exit_code"].(float64); code == 0 {
		t.Fatalf("a command the device refused reported success: %v", out)
	}
	if out["stdout"] != "" {
		t.Fatalf("a refused command produced stdout: %q", out["stdout"])
	}
}

// TestExecIsAuthorisedSeparatelyFromShell: the whole point of the profile is that support
// work can be granted without granting a shell, which only works if a grant for one is
// not a grant for the other.
func TestExecIsAuthorisedSeparatelyFromShell(t *testing.T) {
	log := quiet()
	d := deploy(t, log)
	d.serve(t)
	d.startAgent(t, log)

	// The rules file grants exec to phuc@example.com and nobody else, so a principal
	// with no grant at all is refused before a row exists.
	req, err := http.NewRequest(http.MethodPost,
		"http://"+d.httpAddr+"/api/v1/devices/treadmill-4821/exec",
		strings.NewReader(`{"argv":["/bin/echo","hello"]}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer not-a-configured-token-but-long")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("an unauthenticated caller ran a command")
	}
}

// TestExecRefusesAnEmptyArgv, because "run nothing" is a bug in the caller and silently
// doing nothing would hide it.
func TestExecRefusesAnEmptyArgv(t *testing.T) {
	log := quiet()
	d := deploy(t, log)
	d.serve(t)
	d.startAgent(t, log)

	if status, out := execViaAPI(t, d, `{"argv":[]}`); status != http.StatusBadRequest {
		t.Fatalf("status %d: %v", status, out)
	}
	// And a shell string where an argv belongs: there is no shell on this path, so a
	// string could only be mis-split by whoever eventually split it.
	if status, _ := execViaAPI(t, d, `{"argv":["/bin/echo hello"]}`); status != http.StatusOK {
		t.Fatalf("status %d; a single-element argv is well-formed, just not allowed", status)
	}
}

// TestExecTruncatesRatherThanFillingMemory. The output is buffered to be returned as
// JSON, so a command that never stops is this process's memory — and a caller parsing a
// truncated log has to be told.
func TestExecTruncatesRatherThanFillingMemory(t *testing.T) {
	if _, err := os.Stat("/usr/bin/yes"); err != nil {
		t.Skip("/usr/bin/yes is not on this system")
	}
	log := quiet()
	d := deploy(t, log)
	d.serve(t)
	d.startAgent(t, log)

	status, out := execViaAPI(t, d, `{"argv":["/usr/bin/yes"],"timeout_ms":4000}`)
	if status != http.StatusOK {
		t.Fatalf("status %d: %v", status, out)
	}
	if truncated, _ := out["truncated"].(bool); !truncated {
		t.Fatalf("an unbounded command was not reported as truncated: %v",
			len(out["stdout"].(string)))
	}
	if got := len(out["stdout"].(string)); got > 2<<20 {
		t.Fatalf("stdout was %d bytes; the cap is not holding", got)
	}
}
