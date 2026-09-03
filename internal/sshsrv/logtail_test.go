package sshsrv_test

// The `log` profile from an operator's `ssh -s log:<source>`.
//
// Three properties are the reason this surface exists rather than being `file:read` with a
// different name: the gateway names a source and never a path, the source is authorised on
// its own, and stdout carries nothing but log lines so the thing pipes.

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	xssh "golang.org/x/crypto/ssh"

	"github.com/oarlock/oarlock/internal/sessions"
)

// logFile writes a log the device will publish and returns its path.
func logFile(t *testing.T, name string, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	body := ""
	for _, l := range lines {
		body += l + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// openLog asks for a source and returns stdout, stderr and the session.
func openLog(t *testing.T, s *stack, source string) (*xssh.Session, chan string, chan string) {
	t.Helper()
	c := s.dial(t, nil, s.dev.ID)
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	outCh, errCh := make(chan string, 1), make(chan string, 1)
	collect := func(r interface{ Read([]byte) (int, error) }, ch chan string) {
		var b strings.Builder
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			b.WriteString(sc.Text() + "\n")
		}
		ch <- b.String()
	}
	go collect(stdout, outCh)
	go collect(stderr, errCh)

	if err := sess.RequestSubsystem("log:" + source); err != nil {
		t.Fatalf("the log subsystem was refused: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess, outCh, errCh
}

// ── the stream ──────────────────────────────────────────────────────────────────

// TestALogSourceStreamsToStdout, and stdout carries nothing else — which is what makes
// `ssh -s log:app device@gw | grep` a thing that works.
func TestALogSourceStreamsToStdout(t *testing.T) {
	path := logFile(t, "app.log", "boot ok", "listening on 8080", "request refused")
	s := newStackLogs(t, map[string]string{"app": path})

	sess, outCh, errCh := openLog(t, s, "app")
	time.Sleep(500 * time.Millisecond)
	_ = sess.Close()

	out := <-outCh
	for _, want := range []string{"boot ok", "listening on 8080", "request refused"} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout is missing %q:\n%s", want, out)
		}
	}
	// The disclosure is on stderr, so a pipeline never sees it. A banner on stdout is a
	// line somebody's alerting matches on.
	if strings.Contains(out, "oarlock:") {
		t.Fatalf("gateway chrome leaked onto stdout:\n%s", out)
	}
	if e := <-errCh; !strings.Contains(e, "app log on "+s.dev.ID) {
		t.Fatalf("stderr does not carry the disclosure:\n%s", e)
	}
}

// TestAnUnpublishedSourceIsRefused. The device holds the allow-list; the gateway naming
// something else gets nowhere.
func TestAnUnpublishedSourceIsRefused(t *testing.T) {
	path := logFile(t, "app.log", "x")
	s := newStackLogs(t, map[string]string{"app": path})

	sess, _, errCh := openLog(t, s, "/etc/passwd")
	time.Sleep(500 * time.Millisecond)
	_ = sess.Close()

	if e := <-errCh; !strings.Contains(e, "oarlock:") {
		t.Fatalf("an unpublished source produced no refusal:\n%s", e)
	}
}

// TestNamingNoSourceIsRefusedWithHelp. `-s log` on its own is a plausible mistake, and the
// answer has to say what the operator should have typed.
func TestNamingNoSourceIsRefusedWithHelp(t *testing.T) {
	path := logFile(t, "app.log", "x")
	s := newStackLogs(t, map[string]string{"app": path})

	c := s.dial(t, nil, s.dev.ID)
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	stderr, err := sess.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.RequestSubsystem("log:"); err != nil {
		return // refused outright is also a refusal
	}
	buf := make([]byte, 256)
	n, _ := stderr.Read(buf)
	if !strings.Contains(string(buf[:n]), "log:messages") {
		t.Fatalf("the refusal does not show the form: %q", buf[:n])
	}
}

// TestARegistryThatSaysNoLogRefusesBeforeWakingTheDevice.
//
// The gateway's pre-check reads the device's *registry record*, not what the agent
// advertised over its control channel — a dispatch-mode device has no control channel to
// have advertised anything on. So this is the check that saves waking a device for a
// session it was never going to serve.
func TestARegistryThatSaysNoLogRefusesBeforeWakingTheDevice(t *testing.T) {
	s := newStackWithProfiles(t, []string{"shell", "exec"})

	c := s.dial(t, nil, s.dev.ID)
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	stderr, err := sess.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.RequestSubsystem("log:app"); err != nil {
		return
	}
	buf := make([]byte, 256)
	n, _ := stderr.Read(buf)
	if !strings.Contains(string(buf[:n]), "does not offer log") {
		t.Fatalf("the refusal does not name the cause: %q", buf[:n])
	}
}

// TestADeviceWithNoLogsConfiguredRefusesAfterTheRoundTrip.
//
// The other half, and worth stating because the two refusals come from different places
// and read differently to an operator. A registry that permits `log` on a build with no
// Tail configured produces a session the *agent* refuses — one round trip later, with
// `profile_unsupported`. That is the disagreement the Caps mechanism exists to avoid, and
// this is what it looks like when it has not been configured.
func TestADeviceWithNoLogsConfiguredRefusesAfterTheRoundTrip(t *testing.T) {
	s := newStackLogs(t, nil) // registry permits everything; the agent has no Tail

	sess, _, errCh := openLog(t, s, "app")
	time.Sleep(700 * time.Millisecond)
	_ = sess.Close()

	if e := <-errCh; !strings.Contains(e, "oarlock:") {
		t.Fatalf("the operator was told nothing:\n%s", e)
	}
}

// ── the ledger ──────────────────────────────────────────────────────────────────

// TestALogSessionIsARowLikeAnyOther. A log read is somebody reading a device, and "who
// looked at what" is the question the ledger exists to answer.
func TestALogSessionIsARowLikeAnyOther(t *testing.T) {
	path := logFile(t, "app.log", "x")
	s := newStackLogs(t, map[string]string{"app": path})

	sess, _, _ := openLog(t, s, "app")
	defer sess.Close()

	var row *sessions.Session
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		rows, _, err := s.ledger.List(context.Background(), sessions.Query{})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) > 0 {
			row = rows[0]
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if row == nil {
		t.Fatal("a log session left no row")
	}
	if row.Profile != "log" {
		t.Fatalf("profile = %q, want log", row.Profile)
	}
	if row.Principal == "" {
		t.Fatal("the row does not say who read the log")
	}
}
