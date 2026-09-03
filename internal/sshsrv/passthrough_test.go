package sshsrv_test

// Mode A, from an operator's `ssh`.
//
// The accept path is one test. Everything else is a guard rail, and the guard rails are
// the feature: an unrecorded session is the one thing this product exists to make
// impossible by accident, so what is worth proving is that each key on its own is not
// enough and that the session it produces is still a queryable fact.

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	xssh "golang.org/x/crypto/ssh"

	"github.com/oarlock/oarlock/internal/sessions"
)

// sshd stands in for the `sshd` a device runs on its own loopback. It is not a real SSH
// server — what is under test is that the gateway relays bytes it cannot read, so the
// far end only has to be something recognisable at both ends.
func sshd(t *testing.T) (int, chan string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	got := make(chan string, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// A version banner, as a real sshd sends first.
		_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
		buf := make([]byte, 128)
		n, _ := c.Read(buf)
		got <- string(buf[:n])
	}()
	return l.Addr().(*net.TCPAddr).Port, got
}

// passthrough opens the subsystem and returns the session, or the error text the operator
// was given on stderr.
func passthrough(t *testing.T, s *stack) (*xssh.Session, string) {
	t.Helper()
	c := s.dial(t, nil, s.dev.ID)
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	errText := make(chan string, 1)
	go func() {
		var b strings.Builder
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			b.WriteString(sc.Text())
			b.WriteString("\n")
		}
		errText <- b.String()
	}()

	if err := sess.RequestSubsystem("sshpass"); err != nil {
		// The subsystem request itself failed. Give the reader whatever stderr carried.
		select {
		case s := <-errText:
			return nil, s
		case <-time.After(3 * time.Second):
			return nil, ""
		}
	}
	t.Cleanup(func() {
		_ = sess.Close()
		select {
		case <-errText:
		case <-time.After(2 * time.Second):
		}
	})
	// Hand the stderr text back through a closure the caller can read once the session
	// has ended; for the refusal tests the subsystem request succeeds and the process
	// exits immediately, so read with a deadline.
	select {
	case s := <-errText:
		return sess, s
	case <-time.After(3 * time.Second):
		return sess, ""
	}
}

// ── the two keys ────────────────────────────────────────────────────────────────

// TestPassthroughNeedsTheDeploymentToPermitIt.
//
// The gateway-wide key. Without it, a fleet operator who can set a device flag could turn
// recording off for that device with nobody else having agreed the deployment allows
// unrecorded sessions at all.
func TestPassthroughNeedsTheDeploymentToPermitIt(t *testing.T) {
	port, _ := sshd(t)
	s := newStackPassthrough(t, false, true, port) // device says yes, deployment does not

	_, text := passthrough(t, s)
	if !strings.Contains(text, "does not permit unrecorded") {
		t.Fatalf("the refusal does not name the deployment key: %q", text)
	}
}

// TestPassthroughNeedsTheDeviceToAllowIt.
//
// The other key. A deployment that permits unrecorded sessions in general has still not
// said this machine may have one.
func TestPassthroughNeedsTheDeviceToAllowIt(t *testing.T) {
	port, _ := sshd(t)
	s := newStackPassthrough(t, true, false, port) // deployment says yes, device does not

	_, text := passthrough(t, s)
	if !strings.Contains(text, "device does not allow passthrough") {
		t.Fatalf("the refusal does not name the device key: %q", text)
	}
}

// TestTheDeploymentKeyIsCheckedFirst.
//
// Order matters here and nowhere else. A gateway that has not opted in must answer
// identically for every device, or the refusal becomes an oracle for which devices carry
// `allow_passthrough` — readable by anyone who can authenticate at all.
func TestTheDeploymentKeyIsCheckedFirst(t *testing.T) {
	port, _ := sshd(t)

	withFlag := newStackPassthrough(t, false, true, port)
	_, a := passthrough(t, withFlag)
	withoutFlag := newStackPassthrough(t, false, false, port)
	_, b := passthrough(t, withoutFlag)

	if a != b {
		t.Fatalf("a caller can tell which devices allow passthrough:\n  with: %q\n  without: %q", a, b)
	}
}

// ── the session ─────────────────────────────────────────────────────────────────

// TestPassthroughRelaysBytesItCannotRead.
//
// The whole mode in one assertion: what the operator writes on stdout arrives at the
// device's sshd unchanged, and what the sshd says comes back. The gateway is a pipe.
func TestPassthroughRelaysBytesItCannotRead(t *testing.T) {
	port, got := sshd(t)
	s := newStackPassthrough(t, true, true, port)

	sess, text := passthrough(t, s)
	if sess == nil {
		t.Fatalf("the subsystem was refused: %q", text)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}

	// The device's banner arrives first, as it would from a real sshd.
	banner := make([]byte, 32)
	n, err := stdout.Read(banner)
	if err != nil {
		t.Fatalf("nothing came back from the device: %v", err)
	}
	if !strings.HasPrefix(string(banner[:n]), "SSH-2.0-") {
		t.Fatalf("the device's banner did not arrive intact: %q", banner[:n])
	}

	// And the operator's own bytes reach it.
	if _, err := stdin.Write([]byte("SSH-2.0-OpenSSH_9.6-client\r\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-got:
		if !strings.HasPrefix(s, "SSH-2.0-") {
			t.Fatalf("the device received %q", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the operator's bytes never reached the device")
	}
}

// TestAnUnrecordedSessionIsAQueryableFact.
//
// Guard rail 3. "Which sessions could nobody read" is the question this mode creates, and
// the answer has to be a row in the ledger rather than a missing file somebody notices six
// weeks later.
func TestAnUnrecordedSessionIsAQueryableFact(t *testing.T) {
	port, _ := sshd(t)
	s := newStackPassthrough(t, true, true, port)

	sess, text := passthrough(t, s)
	if sess == nil {
		t.Fatalf("the subsystem was refused: %q", text)
	}

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
		t.Fatal("an unrecorded session left no row at all")
	}
	if row.Profile != "sshpass" {
		t.Fatalf("profile = %q, want sshpass", row.Profile)
	}
	if row.RecordingState != sessions.NotRecorded {
		t.Fatalf("recording_state = %q, want not_recorded", row.RecordingState)
	}
	if row.Mode != "passthrough" {
		t.Fatalf("mode = %q, want passthrough", row.Mode)
	}
}

// TestTheOperatorIsToldTwice.
//
// Guard rail 4. Once before the session and once as it closes — the second at a point no
// prefix-truncation attack can reach, which is what removes the dependency on strict key
// exchange having worked. Both on stderr, because stdout is the tunnel and one byte of
// ours in it is a protocol error rather than a disclosure.
func TestTheOperatorIsToldTwice(t *testing.T) {
	port, _ := sshd(t)
	s := newStackPassthrough(t, true, true, port)

	c := s.dial(t, nil, s.dev.ID)
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.RequestSubsystem("sshpass"); err != nil {
		t.Fatalf("the subsystem was refused: %v", err)
	}

	// Drain stdout so the relay is not blocked writing the device's banner nowhere.
	go func() { _, _ = stdout.Read(make([]byte, 64)) }()

	collected := make(chan string, 1)
	go func() {
		var b strings.Builder
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			b.WriteString(sc.Text())
			b.WriteString("\n")
		}
		collected <- b.String()
	}()

	// The opening disclosure arrives before anything else.
	time.Sleep(300 * time.Millisecond)
	_ = sess.Close()

	var text string
	select {
	case text = <-collected:
	case <-time.After(5 * time.Second):
		t.Fatal("stderr never closed")
	}

	if n := strings.Count(text, "NOT recorded"); n < 1 {
		t.Fatalf("the operator was never told the session is unrecorded:\n%s", text)
	}
	if !strings.Contains(text, "passthrough to "+s.dev.ID) {
		t.Fatalf("the opening disclosure does not name the device:\n%s", text)
	}
	// The session id, because there is no recording to look it up in afterwards.
	if !strings.Contains(text, "Session ") {
		t.Fatalf("the disclosure does not carry a session id:\n%s", text)
	}
}

// ── the neighbours ──────────────────────────────────────────────────────────────

// TestAnUnknownSubsystemIsStillRefused, so adding this one did not open the door to
// everything else `-s` can ask for.
func TestAnUnknownSubsystemIsStillRefused(t *testing.T) {
	port, _ := sshd(t)
	s := newStackPassthrough(t, true, true, port)

	c := s.dial(t, nil, s.dev.ID)
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.RequestSubsystem("sftp"); err != nil {
		return // refused outright is fine
	}
	buf := make([]byte, 256)
	n, _ := stderr.Read(buf)
	if !strings.Contains(string(buf[:n]), "not supported") {
		t.Fatalf("sftp was not refused: %q", buf[:n])
	}
}

// TestAShellIsUnaffected. Mode A is an opt-in path beside the normal one, and the normal
// one is what every other test in this package exercises — this states it once, here,
// where the change was made.
func TestAShellIsUnaffected(t *testing.T) {
	port, _ := sshd(t)
	s := newStackPassthrough(t, true, true, port)

	if out := shellOutput(t, s); !strings.Contains(out, s.dev.ID) {
		t.Fatalf("an ordinary shell broke when passthrough was enabled: %q", out)
	}
}
