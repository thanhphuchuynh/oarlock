package sshsrv_test

import (
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// TestUnauthenticatedConnectionIsClosed is the slowloris case: a peer that opens a
// TCP connection to the front door and then does nothing.
//
// Before the budget existed this connection stayed open forever, holding a goroutine
// and a file descriptor, unauthenticated, on the door that leads to a shell. Nothing
// in gliderlabs bounds it — IdleTimeout and MaxTimeout both default to zero, and both
// would be the wrong shape even when set (see preauth.go).
func TestUnauthenticatedConnectionIsClosed(t *testing.T) {
	s := newStackBudget(t, 300*time.Millisecond)

	conn, err := net.Dial("tcp", s.sshAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Say nothing at all. Not even the version string: a peer that never identifies
	// itself is the cheapest possible way to hold the resource.
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal("the front door held an unauthenticated connection open past the budget")
			}
			return // EOF or reset: the gateway hung up, which is the point.
		}
		_ = n // the server's own version banner arrives first; keep reading.
	}
}

// TestHalfHandshakeIsClosed is the same threat one step further in: a peer that sends
// a plausible version string and then stalls inside the key exchange, which is what a
// real slowloris does rather than staying silent.
func TestHalfHandshakeIsClosed(t *testing.T) {
	s := newStackBudget(t, 300*time.Millisecond)

	conn, err := net.Dial("tcp", s.sshAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("SSH-2.0-slowloris\r\n")); err != nil {
		t.Fatal(err)
	}
	// And then never send a KEXINIT.
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	for {
		if _, err := conn.Read(buf); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal("the front door held a half-finished handshake open past the budget")
			}
			return
		}
	}
}

// TestAuthenticatedConnectionSurvivesTheBudget is the control, and it is the test that
// matters most: the budget must end at authentication and not one moment later.
//
// `ssh -N -L 8080:localhost:3000 device@gateway` authenticates and then opens no
// channel at all until somebody connects to the local port, which may be hours. A
// budget that kept running past authentication would look correct in the two tests
// above and silently break the `tcp` profile.
func TestAuthenticatedConnectionSurvivesTheBudget(t *testing.T) {
	budget := 300 * time.Millisecond
	s := newStackBudget(t, budget)

	c := s.dial(t, s.client, deviceID)

	// Idle across several budgets without opening a channel, exactly as `-N` does.
	time.Sleep(3 * budget)

	sess, err := c.NewSession()
	if err != nil {
		t.Fatalf("the connection was killed after authentication: %v", err)
	}
	defer sess.Close()

	out, err := sess.Output("/bin/echo hello")
	if err != nil {
		t.Fatalf("running a command after idling past the budget: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "hello" {
		t.Errorf("output %q, want %q", got, "hello")
	}
}
