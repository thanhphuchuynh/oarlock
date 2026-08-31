package sshsrv_test

import (
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	xssh "golang.org/x/crypto/ssh"
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

// slowSigner answers the "would you accept this key?" query immediately — that costs no
// signature — and then takes its time producing one.
//
// A public key is not a secret. It sits in `authorized_keys`, usually in a `.pub` file
// beside it, sometimes on a profile page. Offering one costs an attacker nothing.
type slowSigner struct {
	inner xssh.Signer
	delay time.Duration
}

func (s slowSigner) PublicKey() xssh.PublicKey { return s.inner.PublicKey() }

func (s slowSigner) Sign(r io.Reader, data []byte) (*xssh.Signature, error) {
	time.Sleep(s.delay)
	return s.inner.Sign(r, data)
}

// TestAPublicKeyQueryDoesNotDisarmTheBudget is the case the first version of this budget
// failed, and it failed in the direction that removed the control entirely.
//
// Every OpenSSH client asks "would you accept this key?" before it signs anything, and
// x/crypto answers by calling PublicKeyCallback — *before* it looks at whether the request
// carried a signature at all. Disarming from that callback meant merely knowing an
// authorised public key was enough to hold a connection open indefinitely.
//
// So: offer a real authorised key, answer the query, then dawdle past the budget before
// signing. A gateway that disarmed on the query lets the late signature through and the
// handshake completes. One that did not has already hung up.
func TestAPublicKeyQueryDoesNotDisarmTheBudget(t *testing.T) {
	budget := 300 * time.Millisecond
	s := newStackBudget(t, budget)

	done := make(chan error, 1)
	go func() {
		c, err := xssh.Dial("tcp", s.sshAddr, &xssh.ClientConfig{
			User:            deviceID,
			Auth:            []xssh.AuthMethod{xssh.PublicKeys(slowSigner{inner: s.client, delay: 3 * budget})},
			HostKeyCallback: xssh.InsecureIgnoreHostKey(),
			Timeout:         10 * time.Second,
		})
		if c != nil {
			_ = c.Close()
		}
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a connection that had signed nothing by the budget completed the " +
				"handshake — knowing an authorised public key was enough to disarm it")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the client never finished; the front door neither closed nor completed")
	}
}
