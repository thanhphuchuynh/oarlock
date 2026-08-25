package sshsrv_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	xssh "golang.org/x/crypto/ssh"

	"github.com/oarlock/oarlock/internal/authz"
	"github.com/oarlock/oarlock/internal/sessions"

	"github.com/oarlock/oarlock/pkg/plugin"
)

// echoServer is a device-local service: it listens on loopback and echoes back what it
// is sent, upper-cased so a test can tell the two directions apart.
func echoServer(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write([]byte(
							strings.ToUpper(string(buf[:n])))); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

// forward opens a direct-tcpip channel the way `ssh -L` does.
func forward(c *xssh.Client, host string, port int) (net.Conn, error) {
	return c.Dial("tcp", net.JoinHostPort(host, fmt.Sprint(port)))
}

// TestForwardCarriesBytesToADeviceLocalPort is `ssh -L` working end to end: a real SSH
// client, a real gateway, a real agent, and a service listening on the device's loopback.
func TestForwardCarriesBytesToADeviceLocalPort(t *testing.T) {
	port := echoServer(t)
	s := newStackForwarding(t, []int{port})
	c := s.dial(t, nil, "")

	conn, err := forward(c, "localhost", port)
	if err != nil {
		t.Fatalf("opening the forward: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("writing through the forward: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("reading back through the forward: %v", err)
	}
	if got := string(buf); got != "HELLO" {
		t.Fatalf("through the forward: got %q, want %q", got, "HELLO")
	}
}

// TestForwardCarriesHTTP is the case the feature exists for: a web UI on a device that
// cannot be dialled, reached with an ordinary HTTP client through the forward.
func TestForwardCarriesHTTP(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	srv := &http.Server{Handler: http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, "device console")
		})}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	port := l.Addr().(*net.TCPAddr).Port

	s := newStackForwarding(t, []int{port})
	c := s.dial(t, nil, "")

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return forward(c, "localhost", port)
			},
		},
		Timeout: 15 * time.Second,
	}
	resp, err := client.Get(fmt.Sprintf("http://localhost:%d/", port))
	if err != nil {
		t.Fatalf("GET through the forward: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "device console" {
		t.Fatalf("body through the forward: got %q", body)
	}
}

// TestForwardRefusesANonLoopbackDestination is the property that keeps a compromised
// gateway from turning every agent into a proxy into the network it sits on.
func TestForwardRefusesANonLoopbackDestination(t *testing.T) {
	port := echoServer(t)
	s := newStackForwarding(t, []int{port})
	c := s.dial(t, nil, "")

	_, err := forward(c, "10.0.0.5", port)
	if err == nil {
		t.Fatal("forwarding to a non-loopback host was allowed")
	}
	// The operator has to be able to tell which half of `-L` was wrong.
	if !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("refusal does not say why: %v", err)
	}
}

// TestForwardRefusesAPortNotOnTheDeviceAllowList is the device's half of the bargain:
// the gateway authorises the action, the device decides what is actually reachable.
func TestForwardRefusesAPortNotOnTheDeviceAllowList(t *testing.T) {
	allowed := echoServer(t)
	other := echoServer(t)
	s := newStackForwarding(t, []int{allowed})
	c := s.dial(t, nil, "")

	conn, err := forward(c, "localhost", other)
	if err != nil {
		// Refused at channel-open: also correct, and nothing more to check.
		return
	}
	defer conn.Close()
	// The channel opened because the gateway had no reason to refuse — the device is
	// the side holding the allow-list. It must then close without carrying bytes.
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = conn.Write([]byte("hello"))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err == nil {
		t.Fatalf("a port that is not on the device's allow-list carried bytes: %q", buf)
	}
}

// TestForwardRefusedWithoutTheTCPAction: `tcp` is its own grant. A shell grant is not a
// grant to reach every listening socket on the device.
func TestForwardRefusedWithoutTheTCPAction(t *testing.T) {
	port := echoServer(t)

	withAuthz(t, denyAction{deny: plugin.ActionTCP, reason: "not on the forwarding list"})

	s := newStackForwarding(t, []int{port})
	c := s.dial(t, nil, "")

	_, err := forward(c, "localhost", port)
	if err == nil {
		t.Fatal("a forward opened without the tcp action")
	}
	if !strings.Contains(err.Error(), "not on the forwarding list") {
		t.Fatalf("the backend's own sentence did not reach the operator: %v", err)
	}

	// The same connection must still be able to open a shell: the refusal is scoped to
	// the action, not to the operator.
	sess, _, _ := shellSession(t, c)
	defer sess.Close()
}

// TestForwardDoesNotHoldTheDeviceSlot is the accounting property. The stack's ledger caps
// the device at one session; a live forward must not be the one.
func TestForwardDoesNotHoldTheDeviceSlot(t *testing.T) {
	port := echoServer(t)
	s := newStackForwarding(t, []int{port})
	c := s.dial(t, nil, "")

	conn, err := forward(c, "localhost", port)
	if err != nil {
		t.Fatalf("opening the forward: %v", err)
	}
	defer conn.Close()
	// Make sure it is genuinely live before asking for the shell.
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatalf("writing through the forward: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
		t.Fatalf("the forward never carried anything: %v", err)
	}

	sess, stdin, out := shellSession(t, c)
	defer sess.Close()
	if _, err := io.WriteString(stdin, "echo still-here\n"); err != nil {
		t.Fatalf("writing to the shell: %v", err)
	}
	// waitFor fails the test itself if the shell never answers, which is what a
	// forward holding the device's only slot would look like.
	waitFor(t, out, "still-here")
}

// denyAction refuses exactly one action and allows the rest, so a test can show that a
// grant to open a shell is not a grant to forward a port.
type denyAction struct {
	deny   plugin.Action
	reason string
}

func (d denyAction) Authorize(_ context.Context, _ *plugin.Principal, _ *plugin.Device,
	a plugin.Action) (plugin.Decision, error) {
	if a == d.deny {
		return plugin.Decision{Allow: false, Reason: d.reason}, nil
	}
	return plugin.Decision{Allow: true}, nil
}

func (denyAction) Watch(context.Context) (<-chan plugin.RevocationEvent, error) {
	return nil, plugin.ErrUnsupported
}

// recordingAuthz allows everything and remembers which actions it was asked about.
type recordingAuthz struct {
	mu   sync.Mutex
	seen []plugin.Action
}

func (r *recordingAuthz) Authorize(_ context.Context, _ *plugin.Principal,
	_ *plugin.Device, a plugin.Action) (plugin.Decision, error) {
	r.mu.Lock()
	r.seen = append(r.seen, a)
	r.mu.Unlock()
	return plugin.Decision{Allow: true}, nil
}

func (*recordingAuthz) Watch(context.Context) (<-chan plugin.RevocationEvent, error) {
	return nil, plugin.ErrUnsupported
}

func (r *recordingAuthz) actions() []plugin.Action {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]plugin.Action(nil), r.seen...)
}

// TestAForwardIsSupervisedAgainstTheTCPAction.
//
// Supervision used to re-check every live session against plugin.ActionShell whatever its
// profile. For a forward that is wrong twice over: withdrawing somebody's `tcp` would
// leave the forward they already had running, and an operator granted `tcp` but not
// `shell` would have their forward killed a few seconds after it opened.
func TestAForwardIsSupervisedAgainstTheTCPAction(t *testing.T) {
	port := echoServer(t)

	backend := &recordingAuthz{}
	prevChecker, prevSup := authzChecker, authzSupervisor
	authzChecker = &authz.Checker{Backend: backend, Log: quiet()}
	authzSupervisor = &authz.Supervisor{
		Checker:  authzChecker,
		Live:     sessions.NewRegistry(),
		Interval: 10 * time.Millisecond,
		Log:      quiet(),
	}
	t.Cleanup(func() { authzChecker, authzSupervisor = prevChecker, prevSup })

	s := newStackForwarding(t, []int{port})
	c := s.dial(t, nil, "")

	conn, err := forward(c, "localhost", port)
	if err != nil {
		t.Fatalf("opening the forward: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
		t.Fatalf("the forward never carried anything: %v", err)
	}

	// Long enough for several re-check intervals to fire.
	deadline := time.Now().Add(5 * time.Second)
	var seen []plugin.Action
	for time.Now().Before(deadline) {
		seen = backend.actions()
		if len(seen) >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(seen) < 3 {
		t.Fatalf("the session was never re-checked; saw %v", seen)
	}
	for _, a := range seen {
		if a != plugin.ActionTCP {
			t.Fatalf("a forward was checked against %q; every check must be %q. saw %v",
				a, plugin.ActionTCP, seen)
		}
	}
}
