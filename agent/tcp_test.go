package agent_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/oarlock/oarlock/agent"
)

func listener(t *testing.T) (int, chan string) {
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
		buf := make([]byte, 64)
		n, _ := c.Read(buf)
		got <- string(buf[:n])
	}()
	return l.Addr().(*net.TCPAddr).Port, got
}

// TestDialReachesAnAllowListedPort.
func TestDialReachesAnAllowListedPort(t *testing.T) {
	port, got := listener(t)
	dial := agent.Dial([]int{port})
	if dial == nil {
		t.Fatal("Dial returned nil for a non-empty allow-list")
	}
	conn, err := dial(context.Background(), agent.DialRequest{Port: port})
	if err != nil {
		t.Fatalf("dialling an allow-listed port: %v", err)
	}
	defer conn.Close()

	// Loopback, always. There is no host field on DialRequest, so this is structural
	// rather than a check that could be bypassed — asserted anyway, because the day
	// somebody adds one is the day this should start failing.
	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		t.Fatalf("dialled %s, which is not loopback", conn.RemoteAddr())
	}

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if s := <-got; s != "ping" {
		t.Fatalf("the service received %q", s)
	}
}

// TestDialRefusesAPortNotOnTheAllowList is the device's half of the bargain: the
// gateway authorises the action, the device decides what is reachable.
func TestDialRefusesAPortNotOnTheAllowList(t *testing.T) {
	allowed, _ := listener(t)
	other, _ := listener(t)

	dial := agent.Dial([]int{allowed})
	_, err := dial(context.Background(), agent.DialRequest{Port: other})
	if !errors.Is(err, agent.ErrPortNotAllowed) {
		t.Fatalf("dialling an unlisted port: got %v, want ErrPortNotAllowed", err)
	}
	// The operator has to learn what to put in the config file.
	if got := err.Error(); !strings.Contains(got, "not forwardable") {
		t.Fatalf("refusal is not actionable: %q", got)
	}
}

// TestDialWithNoPortsIsNil: nil is how the caller decides not to advertise "tcp" at
// all, so the gateway refuses at open time instead of after a round trip.
func TestDialWithNoPortsIsNil(t *testing.T) {
	if agent.Dial(nil) != nil {
		t.Fatal("an empty allow-list produced a dialler")
	}
	if agent.Dial([]int{}) != nil {
		t.Fatal("an empty allow-list produced a dialler")
	}
	// A config holding only nonsense is an empty allow-list, not a working one.
	if agent.Dial([]int{0, -1, 70000}) != nil {
		t.Fatal("an allow-list of impossible ports produced a dialler")
	}
}

// TestDialDropsImpossiblePortsFromTheAllowList: a typo in the config must not become a
// port that can be asked for.
func TestDialDropsImpossiblePortsFromTheAllowList(t *testing.T) {
	port, _ := listener(t)
	dial := agent.Dial([]int{port, 0, 99999})
	if dial == nil {
		t.Fatal("Dial returned nil despite one valid port")
	}
	for _, bad := range []int{0, 99999} {
		if _, err := dial(context.Background(), agent.DialRequest{Port: bad}); err == nil {
			t.Fatalf("port %d was dialable", bad)
		}
	}
}
