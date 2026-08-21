package exec_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
	dispatchexec "github.com/oarlock/oarlock/plugins/dispatch/exec"
)

const secret = "hK3ThisIsTheTicketAndItMustNotLeak"

func dev() *plugin.Device {
	return &plugin.Device{ID: "treadmill-4821", Platform: plugin.PlatformAndroid}
}

func inv() frame.Invitation {
	return frame.Invitation{
		SessionID: "sess_1", Ticket: secret,
		URL: "wss://gw-a.example.org/ws/session", Profile: "shell",
	}
}

// script writes a shell script and returns the argv to run it.
func script(t *testing.T, body string) []string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "doorbell.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return []string{p}
}

func TestInvitationArrivesOnStdin(t *testing.T) {
	out := filepath.Join(t.TempDir(), "stdin.json")
	d, err := dispatchexec.New(script(t, "cat > "+out+"\n"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Wake(context.Background(), dev(), inv()); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{secret, "sess_1", "wss://gw-a.example.org/ws/session", "shell"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("stdin is missing %q:\n%s", want, body)
		}
	}
}

// TestTicketNeverReachesArgv is the reason the invitation goes on stdin. A ticket in
// a command line is visible in `ps` to every process on the host, and lands in shell
// history and process audit logs — the same reason it never travels in a URL.
func TestTicketNeverReachesArgv(t *testing.T) {
	out := filepath.Join(t.TempDir(), "argv.txt")
	d, err := dispatchexec.New(script(t, `printf '%s\n' "$@" > `+out+`
cat > /dev/null
`), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Wake(context.Background(), dev(), inv()); err != nil {
		t.Fatal(err)
	}
	argv, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(argv), secret) {
		t.Fatalf("the ticket reached argv:\n%s", argv)
	}
}

func TestDeviceIDIsExportedButTheTicketIsNot(t *testing.T) {
	out := filepath.Join(t.TempDir(), "env.txt")
	d, err := dispatchexec.New(script(t, "env > "+out+"\ncat > /dev/null\n"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Wake(context.Background(), dev(), inv()); err != nil {
		t.Fatal(err)
	}
	env, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(env), "OARLOCK_DEVICE_ID=treadmill-4821") {
		t.Errorf("device id not exported:\n%s", env)
	}
	// The environment is readable from /proc on Linux for anything running as the
	// same user, so it is no better than argv for a secret.
	if strings.Contains(string(env), secret) {
		t.Error("the ticket was exported into the environment")
	}
}

// TestExitCodeThreeMeansUnreachable is the documented convention that lets a script
// distinguish the two failures. "Device is offline" sends someone to look at
// hardware in a gym; "I couldn't deliver" sends them to look at the broker.
func TestExitCodeThreeMeansUnreachable(t *testing.T) {
	d, err := dispatchexec.New(script(t, "cat > /dev/null\nexit 3\n"), 0)
	if err != nil {
		t.Fatal(err)
	}
	err = d.Wake(context.Background(), dev(), inv())
	if !errors.Is(err, plugin.ErrDeviceUnreachable) {
		t.Fatalf("got %v, want ErrDeviceUnreachable", err)
	}
}

func TestOtherFailuresAreDeliveryFailures(t *testing.T) {
	d, err := dispatchexec.New(script(t, "cat > /dev/null\necho 'broker refused' >&2\nexit 1\n"), 0)
	if err != nil {
		t.Fatal(err)
	}
	err = d.Wake(context.Background(), dev(), inv())
	if err == nil {
		t.Fatal("a failing command reported success")
	}
	if errors.Is(err, plugin.ErrDeviceUnreachable) {
		t.Fatal("a delivery failure was reported as the device being unreachable")
	}
	// stderr is surfaced, because a doorbell that fails silently is a doorbell
	// nobody can debug.
	if !strings.Contains(err.Error(), "broker refused") {
		t.Errorf("stderr not surfaced: %v", err)
	}
}

func TestTimeoutIsBounded(t *testing.T) {
	d, err := dispatchexec.New(script(t, "cat > /dev/null\nsleep 30\n"), 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := d.Wake(context.Background(), dev(), inv()); err == nil {
		t.Fatal("a hanging doorbell reported success")
	}
	// A doorbell that takes longer than its timeout is a dependency of session setup
	// nobody is going to wait for.
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("took %v; the timeout did not bound it", elapsed)
	}
}

func TestConfigValidation(t *testing.T) {
	if _, err := dispatchexec.New(nil, 0); err == nil {
		t.Error("an empty command was accepted")
	}
	var zero dispatchexec.Dispatcher
	if err := zero.Wake(context.Background(), dev(), inv()); err == nil {
		t.Error("the zero Dispatcher accepted a wake")
	}
}
