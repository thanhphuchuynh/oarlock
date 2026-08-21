package exec_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
	"github.com/oarlock/oarlock/pkg/plugin/plugintest"
	execdispatch "github.com/oarlock/oarlock/plugins/dispatch/exec"
)

// TestConformance runs the shipped exec dispatcher through the conformance suite.
//
// Its "transport" is a command on disk, so breaking it means making the command not work
// — which is exactly the deployment failure it has to distinguish from a device that is
// not there.
func TestConformance(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "wake")

	// The device id arrives in OARLOCK_DEVICE_ID, not on stdin — the invitation body
	// carries the session, the ticket and the URL, and deliberately not the device.
	// Checking stdin for it made the suite's first run report a false pass here, which
	// is a fair demonstration of why the case exists at all.
	working := "#!/bin/sh\ncat >/dev/null\ncase \"$OARLOCK_DEVICE_ID\" in gone-*) exit " +
		itoa(execdispatch.UnreachableExitCode) + ";; esac\nexit 0\n"
	if err := os.WriteFile(script, []byte(working), 0o755); err != nil {
		t.Fatal(err)
	}
	// Chmod rather than a rewrite: os.WriteFile applies its mode only when *creating*
	// a file, so rewriting an existing 0755 script with 0644 leaves it executable —
	// and the "broken transport" case then silently tests nothing.
	chmod := func(t *testing.T, mode os.FileMode) {
		t.Helper()
		if err := os.Chmod(script, mode); err != nil {
			t.Fatal(err)
		}
	}

	plugintest.Dispatcher(t, plugintest.DispatcherHarness{
		New: func(t *testing.T) plugin.Dispatcher {
			d, err := execdispatch.New([]string{script}, 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			return d
		},
		Device: func() *plugin.Device {
			return &plugin.Device{ID: "treadmill-4821", Mode: plugin.ModeDispatch}
		},
		UnreachableDevice: func() *plugin.Device {
			return &plugin.Device{ID: "gone-4821", Mode: plugin.ModeDispatch}
		},
		Invitation: func() frame.Invitation {
			return frame.Invitation{
				SessionID: "sess_conformance",
				Ticket:    "conformance-ticket-abcdefghijklmnop",
				URL:       "wss://gw.example.org/ws/session",
				Profile:   "shell",
			}
		},
		BreakTransport: func(t *testing.T) func() {
			// The command itself stops working: not executable. A deployment mistake,
			// and it must not be reported as the device being offline.
			chmod(t, 0o644)
			return func() { chmod(t, 0o755) }
		},
	})
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
