package webhook_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
	"github.com/oarlock/oarlock/pkg/plugin/plugintest"
	"github.com/oarlock/oarlock/plugins/dispatch/webhook"
)

// TestConformance runs the shipped webhook dispatcher through the conformance suite.
//
// Running our own plugins through it is not ceremony: the suite is what third-party
// authors are told to trust, and a suite the first-party implementations do not pass is
// one nobody should. It also means a change to the contract shows up here rather than in
// somebody else's repository.
func TestConformance(t *testing.T) {
	var broken atomic.Bool
	var absent atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if broken.Load() {
			// The broker is down: a 500, which the dispatcher must report as its own
			// failure rather than as the device being absent.
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// The device id is in the body, not a header — reading it is how a real
		// receiver decides whether it knows the device. Getting this wrong in the stub
		// is what made the suite's first run report a false pass for the unreachable
		// case, which is a fair demonstration of why the case exists.
		body, _ := io.ReadAll(r.Body)
		if absent.Load() || bytes.Contains(body, []byte("gone-4821")) {
			// The doorbell worked and the device is not there.
			w.WriteHeader(webhook.UnreachableStatus)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	plugintest.Dispatcher(t, plugintest.DispatcherHarness{
		New: func(t *testing.T) plugin.Dispatcher {
			d, err := webhook.New(srv.URL, []byte("conformance-secret-long-enough"),
				2*time.Second)
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
		BreakTransport: func(*testing.T) func() {
			broken.Store(true)
			return func() { broken.Store(false) }
		},
	})
}
