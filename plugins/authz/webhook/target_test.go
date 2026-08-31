package webhook_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oarlock/oarlock/pkg/plugin"
	"github.com/oarlock/oarlock/plugins/authz/webhook"
)

// targetServer allows exactly one port and records how many times it was asked.
func targetServer(t *testing.T, allowPort int, calls *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var body struct {
			Action plugin.Action `json:"action"`
			Target *struct {
				Port int      `json:"port"`
				Path string   `json:"path"`
				Argv []string `json:"argv"`
			} `json:"target"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		allow := body.Target != nil && body.Target.Port == allowPort
		_, _ = w.Write([]byte(`{"allow":` + boolJSON(allow) + `}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func boolJSON(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// TestTheCacheIsKeyedByTarget is the bug this test exists to keep out.
//
// The decision cache was keyed by (principal, device, action). Adding a target without
// adding it to that key would have made the cache the hole the target was introduced to
// close: ask for port 3000, get an allow, then ask for port 22 within the TTL and be
// handed the cached yes for a port the backend would have refused.
func TestTheCacheIsKeyedByTarget(t *testing.T) {
	var calls atomic.Int32
	srv := targetServer(t, 3000, &calls)
	a, err := webhook.New(srv.URL, "", "", time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	p := &plugin.Principal{ID: "support@example.com"}
	dev := &plugin.Device{ID: "treadmill-4821"}
	ctx := context.Background()

	allowed, err := a.Authorize(ctx, p, dev, plugin.ActionTCP, plugin.Target{Port: 3000})
	if err != nil {
		t.Fatal(err)
	}
	if !allowed.Allow {
		t.Fatal("port 3000 was refused")
	}

	refused, err := a.Authorize(ctx, p, dev, plugin.ActionTCP, plugin.Target{Port: 22})
	if err != nil {
		t.Fatal(err)
	}
	if refused.Allow {
		t.Fatal("port 22 was allowed — the cached decision for port 3000 was served for it")
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("the backend was asked %d times, want 2: a second target is a second question", n)
	}
}

// TestTheCacheStillWorksForTheSameTarget is the other half: keying by target must not
// have turned the cache off, which would answer the test above while quietly making every
// re-check a network round trip.
func TestTheCacheStillWorksForTheSameTarget(t *testing.T) {
	var calls atomic.Int32
	srv := targetServer(t, 3000, &calls)
	a, err := webhook.New(srv.URL, "", "", time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	p := &plugin.Principal{ID: "support@example.com"}
	dev := &plugin.Device{ID: "treadmill-4821"}
	for range 3 {
		d, err := a.Authorize(context.Background(), p, dev, plugin.ActionTCP, plugin.Target{Port: 3000})
		if err != nil {
			t.Fatal(err)
		}
		if !d.Allow {
			t.Fatal("port 3000 was refused")
		}
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("the backend was asked %d times for one target, want 1", n)
	}
}

// TestAnActionWithNoTargetSendsNoTargetField pins the wire compatibility promise: a
// backend written before targets existed sees exactly the body it saw before.
func TestAnActionWithNoTargetSendsNoTargetField(t *testing.T) {
	var raw map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			t.Errorf("decode request: %v", err)
		}
		_, _ = w.Write([]byte(`{"allow":true}`))
	}))
	defer srv.Close()

	a, err := webhook.New(srv.URL, "", "", time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Authorize(context.Background(), &plugin.Principal{ID: "phuc@example.com"},
		&plugin.Device{ID: "treadmill-4821"}, plugin.ActionShell, plugin.Target{}); err != nil {
		t.Fatal(err)
	}
	if _, present := raw["target"]; present {
		t.Errorf("shell sent a target field: %v", raw["target"])
	}
}
