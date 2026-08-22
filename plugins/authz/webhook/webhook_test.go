package webhook_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oarlock/oarlock/pkg/plugin"
	"github.com/oarlock/oarlock/pkg/plugin/plugintest"
	"github.com/oarlock/oarlock/plugins/authz/webhook"
)

func TestAuthorizePostsTheDecisionRequest(t *testing.T) {
	var got struct {
		Principal struct {
			ID     string   `json:"id"`
			Groups []string `json:"groups"`
		} `json:"principal"`
		Device struct {
			ID           string            `json:"id"`
			ResolvedMode plugin.Mode       `json:"resolved_mode"`
			Tags         map[string]string `json:"tags"`
		} `json:"device"`
		Action plugin.Action `json:"action"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Errorf("authorization header = %q", r.Header.Get("Authorization"))
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode request: %v", err)
		}
		_, _ = w.Write([]byte(`{"allow":true,"limits":{"max_duration":"15m","idle":"2m","rate":4096},"ttl":"3s"}`))
	}))
	defer srv.Close()

	a, err := webhook.New(srv.URL, "", "secret", time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	d, err := a.Authorize(context.Background(),
		&plugin.Principal{ID: "phuc@example.com", Groups: []string{"oncall"}},
		&plugin.Device{
			ID: "treadmill-4821", Platform: plugin.PlatformAndroid,
			Tags: map[string]string{"scope": "pci"},
		},
		plugin.ActionShell,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Allow {
		t.Fatal("decision did not allow")
	}
	if got.Principal.ID != "phuc@example.com" || got.Principal.Groups[0] != "oncall" {
		t.Fatalf("principal payload = %+v", got.Principal)
	}
	if got.Device.ResolvedMode != plugin.ModeDispatch || got.Device.Tags["scope"] != "pci" {
		t.Fatalf("device payload = %+v", got.Device)
	}
	if got.Action != plugin.ActionShell {
		t.Fatalf("action = %q", got.Action)
	}
	if d.Limits == nil || d.Limits.MaxDuration == nil || *d.Limits.MaxDuration != 15*time.Minute {
		t.Fatalf("limits = %+v", d.Limits)
	}
	if d.TTL != 3*time.Second {
		t.Fatalf("ttl = %v", d.TTL)
	}
}

func TestHTTPFailureIsUnavailableNotADenial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "database down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	a, err := webhook.New(srv.URL, "", "", time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	d, err := a.Authorize(context.Background(), who("phuc@example.com"), dev("treadmill-4821"), plugin.ActionShell)
	if err == nil {
		t.Fatalf("Authorize error = nil, decision = %+v", d)
	}
	if d.Allow {
		t.Fatal("broken dependency allowed")
	}
}

func TestForbiddenIsADenial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"allow":false,"reason":"not in on-call"}`))
	}))
	defer srv.Close()
	a, err := webhook.New(srv.URL, "", "", time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	d, err := a.Authorize(context.Background(), who("bob@example.com"), dev("treadmill-4821"), plugin.ActionShell)
	if err != nil {
		t.Fatal(err)
	}
	if d.Allow || d.Reason != "not in on-call" {
		t.Fatalf("decision = %+v", d)
	}
}

func TestCacheTTL(t *testing.T) {
	var calls atomic.Int32
	now := time.Unix(100, 0)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"allow":true}`))
	}))
	defer srv.Close()
	a, err := webhook.New(srv.URL, "", "", time.Second, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	a.Now = func() time.Time { return now }
	for range 2 {
		if _, err := a.Authorize(context.Background(), who("phuc@example.com"), dev("treadmill-4821"), plugin.ActionShell); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("calls before expiry = %d", calls.Load())
	}
	now = now.Add(3 * time.Second)
	if _, err := a.Authorize(context.Background(), who("phuc@example.com"), dev("treadmill-4821"), plugin.ActionShell); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls after expiry = %d", calls.Load())
	}
}

func TestWatchStreamsRevocations(t *testing.T) {
	events := make(chan plugin.RevocationEvent, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/watch" {
			_, _ = w.Write([]byte(`{"allow":true}`))
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("response is not flushable")
			return
		}
		flusher.Flush()
		select {
		case ev := <-events:
			b, _ := json.Marshal(map[string]string{
				"principal_id": ev.PrincipalID,
				"device_id":    ev.DeviceID,
				"reason":       ev.Reason,
			})
			_, _ = fmt.Fprintf(w, "event: revoke\ndata: %s\n\n", b)
			flusher.Flush()
		case <-r.Context().Done():
		}
		<-r.Context().Done()
	}))
	defer srv.Close()
	a, err := webhook.New(srv.URL, srv.URL+"/watch", "", time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := a.Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	events <- plugin.RevocationEvent{PrincipalID: "phuc@example.com", DeviceID: "treadmill-4821", Reason: "left group"}
	select {
	case ev := <-ch:
		if ev.PrincipalID != "phuc@example.com" || ev.DeviceID != "treadmill-4821" {
			t.Fatalf("event = %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event")
	}
	cancel()
	select {
	case _, open := <-ch:
		if open {
			t.Fatal("watch channel stayed open after cancellation")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watch did not close")
	}
}

func TestConformance(t *testing.T) {
	var (
		mu     sync.Mutex
		broken bool
		events chan plugin.RevocationEvent
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		isBroken := broken
		if events == nil {
			events = make(chan plugin.RevocationEvent, 4)
		}
		evs := events
		mu.Unlock()

		if r.URL.Path == "/watch" {
			if isBroken {
				http.Error(w, "down", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			flusher := w.(http.Flusher)
			flusher.Flush()
			for {
				select {
				case ev := <-evs:
					b, _ := json.Marshal(map[string]string{
						"principal_id": ev.PrincipalID,
						"device_id":    ev.DeviceID,
						"reason":       ev.Reason,
					})
					_, _ = fmt.Fprintf(w, "data: %s\n\n", b)
					flusher.Flush()
				case <-r.Context().Done():
					return
				}
			}
		}
		if isBroken {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		var req struct {
			Principal struct {
				ID string `json:"id"`
			} `json:"principal"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if req.Principal.ID == "phuc@example.com" {
			_, _ = w.Write([]byte(`{"allow":true}`))
			return
		}
		_, _ = w.Write([]byte(`{"allow":false,"reason":"not in the on-call group"}`))
	}))
	defer srv.Close()

	plugintest.Authorizer(t, plugintest.AuthorizerHarness{
		New: func(t *testing.T) plugin.Authorizer {
			a, err := webhook.New(srv.URL, srv.URL+"/watch", "", time.Second, 10*time.Millisecond)
			if err != nil {
				t.Fatal(err)
			}
			return a
		},
		Allowed: func() (*plugin.Principal, *plugin.Device, plugin.Action) {
			return who("phuc@example.com"), dev("treadmill-4821"), plugin.ActionShell
		},
		Denied: func() (*plugin.Principal, *plugin.Device, plugin.Action) {
			return who("nobody@example.com"), dev("treadmill-4821"), plugin.ActionShell
		},
		BreakDependency: func(t *testing.T) func() {
			mu.Lock()
			broken = true
			mu.Unlock()
			return func() {
				mu.Lock()
				broken = false
				mu.Unlock()
			}
		},
		SupportsWatch: true,
		Revoke: func(t *testing.T, p *plugin.Principal, dev *plugin.Device) {
			mu.Lock()
			if events == nil {
				events = make(chan plugin.RevocationEvent, 4)
			}
			ch := events
			mu.Unlock()
			select {
			case ch <- plugin.RevocationEvent{PrincipalID: p.ID, DeviceID: dev.ID, Reason: "left group"}:
			case <-time.After(time.Second):
				t.Fatal("revocation send blocked")
			}
		},
	})
}

func TestWatchUnsupportedWithoutURL(t *testing.T) {
	a, err := webhook.New("http://example.invalid/authorize", "", "", time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Watch(context.Background())
	if !errors.Is(err, plugin.ErrUnsupported) {
		t.Fatalf("Watch err = %v", err)
	}
}

func who(id string) *plugin.Principal { return &plugin.Principal{ID: id} }

func dev(id string) *plugin.Device { return &plugin.Device{ID: id, Platform: plugin.PlatformLinux} }
