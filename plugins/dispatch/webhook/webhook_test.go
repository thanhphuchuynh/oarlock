package webhook_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
	"github.com/oarlock/oarlock/plugins/dispatch/webhook"
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

type capture struct {
	uri    string
	body   []byte
	header http.Header
}

func serve(t *testing.T, status int, got *capture) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got.uri, got.body, got.header = r.URL.RequestURI(), b, r.Header.Clone()
		w.WriteHeader(status)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/doorbell"
}

func TestInvitationGoesInTheBody(t *testing.T) {
	var got capture
	d, err := webhook.New(serve(t, 202, &got), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Wake(context.Background(), dev(), inv()); err != nil {
		t.Fatal(err)
	}

	var payload struct {
		DeviceID   string           `json:"device_id"`
		Platform   string           `json:"platform"`
		Invitation frame.Invitation `json:"invitation"`
	}
	if err := json.Unmarshal(got.body, &payload); err != nil {
		t.Fatalf("body is not the documented shape: %v\n%s", err, got.body)
	}
	if payload.DeviceID != "treadmill-4821" || payload.Platform != "android" {
		t.Errorf("payload: %+v", payload)
	}
	if payload.Invitation.Ticket != secret {
		t.Errorf("ticket did not arrive: %+v", payload.Invitation)
	}
	// The URL must name a node, and the dispatcher must not rewrite it.
	if payload.Invitation.URL != "wss://gw-a.example.org/ws/session" {
		t.Errorf("the dispatcher rewrote the node URL: %q", payload.Invitation.URL)
	}
	if got.header.Get("Oarlock-Event") != "device.wake" {
		t.Errorf("event header %q", got.header.Get("Oarlock-Event"))
	}
}

// TestTicketNeverReachesTheURL is the rule from protocol § 1.2, enforced here
// because a doorbell is the easiest place to break it: query strings land in
// ingress access logs, load-balancer logs, APM traces and browser history, and a
// single-use ticket sitting in a log file is still a ticket until it is redeemed.
func TestTicketNeverReachesTheURL(t *testing.T) {
	var got capture
	d, _ := webhook.New(serve(t, 200, &got), nil, 0)
	if err := d.Wake(context.Background(), dev(), inv()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got.uri, secret) {
		t.Fatalf("the ticket appeared in the request URI: %s", got.uri)
	}
	if got.uri != "/doorbell" {
		t.Errorf("unexpected request URI %q", got.uri)
	}
	// Nor in any header — headers are logged by roughly everything.
	for k, vs := range got.header {
		for _, v := range vs {
			if strings.Contains(v, secret) {
				t.Errorf("the ticket appeared in header %s", k)
			}
		}
	}
}

func TestSignature(t *testing.T) {
	var got capture
	key := []byte("doorbell-secret")
	at := time.Unix(1787218725, 0)
	d, _ := webhook.New(serve(t, 200, &got), key, 0)
	d.Now = func() time.Time { return at }

	if err := d.Wake(context.Background(), dev(), inv()); err != nil {
		t.Fatal(err)
	}
	sig := got.header.Get("Oarlock-Signature")
	if sig == "" {
		t.Fatal("no signature header")
	}
	ts, mac, ok := parseSig(sig)
	if !ok {
		t.Fatalf("unparseable signature %q", sig)
	}
	if ts != strconv.FormatInt(at.Unix(), 10) {
		t.Errorf("timestamp %q, want %d", ts, at.Unix())
	}

	h := hmac.New(sha256.New, key)
	h.Write([]byte(ts + "."))
	h.Write(got.body)
	if want := hex.EncodeToString(h.Sum(nil)); mac != want {
		t.Errorf("mac %s, want %s", mac, want)
	}

	// The timestamp is inside the signed material, so a captured request is not
	// replayable forever — the receiver rejects anything older than five minutes.
	h2 := hmac.New(sha256.New, key)
	h2.Write([]byte("999."))
	h2.Write(got.body)
	if mac == hex.EncodeToString(h2.Sum(nil)) {
		t.Error("the signature does not cover the timestamp")
	}
}

func TestNoSignatureWithoutASecret(t *testing.T) {
	var got capture
	d, _ := webhook.New(serve(t, 200, &got), nil, 0)
	if err := d.Wake(context.Background(), dev(), inv()); err != nil {
		t.Fatal(err)
	}
	if got.header.Get("Oarlock-Signature") != "" {
		t.Error("signed without a secret")
	}
}

// TestStatusMapping is the distinction that decides who gets paged.
func TestStatusMapping(t *testing.T) {
	tests := map[int]struct {
		unreachable bool
		fails       bool
	}{
		200: {false, false},
		202: {false, false},
		204: {false, false},
		404: {true, true},  // the device is not there
		410: {true, true},  // it is gone
		500: {false, true}, // we could not deliver
		502: {false, true},
		403: {false, true},
	}
	for status, want := range tests {
		var got capture
		d, _ := webhook.New(serve(t, status, &got), nil, 0)
		err := d.Wake(context.Background(), dev(), inv())
		if want.fails != (err != nil) {
			t.Errorf("%d: err=%v, want failure=%v", status, err, want.fails)
		}
		if got := errors.Is(err, plugin.ErrDeviceUnreachable); got != want.unreachable {
			t.Errorf("%d: unreachable=%v, want %v (err=%v)", status, got, want.unreachable, err)
		}
	}
}

func TestErrorExcerptIsBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(500)
		_, _ = w.Write([]byte(strings.Repeat("A", 100_000)))
	}))
	defer srv.Close()

	d, _ := webhook.New(srv.URL, nil, 0)
	err := d.Wake(context.Background(), dev(), inv())
	if err == nil {
		t.Fatal("expected a failure")
	}
	// A doorbell that returns a megabyte of HTML must not put it in a log line.
	if len(err.Error()) > 500 {
		t.Errorf("error is %d bytes; the body excerpt is not bounded", len(err.Error()))
	}
}

func TestTimeoutIsBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()

	d, _ := webhook.New(srv.URL, nil, 100*time.Millisecond)
	start := time.Now()
	if err := d.Wake(context.Background(), dev(), inv()); err == nil {
		t.Fatal("a hanging doorbell reported success")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("took %v; the timeout did not bound it", elapsed)
	}
}

func TestConfigValidation(t *testing.T) {
	if _, err := webhook.New("", nil, 0); err == nil {
		t.Error("an empty URL was accepted")
	}
	var zero webhook.Dispatcher
	if err := zero.Wake(context.Background(), dev(), inv()); err == nil {
		t.Error("the zero Dispatcher accepted a wake")
	}
}

func parseSig(s string) (ts, mac string, ok bool) {
	for _, part := range strings.Split(s, ",") {
		k, v, found := strings.Cut(part, "=")
		if !found {
			return "", "", false
		}
		switch k {
		case "t":
			ts = v
		case "v1":
			mac = v
		}
	}
	return ts, mac, ts != "" && mac != ""
}
