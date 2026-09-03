package controlsrv_test

// The device's front door: /ws/control.
//
// Three lines of orchestration, and each of them is load-bearing. The handshake's own
// rules are tested in internal/handshake and the hub's in internal/hub; what is only
// testable here is the wiring between them — that a rejected device never reaches the
// hub, that an accepted one does, and that the handler stays for the life of the channel
// rather than returning and closing the socket the gateway needs later.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/controlsrv"
	"github.com/oarlock/oarlock/internal/handshake"
	"github.com/oarlock/oarlock/internal/hub"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
	"github.com/oarlock/oarlock/pkg/transport"
	"github.com/oarlock/oarlock/pkg/transport/memory"
)

// ── doubles ─────────────────────────────────────────────────────────────────────

type upgrader struct {
	conn transport.Conn
	err  error
}

func (u upgrader) Upgrade(http.ResponseWriter, *http.Request, transport.Options) (transport.Conn, error) {
	if u.err != nil {
		return nil, u.err
	}
	return u.conn, nil
}

// registry is a device registry in a map.
type registry struct{ devices map[string]*plugin.Device }

func (r registry) Get(_ context.Context, id string) (*plugin.Device, error) {
	if d, ok := r.devices[id]; ok {
		return d, nil
	}
	return nil, plugin.ErrNoDevice
}
func (r registry) List(context.Context, plugin.DeviceQuery) ([]*plugin.Device, string, error) {
	return nil, "", plugin.ErrUnsupported
}

// syncBuffer is a log sink a test can read while the handler is still writing to it.
// bytes.Buffer is not, and -race is right to say so.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// ── harness ─────────────────────────────────────────────────────────────────────

const deviceID = "build-runner-2"

type harness struct {
	srv  *controlsrv.Server
	hub  *hub.Hub
	reg  registry
	logs *syncBuffer

	client transport.Conn
	done   chan struct{}
	cancel context.CancelFunc
}

func newHarness(t *testing.T, dev *plugin.Device) *harness {
	t.Helper()
	h := &harness{
		reg:  registry{devices: map[string]*plugin.Device{}},
		logs: &syncBuffer{},
		done: make(chan struct{}),
	}
	if dev != nil {
		h.reg.devices[dev.ID] = dev
	}
	log := slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	// A ping interval long enough that no test races the hub's own timer.
	h.hub = hub.New(hub.Options{PingInterval: time.Hour, Log: log})

	server, client := memory.Pair(0)
	h.client = client
	h.srv = &controlsrv.Server{
		Upgrader:  upgrader{conn: server},
		Handshake: &handshake.Gateway{Registry: h.reg, GatewayID: "gw-a", Log: log},
		Hub:       h.hub,
		Log:       log,
	}
	return h
}

func (h *harness) serve(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	req := httptest.NewRequest(http.MethodGet, "/ws/control", nil).WithContext(ctx)
	go func() {
		defer close(h.done)
		h.srv.ServeHTTP(httptest.NewRecorder(), req)
	}()
	t.Cleanup(func() {
		cancel()
		_ = h.client.Close(transport.CloseNormal, "test over")
		select {
		case <-h.done:
		case <-time.After(3 * time.Second):
			t.Error("the handler did not return after the request was cancelled")
		}
	})
}

func newDevice(t *testing.T, id string) (*plugin.Device, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &plugin.Device{ID: id, Platform: plugin.PlatformLinux, Keys: []ed25519.PublicKey{pub}}, priv
}

// handshakeAs runs the agent side on the client end and returns the WELCOME.
func handshakeAs(t *testing.T, conn transport.Conn, id string, key ed25519.PrivateKey) (*frame.Welcome, error) {
	t.Helper()
	a := &handshake.Agent{DeviceID: id, Signer: key, Caps: []string{"shell"},
		Info: frame.AgentInfo{Version: "test"}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return a.Perform(ctx, conn)
}

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal(msg)
}

// ── refusal ─────────────────────────────────────────────────────────────────────

// TestAnUnknownDeviceNeverReachesTheHub.
//
// The hub is what makes a device *addressable* — anything holding a channel there can be
// sent a DIAL. A device that failed the handshake must therefore not be in it, and the
// only thing standing between those two facts is this handler returning early.
func TestAnUnknownDeviceNeverReachesTheHub(t *testing.T) {
	h := newHarness(t, nil) // an empty registry: nobody is enrolled
	h.serve(t)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handshakeAs(t, h.client, "not-enrolled", priv); err == nil {
		t.Fatal("an unenrolled device completed the handshake")
	}

	if h.hub.Len() != 0 {
		t.Fatalf("the hub holds %d channels after a failed handshake", h.hub.Len())
	}
	if h.hub.Connected("not-enrolled") {
		t.Fatal("a device that failed authentication is addressable")
	}
}

// TestAWrongKeyIsRefused. The device exists; the signature does not verify against any
// key registered for it.
func TestAWrongKeyIsRefused(t *testing.T) {
	dev, _ := newDevice(t, deviceID)
	h := newHarness(t, dev)
	h.serve(t)

	_, wrongKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handshakeAs(t, h.client, deviceID, wrongKey); err == nil {
		t.Fatal("a device signing with an unregistered key was accepted")
	}
	if h.hub.Connected(deviceID) {
		t.Fatal("a device that failed authentication is addressable")
	}
}

// TestARejectedDeviceLearnsOnlyThatAuthenticationFailed.
//
// The wire code is auth_failed whether the device is unknown, disabled, or signing with
// the wrong key. Anything finer is an enumeration oracle for the fleet, answerable
// without any credential at all.
func TestARejectedDeviceLearnsOnlyThatAuthenticationFailed(t *testing.T) {
	known, knownKey := newDevice(t, deviceID)
	disabled, disabledKey := newDevice(t, "disabled-device")
	disabled.Disabled = true

	_, strangerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, wrongKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = knownKey

	cases := map[string]struct {
		enrolled *plugin.Device
		id       string
		key      ed25519.PrivateKey
	}{
		"a device that was never enrolled": {nil, "not-enrolled", strangerKey},
		"a device that has been disabled":  {disabled, disabled.ID, disabledKey},
		"a key that is not registered":     {known, deviceID, wrongKey},
	}

	// The assertion is on what the *peer* observed. recvInto surfaces a remote ERROR as
	// "peer returned an error: <code>: <message>", so the agent's error string is a
	// faithful record of the frame that went out — which is the thing that must not
	// differ between these three.
	var first, firstName string
	for name, tc := range cases {
		h := newHarness(t, tc.enrolled)
		h.serve(t)

		_, err := handshakeAs(t, h.client, tc.id, tc.key)
		if err == nil {
			t.Fatalf("%s: the handshake succeeded", name)
		}
		if !errors.Is(err, handshake.ErrRemoteError) {
			t.Fatalf("%s: the agent saw %v, not a refusal from the gateway", name, err)
		}
		got := err.Error()

		if !strings.Contains(got, "auth_failed") {
			t.Errorf("%s: the peer was told %q, want auth_failed", name, got)
		}
		if firstName == "" {
			first, firstName = got, name
			continue
		}
		if got != first {
			t.Errorf("a caller can tell these apart:\n  %s: %s\n  %s: %s",
				firstName, first, name, got)
		}
	}

	// And the sentence carries nothing either.
	for _, leak := range []string{deviceID, "disabled", "unknown", "key"} {
		if strings.Contains(strings.ToLower(first), strings.ToLower(leak)) {
			t.Fatalf("the refusal names what was wrong (%q): %s", leak, first)
		}
	}
}

// TestTheRealReasonIsLogged. Telling the peer nothing is only defensible because the
// operator can still find out which of the three it was.
func TestTheRealReasonIsLogged(t *testing.T) {
	dev, _ := newDevice(t, deviceID)
	h := newHarness(t, dev)
	h.serve(t)

	_, wrongKey, _ := ed25519.GenerateKey(rand.Reader)
	_, _ = handshakeAs(t, h.client, deviceID, wrongKey)

	logs := h.logs.String()
	for _, want := range []string{deviceID, "no registered key verifies the signature"} {
		if !strings.Contains(logs, want) {
			t.Fatalf("the log does not mention %q:\n%s", want, logs)
		}
	}
	if !strings.Contains(logs, "control handshake failed") {
		t.Fatalf("the handler did not log the failure:\n%s", logs)
	}
}

// ── acceptance ──────────────────────────────────────────────────────────────────

// TestAnAuthenticatedDeviceBecomesAddressable.
//
// This is the whole point of the endpoint: after the handshake the gateway can reach a
// device that has no listener, no host key and no open port, because the device is
// holding this channel. The proof is an invitation arriving at the agent's end.
func TestAnAuthenticatedDeviceBecomesAddressable(t *testing.T) {
	dev, key := newDevice(t, deviceID)
	h := newHarness(t, dev)
	h.serve(t)

	w, err := handshakeAs(t, h.client, deviceID, key)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if w.GatewayID != "gw-a" {
		t.Fatalf("gateway id = %q, want gw-a", w.GatewayID)
	}

	// Registration happens on the handler's goroutine, just after Accept returns.
	waitFor(t, func() bool { return h.hub.Connected(deviceID) },
		"the device never became addressable through the hub")

	inv := frame.Invitation{
		SessionID: "s-1", Ticket: "opaque", Profile: "shell",
		URL: "wss://gw-a.example.org/ws/session",
	}
	if err := h.hub.Invite(context.Background(), deviceID, inv); err != nil {
		t.Fatalf("inviting a connected device: %v", err)
	}

	f := recv(t, h.client)
	if f.Type != frame.TypeDial {
		t.Fatalf("got %s, want DIAL", f.Type)
	}
	var got frame.Invitation
	if err := frame.Unmarshal(f, &got); err != nil {
		t.Fatal(err)
	}
	if got.SessionID != "s-1" || got.Ticket != "opaque" {
		t.Fatalf("the invitation arrived as %+v", got)
	}
}

// TestTheHandlerStaysForTheLifeOfTheChannel.
//
// Returning from ServeHTTP closes the socket. A control channel is long-lived by
// definition, so a handler that returned after a successful handshake would leave the
// gateway unable to reach the device it had just authenticated — and the device would
// reconnect immediately, forever.
func TestTheHandlerStaysForTheLifeOfTheChannel(t *testing.T) {
	dev, key := newDevice(t, deviceID)
	h := newHarness(t, dev)
	h.serve(t)

	if _, err := handshakeAs(t, h.client, deviceID, key); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	waitFor(t, func() bool { return h.hub.Connected(deviceID) }, "the device never registered")

	select {
	case <-h.done:
		t.Fatal("the handler returned while the control channel was still up")
	case <-time.After(150 * time.Millisecond):
	}

	// The device hanging up is what ends it.
	_ = h.client.Close(transport.CloseNormal, "device going away")
	select {
	case <-h.done:
	case <-time.After(3 * time.Second):
		t.Fatal("the handler outlived the connection")
	}
	waitFor(t, func() bool { return !h.hub.Connected(deviceID) },
		"a disconnected device is still addressable")
}

// TestTheAgentsCapabilitiesAreLogged.
//
// Caps is how a build without a PTY says so, and it decides whether the gateway refuses
// a shell at open time or after a round trip. It travels through this handler, so it is
// worth knowing it arrives.
func TestTheAgentsCapabilitiesAreLogged(t *testing.T) {
	dev, key := newDevice(t, deviceID)
	h := newHarness(t, dev)
	h.serve(t)

	if _, err := handshakeAs(t, h.client, deviceID, key); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	waitFor(t, func() bool { return strings.Contains(h.logs.String(), "control channel up") },
		"the accepted channel was never logged")

	logs := h.logs.String()
	for _, want := range []string{deviceID, "shell"} {
		if !strings.Contains(logs, want) {
			t.Fatalf("the log does not mention %q:\n%s", want, logs)
		}
	}
}

// TestAFailedUpgradeIsNotAPanic.
func TestAFailedUpgradeIsNotAPanic(t *testing.T) {
	logs := &bytes.Buffer{}
	srv := &controlsrv.Server{
		Upgrader:  upgrader{err: errors.New("not a websocket request")},
		Handshake: &handshake.Gateway{Registry: registry{}, GatewayID: "gw-a"},
		Hub:       hub.New(hub.Options{}),
		Log:       slog.New(slog.NewTextHandler(logs, nil)),
	}
	srv.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/ws/control", nil))

	if !strings.Contains(logs.String(), "control upgrade failed") {
		t.Fatalf("a failed upgrade was not logged:\n%s", logs.String())
	}
}

// ── wire helper ─────────────────────────────────────────────────────────────────

func recv(t *testing.T, conn transport.Conn) frame.Frame {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	msg, err := conn.Recv(ctx)
	if err != nil {
		t.Fatalf("receiving: %v", err)
	}
	f, err := frame.Codec{}.Decode(msg)
	if err != nil {
		t.Fatalf("decoding: %v", err)
	}
	return f.Clone()
}
