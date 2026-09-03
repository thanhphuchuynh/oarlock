package agent_test

// The control channel: the doorbell a persistent-mode device holds open.
//
// It carries no session traffic, which makes what it *does* carry easy to undervalue.
// This is the connection that decides whether a device is reachable at all, whether it
// stops when told to, and how hard a fleet hammers a gateway that is refusing them. The
// last one is why the GOAWAY tests are here: a drain where every device ignores the
// gateway's delay and falls back to its own backoff is a thundering herd, and it arrives
// at exactly the moment the gateway said it was struggling.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oarlock/oarlock/agent"
	"github.com/oarlock/oarlock/internal/backoff"
	"github.com/oarlock/oarlock/internal/handshake"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
	"github.com/oarlock/oarlock/pkg/transport"
	"github.com/oarlock/oarlock/pkg/transport/memory"
)

const controlURL = "wss://gw-a.example.org/ws/control"

// ── a gateway on the other end of a pipe ────────────────────────────────────────

// dialer hands each Dial one end of a fresh in-memory pair and publishes the other end
// on a channel, so a test can play gateway. Every dial is recorded with its URL and the
// time it happened, which is what the reconnect-timing tests read.
type dialer struct {
	conns chan transport.Conn

	mu    sync.Mutex
	dials []dial
	err   error // when set, every Dial fails
}

type dial struct {
	url string
	at  time.Time
}

func newDialer() *dialer {
	return &dialer{conns: make(chan transport.Conn, 8)}
}

func (d *dialer) Dial(_ context.Context, url string, _ transport.Options) (transport.Conn, error) {
	d.mu.Lock()
	d.dials = append(d.dials, dial{url: url, at: time.Now()})
	err := d.err
	d.mu.Unlock()
	if err != nil {
		return nil, err
	}
	agentEnd, gatewayEnd := memory.Pair(0)
	d.conns <- gatewayEnd
	return agentEnd, nil
}

func (d *dialer) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.dials)
}

func (d *dialer) at(i int) dial {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dials[i]
}

// gateway waits for the agent to dial and returns the gateway's end.
func (d *dialer) gateway(t *testing.T) transport.Conn {
	t.Helper()
	select {
	case c := <-d.conns:
		return c
	case <-time.After(3 * time.Second):
		t.Fatal("the agent never dialled")
		return nil
	}
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

type controlHarness struct {
	ctrl   *agent.Control
	dialer *dialer
	key    ed25519.PrivateKey
	device *plugin.Device
	logs   *syncBuffer

	gwLogs *syncBuffer
	resume func(ctx context.Context, deviceID string) []frame.Invitation

	// finished is closed after Run returns; runErr is then readable. A channel that
	// tests receive from would be drained by whichever of the test body and the
	// cleanup got there first.
	finished chan struct{}
	runErr   error
	cancel   context.CancelFunc
}

func newControlHarness(t *testing.T, tweak func(*agent.Config)) *controlHarness {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := &controlHarness{
		dialer:   newDialer(),
		key:      priv,
		device:   &plugin.Device{ID: "build-runner-2", Platform: plugin.PlatformLinux, Keys: []ed25519.PublicKey{pub}},
		logs:     &syncBuffer{},
		gwLogs:   &syncBuffer{},
		finished: make(chan struct{}),
	}
	cfg := agent.Config{
		Gateway:   controlURL,
		DeviceID:  h.device.ID,
		Signer:    priv,
		Dialer:    h.dialer,
		PinSHA256: []string{"a-pin"},
		Caps:      []string{"shell"},
		Info:      frame.AgentInfo{Version: "test"},
		Log:       slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		// Tight, so a reconnect test does not spend a second waiting. Individual tests
		// widen it where the point is that a delay was honoured.
		Backoff:      backoff.Policy{Base: time.Millisecond, Cap: 5 * time.Millisecond, Factor: 1},
		WriteTimeout: 2 * time.Second,
	}
	if tweak != nil {
		tweak(&cfg)
	}
	c, err := agent.NewControl(cfg)
	if err != nil {
		t.Fatalf("NewControl: %v", err)
	}
	h.ctrl = c
	return h
}

func (h *controlHarness) run(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() {
		h.runErr = h.ctrl.Run(ctx)
		close(h.finished)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-h.finished:
		case <-time.After(3 * time.Second):
			t.Error("Run did not return after its context was cancelled")
		}
	})
}

// accept plays the gateway side of the handshake on one connection.
func (h *controlHarness) accept(t *testing.T, conn transport.Conn) *handshake.Result {
	t.Helper()
	g := &handshake.Gateway{
		Registry:  reg{devices: map[string]*plugin.Device{h.device.ID: h.device}},
		GatewayID: "gw-a",
		Resume:    h.resume,
		Log:       slog.New(slog.NewTextHandler(h.gwLogs, nil)),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := g.Accept(ctx, conn)
	if err != nil {
		t.Fatalf("gateway handshake: %v", err)
	}
	return res
}

// up brings one channel all the way up and returns the gateway's end.
func (h *controlHarness) up(t *testing.T) transport.Conn {
	t.Helper()
	conn := h.dialer.gateway(t)
	h.accept(t, conn)
	waitFor(t, h.ctrl.Up, "the control channel never came up")
	return conn
}

type reg struct{ devices map[string]*plugin.Device }

func (r reg) Get(_ context.Context, id string) (*plugin.Device, error) {
	if d, ok := r.devices[id]; ok {
		return d, nil
	}
	return nil, plugin.ErrNoDevice
}
func (r reg) List(context.Context, plugin.DeviceQuery) ([]*plugin.Device, string, error) {
	return nil, "", plugin.ErrUnsupported
}

// ── wire helpers ────────────────────────────────────────────────────────────────

func send(t *testing.T, conn transport.Conn, typ frame.Type, v any) {
	t.Helper()
	f, err := frame.Marshal(typ, v)
	if err != nil {
		t.Fatalf("marshalling %s: %v", typ, err)
	}
	sendFrame(t, conn, f)
}

func sendFrame(t *testing.T, conn transport.Conn, f frame.Frame) {
	t.Helper()
	wire, err := frame.Codec{}.Encode(nil, f)
	if err != nil {
		t.Fatalf("encoding %s: %v", f.Type, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := conn.Send(ctx, wire); err != nil {
		t.Fatalf("sending %s: %v", f.Type, err)
	}
}

func recv(t *testing.T, conn transport.Conn) frame.Frame {
	t.Helper()
	return recvWithin(t, conn, 3*time.Second)
}

func recvWithin(t *testing.T, conn transport.Conn, d time.Duration) frame.Frame {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
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

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal(msg)
}

// ── configuration ───────────────────────────────────────────────────────────────

// TestNewControlRefusesAnUnusableConfig. Each of these produces an agent that looks
// running and can never connect, which is the worst way for a device to be broken:
// silent, and indistinguishable from a network problem.
func TestNewControlRefusesAnUnusableConfig(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	full := agent.Config{
		Gateway: controlURL, DeviceID: "d1", Signer: key, Dialer: newDialer(),
	}
	for _, tc := range []struct {
		field  string
		broken func(*agent.Config)
	}{
		{"Gateway", func(c *agent.Config) { c.Gateway = "" }},
		{"DeviceID", func(c *agent.Config) { c.DeviceID = "" }},
		{"Signer", func(c *agent.Config) { c.Signer = nil }},
		{"Dialer", func(c *agent.Config) { c.Dialer = nil }},
	} {
		cfg := full
		tc.broken(&cfg)
		_, err := agent.NewControl(cfg)
		if err == nil {
			t.Fatalf("a config with no %s was accepted", tc.field)
		}
		if !strings.Contains(err.Error(), tc.field) {
			t.Fatalf("the error for a missing %s is %q; it should name the field",
				tc.field, err)
		}
	}
}

// TestAnUnpinnedAgentSaysSoOutLoud.
//
// v0 has no channel binding, so the pin is the only thing between this handshake and a
// TLS-terminating middlebox relaying it. An unpinned agent still works, which is exactly
// why the warning matters: the operator has a weaker guarantee than the documentation
// describes and nothing else would tell them.
func TestAnUnpinnedAgentSaysSoOutLoud(t *testing.T) {
	logs := &bytes.Buffer{}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := agent.NewControl(agent.Config{
		Gateway: controlURL, DeviceID: "d1", Signer: key, Dialer: newDialer(),
		Log: slog.New(slog.NewTextHandler(logs, nil)),
	}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"no certificate pin", "channel binding", "d1"} {
		if !strings.Contains(logs.String(), want) {
			t.Fatalf("the warning does not mention %q:\n%s", want, logs.String())
		}
	}
}

// TestAPinnedAgentIsQuiet is the other half: a correctly configured agent must not warn,
// or the warning becomes noise nobody reads.
func TestAPinnedAgentIsQuiet(t *testing.T) {
	logs := &bytes.Buffer{}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := agent.NewControl(agent.Config{
		Gateway: controlURL, DeviceID: "d1", Signer: key, Dialer: newDialer(),
		PinSHA256: []string{"a-pin"},
		Log:       slog.New(slog.NewTextHandler(logs, nil)),
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), "no certificate pin") {
		t.Fatalf("a pinned agent warned anyway:\n%s", logs.String())
	}
}

// TestThePinReachesTheDialer. A pin configured and not passed down is worse than no pin
// at all, because the operator believes they have one.
func TestThePinReachesTheDialer(t *testing.T) {
	var seen []string
	d := &recordingDialer{dialer: newDialer(), onOptions: func(o transport.Options) {
		seen = o.PinSHA256
	}}
	h := newControlHarness(t, func(c *agent.Config) {
		c.Dialer = d
		c.PinSHA256 = []string{"sha256-of-the-gateway-key"}
	})
	h.run(t)
	_ = d.dialer.gateway(t)

	if len(seen) != 1 || seen[0] != "sha256-of-the-gateway-key" {
		t.Fatalf("the dialer was given pins %v", seen)
	}
}

type recordingDialer struct {
	dialer    *dialer
	onOptions func(transport.Options)
}

func (r *recordingDialer) Dial(ctx context.Context, url string, o transport.Options) (transport.Conn, error) {
	r.onOptions(o)
	return r.dialer.Dial(ctx, url, o)
}

// ── liveness ────────────────────────────────────────────────────────────────────

// TestAPingIsEchoedVerbatim.
//
// The stamp is the gateway's round-trip clock. Echoing anything other than the exact
// eight bytes — recomputing "now", or truncating — turns the gateway's latency
// measurement into a measurement of the agent's clock.
func TestAPingIsEchoedVerbatim(t *testing.T) {
	h := newControlHarness(t, nil)
	h.run(t)
	conn := h.up(t)

	const stamp = uint64(0x0123456789abcdef)
	ping, err := frame.Stamp(frame.TypePing, stamp)
	if err != nil {
		t.Fatal(err)
	}
	sendFrame(t, conn, ping)

	f := recv(t, conn)
	if f.Type != frame.TypePong {
		t.Fatalf("got %s, want PONG", f.Type)
	}
	got, err := frame.ReadStamp(f)
	if err != nil {
		t.Fatal(err)
	}
	if got != stamp {
		t.Fatalf("stamp came back as %#x, want %#x", got, stamp)
	}
}

// TestTheAgentPingsWhenAskedTo. Usually the gateway owns the timer — the side with
// thousands of peers should — but a network that silently drops idle connections needs
// the device to speak first, and PingInterval is how an operator turns that on.
func TestTheAgentPingsWhenAskedTo(t *testing.T) {
	h := newControlHarness(t, func(c *agent.Config) { c.PingInterval = 10 * time.Millisecond })
	h.run(t)
	conn := h.up(t)

	f := recv(t, conn)
	if f.Type != frame.TypePing {
		t.Fatalf("got %s, want PING", f.Type)
	}
	if _, err := frame.ReadStamp(f); err != nil {
		t.Fatalf("the agent's PING carries no readable stamp: %v", err)
	}
}

// ── scope ───────────────────────────────────────────────────────────────────────

// TestASessionFrameOnTheControlChannelEndsIt.
//
// Not recoverable per-frame, deliberately. A DATA frame arriving here means the gateway
// has confused two connections, and continuing would mean guessing which one this is.
func TestASessionFrameOnTheControlChannelEndsIt(t *testing.T) {
	h := newControlHarness(t, nil)
	h.run(t)
	conn := h.up(t)

	sendFrame(t, conn, frame.Data([]byte("this belongs on a session")))

	f := recv(t, conn)
	if f.Type != frame.TypeError {
		t.Fatalf("got %s, want ERROR", f.Type)
	}
	waitFor(t, func() bool { return !h.ctrl.Up() }, "the channel stayed up after a scope violation")
}

// TestAHandshakeFrameAfterTheHandshakeEndsTheChannel. A second WELCOME is either a
// confused gateway or somebody injecting; either way the connection's state is no longer
// something this agent can reason about.
func TestAHandshakeFrameAfterTheHandshakeEndsTheChannel(t *testing.T) {
	h := newControlHarness(t, nil)
	h.run(t)
	conn := h.up(t)

	send(t, conn, frame.TypeWelcome, frame.Welcome{Version: 0, GatewayID: "gw-a"})

	if f := recv(t, conn); f.Type != frame.TypeError {
		t.Fatalf("got %s, want ERROR", f.Type)
	}
	waitFor(t, func() bool { return !h.ctrl.Up() }, "the channel stayed up after a second WELCOME")
}

// ── invitations ─────────────────────────────────────────────────────────────────

// TestADialFrameBecomesAnInvitation.
func TestADialFrameBecomesAnInvitation(t *testing.T) {
	got := make(chan frame.Invitation, 1)
	h := newControlHarness(t, func(c *agent.Config) {
		c.OnInvitation = func(_ context.Context, inv frame.Invitation) { got <- inv }
	})
	h.run(t)
	conn := h.up(t)

	want := frame.Invitation{
		SessionID: "s-1", Ticket: "opaque", Profile: "shell",
		URL: "wss://gw-a.example.org/ws/session",
	}
	send(t, conn, frame.TypeDial, want)

	select {
	case inv := <-got:
		if inv.SessionID != want.SessionID || inv.Ticket != want.Ticket || inv.URL != want.URL {
			t.Fatalf("the invitation arrived as %+v", inv)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the invitation never reached the handler")
	}
}

// TestASlowSessionDoesNotStallTheChannel.
//
// Dialling a session involves a TLS handshake. Running that inline would mean a device
// asked for two sessions at once serialises them behind a network round trip — and, worse,
// stops answering the gateway's pings while it does, which looks exactly like a device
// that has dropped off the network.
func TestASlowSessionDoesNotStallTheChannel(t *testing.T) {
	release := make(chan struct{})
	var started atomic.Int32
	h := newControlHarness(t, func(c *agent.Config) {
		c.OnInvitation = func(context.Context, frame.Invitation) {
			started.Add(1)
			<-release
		}
	})
	h.run(t)
	conn := h.up(t)
	defer close(release)

	send(t, conn, frame.TypeDial, frame.Invitation{SessionID: "s-1", Ticket: "t1", URL: "u"})
	send(t, conn, frame.TypeDial, frame.Invitation{SessionID: "s-2", Ticket: "t2", URL: "u"})

	waitFor(t, func() bool { return started.Load() == 2 },
		"the second invitation waited for the first to finish")

	// And the channel is still answering, which is the part a stalled read loop would lose.
	ping, _ := frame.Stamp(frame.TypePing, 7)
	sendFrame(t, conn, ping)
	if f := recv(t, conn); f.Type != frame.TypePong {
		t.Fatalf("got %s, want PONG from a channel with two sessions dialling", f.Type)
	}
}

// TestACancelWithdrawsAnInvitation. Without it a device that woke slowly dials for a
// session nobody is waiting on, spends its ticket, and is told to go away — which from
// the device's side is indistinguishable from a bug.
func TestACancelWithdrawsAnInvitation(t *testing.T) {
	type cancelled struct{ session, reason string }
	got := make(chan cancelled, 1)
	h := newControlHarness(t, func(c *agent.Config) {
		c.OnCancel = func(_ context.Context, session, reason string) {
			got <- cancelled{session, reason}
		}
	})
	h.run(t)
	conn := h.up(t)

	send(t, conn, frame.TypeCancel, frame.Cancel{SessionID: "s-1", Reason: "operator_gone"})

	select {
	case c := <-got:
		if c.session != "s-1" || c.reason != "operator_gone" {
			t.Fatalf("cancel arrived as %+v", c)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the cancellation never reached the handler")
	}
}

// TestSessionsAreResumedFromWelcome.
//
// A device on cellular loses its socket regularly. Dialling back for each held session is
// what makes that invisible to the operator instead of killing their shell; without it a
// long command dies with the radio.
func TestSessionsAreResumedFromWelcome(t *testing.T) {
	got := make(chan frame.Invitation, 4)
	h := newControlHarness(t, func(c *agent.Config) {
		c.OnInvitation = func(_ context.Context, inv frame.Invitation) { got <- inv }
	})
	h.resume = func(context.Context, string) []frame.Invitation {
		return []frame.Invitation{
			{SessionID: "s-1", Ticket: "t1", URL: "u", Profile: "shell"},
			{SessionID: "s-2", Ticket: "t2", URL: "u", Profile: "shell"},
		}
	}
	h.run(t)
	_ = h.up(t)

	seen := map[string]bool{}
	for range 2 {
		select {
		case inv := <-got:
			seen[inv.SessionID] = true
		case <-time.After(3 * time.Second):
			t.Fatalf("only %d of 2 held sessions were resumed", len(seen))
		}
	}
	if !seen["s-1"] || !seen["s-2"] {
		t.Fatalf("resumed %v", seen)
	}
}

// ── going away ──────────────────────────────────────────────────────────────────

// TestAnAdminStopEndsTheAgentRatherThanReconnecting.
//
// The distinction is the whole point of the frame: a gateway that is restarting wants the
// fleet back, and one that has been told to stop this device does not. An agent that
// reconnected after admin_stop would make the button not work.
func TestAnAdminStopEndsTheAgentRatherThanReconnecting(t *testing.T) {
	for _, reason := range []string{"admin_stop", "admin_disconnect"} {
		t.Run(reason, func(t *testing.T) {
			h := newControlHarness(t, nil)
			h.run(t)
			conn := h.up(t)

			send(t, conn, frame.TypeGoAway, frame.GoAway{Reason: reason})

			select {
			case <-h.finished:
				if h.runErr != nil {
					t.Fatalf("Run returned %v; a requested stop is not an error", h.runErr)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("the agent did not stop when told to")
			}
			if n := h.dialer.count(); n != 1 {
				t.Fatalf("the agent dialled %d times after being told to stop", n)
			}
		})
	}
}

// TestTheGatewaysReconnectDelayBeatsLocalBackoff.
//
// During a drain the gateway is the only party that can see the whole fleet, so its delay
// has to win — otherwise every device falls back to its own backoff, which for a fleet
// that all disconnected at the same moment means they all come back at the same moment
// too. The agent's own backoff here is set to a millisecond, so honouring the gateway's
// 400 ms is the only way this test can pass.
func TestTheGatewaysReconnectDelayBeatsLocalBackoff(t *testing.T) {
	const delay = 400 * time.Millisecond
	h := newControlHarness(t, nil)
	h.run(t)
	conn := h.up(t)

	send(t, conn, frame.TypeGoAway, frame.GoAway{
		Reason: "draining", ReconnectAfterMS: int(delay / time.Millisecond),
	})

	waitFor(t, func() bool { return h.dialer.count() == 2 }, "the agent never reconnected")

	gap := h.dialer.at(1).at.Sub(h.dialer.at(0).at)
	if gap < delay/2 {
		t.Fatalf("reconnected after %v; the gateway asked for %v and local backoff is 1ms",
			gap, delay)
	}
}

// TestTheAgentReconnectsAfterTheChannelDrops. The default behaviour, and the reason the
// device is reachable at all: a dropped socket is normal on a device that sleeps.
func TestTheAgentReconnectsAfterTheChannelDrops(t *testing.T) {
	h := newControlHarness(t, nil)
	h.run(t)
	conn := h.up(t)

	_ = conn.Close(transport.CloseNormal, "gateway restarting")

	waitFor(t, func() bool { return h.dialer.count() >= 2 }, "the agent did not redial")
	if url := h.dialer.at(1).url; url != controlURL {
		t.Fatalf("redialled %q, want the configured gateway", url)
	}
}

// ── errors from the gateway ─────────────────────────────────────────────────────

// TestANonRetryableErrorEndsTheChannel.
func TestANonRetryableErrorEndsTheChannel(t *testing.T) {
	h := newControlHarness(t, nil)
	h.run(t)
	conn := h.up(t)

	send(t, conn, frame.TypeError, frame.Error{
		Code: "internal", Message: "something is wrong", Retryable: false,
	})

	waitFor(t, func() bool { return !h.ctrl.Up() }, "a fatal error left the channel up")
}

// TestARetryableErrorDoesNotEndTheChannel. The gateway saying "that one session failed"
// must not cost the device its doorbell.
func TestARetryableErrorDoesNotEndTheChannel(t *testing.T) {
	h := newControlHarness(t, nil)
	h.run(t)
	conn := h.up(t)

	send(t, conn, frame.TypeError, frame.Error{
		Code: "device_offline", Message: "that session went away", Retryable: true,
	})

	// The channel is still there and still answering.
	ping, _ := frame.Stamp(frame.TypePing, 1)
	sendFrame(t, conn, ping)
	if f := recv(t, conn); f.Type != frame.TypePong {
		t.Fatalf("got %s, want PONG", f.Type)
	}
	if !h.ctrl.Up() {
		t.Fatal("a retryable error tore the channel down")
	}
}

// ── state ───────────────────────────────────────────────────────────────────────

// TestUpAndWelcomeReportTheChannelState. Both are what an embedder's health check reads,
// so "connected" must mean authenticated rather than merely dialled.
func TestUpAndWelcomeReportTheChannelState(t *testing.T) {
	h := newControlHarness(t, nil)
	if h.ctrl.Up() {
		t.Fatal("a control channel reported itself up before Run")
	}
	if h.ctrl.Welcome() != nil {
		t.Fatal("a control channel had a WELCOME before it connected")
	}
	h.run(t)

	// Dialled but not yet authenticated: still down.
	conn := h.dialer.gateway(t)
	if h.ctrl.Up() {
		t.Fatal("the channel reported itself up before the handshake completed")
	}
	h.accept(t, conn)

	waitFor(t, h.ctrl.Up, "the channel never came up")
	w := h.ctrl.Welcome()
	if w == nil || w.GatewayID != "gw-a" {
		t.Fatalf("Welcome() = %+v", w)
	}
}

// TestADialFailureIsRetried. A gateway that is down is the normal case on a device that
// boots before the network is up.
func TestADialFailureIsRetried(t *testing.T) {
	h := newControlHarness(t, nil)
	h.dialer.mu.Lock()
	h.dialer.err = errors.New("connection refused")
	h.dialer.mu.Unlock()
	h.run(t)

	waitFor(t, func() bool { return h.dialer.count() >= 3 },
		"the agent gave up after a failed dial")
	if h.ctrl.Up() {
		t.Fatal("the channel reported itself up with no gateway behind it")
	}
}
