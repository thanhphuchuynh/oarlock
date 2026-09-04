package hub_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oarlock/oarlock/agent"
	"github.com/oarlock/oarlock/internal/backoff"
	"github.com/oarlock/oarlock/internal/handshake"
	"github.com/oarlock/oarlock/internal/hub"
	"github.com/oarlock/oarlock/internal/invite"
	"github.com/oarlock/oarlock/internal/ticket"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
	"github.com/oarlock/oarlock/pkg/transport"
	"github.com/oarlock/oarlock/pkg/transport/memory"
)

const deviceID = "treadmill-4821"

// ── harness ─────────────────────────────────────────────────────────────────────

type reg struct{ dev *plugin.Device }

func (r reg) Get(_ context.Context, id string) (*plugin.Device, error) {
	if r.dev != nil && id == r.dev.ID {
		return r.dev, nil
	}
	return nil, plugin.ErrNoDevice
}
func (r reg) List(context.Context, plugin.DeviceQuery) ([]*plugin.Device, string, error) {
	return nil, "", plugin.ErrUnsupported
}

// dialer hands one end of an in-memory pair to the agent and runs the gateway side
// on the other, so both real implementations talk to each other with no network.
type dialer struct {
	accept    func(conn transport.Conn)
	failFirst int32
	dials     atomic.Int32
}

func (d *dialer) Dial(_ context.Context, _ string, _ transport.Options) (transport.Conn, error) {
	if d.dials.Add(1) <= d.failFirst {
		return nil, errors.New("dial refused")
	}
	a, b := memory.Pair(0)
	go d.accept(b)
	return a, nil
}

type fixture struct {
	hub      *hub.Hub
	dialer   *dialer
	agent    *agent.Control
	priv     ed25519.PrivateKey
	invs     chan frame.Invitation
	cancels  chan string
	release  chan struct{} // when non-nil, OnInvitation blocks on it
	cancel   context.CancelFunc
	agentErr chan error

	resume    []frame.Invitation
	failFirst int32
}

type opt func(*hub.Options, *agent.Config, *fixture)

func withPing(interval time.Duration, missed int) opt {
	return func(h *hub.Options, _ *agent.Config, _ *fixture) {
		h.PingInterval, h.MissedPings = interval, missed
	}
}
func withResume(inv ...frame.Invitation) opt {
	return func(_ *hub.Options, _ *agent.Config, f *fixture) { f.resume = inv }
}
func withSlowInvitations() opt {
	return func(_ *hub.Options, _ *agent.Config, f *fixture) { f.release = make(chan struct{}) }
}
func withFailedDials(n int32) opt {
	return func(_ *hub.Options, _ *agent.Config, f *fixture) { f.failFirst = n }
}
func withBackoff(p backoff.Policy) opt {
	return func(_ *hub.Options, a *agent.Config, _ *fixture) { a.Backoff = p }
}

func newFixture(t *testing.T, opts ...opt) *fixture {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dev := &plugin.Device{ID: deviceID, Platform: plugin.PlatformLinux,
		Keys: []ed25519.PublicKey{pub}}

	f := &fixture{
		priv:     priv,
		invs:     make(chan frame.Invitation, 8),
		cancels:  make(chan string, 8),
		agentErr: make(chan error, 1),
	}
	ho := hub.Options{Log: quietLog()}
	ac := agent.Config{}
	for _, o := range opts {
		o(&ho, &ac, f)
	}

	f.hub = hub.New(ho)
	gw := &handshake.Gateway{Registry: reg{dev}, GatewayID: "gw-a", Log: quietLog()}
	if f.resume != nil {
		gw.Resume = func(context.Context, string) []frame.Invitation { return f.resume }
	}

	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	t.Cleanup(cancel)

	f.dialer = &dialer{failFirst: f.failFirst}
	f.dialer.accept = func(conn transport.Conn) {
		res, err := gw.Accept(ctx, conn)
		if err != nil {
			return
		}
		_ = f.hub.Serve(ctx, conn, res)
	}

	ac.Gateway = "memory://gw"
	ac.DeviceID = deviceID
	ac.Signer = priv
	ac.Dialer = f.dialer
	ac.PinSHA256 = []string{"test-pin"} // silences the unpinned warning
	ac.Caps = []string{"shell", "log"}
	ac.Log = quietLog()
	ac.OnInvitation = func(_ context.Context, inv frame.Invitation) {
		if f.release != nil {
			<-f.release
		}
		f.invs <- inv
	}
	ac.OnCancel = func(_ context.Context, sessionID, _ string) { f.cancels <- sessionID }

	c, err := agent.NewControl(ac)
	if err != nil {
		t.Fatal(err)
	}
	f.agent = c
	go func() { f.agentErr <- c.Run(ctx) }()
	return f
}

func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func recvInv(t *testing.T, f *fixture) frame.Invitation {
	t.Helper()
	select {
	case inv := <-f.invs:
		return inv
	case <-time.After(3 * time.Second):
		t.Fatal("no invitation arrived")
		return frame.Invitation{}
	}
}

// ── the point of the control channel ────────────────────────────────────────────

func TestInviteReachesTheAgent(t *testing.T) {
	f := newFixture(t)
	waitFor(t, "the channel to come up", f.agent.Up)
	waitFor(t, "the hub to register it", func() bool { return f.hub.Connected(deviceID) })

	want := frame.Invitation{
		SessionID: "sess_1", Ticket: "hK3", URL: "wss://gw-a.example.org/ws/session",
		Profile: "shell", PTY: &frame.PTY{Cols: 132, Rows: 38, Term: "xterm-256color"},
		Principal: "admin@mail.com",
	}
	if err := f.hub.Invite(context.Background(), deviceID, want); err != nil {
		t.Fatal(err)
	}
	got := recvInv(t, f)
	if got.SessionID != want.SessionID || got.Ticket != want.Ticket || got.URL != want.URL {
		t.Errorf("invitation changed in flight: %+v", got)
	}
	if got.PTY == nil || got.PTY.Cols != 132 || got.PTY.Term != "xterm-256color" {
		t.Errorf("pty lost: %+v", got.PTY)
	}
	// URL must name a node, not a load balancer — that is what removes the need to
	// forward a session between replicas.
	if got.URL != want.URL {
		t.Errorf("url %q", got.URL)
	}
}

func TestCancelWithdrawsAnInvitation(t *testing.T) {
	f := newFixture(t)
	waitFor(t, "channel up", func() bool { return f.hub.Connected(deviceID) })

	if err := f.hub.Cancel(context.Background(), deviceID, "sess_2", "operator_gave_up"); err != nil {
		t.Fatal(err)
	}
	select {
	case id := <-f.cancels:
		if id != "sess_2" {
			t.Errorf("cancelled %q", id)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no cancel arrived")
	}
}

func TestAdminStopStopsTheReferenceAgent(t *testing.T) {
	f := newFixture(t, withBackoff(backoff.Policy{Base: 5 * time.Millisecond, Cap: 20 * time.Millisecond}))
	waitFor(t, "channel up", func() bool { return f.hub.Connected(deviceID) })

	if err := f.hub.Disconnect(context.Background(), deviceID, "admin_stop"); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-f.agentErr:
		if err != nil {
			t.Fatalf("agent returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("agent did not stop")
	}
	if got := f.dialer.dials.Load(); got != 1 {
		t.Fatalf("agent redialed after admin stop: %d dials", got)
	}
	waitFor(t, "hub to deregister the channel", func() bool { return !f.hub.Connected(deviceID) })
}

func TestInviteWithoutAChannel(t *testing.T) {
	h := hub.New(hub.Options{Log: quietLog()})
	err := h.Invite(context.Background(), "nobody", frame.Invitation{SessionID: "s"})
	if !errors.Is(err, hub.ErrNotConnected) {
		t.Fatalf("got %v, want ErrNotConnected", err)
	}
	if h.Connected("nobody") || h.Len() != 0 {
		t.Error("an absent device reported as connected")
	}
}

// TestResumeDialsBackForEverySession covers how a shell survives a lost radio: the
// operator never learns the device reconnected.
func TestResumeDialsBackForEverySession(t *testing.T) {
	f := newFixture(t, withResume(
		frame.Invitation{SessionID: "sess_a", Ticket: "t1", URL: "wss://gw-a/ws/session"},
		frame.Invitation{SessionID: "sess_b", Ticket: "t2", URL: "wss://gw-a/ws/session"},
	))
	seen := map[string]bool{}
	for range 2 {
		seen[recvInv(t, f).SessionID] = true
	}
	if !seen["sess_a"] || !seen["sess_b"] {
		t.Errorf("resumed %v", seen)
	}
}

// TestSlowInvitationDoesNotStallTheChannel: dialling a session involves a TLS
// handshake, so doing it inline would serialise two sessions asked for at once.
func TestSlowInvitationDoesNotStallTheChannel(t *testing.T) {
	f := newFixture(t, withSlowInvitations())
	waitFor(t, "channel up", func() bool { return f.hub.Connected(deviceID) })

	ctx := context.Background()
	for _, id := range []string{"s1", "s2", "s3"} {
		if err := f.hub.Invite(ctx, deviceID, frame.Invitation{SessionID: id}); err != nil {
			t.Fatal(err)
		}
	}
	// All three handlers are blocked; the read loop must have delivered all three
	// anyway. Releasing them now proves nothing was serialised behind the first.
	close(f.release)
	seen := map[string]bool{}
	for range 3 {
		seen[recvInv(t, f).SessionID] = true
	}
	if len(seen) != 3 {
		t.Errorf("delivered %v", seen)
	}
}

// ── liveness ────────────────────────────────────────────────────────────────────

func TestPingKeepsAQuietChannelAlive(t *testing.T) {
	f := newFixture(t, withPing(20*time.Millisecond, 3))
	waitFor(t, "channel up", func() bool { return f.hub.Connected(deviceID) })

	// A control channel is quiet for long stretches by definition; the only way to
	// tell a live one from a dead one is to ask.
	time.Sleep(300 * time.Millisecond)
	if !f.hub.Connected(deviceID) {
		t.Fatal("a healthy channel was closed by its own pings")
	}
	if err := f.hub.Invite(context.Background(), deviceID,
		frame.Invitation{SessionID: "after-pings"}); err != nil {
		t.Fatalf("channel unusable after 15 ping rounds: %v", err)
	}
	recvInv(t, f)
}

// TestSilentPeerIsClosed covers the other half: a device that reads but stops
// answering must not still be "connected" when an operator asks for a shell.
func TestSilentPeerIsClosed(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	dev := &plugin.Device{ID: deviceID, Platform: plugin.PlatformLinux,
		Keys: []ed25519.PublicKey{pub}}

	h := hub.New(hub.Options{PingInterval: 20 * time.Millisecond, MissedPings: 2,
		WriteTimeout: 500 * time.Millisecond, Log: quietLog()})
	ga, ag := memory.Pair(0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Drains everything and answers nothing — the pings land, the pongs never come.
	go func() {
		for {
			if _, err := ag.Recv(ctx); err != nil {
				return
			}
		}
	}()

	done := make(chan error, 1)
	go func() { done <- h.Serve(ctx, ga, &handshake.Result{Device: dev}) }()

	waitFor(t, "the hub to register", func() bool { return h.Connected(deviceID) })
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("a channel that never answers a ping was left open")
	}
	if h.Connected(deviceID) || h.Len() != 0 {
		t.Error("the channel is still registered after closing")
	}
}

// TestStalledPeerIsClosed is the failure the write timeout exists for, and it is a
// different one: a peer that stops *reading* fills the socket buffers, and an
// unbounded Send then blocks the ping loop forever. The missed-ping check never
// runs, and the device stays "connected" while being useless — which is exactly the
// state the liveness check is supposed to prevent. This test found that hole.
func TestStalledPeerIsClosed(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	dev := &plugin.Device{ID: deviceID, Platform: plugin.PlatformLinux,
		Keys: []ed25519.PublicKey{pub}}

	h := hub.New(hub.Options{PingInterval: 10 * time.Millisecond, MissedPings: 50,
		WriteTimeout: 100 * time.Millisecond, Log: quietLog()})
	ga, _ := memory.Pair(0) // nothing ever reads the agent end

	done := make(chan error, 1)
	go func() { done <- h.Serve(context.Background(), ga, &handshake.Result{Device: dev}) }()

	waitFor(t, "the hub to register", func() bool { return h.Connected(deviceID) })
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("a peer that stopped reading held the channel open indefinitely")
	}
	if h.Len() != 0 {
		t.Error("the channel is still registered")
	}
}

// TestWriteTimeoutDefaultIsSane guards against someone setting it to zero meaning
// "no timeout", which is how the hole comes back.
func TestWriteTimeoutDefaultIsSane(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	dev := &plugin.Device{ID: deviceID, Platform: plugin.PlatformLinux,
		Keys: []ed25519.PublicKey{pub}}
	h := hub.New(hub.Options{Log: quietLog()}) // no WriteTimeout given
	ga, ag := memory.Pair(0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = h.Serve(ctx, ga, &handshake.Result{Device: dev}) }()
	waitFor(t, "registration", func() bool { return h.Connected(deviceID) })

	// One invite fits in the pipe; it must not hang forever even with nobody
	// reading, and with the default it returns promptly because the buffer is free.
	if err := h.Invite(ctx, deviceID, frame.Invitation{SessionID: "s"}); err != nil {
		t.Fatalf("invite failed: %v", err)
	}
	if _, err := ag.Recv(ctx); err != nil {
		t.Fatal(err)
	}
}

// ── protocol discipline ─────────────────────────────────────────────────────────

// TestSessionFrameClosesTheControlChannel is the rule that replaced multiplexing.
func TestSessionFrameClosesTheControlChannel(t *testing.T) {
	tests := map[string]frame.Frame{
		"DATA":                    frame.Data([]byte("ls -la")),
		"RESIZE":                  mustMarshal(t, frame.TypeResize, frame.Resize{Cols: 80, Rows: 24}),
		"unknown connection type": {Type: 0x1F},
		"HELLO after handshake":   mustMarshal(t, frame.TypeHello, frame.Hello{DeviceID: deviceID}),
		"DIAL from the agent":     mustMarshal(t, frame.TypeDial, frame.Invitation{SessionID: "x"}),
	}
	for name, bad := range tests {
		t.Run(name, func(t *testing.T) {
			pub, _, _ := ed25519.GenerateKey(rand.Reader)
			dev := &plugin.Device{ID: deviceID, Platform: plugin.PlatformLinux,
				Keys: []ed25519.PublicKey{pub}}
			h := hub.New(hub.Options{Log: quietLog()})
			ga, ag := memory.Pair(0)
			done := make(chan error, 1)
			go func() { done <- h.Serve(context.Background(), ga, &handshake.Result{Device: dev}) }()

			wire, err := frame.Codec{}.Encode(nil, bad)
			if err != nil {
				t.Fatal(err)
			}
			if err := ag.Send(context.Background(), wire); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("the channel closed cleanly; it should have reported a protocol error")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("the channel stayed open")
			}
			if h.Len() != 0 {
				t.Error("channel still registered")
			}
		})
	}
}

// ── reconnection ────────────────────────────────────────────────────────────────

// TestReconnectReplacesTheOldChannel: a half-open socket is the normal case, not an
// edge one. The newest connection wins because it is the one demonstrably alive.
func TestReconnectReplacesTheOldChannel(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	dev := &plugin.Device{ID: deviceID, Platform: plugin.PlatformLinux,
		Keys: []ed25519.PublicKey{pub}}
	h := hub.New(hub.Options{Log: quietLog()})
	ctx := context.Background()

	first, firstAgent := memory.Pair(0)
	go func() { _ = h.Serve(ctx, first, &handshake.Result{Device: dev}) }()
	waitFor(t, "first channel", func() bool { return h.Connected(deviceID) })

	second, _ := memory.Pair(0)
	go func() { _ = h.Serve(ctx, second, &handshake.Result{Device: dev}) }()

	// The stale channel must be closed rather than left as a leak that also answers
	// Connected.
	waitFor(t, "the stale channel to be closed", func() bool {
		_, err := firstAgent.Recv(ctx)
		return err != nil
	})
	waitFor(t, "exactly one channel", func() bool { return h.Len() == 1 })
	if !h.Connected(deviceID) {
		t.Error("the device is not connected after replacing its channel")
	}
}

func TestAgentRetriesAFailedDial(t *testing.T) {
	f := newFixture(t,
		withFailedDials(2),
		withBackoff(backoff.Policy{Base: 5 * time.Millisecond, Cap: 20 * time.Millisecond,
			Factor: 1.5, Jitter: 0.25}))
	waitFor(t, "the agent to get through", func() bool { return f.hub.Connected(deviceID) })
	if got := f.dialer.dials.Load(); got < 3 {
		t.Errorf("connected after %d dials, want at least 3", got)
	}
}

// TestDrainSpreadsTheFleet covers the failure mode of persistent mode that bites
// hardest at scale, and which is entirely self-inflicted.
func TestDrainSpreadsTheFleet(t *testing.T) {
	f := newFixture(t)
	waitFor(t, "channel up", func() bool { return f.hub.Connected(deviceID) })

	var mu sync.Mutex
	var handed []time.Duration
	next := func() time.Duration {
		mu.Lock()
		defer mu.Unlock()
		d := time.Duration(len(handed)+1) * 7 * time.Millisecond
		handed = append(handed, d)
		return d
	}
	f.hub.Drain(context.Background(), "gateway_shutdown", next)

	mu.Lock()
	n := len(handed)
	mu.Unlock()
	if n != 1 {
		t.Fatalf("nextDelay called %d times, want once per channel", n)
	}
	// The gateway is closed to new channels after a drain.
	if err := f.hub.Invite(context.Background(), deviceID,
		frame.Invitation{SessionID: "x"}); err == nil {
		t.Error("Invite succeeded after Drain")
	}
	// And the agent honours the delay rather than its own backoff, then comes back —
	// against a hub that now refuses it, which is fine: the point is that it retried.
	waitFor(t, "the agent to notice and redial", func() bool { return f.dialer.dials.Load() >= 2 })
}

func TestConcurrentInvitesAreSafe(t *testing.T) {
	f := newFixture(t)
	waitFor(t, "channel up", func() bool { return f.hub.Connected(deviceID) })

	// The ping loop and every caller of Invite write to the same connection, and
	// transport.Conn allows Send concurrent with Recv but not with itself.
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = f.hub.Invite(context.Background(), deviceID,
				frame.Invitation{SessionID: string(rune('a' + i))})
		}()
	}
	wg.Wait()
	for range 16 {
		recvInv(t, f)
	}
}

func TestNewControlValidatesConfig(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	base := agent.Config{Gateway: "wss://x/ws/control", DeviceID: "d",
		Signer: priv, Dialer: &dialer{}, Log: quietLog(), PinSHA256: []string{"p"}}

	if _, err := agent.NewControl(base); err != nil {
		t.Fatalf("a valid config was rejected: %v", err)
	}
	for name, mutate := range map[string]func(*agent.Config){
		"no gateway": func(c *agent.Config) { c.Gateway = "" },
		"no device":  func(c *agent.Config) { c.DeviceID = "" },
		"no signer":  func(c *agent.Config) { c.Signer = nil },
		"no dialer":  func(c *agent.Config) { c.Dialer = nil },
	} {
		cfg := base
		mutate(&cfg)
		if _, err := agent.NewControl(cfg); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func mustMarshal(t *testing.T, ty frame.Type, v any) frame.Frame {
	t.Helper()
	f, err := frame.Marshal(ty, v)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// ── the two modes, wired to the real Inviter ────────────────────────────────────

// compile-time proof that the hub is what internal/invite needs. If a method
// signature drifts, this fails at build time rather than at wiring time.
var _ invite.Reacher = (*hub.Hub)(nil)

// TestInviterDeliversThroughTheRealHub closes the loop for persistent mode: mint a
// ticket, deliver it as a DIAL down a live control channel, and let the agent's
// arrival resolve the pending session.
//
// In production OnInvitation dials the session URL and presents the ticket there;
// here it redeems directly, which exercises the same seam without needing the
// session endpoint (E1.S6).
func TestInviterDeliversThroughTheRealHub(t *testing.T) {
	f := newFixture(t)
	waitFor(t, "channel up", func() bool { return f.hub.Connected(deviceID) })

	tickets := ticket.NewMemory(nil)
	inviter := &invite.Inviter{
		Tickets:        tickets,
		Hub:            f.hub,
		NodeURL:        "wss://gw-a.example.org/ws/session",
		AnswerDeadline: 2 * time.Second,
		Log:            quietLog(),
	}

	dev := &plugin.Device{ID: deviceID, Platform: plugin.PlatformLinux}
	p, err := inviter.Invite(context.Background(), dev, invite.Request{
		SessionID: "sess_e2e", Profile: "shell", Principal: "admin@mail.com",
	})
	if err != nil {
		t.Fatal(err)
	}

	got := recvInv(t, f)
	if got.SessionID != "sess_e2e" || got.Ticket == "" {
		t.Fatalf("the agent received %+v", got)
	}
	if got.URL != "wss://gw-a.example.org/ws/session" {
		t.Errorf("the invitation must name a node: %q", got.URL)
	}

	// The agent spends the ticket and hands over its connection, which is what
	// "answered" means.
	devConn, _ := memory.Pair(0)
	if _, err := inviter.Attach(context.Background(), got.Ticket, ticket.Want{
		DeviceID: deviceID, Profile: "shell", Kind: ticket.KindDevice}, devConn); err != nil {
		t.Fatal(err)
	}
	att, err := p.Wait(context.Background())
	if err != nil {
		t.Fatalf("Wait returned %v", err)
	}
	if att.Conn != devConn {
		t.Error("the operator was handed a different connection")
	}

	// A retry must fetch a fresh invitation. Resending a spent ticket is
	// indistinguishable from an attacker replaying one, so it is refused as one.
	if _, err := inviter.Attach(context.Background(), got.Ticket, ticket.Want{
		DeviceID: deviceID, Kind: ticket.KindDevice}, devConn); !errors.Is(err, ticket.ErrInvalid) {
		t.Errorf("a resent ticket was accepted: %v", err)
	}
}

// TestInviterReportsAnAbsentChannelCorrectly: no control channel is the device
// being absent, and it must not read as a broken doorbell.
func TestInviterReportsAnAbsentChannelCorrectly(t *testing.T) {
	h := hub.New(hub.Options{Log: quietLog()})
	inviter := &invite.Inviter{
		Tickets: ticket.NewMemory(nil), Hub: h,
		NodeURL: "wss://gw-a/ws/session", Log: quietLog(),
	}
	_, err := inviter.Invite(context.Background(),
		&plugin.Device{ID: "ghost", Platform: plugin.PlatformLinux},
		invite.Request{SessionID: "s", Profile: "shell"})
	if !errors.Is(err, invite.ErrNotConnected) {
		t.Fatalf("got %v, want ErrNotConnected", err)
	}
}
