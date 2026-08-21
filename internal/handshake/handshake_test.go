package handshake_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/handshake"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
	"github.com/oarlock/oarlock/pkg/transport"
	"github.com/oarlock/oarlock/pkg/transport/memory"
)

// ── a registry and a signer, in memory ──────────────────────────────────────────

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

// countingSigner wraps a key so a test can prove the crypto.Signer seam is
// actually used — which is what lets a hardware-backed keystore be handed in on a
// platform that offers one.
type countingSigner struct {
	key   ed25519.PrivateKey
	calls int
}

func (s *countingSigner) Public() crypto.PublicKey { return s.key.Public() }
func (s *countingSigner) Sign(r io.Reader, msg []byte, o crypto.SignerOpts) ([]byte, error) {
	s.calls++
	return s.key.Sign(r, msg, o)
}

func newDevice(t *testing.T, id string, platform plugin.Platform) (*plugin.Device, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &plugin.Device{ID: id, Platform: platform, Keys: []ed25519.PublicKey{pub}}, priv
}

// run performs both sides concurrently and returns both outcomes.
func run(t *testing.T, g *handshake.Gateway, a *handshake.Agent) (*handshake.Result, *frame.Welcome, error, error) {
	t.Helper()
	ga, ag := memory.Pair(0)
	ctx := context.Background()

	type gout struct {
		res *handshake.Result
		err error
	}
	ch := make(chan gout, 1)
	go func() {
		res, err := g.Accept(ctx, ga)
		ch <- gout{res, err}
	}()
	w, aerr := a.Perform(ctx, ag)
	o := <-ch
	return o.res, w, o.err, aerr
}

// ── the property that matters most ──────────────────────────────────────────────

// TestSigningInputIsInjective is the reason SigningInput length-prefixes its
// fields instead of concatenating them, as the first draft of the protocol
// described.
//
// Plain concatenation of variable-length fields is ambiguous: device "ab" with
// gateway "c" produces the same bytes as device "a" with gateway "bc". A peer that
// controls one field can then shift the boundary and obtain a signature that
// validates against values nobody agreed to.
func TestSigningInputIsInjective(t *testing.T) {
	nS := bytes.Repeat([]byte{1}, handshake.NonceLen)
	nC := bytes.Repeat([]byte{2}, handshake.NonceLen)

	pairs := [][2]string{
		{"ab", "c"}, {"a", "bc"},
		{"", "abc"}, {"abc", ""},
		{"dev", "gw"}, {"devg", "w"},
	}
	seen := map[string][2]string{}
	for _, p := range pairs {
		key := string(handshake.SigningInput(nS, nC, p[0], p[1]))
		if other, dup := seen[key]; dup {
			t.Fatalf("(%q,%q) and (%q,%q) produce identical signing input",
				other[0], other[1], p[0], p[1])
		}
		seen[key] = p
	}

	// The nonces must matter too, or a signature would replay across handshakes.
	base := handshake.SigningInput(nS, nC, "d", "g")
	if bytes.Equal(base, handshake.SigningInput(nC, nS, "d", "g")) {
		t.Error("swapping the nonces produces the same input")
	}
	// And the domain separator must be there, so a device key signature can never
	// be valid in some other protocol that hashes similar bytes.
	if !bytes.HasPrefix(base, []byte("oarlock-control-v0\x00")) {
		t.Error("signing input is not domain-separated")
	}
}

// ── the happy path ──────────────────────────────────────────────────────────────

func TestHandshakeSucceeds(t *testing.T) {
	dev, priv := newDevice(t, "treadmill-4821", plugin.PlatformAndroid)
	signer := &countingSigner{key: priv}

	g := &handshake.Gateway{Registry: reg{map[string]*plugin.Device{dev.ID: dev}}, GatewayID: "gw-a"}
	a := &handshake.Agent{
		DeviceID: dev.ID,
		Signer:   signer,
		Caps:     []string{"shell", "log"},
		Info:     frame.AgentInfo{Version: "0.1.0", Platform: "android/34", Arch: "arm64"},
	}

	res, w, gerr, aerr := run(t, g, a)
	if gerr != nil || aerr != nil {
		t.Fatalf("gateway: %v; agent: %v", gerr, aerr)
	}
	if res.Device.ID != dev.ID {
		t.Errorf("gateway identified %q", res.Device.ID)
	}
	if res.Version != handshake.Version || w.Version != handshake.Version {
		t.Errorf("versions: gateway %d, agent saw %d", res.Version, w.Version)
	}
	if w.GatewayID != "gw-a" {
		t.Errorf("gateway id %q", w.GatewayID)
	}
	if signer.calls != 1 {
		t.Errorf("signer called %d times, want 1", signer.calls)
	}
	// Caps are recorded so a session for a profile the agent never advertised can be
	// refused at open time rather than after a round trip.
	if !res.Supports("shell") || res.Supports("tcp") {
		t.Errorf("caps not recorded: %v", res.Caps)
	}
	if res.Agent.Platform != "android/34" {
		t.Errorf("agent info lost: %+v", res.Agent)
	}
	if w.Limits == nil || w.Limits.Frame != frame.MaxFrame || w.Limits.Batch != frame.MaxBatch {
		t.Errorf("welcome limits: %+v", w.Limits)
	}
}

// TestKeyRotation covers the reason Device.Keys is a list.
func TestKeyRotation(t *testing.T) {
	oldPub, _, _ := ed25519.GenerateKey(rand.Reader)
	newPub, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	dev := &plugin.Device{
		ID: "rower-1", Platform: plugin.PlatformLinux,
		Keys: []ed25519.PublicKey{oldPub, newPub}, // both published during rollover
	}
	g := &handshake.Gateway{Registry: reg{map[string]*plugin.Device{dev.ID: dev}}, GatewayID: "gw-a"}
	a := &handshake.Agent{DeviceID: dev.ID, Signer: newPriv}

	if _, _, gerr, aerr := run(t, g, a); gerr != nil || aerr != nil {
		t.Fatalf("a device using the second registered key was rejected: %v / %v", gerr, aerr)
	}
}

func TestResumeCarriesInvitations(t *testing.T) {
	dev, priv := newDevice(t, "treadmill-1", plugin.PlatformLinux)
	g := &handshake.Gateway{
		Registry:  reg{map[string]*plugin.Device{dev.ID: dev}},
		GatewayID: "gw-a",
		Resume: func(context.Context, string) []frame.Invitation {
			return []frame.Invitation{{SessionID: "sess_1", Ticket: "tk", URL: "wss://gw-a/ws/session"}}
		},
	}
	a := &handshake.Agent{DeviceID: dev.ID, Signer: priv}
	_, w, gerr, aerr := run(t, g, a)
	if gerr != nil || aerr != nil {
		t.Fatalf("%v / %v", gerr, aerr)
	}
	// A device on cellular loses its socket regularly; a shell that dies with the
	// radio is a shell nobody trusts with a long command.
	if w.Resume == nil || len(w.Resume.Sessions) != 1 || w.Resume.Sessions[0].SessionID != "sess_1" {
		t.Fatalf("resume not delivered: %+v", w.Resume)
	}
}

// ── rejection paths ─────────────────────────────────────────────────────────────

// TestUnknownDeviceLooksExactlyLikeABadSignature is the enumeration-oracle
// criterion. The protocol has a device_unknown code; sending it to an
// unauthenticated peer would hand it a way to enumerate the fleet.
func TestUnknownDeviceLooksExactlyLikeABadSignature(t *testing.T) {
	known, priv := newDevice(t, "known-1", plugin.PlatformLinux)
	g := &handshake.Gateway{Registry: reg{map[string]*plugin.Device{known.ID: known}}, GatewayID: "gw-a"}

	// Unknown device id.
	_, _, gerr, aerr := run(t, g, &handshake.Agent{DeviceID: "ghost-9", Signer: priv})
	if !errors.Is(gerr, handshake.ErrAuthFailed) {
		t.Fatalf("unknown device: gateway returned %v, want ErrAuthFailed", gerr)
	}
	unknownMsg := errString(aerr)

	// Known device, wrong key.
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, _, gerr2, aerr2 := run(t, g, &handshake.Agent{DeviceID: known.ID, Signer: wrongPriv})
	if !errors.Is(gerr2, handshake.ErrAuthFailed) {
		t.Fatalf("wrong key: gateway returned %v, want ErrAuthFailed", gerr2)
	}
	badSigMsg := errString(aerr2)

	if unknownMsg != badSigMsg {
		t.Errorf("the two failures are distinguishable from the client:\n unknown: %s\n bad sig: %s",
			unknownMsg, badSigMsg)
	}
	if unknownMsg == "" {
		t.Fatal("the agent was told nothing at all")
	}
}

// TestUnknownDeviceStillReachesAuth proves the flow does not short-circuit: the
// *shape* of the exchange must not distinguish the two failures either.
func TestUnknownDeviceStillReachesAuth(t *testing.T) {
	g := &handshake.Gateway{Registry: reg{map[string]*plugin.Device{}}, GatewayID: "gw-a"}
	ga, ag := memory.Pair(0)
	ctx := context.Background()
	go func() { _, _ = g.Accept(ctx, ga) }()

	c := frame.Codec{}
	send := func(t frame.Type, v any) {
		f, err := frame.Marshal(t, v)
		if err != nil {
			panic(err)
		}
		wire, _ := c.Encode(nil, f)
		_ = ag.Send(ctx, wire)
	}
	send(frame.TypeHello, frame.Hello{
		DeviceID: "ghost-9", Versions: []int{0},
		NonceC: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	})
	msg, err := ag.Recv(ctx)
	if err != nil {
		t.Fatalf("no CHALLENGE for an unknown device: %v", err)
	}
	f, err := c.Decode(msg)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != frame.TypeChallenge {
		t.Fatalf("got %s, want CHALLENGE — the gateway short-circuited and leaked "+
			"that the device is unknown through the shape of the exchange", f.Type)
	}
}

func TestVersionNegotiationFailure(t *testing.T) {
	dev, priv := newDevice(t, "rower-2", plugin.PlatformLinux)
	g := &handshake.Gateway{Registry: reg{map[string]*plugin.Device{dev.ID: dev}}, GatewayID: "gw-a"}
	a := &handshake.Agent{DeviceID: dev.ID, Signer: priv, Versions: []int{7, 9}}

	_, _, gerr, aerr := run(t, g, a)
	if !errors.Is(gerr, handshake.ErrVersion) {
		t.Errorf("gateway: %v, want ErrVersion", gerr)
	}
	// The agent must learn *why*, not just that the socket closed. A clear failure
	// at the handshake beats a mysterious parse error six frames later.
	if !errors.Is(aerr, handshake.ErrRemoteError) {
		t.Errorf("agent: %v, want ErrRemoteError", aerr)
	}
	if aerr != nil && !bytes.Contains([]byte(aerr.Error()), []byte("version_unsupported")) {
		t.Errorf("agent error does not name the code: %v", aerr)
	}
}

func TestMalformedHello(t *testing.T) {
	dev, priv := newDevice(t, "rower-3", plugin.PlatformLinux)
	g := &handshake.Gateway{Registry: reg{map[string]*plugin.Device{dev.ID: dev}}, GatewayID: "gw-a"}

	t.Run("bad device id", func(t *testing.T) {
		_, _, gerr, _ := run(t, g, &handshake.Agent{DeviceID: "../etc/passwd", Signer: priv})
		if !errors.Is(gerr, handshake.ErrProtocol) {
			t.Errorf("got %v, want ErrProtocol", gerr)
		}
	})

	t.Run("short nonce", func(t *testing.T) {
		ga, ag := memory.Pair(0)
		ctx := context.Background()
		done := make(chan error, 1)
		go func() { _, err := g.Accept(ctx, ga); done <- err }()

		c := frame.Codec{}
		f, _ := frame.Marshal(frame.TypeHello, frame.Hello{
			DeviceID: dev.ID, Versions: []int{0}, NonceC: "c2hvcnQ", // "short"
		})
		wire, _ := c.Encode(nil, f)
		_ = ag.Send(ctx, wire)
		if err := <-done; !errors.Is(err, handshake.ErrProtocol) {
			t.Errorf("got %v, want ErrProtocol", err)
		}
	})
}

// TestSessionFrameOnTheControlChannel covers the rule that replaced multiplexing:
// a connection is one session or the control channel, and a frame from the wrong
// family means the peer is confused about which it is holding.
func TestSessionFrameOnTheControlChannel(t *testing.T) {
	g := &handshake.Gateway{Registry: reg{map[string]*plugin.Device{}}, GatewayID: "gw-a"}
	ga, ag := memory.Pair(0)
	ctx := context.Background()
	done := make(chan error, 1)
	go func() { _, err := g.Accept(ctx, ga); done <- err }()

	wire, _ := frame.Codec{}.Encode(nil, frame.Data([]byte("ls -la")))
	_ = ag.Send(ctx, wire)
	if err := <-done; !errors.Is(err, handshake.ErrProtocol) {
		t.Errorf("got %v, want ErrProtocol", err)
	}
}

// TestBudgetIsEnforced covers the resource limit: a stalled handshake is a socket
// an unauthenticated peer is holding open.
func TestBudgetIsEnforced(t *testing.T) {
	g := &handshake.Gateway{Registry: reg{map[string]*plugin.Device{}}, GatewayID: "gw-a"}
	ga, _ := memory.Pair(0)

	start := time.Now()
	_, err := g.Accept(context.Background(), ga) // nothing is ever sent
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a silent peer was accepted")
	}
	if elapsed > handshake.Budget+2*time.Second {
		t.Errorf("took %v, want roughly %v", elapsed, handshake.Budget)
	}
	if elapsed < handshake.Budget/2 {
		t.Errorf("returned after %v — the budget is not what ended it", elapsed)
	}
}

func TestClosedConnection(t *testing.T) {
	g := &handshake.Gateway{Registry: reg{map[string]*plugin.Device{}}, GatewayID: "gw-a"}
	ga, ag := memory.Pair(0)
	_ = ag.Close(transport.CloseNormal, "gone")
	if _, err := g.Accept(context.Background(), ga); err == nil {
		t.Fatal("a closed connection produced a successful handshake")
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
