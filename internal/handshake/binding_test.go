package handshake_test

// Channel binding: threat-model gap 1, and the attack it closes.
//
// v0's handshake proves the device holds its key. It does not prove the device is talking
// to *this* gateway over *this* connection, and certificate pinning was the stopgap for
// that — a stopgap because it only covers the case where the middlebox has to present a
// certificate the agent would reject. A relay that terminates TLS with a certificate the
// agent *does* accept — a corporate inspection appliance, a compromised load balancer, a
// CA the device trusts — passes pinning and then holds an authenticated control channel of
// its own.
//
// v1 mixes RFC 5705 exported keying material into what the device signs. A relay has two
// TLS sessions, so it exports two different values: the signature is made over one channel
// and verified over the other, and it does not verify. Nothing new goes on the wire.
//
// The tests below are in two halves. The first is that binding works and that a mismatch
// is caught — the cryptographic half. The second is downgrade, which is not cryptographic
// at all: the version is chosen by the gateway, so an attacker who can rewrite HELLO can
// ask for v0, and the only thing that can refuse is the agent's own policy.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/handshake"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
	"github.com/oarlock/oarlock/pkg/transport"
	"github.com/oarlock/oarlock/pkg/transport/memory"
)

func hush() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// bound runs both sides over a pair reporting `binding`, and returns both outcomes.
func bound(t *testing.T, g *handshake.Gateway, a *handshake.Agent,
	binding []byte) (*handshake.Result, *frame.Welcome, error, error) {
	t.Helper()
	ga, ag := memory.PairBound(0, binding)
	return over(t, g, a, ga, ag)
}

func over(t *testing.T, g *handshake.Gateway, a *handshake.Agent,
	ga, ag transport.Conn) (*handshake.Result, *frame.Welcome, error, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

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
	out := <-ch
	return out.res, w, out.err, aerr
}

func device(t *testing.T, id string) (*plugin.Device, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &plugin.Device{ID: id, Platform: plugin.PlatformLinux,
		Keys: []ed25519.PublicKey{pub}}, priv
}

func gw(dev *plugin.Device, require bool) *handshake.Gateway {
	return &handshake.Gateway{
		Registry:              reg{devices: map[string]*plugin.Device{dev.ID: dev}},
		GatewayID:             "gw-a",
		RequireChannelBinding: require,
		Log:                   hush(),
	}
}

// ── the binding itself ──────────────────────────────────────────────────────────

// TestABoundChannelNegotiatesV1. The baseline: given something to bind to, both sides use
// it, and the version says so.
func TestABoundChannelNegotiatesV1(t *testing.T) {
	dev, key := device(t, "rower-1")
	res, w, gerr, aerr := bound(t,
		gw(dev, true),
		&handshake.Agent{DeviceID: dev.ID, Signer: key, RequireChannelBinding: true},
		[]byte("one tls session"))

	if gerr != nil || aerr != nil {
		t.Fatalf("gateway: %v; agent: %v", gerr, aerr)
	}
	if res.Version != handshake.Version || w.Version != handshake.Version {
		t.Fatalf("versions: gateway %d, agent %d; want v%d",
			res.Version, w.Version, handshake.Version)
	}
}

// TestARelayCannotForwardTheHandshake is the whole point of v1.
//
// Two pairs with two bindings is exactly what a TLS-terminating middlebox has: one session
// to the agent, another to the gateway. It forwards every frame faithfully — it does not
// need to modify anything — and the signature the agent produced over its own channel does
// not verify over the gateway's.
//
// Note what the relay does *not* have to defeat: the device key, the nonces, the pinning.
// It passes all of those. The binding is the only thing that notices.
func TestARelayCannotForwardTheHandshake(t *testing.T) {
	dev, key := device(t, "rower-1")

	// The agent's leg and the gateway's leg, with different keying material.
	agentSide, relayToAgent := memory.PairBound(0, []byte("session A: agent to relay"))
	relayToGateway, gatewaySide := memory.PairBound(0, []byte("session B: relay to gateway"))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// A faithful relay: every frame, unmodified, in both directions.
	relay := func(from, to transport.Conn) {
		for {
			msg, err := from.Recv(ctx)
			if err != nil {
				return
			}
			if err := to.Send(ctx, msg); err != nil {
				return
			}
		}
	}
	go relay(relayToAgent, relayToGateway)
	go relay(relayToGateway, relayToAgent)

	type gout struct {
		res *handshake.Result
		err error
	}
	ch := make(chan gout, 1)
	go func() {
		res, err := gw(dev, true).Accept(ctx, gatewaySide)
		ch <- gout{res, err}
	}()
	a := &handshake.Agent{DeviceID: dev.ID, Signer: key, RequireChannelBinding: true}
	_, aerr := a.Perform(ctx, agentSide)
	out := <-ch

	if out.err == nil {
		t.Fatal("a relayed handshake was accepted: the gateway believes it is talking " +
			"to the device, and the relay holds an authenticated control channel")
	}
	if !errors.Is(out.err, handshake.ErrAuthFailed) {
		t.Fatalf("the gateway refused with %v, want ErrAuthFailed", out.err)
	}
	if aerr == nil {
		t.Fatal("the agent thought the handshake succeeded")
	}
}

// TestTheBindingIsActuallyInTheSignedInput, stated at the level of the bytes so it does
// not depend on a whole handshake to notice.
func TestTheBindingIsActuallyInTheSignedInput(t *testing.T) {
	nS := bytes.Repeat([]byte{1}, handshake.NonceLen)
	nC := bytes.Repeat([]byte{2}, handshake.NonceLen)
	base := handshake.Signed{
		Version: handshake.Version, NonceS: nS, NonceC: nC,
		DeviceID: "d", GatewayID: "g", Channel: []byte("channel one"),
	}
	other := base
	other.Channel = []byte("channel two")

	if bytes.Equal(handshake.SigningInput(base), handshake.SigningInput(other)) {
		t.Fatal("two different channels produce the same signing input, so the binding " +
			"is not covered by the signature at all")
	}
	// And v0 ignores it, which is what makes v0 v0.
	v0 := base
	v0.Version = handshake.VersionUnbound
	v0other := other
	v0other.Version = handshake.VersionUnbound
	if !bytes.Equal(handshake.SigningInput(v0), handshake.SigningInput(v0other)) {
		t.Fatal("v0 covers the channel binding; it is meant to be the unbound version")
	}
}

// TestAV0SignatureCannotBeReplayedAsV1.
//
// The version is the domain separator rather than a field, so this is true by construction
// — but "by construction" is a claim about the construction, and the construction is one
// function that somebody will edit.
func TestAV0SignatureCannotBeReplayedAsV1(t *testing.T) {
	s := handshake.Signed{
		NonceS:   bytes.Repeat([]byte{1}, handshake.NonceLen),
		NonceC:   bytes.Repeat([]byte{2}, handshake.NonceLen),
		DeviceID: "d", GatewayID: "g",
	}
	v0 := s
	v0.Version = handshake.VersionUnbound
	v1 := s
	v1.Version = handshake.Version

	if bytes.Equal(handshake.SigningInput(v0), handshake.SigningInput(v1)) {
		t.Fatal("the two versions sign the same bytes")
	}
	if !bytes.HasPrefix(handshake.SigningInput(v1), []byte("oarlock-control-v1\x00")) {
		t.Fatal("v1's signing input is not separated from v0's by its domain")
	}
}

// ── downgrade ───────────────────────────────────────────────────────────────────

// TestAnAgentThatRequiresBindingRefusesAnUnboundGateway.
//
// The half that is not cryptography. The gateway picks the version, so anything that can
// rewrite HELLO can ask for v0 — and at that point the agent has a connection it *could*
// bind and a gateway saying it would rather not. Only the agent can refuse, and this is it
// refusing.
func TestAnAgentThatRequiresBindingRefusesAnUnboundGateway(t *testing.T) {
	dev, key := device(t, "rower-1")

	// A gateway that does not require binding, on a channel that has one: it would
	// happily run v0 if the agent let it.
	_, _, _, aerr := bound(t,
		gw(dev, false),
		&handshake.Agent{
			DeviceID: dev.ID, Signer: key,
			RequireChannelBinding: true,
			// Offering v0 explicitly, which is what a rewritten HELLO looks like from
			// the gateway's side.
			Versions: []int{handshake.VersionUnbound},
		},
		[]byte("a channel that could have been bound"))

	if aerr == nil {
		t.Fatal("an agent requiring binding accepted a v0 handshake")
	}
	if !errors.Is(aerr, handshake.ErrVersion) {
		t.Fatalf("the agent refused with %v, want ErrVersion", aerr)
	}
}

// TestAnAgentThatRequiresBindingDoesNotOfferV0.
//
// Belt to the braces above. Advertising a version you will not accept gives a gateway —
// or something impersonating one — something to choose, and the refusal then happens one
// round trip later than it needed to.
func TestAnAgentThatRequiresBindingDoesNotOfferV0(t *testing.T) {
	dev, key := device(t, "rower-1")
	// The gateway records what it was offered. It does not require binding, so if the
	// agent offered v0 this would negotiate v0 and succeed.
	res, _, gerr, aerr := bound(t,
		gw(dev, false),
		&handshake.Agent{DeviceID: dev.ID, Signer: key, RequireChannelBinding: true},
		[]byte("one tls session"))

	if gerr != nil || aerr != nil {
		t.Fatalf("gateway: %v; agent: %v", gerr, aerr)
	}
	if res.Version != handshake.Version {
		t.Fatalf("negotiated v%d: the agent offered a version it would have refused",
			res.Version)
	}
}

// TestAGatewayThatRequiresBindingRefusesAnUnbindableConnection.
//
// The mirror, and the deployment mistake it catches: binding configured on, and something
// in the path — `ws://`, a TLS 1.2 session resumed without extended master secret — that
// cannot provide one. Running unbound anyway would be the gateway defeating its own
// configuration silently, which is the failure that would never be noticed.
func TestAGatewayThatRequiresBindingRefusesAnUnbindableConnection(t *testing.T) {
	dev, key := device(t, "rower-1")
	_, _, gerr, _ := bound(t,
		gw(dev, true),
		&handshake.Agent{DeviceID: dev.ID, Signer: key},
		nil) // no channel at all

	if gerr == nil {
		t.Fatal("a gateway requiring binding accepted an unbindable connection")
	}
	if !errors.Is(gerr, handshake.ErrVersion) {
		t.Fatalf("the gateway refused with %v, want ErrVersion", gerr)
	}
}

// TestAnUnboundDeploymentStillWorks. A development gateway on `ws://` has nothing to bind
// to, and refusing to run at all would make the feature something people turn off rather
// than turn on.
func TestAnUnboundDeploymentStillWorks(t *testing.T) {
	dev, key := device(t, "rower-1")
	res, w, gerr, aerr := bound(t,
		gw(dev, false),
		&handshake.Agent{DeviceID: dev.ID, Signer: key},
		nil)

	if gerr != nil || aerr != nil {
		t.Fatalf("gateway: %v; agent: %v", gerr, aerr)
	}
	if res.Version != handshake.VersionUnbound || w.Version != handshake.VersionUnbound {
		t.Fatalf("versions: gateway %d, agent %d", res.Version, w.Version)
	}
}

// TestTheChallengeCarriesTheVersion.
//
// It has to arrive before AUTH, because the version selects the domain separator and
// whether the binding is covered. An agent that learned it from WELCOME would already have
// signed — and would have signed the wrong thing.
func TestTheChallengeCarriesTheVersion(t *testing.T) {
	dev, _ := device(t, "rower-1")
	ga, ag := memory.PairBound(0, []byte("one tls session"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { _, _ = gw(dev, true).Accept(ctx, ga) }()

	// Play the agent by hand as far as CHALLENGE.
	hello, err := frame.Marshal(frame.TypeHello, frame.Hello{
		DeviceID: dev.ID, Versions: handshake.SupportedVersions,
		NonceC: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := frame.Codec{}.Encode(nil, hello)
	if err != nil {
		t.Fatal(err)
	}
	if err := ag.Send(ctx, wire); err != nil {
		t.Fatal(err)
	}

	msg, err := ag.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f, err := frame.Codec{}.Decode(msg)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != frame.TypeChallenge {
		t.Fatalf("got %s, want CHALLENGE", f.Type)
	}
	var ch frame.Challenge
	if err := frame.Unmarshal(f, &ch); err != nil {
		t.Fatal(err)
	}
	if ch.Version != handshake.Version {
		t.Fatalf("CHALLENGE carried v%d, want v%d — an agent cannot know what to sign",
			ch.Version, handshake.Version)
	}
}
