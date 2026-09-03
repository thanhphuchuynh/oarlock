// Package handshake implements the control-channel handshake from
// docs/protocol.md § 3.1 — both sides of it.
//
// A persistent-mode agent holds one control channel, so it needs a long-lived
// identity. It gets an Ed25519 key pair generated on the device at first boot; the
// public half is registered out of band by whatever does enrollment. The private
// key never leaves the device and is never sent. A bearer token would be replayable
// by anything that read a log, which is the whole reason this is challenge-response
// rather than a header.
package handshake

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
	"github.com/oarlock/oarlock/pkg/transport"
)

// Budget is how long the whole exchange may take from socket open. A handshake
// that stalls is a socket an unauthenticated peer is holding, so this is a
// resource limit as much as a liveness one.
const Budget = 5 * time.Second

// NonceLen is the length of each side's nonce, before base64.
const NonceLen = 32

// Version is the highest wire version this build speaks.
//
// v1 adds channel binding: the device's signature covers RFC 5705 exported keying material
// from the TLS connection underneath, so a middlebox that terminates TLS and relays the
// handshake signs over one channel and is verified over another. Nothing new travels on
// the wire — the binding is computed independently at both ends and only mixed into what
// is signed.
const Version = 1

// VersionUnbound is v0: the same handshake with nothing tying it to the channel.
//
// Kept because a development gateway on `ws://` has no channel to bind to, and because an
// agent in the field is not upgraded on the same day as its gateway. It is also the
// downgrade an attacker wants, which is why both sides carry an explicit policy rather
// than accepting whatever the peer offers — see RequireChannelBinding.
const VersionUnbound = 0

// SupportedVersions is what this build offers, highest first.
var SupportedVersions = []int{Version, VersionUnbound}

// ChannelBindingLabel is the RFC 5705 exporter label.
//
// Versioned, and specific to this protocol: the same label on two different connections
// must not produce the same bytes, and a label shared with another protocol using the same
// TLS session would let one protocol's exporter answer the other's question.
const ChannelBindingLabel = "EXPORTER-oarlock-control-v1"

// ChannelBindingLen is how many bytes of keying material are mixed in.
const ChannelBindingLen = 32

// Errors. AuthFailed is deliberately coarse — see the note on Accept.
var (
	ErrAuthFailed  = errors.New("handshake: authentication failed")
	ErrProtocol    = errors.New("handshake: protocol error")
	ErrVersion     = errors.New("handshake: no shared protocol version")
	ErrRemoteError = errors.New("handshake: peer returned an error")
)

// domainFor separates these signatures from anything else the device key might ever sign,
// and separates each protocol version from the others.
//
// Without the first, a signature produced for one purpose could be replayed into another
// protocol that happens to hash similar bytes. Without the second, a v0 signature — made
// with nothing binding it to a channel — would verify as a v1 one, and the whole point of
// v1 is that it cannot. The version *is* the domain separator rather than a field inside
// the input, because that makes cross-version replay impossible by construction rather
// than by a length prefix being right.
func domainFor(version int) string {
	if version >= Version {
		return "oarlock-control-v1"
	}
	return "oarlock-control-v0"
}

// SigningInput builds the bytes both sides sign over.
//
// Every field is length-prefixed and the whole thing is domain-separated, rather
// than concatenated as the first draft of the protocol described. Plain
// concatenation of variable-length fields is ambiguous: device_id "ab" with
// gateway_id "c" produces the same bytes as "a" and "bc", so a peer that controls
// one field can shift the boundary and get a signature that validates against
// values nobody agreed to. Length prefixes make the encoding injective, which is
// what makes the signature mean what it appears to mean.
func SigningInput(s Signed) []byte {
	domain := domainFor(s.Version)
	parts := [][]byte{s.NonceS, s.NonceC, []byte(s.DeviceID), []byte(s.GatewayID)}
	if s.Version >= Version {
		// Appended rather than inserted, so a v1 input is a v0 input plus one field and
		// the two can be read side by side.
		parts = append(parts, s.Channel)
	}
	n := len(domain) + 1
	for _, p := range parts {
		n += 2 + len(p)
	}
	out := make([]byte, 0, n)
	out = append(out, domain...)
	out = append(out, 0)
	for _, part := range parts {
		out = binary.BigEndian.AppendUint16(out, uint16(len(part)))
		out = append(out, part...)
	}
	return out
}

// Signed is everything a device signature covers.
//
// A struct rather than five positional arguments because the set grew once — v1 added the
// channel binding — and a call site that silently transposed two byte slices would produce
// a signature that verifies against values nobody agreed to.
type Signed struct {
	// Version selects the domain separator and whether Channel is covered.
	Version int
	NonceS  []byte
	NonceC  []byte
	// DeviceID and GatewayID are each in the input so a signature captured by one
	// gateway cannot be replayed to another, or for another device.
	DeviceID  string
	GatewayID string
	// Channel is RFC 5705 exported keying material from the connection underneath.
	// Ignored at v0, which is the whole difference between the versions.
	Channel []byte
}

// Result is what the gateway learned from a successful handshake.
type Result struct {
	Device  *plugin.Device
	Version int
	Caps    []string
	Agent   frame.AgentInfo
}

// Supports reports whether the agent advertised a capability. An agent built
// without a PTY omits "shell", and the gateway can then refuse a session at open
// time with a real reason instead of after a round trip.
func (r *Result) Supports(cap string) bool {
	for _, c := range r.Caps {
		if c == cap {
			return true
		}
	}
	return false
}

// Gateway performs the server side.
type Gateway struct {
	Registry  plugin.DeviceRegistry
	GatewayID string

	// RequireChannelBinding refuses any handshake that is not bound to the connection
	// underneath it.
	//
	// This is a policy and not a question asked of the connection, and that distinction
	// is the whole control. Binding stops a TLS-terminating middlebox from relaying the
	// handshake — its two TLS sessions export different keying material — and that
	// protection evaporates if a peer can say "I cannot bind" and be believed, which is
	// exactly what a middlebox would say. So a gateway that requires it refuses v0
	// outright rather than negotiating down.
	//
	// Off by default because a development gateway on `ws://` has nothing to bind to.
	// internal/safety refuses production without it.
	RequireChannelBinding bool

	// Rand defaults to crypto/rand.
	Rand io.Reader
	// Log defaults to slog.Default().
	Log *slog.Logger
	// Resume, if set, is asked for sessions the gateway is still holding for this
	// device, so a reconnecting agent can dial back for each instead of losing the
	// operator's shell.
	Resume func(ctx context.Context, deviceID string) []frame.Invitation
}

// Accept runs the gateway side of the handshake on an already-connected channel.
//
// # On telling a peer as little as possible
//
// A failure returns ErrAuthFailed whether the device is unknown, the signature is
// wrong, or the key has been retired, and the wire error is always `auth_failed`.
// The protocol has a `device_unknown` code, and sending it here would hand an
// unauthenticated peer an enumeration oracle for the fleet. The specific reason is
// logged, where it belongs.
//
// For the same reason the flow does not short-circuit: an unknown device still
// receives a CHALLENGE and is still asked for an AUTH, so the shape of the
// exchange does not distinguish "no such device" from "bad signature" either.
func (g *Gateway) Accept(ctx context.Context, conn transport.Conn) (*Result, error) {
	ctx, cancel := context.WithTimeout(ctx, Budget)
	defer cancel()

	log := g.Log
	if log == nil {
		log = slog.Default()
	}
	rnd := g.Rand
	if rnd == nil {
		rnd = rand.Reader
	}
	c := frame.Codec{}

	// ── HELLO ─────────────────────────────────────────────────────────────────
	var hello frame.Hello
	if err := recvInto(ctx, conn, c, frame.TypeHello, &hello); err != nil {
		return nil, err
	}
	if !plugin.ValidDeviceID(hello.DeviceID) {
		return nil, fmt.Errorf("%w: device id %q", ErrProtocol, hello.DeviceID)
	}
	nonceC, err := decodeNonce(hello.NonceC)
	if err != nil {
		return nil, fmt.Errorf("%w: client nonce: %v", ErrProtocol, err)
	}
	// The channel binding is computed before the version is chosen, because whether one
	// is available is what decides whether v1 is on the table at all.
	binding, bindErr := transport.Binding(conn, ChannelBindingLabel, ChannelBindingLen)
	if bindErr != nil && g.RequireChannelBinding {
		// Refused, loudly, and not downgraded. A gateway configured to require binding
		// and unable to compute one is a deployment problem — `ws://`, or a TLS 1.2
		// session resumed without extended master secret — and running unbound anyway
		// would be the gateway defeating its own configuration.
		log.Error("channel binding is required and unavailable",
			"device", hello.DeviceID, "remote", conn.RemoteAddr(), "error", bindErr)
		_ = send(ctx, conn, c, frame.TypeError, frame.Error{
			Code: "version_unsupported",
			Message: "this gateway requires a channel-bound handshake and this " +
				"connection cannot provide one"})
		return nil, fmt.Errorf("%w: %v", ErrVersion, bindErr)
	}
	version, err := negotiate(hello.Versions, bindErr == nil, g.RequireChannelBinding)
	if err != nil {
		_ = send(ctx, conn, c, frame.TypeError, frame.Error{
			Code: "version_unsupported", Message: "no shared protocol version"})
		return nil, err
	}

	// The lookup happens now, but its outcome is not acted on until after AUTH.
	dev, lookupErr := g.Registry.Get(ctx, hello.DeviceID)

	// ── CHALLENGE ─────────────────────────────────────────────────────────────
	nonceS := make([]byte, NonceLen)
	if _, err := io.ReadFull(rnd, nonceS); err != nil {
		return nil, fmt.Errorf("handshake: generating a nonce: %w", err)
	}
	if err := send(ctx, conn, c, frame.TypeChallenge, frame.Challenge{
		NonceS:    base64.RawURLEncoding.EncodeToString(nonceS),
		GatewayID: g.GatewayID,
		Version:   version,
	}); err != nil {
		return nil, err
	}

	// ── AUTH ──────────────────────────────────────────────────────────────────
	var auth frame.Auth
	if err := recvInto(ctx, conn, c, frame.TypeAuth, &auth); err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(auth.Sig)
	if err != nil {
		sig, err = base64.StdEncoding.DecodeString(auth.Sig)
	}
	if err != nil || len(sig) != ed25519.SignatureSize {
		g.reject(ctx, conn, c, log, hello.DeviceID, "malformed signature")
		return nil, ErrAuthFailed
	}

	if lookupErr != nil || dev.Disabled {
		g.reject(ctx, conn, c, log, hello.DeviceID, "unknown device")
		return nil, ErrAuthFailed
	}

	msg := SigningInput(Signed{
		Version: version, NonceS: nonceS, NonceC: nonceC,
		DeviceID: hello.DeviceID, GatewayID: g.GatewayID, Channel: binding,
	})
	var matched bool
	var retired bool
	for _, key := range dev.RetiredKeys {
		if ed25519.Verify(key, msg, sig) {
			retired = true
			break
		}
	}
	if retired {
		g.reject(ctx, conn, c, log, hello.DeviceID, "retired key verifies the signature")
		return nil, ErrAuthFailed
	}
	for _, key := range dev.Keys {
		// Every registered key is tried, which is what makes rotation work: publish
		// the new key alongside the old, let devices roll over, retire the old.
		if ed25519.Verify(key, msg, sig) {
			matched = true
			break
		}
	}
	if !matched {
		g.reject(ctx, conn, c, log, hello.DeviceID, "no registered key verifies the signature")
		return nil, ErrAuthFailed
	}

	// ── WELCOME ───────────────────────────────────────────────────────────────
	w := frame.Welcome{
		Version:   version,
		GatewayID: g.GatewayID,
		Limits: &frame.Limits{
			Frame:        frame.MaxFrame,
			Batch:        frame.MaxBatch,
			PingInterval: 30,
		},
	}
	if g.Resume != nil {
		if sessions := g.Resume(ctx, dev.ID); len(sessions) > 0 {
			w.Resume = &frame.Resume{Sessions: sessions}
		}
	}
	if err := send(ctx, conn, c, frame.TypeWelcome, w); err != nil {
		return nil, err
	}

	if dev.ModeWasDefaulted() {
		log.Info("device reachability mode defaulted from platform",
			"device", dev.ID, "platform", dev.Platform, "mode", dev.ResolvedMode())
	}
	return &Result{Device: dev, Version: version, Caps: hello.Caps, Agent: hello.Agent}, nil
}

func (g *Gateway) reject(ctx context.Context, conn transport.Conn, c frame.Codec,
	log *slog.Logger, deviceID, why string) {
	log.Warn("control channel handshake rejected",
		"device", deviceID, "reason", why, "remote", conn.RemoteAddr())
	_ = send(ctx, conn, c, frame.TypeError, frame.Error{
		Code: "auth_failed", Message: "authentication failed"})
}

// Agent performs the client side.
type Agent struct {
	DeviceID string

	// RequireChannelBinding refuses a handshake the gateway will not bind to the
	// connection.
	//
	// The agent's half of the policy, and it is the half that actually stops a downgrade.
	// The version is chosen by the gateway, so a middlebox that can rewrite HELLO can ask
	// for v0 — and the agent is the only party in a position to say no. An agent dialling
	// `wss://` with a pin and no binding requirement is an agent whose pin a relay can
	// work around by claiming to be old.
	//
	// Off by default so an agent still works against a development gateway on `ws://`.
	// The reference agent turns it on whenever it is pinning.
	RequireChannelBinding bool
	// Signer holds the device key. crypto.Signer rather than ed25519.PrivateKey so
	// a hardware-backed keystore can be handed in without this package caring —
	// which is the point on a platform that offers one.
	Signer crypto.Signer

	Versions []int // defaults to []int{Version}
	Caps     []string
	Info     frame.AgentInfo
	Rand     io.Reader
}

// Perform runs the agent side and returns the gateway's WELCOME.
func (a *Agent) Perform(ctx context.Context, conn transport.Conn) (*frame.Welcome, error) {
	ctx, cancel := context.WithTimeout(ctx, Budget)
	defer cancel()

	rnd := a.Rand
	if rnd == nil {
		rnd = rand.Reader
	}
	versions := a.Versions
	if len(versions) == 0 {
		versions = SupportedVersions
		if a.RequireChannelBinding {
			// Offering v0 at all would give a gateway — or something pretending to be
			// one — something to choose. An agent that will not accept an unbound
			// handshake should not advertise that it would.
			versions = []int{Version}
		}
	}
	c := frame.Codec{}

	nonceC := make([]byte, NonceLen)
	if _, err := io.ReadFull(rnd, nonceC); err != nil {
		return nil, fmt.Errorf("handshake: generating a nonce: %w", err)
	}
	if err := send(ctx, conn, c, frame.TypeHello, frame.Hello{
		DeviceID: a.DeviceID,
		Versions: versions,
		NonceC:   base64.RawURLEncoding.EncodeToString(nonceC),
		Caps:     a.Caps,
		Agent:    a.Info,
	}); err != nil {
		return nil, err
	}

	var ch frame.Challenge
	if err := recvInto(ctx, conn, c, frame.TypeChallenge, &ch); err != nil {
		return nil, err
	}
	nonceS, err := decodeNonce(ch.NonceS)
	if err != nil {
		return nil, fmt.Errorf("%w: server nonce: %v", ErrProtocol, err)
	}

	// The gateway chose a version. Check it is one we offered before signing anything
	// with it: a version we did not offer is either a confused gateway or somebody
	// steering us onto a handshake we did not agree to.
	chosen := ch.Version
	if !contains(versions, chosen) {
		return nil, fmt.Errorf("%w: gateway chose v%d, which we did not offer",
			ErrVersion, chosen)
	}
	var binding []byte
	if chosen >= Version {
		binding, err = transport.Binding(conn, ChannelBindingLabel, ChannelBindingLen)
		if err != nil {
			// The gateway asked for a bound handshake on a connection we cannot bind.
			// Refusing is the only honest answer: signing without the binding would
			// produce a signature the gateway cannot verify anyway, and pretending
			// otherwise would just move the failure somewhere less legible.
			return nil, fmt.Errorf("%w: gateway chose v%d but this connection cannot "+
				"be bound: %v", ErrVersion, chosen, err)
		}
	} else if a.RequireChannelBinding {
		// The downgrade. The gateway — or whatever is between us and it — offered a
		// handshake with nothing tying it to this channel, and this agent was configured
		// not to accept one.
		return nil, fmt.Errorf("%w: gateway chose v%d, and this agent requires a "+
			"channel-bound handshake", ErrVersion, chosen)
	}

	msg := SigningInput(Signed{
		Version: chosen, NonceS: nonceS, NonceC: nonceC,
		DeviceID: a.DeviceID, GatewayID: ch.GatewayID, Channel: binding,
	})
	// ed25519 signs the message itself, so the hash argument is zero.
	sig, err := a.Signer.Sign(rnd, msg, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("handshake: signing: %w", err)
	}
	if err := send(ctx, conn, c, frame.TypeAuth, frame.Auth{
		Sig: base64.RawURLEncoding.EncodeToString(sig),
	}); err != nil {
		return nil, err
	}

	var w frame.Welcome
	if err := recvInto(ctx, conn, c, frame.TypeWelcome, &w); err != nil {
		return nil, err
	}
	if w.Version != chosen {
		// WELCOME disagreeing with CHALLENGE means the version we signed for is not the
		// one the connection is about to run on. Nothing good follows from continuing.
		return nil, fmt.Errorf("%w: gateway challenged for v%d and welcomed v%d",
			ErrVersion, chosen, w.Version)
	}
	return &w, nil
}

// ── plumbing ────────────────────────────────────────────────────────────────────

// negotiate picks the highest version both sides can actually run.
//
// `canBind` rather than a preference: v1 is not merely newer, it is a handshake that covers
// keying material, so offering it on a connection with none would produce a signature
// neither side could reproduce. And when binding is required, v0 is not a fallback — it is
// the thing being refused.
func negotiate(offered []int, canBind, requireBinding bool) (int, error) {
	best := -1
	for _, v := range offered {
		switch v {
		case Version:
			if canBind && v > best {
				best = v
			}
		case VersionUnbound:
			if !requireBinding && v > best {
				best = v
			}
		}
	}
	if best < 0 {
		return 0, fmt.Errorf("%w: peer offered %v, we speak %v (channel binding "+
			"available=%v, required=%v)",
			ErrVersion, offered, SupportedVersions, canBind, requireBinding)
	}
	return best, nil
}

func contains(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func decodeNonce(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		if b, err = base64.URLEncoding.DecodeString(s); err != nil {
			return nil, fmt.Errorf("not base64url: %w", err)
		}
	}
	if len(b) != NonceLen {
		return nil, fmt.Errorf("%d bytes, want %d", len(b), NonceLen)
	}
	return b, nil
}

func send(ctx context.Context, conn transport.Conn, c frame.Codec, t frame.Type, v any) error {
	f, err := frame.Marshal(t, v)
	if err != nil {
		return err
	}
	wire, err := c.Encode(nil, f)
	if err != nil {
		return err
	}
	if err := conn.Send(ctx, wire); err != nil {
		return fmt.Errorf("handshake: sending %s: %w", t, err)
	}
	return nil
}

// recvInto reads one frame, insists it is the expected type on the expected kind of
// connection, and decodes it. An ERROR frame arriving instead is surfaced as the
// peer's own message rather than as a type mismatch, because "the gateway said
// version_unsupported" is a far more useful log line than "expected WELCOME".
func recvInto(ctx context.Context, conn transport.Conn, c frame.Codec, want frame.Type, v any) error {
	msg, err := conn.Recv(ctx)
	if err != nil {
		return fmt.Errorf("handshake: waiting for %s: %w", want, err)
	}
	f, err := c.Decode(msg)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	if err := frame.Expect(frame.ScopeConnection, f); err != nil {
		return fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	if f.Type == frame.TypeError && want != frame.TypeError {
		var e frame.Error
		if uerr := frame.Unmarshal(f, &e); uerr == nil {
			return fmt.Errorf("%w: %s: %s", ErrRemoteError, e.Code, e.Message)
		}
		return fmt.Errorf("%w: unreadable ERROR frame", ErrRemoteError)
	}
	if f.Type != want {
		return fmt.Errorf("%w: got %s, want %s", ErrProtocol, f.Type, want)
	}
	return frame.Unmarshal(f, v)
}
