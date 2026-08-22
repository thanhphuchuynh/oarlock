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

// Version is the wire version this build speaks.
const Version = 0

// Errors. AuthFailed is deliberately coarse — see the note on Accept.
var (
	ErrAuthFailed  = errors.New("handshake: authentication failed")
	ErrProtocol    = errors.New("handshake: protocol error")
	ErrVersion     = errors.New("handshake: no shared protocol version")
	ErrRemoteError = errors.New("handshake: peer returned an error")
)

// domain separates these signatures from anything else the device key might ever
// sign. Without it, a signature produced for one purpose could be replayed into
// another protocol that happens to hash similar bytes.
const domain = "oarlock-control-v0"

// SigningInput builds the bytes both sides sign over.
//
// Every field is length-prefixed and the whole thing is domain-separated, rather
// than concatenated as the first draft of the protocol described. Plain
// concatenation of variable-length fields is ambiguous: device_id "ab" with
// gateway_id "c" produces the same bytes as "a" and "bc", so a peer that controls
// one field can shift the boundary and get a signature that validates against
// values nobody agreed to. Length prefixes make the encoding injective, which is
// what makes the signature mean what it appears to mean.
func SigningInput(nonceS, nonceC []byte, deviceID, gatewayID string) []byte {
	out := make([]byte, 0, len(domain)+1+8+len(nonceS)+len(nonceC)+len(deviceID)+len(gatewayID))
	out = append(out, domain...)
	out = append(out, 0)
	for _, part := range [][]byte{nonceS, nonceC, []byte(deviceID), []byte(gatewayID)} {
		out = binary.BigEndian.AppendUint16(out, uint16(len(part)))
		out = append(out, part...)
	}
	return out
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
	version, err := negotiate(hello.Versions)
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

	if lookupErr != nil {
		g.reject(ctx, conn, c, log, hello.DeviceID, "unknown device")
		return nil, ErrAuthFailed
	}

	msg := SigningInput(nonceS, nonceC, hello.DeviceID, g.GatewayID)
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
		versions = []int{Version}
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

	msg := SigningInput(nonceS, nonceC, a.DeviceID, ch.GatewayID)
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
	if w.Version != versions[0] && !contains(versions, w.Version) {
		return nil, fmt.Errorf("%w: gateway chose v%d, which we did not offer",
			ErrVersion, w.Version)
	}
	return &w, nil
}

// ── plumbing ────────────────────────────────────────────────────────────────────

func negotiate(offered []int) (int, error) {
	best := -1
	for _, v := range offered {
		if v == Version && v > best {
			best = v
		}
	}
	if best < 0 {
		return 0, fmt.Errorf("%w: peer offered %v, we speak v%d", ErrVersion, offered, Version)
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
