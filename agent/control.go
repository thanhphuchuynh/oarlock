// Package agent is the device side of Oarlock, as a library.
//
// A library and not a binary, and that is a platform constraint rather than a
// preference: Android 10 forbids executing a binary from app storage, so on the
// platform this was designed for the agent must live inside an existing APK.
// Everywhere else, in-process means one thing to supervise instead of two.
//
// This file is the control channel — the doorbell. It holds one outbound connection
// open, answers pings, and calls back when the gateway asks the device to dial for a
// session. It carries no session traffic.
package agent

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/oarlock/oarlock/internal/backoff"
	"github.com/oarlock/oarlock/internal/handshake"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/transport"
)

// Config configures a control channel.
type Config struct {
	// Gateway is the control-channel URL, e.g. wss://gw.example.org/ws/control.
	Gateway  string
	DeviceID string

	// Signer holds the device key. crypto.Signer rather than a raw private key so a
	// hardware-backed keystore can be handed in without this package caring — which
	// is the point on a platform that offers one.
	Signer crypto.Signer

	// Dialer is required. Pass websocket.Dialer{} in production; the memory
	// transport in tests.
	Dialer transport.Dialer

	// PinSHA256 pins the gateway's public key. Strongly recommended and on by default in
	// the reference agent.
	//
	// It is the weaker half of the pair now that channel binding exists: a pin stops a
	// middlebox that has to present a certificate this device would reject, and does
	// nothing about one holding a certificate the device already trusts. Keep both — the
	// pin also fails the connection *earlier*, before any handshake, which is worth
	// having on a device that pays for its radio.
	PinSHA256 []string

	// RequireChannelBinding refuses a handshake the gateway will not bind to the TLS
	// connection underneath it (protocol v1).
	//
	// This is the agent's half of the control and it is the half that stops a downgrade:
	// the gateway picks the version, so anything that can rewrite HELLO can ask for the
	// unbound one, and the agent is the only party in a position to say no.
	//
	// It is what PinSHA256 was standing in for. A pin covers a middlebox that has to
	// present a certificate this device would reject; it does nothing about one holding a
	// certificate the device already trusts — a corporate inspection appliance, or a CA
	// in the platform trust store. Binding covers both, because the relay's two TLS
	// sessions export different keying material whatever certificate it holds.
	//
	// # Off by default, and used anyway
	//
	// The agent always *offers* v1, so binding happens wherever both ends can do it with
	// nothing configured. This flag is the difference between using it and insisting on
	// it, and insisting is opt-in for a reason that has nothing to do with taste: an
	// agent that refuses an unbound handshake refuses to connect at all when the gateway
	// is older, or when anything in the path cannot export keying material. On a device
	// in somebody's plant room, a fleet that will not reconnect is a fleet that needs
	// physical access.
	//
	// So the protection is opportunistic by default and mandatory by choice — and the
	// choice belongs to whoever knows their gateway is v1, which is not this library.
	// Turning it on is what closes the downgrade: without it, something that can rewrite
	// HELLO can ask for v0 and this agent will agree.
	RequireChannelBinding bool

	// Caps is what this build can actually do. Omit "shell" if there is no PTY, and
	// the gateway refuses such a session at open time with a real reason instead of
	// after a round trip.
	Caps []string
	Info frame.AgentInfo

	// Shell opens a terminal. A hook rather than a fixed implementation because
	// "a shell" is platform-specific: which binary, which environment, which uid,
	// and whether a PTY exists at all. Leave it nil on a build that has none — and
	// then leave "shell" out of Caps, so the gateway refuses the session up front
	// rather than after a round trip.
	Shell ShellFunc

	// Exec runs one allow-listed command. A hook for the same reason Shell is one, and
	// nil on a build that has no business running commands — leave "exec" out of Caps
	// too, and the gateway refuses such a session at open time rather than after a round
	// trip.
	Exec ExecFunc

	// File reads and writes under one configured root. Nil on a build with no
	// filesystem worth exposing — and then leave "file" out of Caps too.
	File FileFunc

	// Tail streams a device log source, for the `log` profile. Nil on a build with no
	// logs worth exposing — and then leave "log" out of Caps too.
	//
	// Named Tail rather than Log because Config.Log is already this agent's own logger,
	// and a struct with two fields called Log is a struct somebody will set the wrong one
	// of.
	Tail LogFunc

	// Dial opens one connection to an allow-listed device-local port, for the `tcp`
	// profile — this is what carries `ssh -L`. Nil on a build with nothing worth
	// forwarding, and then leave "tcp" out of Caps too.
	Dial DialFunc

	// OnInvitation is called for every invitation, from a DIAL frame and from
	// WELCOME.resume alike. It runs on its own goroutine: dialling a session must
	// not stall the channel that delivers the next invitation.
	//
	// It is the agent's job to dial, present the ticket, and serve the session. A
	// retry must fetch a *new* invitation and never resend a spent ticket — a
	// replayed ticket is indistinguishable from an attack, so the gateway treats it
	// as one.
	OnInvitation func(ctx context.Context, inv frame.Invitation)

	// OnCancel is called when an invitation is withdrawn before the agent dialled.
	OnCancel func(ctx context.Context, sessionID, reason string)

	Log     *slog.Logger
	Backoff backoff.Policy

	// PingInterval is how often to ping the gateway. Zero disables agent-initiated
	// pings and relies on the gateway's, which is usually right: the side with
	// thousands of peers should own the timer.
	PingInterval time.Duration

	// WriteTimeout bounds every write. Zero means DefaultWriteTimeout. An
	// unbounded write to a peer that has stopped reading blocks the goroutine
	// holding the write lock for as long as the peer cares to hold the socket.
	WriteTimeout time.Duration
}

// DefaultWriteTimeout bounds writes to the control channel.
const DefaultWriteTimeout = 10 * time.Second

// ErrStoppedByGateway means the gateway asked this agent to stop rather than reconnect.
var ErrStoppedByGateway = errors.New("agent: stopped by gateway")

// Control is a control channel with a reconnect loop.
type Control struct {
	cfg   Config
	log   *slog.Logger
	codec frame.Codec

	mu      sync.Mutex
	welcome *frame.Welcome
	up      bool

	// sendMu serialises writes on the current connection. transport.Conn allows
	// Send concurrent with Recv but not with itself, and the ping loop writes from
	// a different goroutine than the read loop does.
	//
	// Per Control, not package-level: an embedder running two agents in one process
	// — which is every test in this package — must not have them serialise on each
	// other's writes.
	sendMu sync.Mutex
	buf    []byte
}

// NewControl validates cfg and returns a Control.
func NewControl(cfg Config) (*Control, error) {
	switch {
	case cfg.Gateway == "":
		return nil, errors.New("agent: Gateway is required")
	case cfg.DeviceID == "":
		return nil, errors.New("agent: DeviceID is required")
	case cfg.Signer == nil:
		return nil, errors.New("agent: Signer is required")
	case cfg.Dialer == nil:
		return nil, errors.New("agent: Dialer is required")
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = DefaultWriteTimeout
	}
	if len(cfg.PinSHA256) > 0 && !cfg.RequireChannelBinding {
		// An agent that pins has said it cares which gateway it is talking to, and a pin
		// is the weaker of the two ways to care: it cannot see a middlebox holding a
		// certificate this device already trusts. Worth saying once, because the
		// stronger control is one flag away and nothing else would mention it.
		cfg.Log.Info("certificate pinning is on and channel binding is not required; "+
			"binding will still be used when the gateway offers it, but a downgrade to "+
			"the unbound handshake would be accepted. Set require_channel_binding once "+
			"every gateway in the path speaks protocol v1",
			"device", cfg.DeviceID)
	}
	if len(cfg.PinSHA256) == 0 {
		// Loud, once, at startup — not silent. An unpinned agent is a working agent
		// with a weaker guarantee than the documentation claims, and the operator
		// should know which one they have.
		cfg.Log.Warn("no certificate pin configured; a TLS-terminating middlebox could "+
			"relay this handshake unless the gateway negotiates a channel-bound one "+
			"(protocol v1), which is not guaranteed unless require_channel_binding is set",
			"device", cfg.DeviceID)
	}
	c := &Control{cfg: cfg, log: cfg.Log.With("device", cfg.DeviceID)}
	if c.cfg.OnInvitation == nil {
		// The default is the only thing an agent sensibly does with an invitation:
		// dial it. Leaving this nil and silently dropping invitations would make a
		// correctly-configured agent look like an unreachable device.
		c.cfg.OnInvitation = c.HandleInvitation
	}
	return c, nil
}

// Up reports whether the channel is currently connected and authenticated.
func (c *Control) Up() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.up
}

// Welcome returns the last WELCOME received, or nil.
func (c *Control) Welcome() *frame.Welcome {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.welcome
}

// Run holds the channel open, reconnecting until ctx is done.
//
// The backoff resets on a successful *handshake*, not on a successful dial: a
// gateway that accepts connections and then rejects every handshake would otherwise
// be hammered at the base interval forever.
func (c *Control) Run(ctx context.Context) error {
	sleeper := &backoff.Sleeper{Policy: c.cfg.Backoff}
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		wait, err := c.runOnce(ctx, sleeper)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			if errors.Is(err, ErrStoppedByGateway) {
				return nil
			}
			c.log.Warn("control channel ended", "error", err, "attempt", sleeper.Attempt())
		}
		if wait <= 0 {
			wait = sleeper.Next()
		}
		c.log.Debug("reconnecting", "in", wait)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// runOnce dials, handshakes and serves one channel. A non-zero first return is a
// gateway-supplied reconnect delay from GOAWAY, which overrides the local backoff:
// during a drain the gateway is the only party that knows how to spread the fleet.
func (c *Control) runOnce(ctx context.Context, sleeper *backoff.Sleeper) (time.Duration, error) {
	conn, err := c.cfg.Dialer.Dial(ctx, c.cfg.Gateway, transport.Options{
		PinSHA256:       c.cfg.PinSHA256,
		MaxMessageBytes: frame.MaxFrame,
	})
	if err != nil {
		return 0, fmt.Errorf("agent: dial: %w", err)
	}
	defer conn.Close(transport.CloseNormal, "done")

	hs := &handshake.Agent{
		DeviceID:              c.cfg.DeviceID,
		Signer:                c.cfg.Signer,
		Caps:                  c.cfg.Caps,
		Info:                  c.cfg.Info,
		RequireChannelBinding: c.cfg.RequireChannelBinding,
	}
	w, err := hs.Perform(ctx, conn)
	if err != nil {
		return 0, fmt.Errorf("agent: handshake: %w", err)
	}

	sleeper.Reset()
	c.setUp(true, w)
	defer c.setUp(false, nil)
	c.log.Info("control channel up", "gateway", w.GatewayID, "version", w.Version)

	// Sessions the gateway is still holding for this device. Dialling back for each
	// is how a shell survives the radio dropping — the operator never learns their
	// device reconnected.
	if w.Resume != nil {
		for _, inv := range w.Resume.Sessions {
			c.log.Info("resuming a session", "session", inv.SessionID)
			c.invite(ctx, inv)
		}
	}
	return c.serve(ctx, conn)
}

func (c *Control) setUp(up bool, w *frame.Welcome) {
	c.mu.Lock()
	c.up = up
	if w != nil {
		c.welcome = w
	}
	c.mu.Unlock()
}

func (c *Control) serve(ctx context.Context, conn transport.Conn) (time.Duration, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	defer wg.Wait()

	if c.cfg.PingInterval > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.pingLoop(ctx, conn)
		}()
	}

	for {
		msg, err := conn.Recv(ctx)
		if err != nil {
			return 0, err
		}
		f, err := c.codec.Decode(msg)
		if err != nil {
			return 0, c.protocolError(ctx, conn, err)
		}
		if err := frame.Expect(frame.ScopeConnection, f); err != nil {
			// A session frame down the control channel means the gateway is confused
			// about which connection it is holding. Not recoverable per-frame.
			return 0, c.protocolError(ctx, conn, err)
		}
		if f.Type.Disposition() == frame.CloseConnection {
			return 0, c.protocolError(ctx, conn,
				fmt.Errorf("unknown connection-scoped frame %s", f.Type))
		}

		switch f.Type {
		case frame.TypeDial:
			var inv frame.Invitation
			if err := frame.Unmarshal(f, &inv); err != nil {
				return 0, c.protocolError(ctx, conn, err)
			}
			c.invite(ctx, inv)

		case frame.TypeCancel:
			var cn frame.Cancel
			if err := frame.Unmarshal(f, &cn); err != nil {
				return 0, c.protocolError(ctx, conn, err)
			}
			c.log.Info("invitation withdrawn", "session", cn.SessionID, "reason", cn.Reason)
			if c.cfg.OnCancel != nil {
				c.cfg.OnCancel(ctx, cn.SessionID, cn.Reason)
			}

		case frame.TypePing:
			stamp, err := frame.ReadStamp(f)
			if err != nil {
				return 0, c.protocolError(ctx, conn, err)
			}
			pong, _ := frame.Stamp(frame.TypePong, stamp)
			if err := c.sendFrame(ctx, conn, pong); err != nil {
				return 0, err
			}

		case frame.TypePong:
			if _, err := frame.ReadStamp(f); err != nil {
				return 0, c.protocolError(ctx, conn, err)
			}

		case frame.TypeGoAway:
			var g frame.GoAway
			_ = frame.Unmarshal(f, &g)
			d := time.Duration(g.ReconnectAfterMS) * time.Millisecond
			c.log.Info("gateway is going away", "reason", g.Reason, "reconnect_in", d)
			if g.Reason == "admin_stop" || g.Reason == "admin_disconnect" {
				return 0, ErrStoppedByGateway
			}
			// The gateway's delay wins over local backoff: during a drain it is the
			// only party that can see the whole fleet and spread it.
			return d, nil

		case frame.TypeError:
			var e frame.Error
			_ = frame.Unmarshal(f, &e)
			c.log.Warn("gateway reported an error", "code", e.Code, "message", e.Message)
			if !e.Retryable {
				return 0, fmt.Errorf("agent: gateway error %s: %s", e.Code, e.Message)
			}

		default:
			// HELLO, CHALLENGE, AUTH, WELCOME after the handshake.
			return 0, c.protocolError(ctx, conn,
				fmt.Errorf("%s after the handshake", f.Type))
		}
	}
}

// invite runs the callback on its own goroutine. Dialling a session involves a TLS
// handshake; doing it inline would stall the channel that delivers the next
// invitation, so a device asked for two sessions at once would serialise them.
func (c *Control) invite(ctx context.Context, inv frame.Invitation) {
	if c.cfg.OnInvitation == nil {
		c.log.Warn("no OnInvitation handler; dropping an invitation",
			"session", inv.SessionID)
		return
	}
	go c.cfg.OnInvitation(ctx, inv)
}

func (c *Control) pingLoop(ctx context.Context, conn transport.Conn) {
	t := time.NewTicker(c.cfg.PingInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			f, _ := frame.Stamp(frame.TypePing, uint64(now.UnixMicro()))
			if err := c.sendFrame(ctx, conn, f); err != nil {
				return
			}
		}
	}
}

func (c *Control) protocolError(ctx context.Context, conn transport.Conn, cause error) error {
	_ = c.send(ctx, conn, frame.TypeError, frame.Error{
		Code: frame.ErrorCode(cause), Message: cause.Error()})
	_ = conn.Close(transport.CloseProtocolError, "protocol error")
	return fmt.Errorf("agent: %w", cause)
}

func (c *Control) send(ctx context.Context, conn transport.Conn, t frame.Type, v any) error {
	f, err := frame.Marshal(t, v)
	if err != nil {
		return err
	}
	return c.sendFrame(ctx, conn, f)
}

func (c *Control) sendFrame(ctx context.Context, conn transport.Conn, f frame.Frame) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	wire, err := c.codec.Encode(c.buf[:0], f)
	if err != nil {
		return err
	}
	c.buf = wire

	ctx, cancel := context.WithTimeout(ctx, c.cfg.WriteTimeout)
	defer cancel()
	if err := conn.Send(ctx, wire); err != nil {
		return fmt.Errorf("agent: sending %s: %w", f.Type, err)
	}
	return nil
}
