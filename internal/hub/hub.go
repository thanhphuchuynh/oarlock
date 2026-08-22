// Package hub is the gateway side of the control channel.
//
// A persistent-mode agent holds one control channel open. The hub is the map from
// device id to that channel, and the only thing it is for is sending invitations:
// *dial me for session X*. **No session traffic crosses a control channel.** That
// is what makes the two reachability modes converge — in both, a session is its own
// connection authenticated by a single-use ticket, and the mode decides only how
// the invitation was delivered (ADR-024).
package hub

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/oarlock/oarlock/internal/handshake"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/transport"
)

// Defaults for liveness. A control channel is quiet for long stretches by
// definition, so the only way to tell a live one from a dead one is to ask.
const (
	DefaultPingInterval = 30 * time.Second
	// DefaultMissedPings closes a channel after this many unanswered pings. Three
	// at 30 s is 90 s of grace, which is long enough to ride out a cellular
	// handover and short enough that a dead device is not still "connected" when an
	// operator asks for a shell.
	DefaultMissedPings = 3

	// DefaultWriteTimeout bounds every write to a control channel.
	//
	// This is not belt-and-braces, it is the fix for a real hole: a peer that stops
	// *reading* — stalled, wedged, or deliberately hostile — fills the socket
	// buffers, and an unbounded Send then blocks the ping loop forever. The missed-
	// ping check never runs, and the device stays "connected" while being useless,
	// which is precisely the state the liveness check exists to prevent. If a frame
	// cannot be handed over within this long, the peer is gone.
	DefaultWriteTimeout = 10 * time.Second
)

var (
	// ErrNotConnected means no control channel is registered for the device. It is
	// not the same as the device being offline: a dispatch-mode device is never
	// expected to have one.
	ErrNotConnected = errors.New("hub: device has no control channel")
	ErrClosed       = errors.New("hub: closed")
)

// Options configure a Hub.
type Options struct {
	PingInterval time.Duration
	MissedPings  int
	WriteTimeout time.Duration
	Log          *slog.Logger
}

// Hub holds the live control channels.
type Hub struct {
	pingInterval time.Duration
	missedPings  int
	writeTimeout time.Duration
	log          *slog.Logger

	mu       sync.RWMutex
	closed   bool
	channels map[string]*channel
}

// New returns a Hub.
func New(o Options) *Hub {
	if o.PingInterval <= 0 {
		o.PingInterval = DefaultPingInterval
	}
	if o.MissedPings <= 0 {
		o.MissedPings = DefaultMissedPings
	}
	if o.WriteTimeout <= 0 {
		o.WriteTimeout = DefaultWriteTimeout
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	return &Hub{
		pingInterval: o.PingInterval,
		missedPings:  o.MissedPings,
		writeTimeout: o.WriteTimeout,
		log:          o.Log,
		channels:     make(map[string]*channel),
	}
}

// channel is one live control channel.
type channel struct {
	deviceID     string
	conn         transport.Conn
	codec        frame.Codec
	log          *slog.Logger
	writeTimeout time.Duration

	// writeMu serialises Send. transport.Conn allows Send concurrent with Recv but
	// not with itself, and the ping loop writes from a different goroutine than
	// Invite does.
	writeMu sync.Mutex
	buf     []byte

	// outstanding counts pings sent since the last pong.
	mu          sync.Mutex
	outstanding int

	done chan struct{}
}

func (c *channel) send(ctx context.Context, t frame.Type, v any) error {
	f, err := frame.Marshal(t, v)
	if err != nil {
		return err
	}
	return c.sendFrame(ctx, f)
}

func (c *channel) sendFrame(ctx context.Context, f frame.Frame) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	wire, err := c.codec.Encode(c.buf[:0], f)
	if err != nil {
		return err
	}
	c.buf = wire

	// Bounded, always. An unbounded write to a peer that has stopped reading blocks
	// this goroutine — and with it the ping loop — for as long as the peer cares to
	// hold the socket.
	ctx, cancel := context.WithTimeout(ctx, c.writeTimeout)
	defer cancel()
	if err := c.conn.Send(ctx, wire); err != nil {
		return fmt.Errorf("hub: sending %s to %s: %w", f.Type, c.deviceID, err)
	}
	return nil
}

// Serve runs one control channel until it ends, and returns why.
//
// The handshake has already happened: Serve is handed its result, so the hub never
// sees an unauthenticated channel.
func (h *Hub) Serve(ctx context.Context, conn transport.Conn, res *handshake.Result) error {
	ch := &channel{
		deviceID:     res.Device.ID,
		conn:         conn,
		log:          h.log.With("device", res.Device.ID),
		writeTimeout: h.writeTimeout,
		done:         make(chan struct{}),
	}

	if err := h.register(ch); err != nil {
		return err
	}
	defer h.deregister(ch)
	defer close(ch.done)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		h.pingLoop(ctx, ch)
	}()
	defer wg.Wait()

	err := h.readLoop(ctx, ch)
	cancel()
	return err
}

// register replaces any existing channel for the device.
//
// A half-open socket is the normal case, not an edge one: a device that lost its
// radio reconnects while the gateway still believes the old channel is fine. The
// newest connection wins, because it is the one demonstrably alive, and the old one
// is closed rather than left to rot as a leak that also answers Connected.
func (h *Hub) register(ch *channel) error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return ErrClosed
	}
	old := h.channels[ch.deviceID]
	h.channels[ch.deviceID] = ch
	h.mu.Unlock()

	if old != nil {
		h.log.Info("replacing an existing control channel", "device", ch.deviceID)
		_ = old.conn.Close(transport.CloseGoingAway, "replaced by a newer channel")
	}
	return nil
}

func (h *Hub) deregister(ch *channel) {
	h.mu.Lock()
	if h.channels[ch.deviceID] == ch {
		delete(h.channels, ch.deviceID)
	}
	h.mu.Unlock()
}

func (h *Hub) readLoop(ctx context.Context, ch *channel) error {
	for {
		msg, err := ch.conn.Recv(ctx)
		if err != nil {
			return err
		}
		f, err := ch.codec.Decode(msg)
		if err != nil {
			return h.fail(ctx, ch, transport.CloseProtocolError, frame.ErrorCode(err), err)
		}

		// A session frame arriving up a control channel means the peer is confused
		// about which connection it is holding. There is no per-frame recovery from
		// that: whatever state it thinks it has does not exist.
		if err := frame.Expect(frame.ScopeConnection, f); err != nil {
			return h.fail(ctx, ch, transport.CloseProtocolError, "protocol_error", err)
		}

		switch f.Type.Disposition() {
		case frame.Ignore:
			// Unreachable for connection scope, but keep the branch so a future
			// scope cannot fall through to CloseConnection by accident.
			ch.log.Debug("ignoring an unknown frame", "type", f.Type)
			continue
		case frame.CloseConnection:
			return h.fail(ctx, ch, transport.CloseProtocolError, "protocol_error",
				fmt.Errorf("unknown connection-scoped frame %s", f.Type))
		}

		switch f.Type {
		case frame.TypePing:
			stamp, err := frame.ReadStamp(f)
			if err != nil {
				return h.fail(ctx, ch, transport.CloseProtocolError, "protocol_error", err)
			}
			pong, _ := frame.Stamp(frame.TypePong, stamp)
			if err := ch.sendFrame(ctx, pong); err != nil {
				return err
			}
		case frame.TypePong:
			if _, err := frame.ReadStamp(f); err != nil {
				return h.fail(ctx, ch, transport.CloseProtocolError, "protocol_error", err)
			}
			ch.mu.Lock()
			ch.outstanding = 0
			ch.mu.Unlock()
		case frame.TypeGoAway:
			var g frame.GoAway
			_ = frame.Unmarshal(f, &g)
			ch.log.Info("agent is going away", "reason", g.Reason)
			return nil
		case frame.TypeHello, frame.TypeChallenge, frame.TypeAuth, frame.TypeWelcome:
			// The handshake is over. A second one on a live channel is either a
			// confused agent or someone trying to re-authenticate as a different
			// device on a channel that is already bound to one.
			return h.fail(ctx, ch, transport.CloseProtocolError, "protocol_error",
				fmt.Errorf("%s after the handshake", f.Type))
		case frame.TypeError:
			var e frame.Error
			_ = frame.Unmarshal(f, &e)
			ch.log.Warn("agent reported an error", "code", e.Code, "message", e.Message)
		default:
			// DIAL and CANCEL are gateway-to-agent only.
			return h.fail(ctx, ch, transport.CloseProtocolError, "protocol_error",
				fmt.Errorf("%s is not valid from an agent", f.Type))
		}
	}
}

func (h *Hub) fail(ctx context.Context, ch *channel, code transport.CloseCode, wire string, cause error) error {
	ch.log.Warn("closing control channel", "reason", cause, "code", wire)
	_ = ch.send(ctx, frame.TypeError, frame.Error{Code: wire, Message: cause.Error()})
	_ = ch.conn.Close(code, wire)
	return cause
}

func (h *Hub) pingLoop(ctx context.Context, ch *channel) {
	t := time.NewTicker(h.pingInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch.done:
			return
		case now := <-t.C:
			ch.mu.Lock()
			ch.outstanding++
			missed := ch.outstanding
			ch.mu.Unlock()

			if missed > h.missedPings {
				ch.log.Warn("control channel is not answering", "missed", missed-1)
				_ = ch.conn.Close(transport.CloseGoingAway, "no pong")
				return
			}
			f, _ := frame.Stamp(frame.TypePing, uint64(now.UnixMicro()))
			if err := ch.sendFrame(ctx, f); err != nil {
				// A write that could not complete inside the timeout means the peer
				// has stopped reading. That is a dead channel, and leaving it
				// registered would mean an operator being told a wedged device is
				// reachable.
				ch.log.Warn("control channel write failed", "error", err)
				_ = ch.conn.Close(transport.CloseGoingAway, "write timeout")
				return
			}
		}
	}
}

// ── what the hub is for ─────────────────────────────────────────────────────────

// Invite asks a device to dial back for one session.
//
// This is the entire purpose of the control channel. The invitation names a
// specific gateway node, so the agent connects to the replica the operator is
// waiting on rather than to whatever a load balancer picks (ADR-025).
func (h *Hub) Invite(ctx context.Context, deviceID string, inv frame.Invitation) error {
	ch, err := h.channel(deviceID)
	if err != nil {
		return err
	}
	if err := ch.send(ctx, frame.TypeDial, inv); err != nil {
		return err
	}
	ch.log.Info("invited device to dial", "session", inv.SessionID, "profile", inv.Profile)
	return nil
}

// Cancel withdraws an invitation.
//
// Without this a device that woke slowly dials for a session nobody is waiting on,
// spends a ticket, and is told to go away — which looks like a bug from the device's
// side and costs a handshake for nothing.
func (h *Hub) Cancel(ctx context.Context, deviceID, sessionID, reason string) error {
	ch, err := h.channel(deviceID)
	if err != nil {
		return err
	}
	return ch.send(ctx, frame.TypeCancel, frame.Cancel{SessionID: sessionID, Reason: reason})
}

// Disconnect closes one agent's control channel.
//
// This is an administrative disconnect, not a remote process kill. The agent may
// reconnect according to its own backoff, which is the right boundary: the gateway
// owns reachability, not process supervision on customer devices.
func (h *Hub) Disconnect(ctx context.Context, deviceID, reason string) error {
	ch, err := h.channel(deviceID)
	if err != nil {
		return err
	}
	if reason == "" {
		reason = "admin_stop"
	}
	_ = ch.send(ctx, frame.TypeGoAway, frame.GoAway{Reason: reason})
	return ch.conn.Close(transport.CloseGoingAway, reason)
}

// Connected reports whether a control channel is live for the device.
func (h *Hub) Connected(deviceID string) bool {
	_, err := h.channel(deviceID)
	return err == nil
}

// Devices lists the devices holding a control channel.
func (h *Hub) Devices() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]string, 0, len(h.channels))
	for id := range h.channels {
		out = append(out, id)
	}
	return out
}

// Len is the number of live channels, for metrics.
func (h *Hub) Len() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.channels)
}

func (h *Hub) channel(deviceID string) (*channel, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.closed {
		return nil, ErrClosed
	}
	ch, ok := h.channels[deviceID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotConnected, deviceID)
	}
	return ch, nil
}

// Drain tells every agent the gateway is going away, with a per-agent delay before
// reconnecting.
//
// nextDelay is called once per channel and must return a *different* value each
// time — that spread is the whole point. Handing every agent the same number just
// moves the herd rather than dispersing it.
func (h *Hub) Drain(ctx context.Context, reason string, nextDelay func() time.Duration) {
	h.mu.Lock()
	h.closed = true
	chans := make([]*channel, 0, len(h.channels))
	for _, ch := range h.channels {
		chans = append(chans, ch)
	}
	h.mu.Unlock()

	for _, ch := range chans {
		d := time.Duration(0)
		if nextDelay != nil {
			d = nextDelay()
		}
		_ = ch.send(ctx, frame.TypeGoAway, frame.GoAway{
			Reason:           reason,
			ReconnectAfterMS: int(d.Milliseconds()),
		})
		_ = ch.conn.Close(transport.CloseGoingAway, reason)
	}
	h.log.Info("drained control channels", "count", len(chans), "reason", reason)
}
