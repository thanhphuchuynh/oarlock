package agentconf

// One control channel, as the suite sees it.

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/oarlock/oarlock/internal/handshake"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
	"github.com/oarlock/oarlock/pkg/transport"
)

// errNoTextSupport means this transport cannot inject a text message, so the binary-only
// rule cannot be exercised.
var errNoTextSupport = errors.New("agentconf: this transport cannot send a text message")

// TextSender is implemented by a transport that can send a text WebSocket message.
//
// Needed because the binary-only rule is one of the few things a *correct* transport goes
// out of its way to make impossible: pkg/transport's Send is binary by construction. So the
// suite asks, and reports a skip rather than a pass when the answer is no.
type TextSender interface {
	SendText(ctx context.Context, b []byte) error
}

type channel struct {
	conn   transport.Conn
	codec  frame.Codec
	result *handshake.Result

	// release lets the HTTP handler holding this connection return. Closed exactly once,
	// by close().
	release  chan struct{}
	released bool

	// resumeWith is what the gateway offers in WELCOME.resume for this case.
	resumeWith []frame.Invitation
}

func (c *channel) resume(context.Context, string) []frame.Invitation { return c.resumeWith }

func (c *channel) close() {
	_ = c.conn.Close(transport.CloseNormal, "case over")
	if c.release != nil && !c.released {
		c.released = true
		close(c.release)
	}
}

func (c *channel) send(ctx context.Context, f frame.Frame) error {
	wire, err := c.codec.Encode(nil, f)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return c.conn.Send(ctx, wire)
}

func (c *channel) sendJSON(ctx context.Context, t frame.Type, v any) error {
	f, err := frame.Marshal(t, v)
	if err != nil {
		return err
	}
	return c.send(ctx, f)
}

func (c *channel) sendText(ctx context.Context, b []byte) error {
	ts, ok := c.conn.(TextSender)
	if !ok {
		return errNoTextSupport
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return ts.SendText(ctx, b)
}

// recvType reads until a frame of type `want` arrives.
//
// Frames of other types are skipped rather than failed, because an agent is entitled to
// send its own PING while a case is waiting — and a suite that failed on that would be
// testing timing rather than the protocol.
func (c *channel) recvType(ctx context.Context, want frame.Type) (frame.Frame, error) {
	for {
		msg, err := c.conn.Recv(ctx)
		if err != nil {
			return frame.Frame{}, err
		}
		f, err := c.codec.Decode(msg)
		if err != nil {
			return frame.Frame{}, fmt.Errorf("the agent sent something that is not a "+
				"frame: %w", err)
		}
		if f.Type == want {
			return f.Clone(), nil
		}
		if f.Type == frame.TypeError {
			var e frame.Error
			_ = frame.Unmarshal(f, &e)
			return frame.Frame{}, fmt.Errorf("the agent returned ERROR %s: %s", e.Code, e.Message)
		}
	}
}

// expectClose reports whether the agent closed the connection, and what it did instead if
// not.
//
// An ERROR frame before the close is welcome and not required: § 2.3 says the connection
// ends, and an agent that says why first is being helpful. What fails is the channel
// staying usable.
func (c *channel) expectClose(ctx context.Context) (bool, string) {
	var said string
	for {
		msg, err := c.conn.Recv(ctx)
		if err != nil {
			// A deadline is not a close. The first version of this returned true for
			// *any* read error, which meant an agent that did nothing at all passed
			// every case that waits for it to hang up — including the two scope cases
			// that exist to catch exactly that agent. The suite's own test found it,
			// which is the entire reason that test exists.
			if ctx.Err() != nil {
				return false, "it never closed the connection"
			}
			return true, said
		}
		f, derr := c.codec.Decode(msg)
		if derr != nil {
			return true, said
		}
		switch f.Type {
		case frame.TypeError:
			var e frame.Error
			_ = frame.Unmarshal(f, &e)
			said = fmt.Sprintf("it sent ERROR %s first, which is fine", e.Code)
		case frame.TypePing, frame.TypePong:
			// Still answering pings means still live. Keep waiting; the deadline decides.
		default:
			return false, fmt.Sprintf("it carried on and sent %s", f.Type)
		}
		if ctx.Err() != nil {
			return false, "it never closed the connection"
		}
	}
}

// ── the registry the suite's gateway reads ──────────────────────────────────────

// oneDevice is a plugin.DeviceRegistry holding exactly the device under test.
type oneDevice struct {
	id  string
	key ed25519.PublicKey
}

func (d oneDevice) Get(_ context.Context, id string) (*plugin.Device, error) {
	if id != d.id {
		// The same refusal a real gateway gives, so an implementer who typos their
		// device id sees what their gateway will show them.
		return nil, plugin.ErrNoDevice
	}
	return &plugin.Device{
		ID: d.id, Platform: plugin.PlatformLinux,
		Keys: []ed25519.PublicKey{d.key},
	}, nil
}

func (d oneDevice) List(context.Context, plugin.DeviceQuery) ([]*plugin.Device, string, error) {
	return nil, "", plugin.ErrUnsupported
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// sendRaw puts bytes on the wire without encoding them as a frame.
//
// For the cases that must do something the codec refuses to produce. An attacker is not
// using our encoder, so a suite that could only send well-formed frames could not check
// what happens to malformed ones.
func (c *channel) sendRaw(ctx context.Context, b []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return c.conn.Send(ctx, b)
}
