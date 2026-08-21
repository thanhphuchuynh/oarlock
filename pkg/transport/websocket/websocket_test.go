package websocket

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ws "github.com/coder/websocket"

	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/transport"
)

// serve stands up an httptest server that upgrades one connection and hands it to
// fn. Tests are in-package so they may reach the WebSocket library directly to
// send things the transport.Conn interface deliberately cannot — a text frame,
// for one.
func serve(t *testing.T, opts transport.Options, fn func(t *testing.T, c transport.Conn)) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (Upgrader{}).Upgrade(w, r, opts)
		if err != nil {
			t.Logf("upgrade: %v", err)
			return
		}
		defer c.Close(transport.CloseNormal, "test over")
		fn(t, c)
	}))
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http")
}

func dial(t *testing.T, url string, opts transport.Options) transport.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dialer{}.Dial(ctx, url, opts)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close(transport.CloseNormal, "done") })
	return c
}

func TestRoundTripBothDirections(t *testing.T) {
	ctx := context.Background()
	c := frame.Codec{}

	url := serve(t, transport.Options{}, func(t *testing.T, sc transport.Conn) {
		msg, err := sc.Recv(ctx)
		if err != nil {
			t.Errorf("server recv: %v", err)
			return
		}
		f, err := c.Decode(msg)
		if err != nil {
			t.Errorf("server decode: %v", err)
			return
		}
		reply, err := c.Encode(nil, frame.Data(append([]byte("echo:"), f.Payload...)))
		if err != nil {
			t.Errorf("server encode: %v", err)
			return
		}
		if err := sc.Send(ctx, reply); err != nil {
			t.Errorf("server send: %v", err)
		}
	})

	cc := dial(t, url, transport.Options{})
	wire, err := c.Encode(nil, frame.Data([]byte("ping")))
	if err != nil {
		t.Fatal(err)
	}
	if err := cc.Send(ctx, wire); err != nil {
		t.Fatal(err)
	}
	msg, err := cc.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f, err := c.Decode(msg)
	if err != nil {
		t.Fatal(err)
	}
	if string(f.Payload) != "echo:ping" {
		t.Errorf("payload %q", f.Payload)
	}
}

// TestTextMessageIsAProtocolError is an acceptance criterion: every Oarlock frame
// is binary, and a text frame means the peer is speaking a different protocol.
func TestTextMessageIsAProtocolError(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := ws.Accept(w, r, &ws.AcceptOptions{Subprotocols: []string{Subprotocol}})
		if err != nil {
			return
		}
		defer c.CloseNow()
		_ = c.Write(ctx, ws.MessageText, []byte("this is not a frame"))
		time.Sleep(50 * time.Millisecond)
	}))
	defer srv.Close()

	cc := dial(t, "ws"+strings.TrimPrefix(srv.URL, "http"), transport.Options{})
	if _, err := cc.Recv(ctx); !errors.Is(err, transport.ErrTextMessage) {
		t.Fatalf("got %v, want ErrTextMessage", err)
	}
	if got := transport.Code(transport.ErrTextMessage); got != "protocol_error" {
		t.Errorf("wire code %q, want protocol_error", got)
	}
}

// TestReadLimitRejectsWithoutBuffering covers the criterion that an oversized
// message is refused *by the transport*. The library stops reading at the limit
// rather than allocating to the size the sender implied.
func TestReadLimitRejectsWithoutBuffering(t *testing.T) {
	ctx := context.Background()
	const limit = 4096

	url := serve(t, transport.Options{MaxMessageBytes: limit}, func(t *testing.T, sc transport.Conn) {
		_, err := sc.Recv(ctx)
		if !errors.Is(err, transport.ErrTooLarge) {
			t.Errorf("server got %v, want ErrTooLarge", err)
		}
	})

	cc := dial(t, url, transport.Options{})
	// Oversized on purpose. The frame codec would refuse to build this; we bypass
	// it because the point is what the transport does with a hostile peer.
	if err := cc.Send(ctx, make([]byte, limit+1)); err != nil {
		t.Logf("send returned %v (the peer may have closed first, which is fine)", err)
	}
	time.Sleep(100 * time.Millisecond)

	if got := transport.Code(transport.ErrTooLarge); got != "frame_too_large" {
		t.Errorf("wire code %q, want frame_too_large", got)
	}
}

func TestSubprotocolMustMatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// A server that negotiates something else must not be treated as an Oarlock
	// peer: the subprotocol is how a v0 client and a future v1 server avoid
	// discovering their incompatibility six frames in.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := ws.Accept(w, r, &ws.AcceptOptions{Subprotocols: []string{"something.else"}})
		if err != nil {
			return
		}
		defer c.CloseNow()
		time.Sleep(50 * time.Millisecond)
	}))
	defer srv.Close()

	// Dial with the default subprotocol: the server offers only "something.else",
	// so nothing is negotiated and Subprotocol() comes back empty. The dialer must
	// treat that as a failure rather than proceeding to speak v0 at it.
	_, err := Dialer{}.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), transport.Options{})
	if err == nil {
		t.Fatal("dial succeeded against a server that negotiated no subprotocol")
	}
	if !strings.Contains(err.Error(), "subprotocol") {
		t.Errorf("error should name the subprotocol: %v", err)
	}
}

func TestDefaultReadLimitIsMaxFrame(t *testing.T) {
	if got := readLimit(transport.Options{}); got != frame.MaxFrame {
		t.Errorf("default read limit %d, want %d", got, frame.MaxFrame)
	}
	if got := readLimit(transport.Options{MaxMessageBytes: 99}); got != 99 {
		t.Errorf("override ignored: %d", got)
	}
}

func TestCloseCodeMapping(t *testing.T) {
	// Callers name a reason, not a WebSocket number. If these stop being distinct
	// the operator-facing close reason stops being informative.
	seen := map[ws.StatusCode]transport.CloseCode{}
	for _, cc := range []transport.CloseCode{
		transport.CloseNormal, transport.CloseGoingAway, transport.CloseProtocolError,
		transport.ClosePolicyViolation, transport.CloseTooLarge, transport.CloseInternal,
	} {
		s := status(cc)
		if prev, dup := seen[s]; dup {
			t.Errorf("%v and %v both map to %v", prev, cc, s)
		}
		seen[s] = cc
	}
}

// TestPinning covers the SPKI pin used by the reference agent. v0 has no channel
// binding, so this is what stands between the handshake and a TLS-terminating
// middlebox relaying it.
func TestPinning(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	cert := srv.Certificate()

	good := Pin(cert)
	if good == "" {
		t.Fatal("Pin returned an empty string")
	}
	if err := pinVerifier([]string{good})([][]byte{cert.Raw}, nil); err != nil {
		t.Errorf("matching pin rejected: %v", err)
	}
	if err := pinVerifier([]string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="})([][]byte{cert.Raw}, nil); err == nil {
		t.Error("a wrong pin was accepted")
	}
	if err := pinVerifier([]string{good})(nil, nil); err == nil {
		t.Error("an empty chain was accepted")
	}
	// A pin set containing the right key among wrong ones must still match, which
	// is what makes key rotation deployable: publish both, then retire the old.
	if err := pinVerifier([]string{"AAAA", good, "BBBB"})([][]byte{cert.Raw}, nil); err != nil {
		t.Errorf("pin set containing the key rejected: %v", err)
	}
}

func TestCloseReasonIsTruncated(t *testing.T) {
	// WebSocket caps close reasons at 123 bytes; a longer one makes Close fail,
	// which would turn a tidy shutdown into an abort exactly when we are trying to
	// report why.
	ctx := context.Background()
	url := serve(t, transport.Options{}, func(t *testing.T, sc transport.Conn) {
		if err := sc.Close(transport.ClosePolicyViolation, strings.Repeat("x", 500)); err != nil {
			t.Errorf("close with a long reason failed: %v", err)
		}
	})
	cc := dial(t, url, transport.Options{})
	_, _ = cc.Recv(ctx)
}
