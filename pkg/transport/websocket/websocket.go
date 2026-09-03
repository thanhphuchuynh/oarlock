// Package websocket is the only package in Oarlock that names a WebSocket type.
//
// Everything above it speaks transport.Conn. That is enforced by a test, not by
// convention: pkg/transport/layering_test.go walks every import in the module and
// fails if this dependency appears anywhere else.
package websocket

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	ws "github.com/coder/websocket"

	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/transport"
)

// Subprotocol is the negotiated WebSocket subprotocol for wire version v0.
const Subprotocol = "oarlock.v0"

const defaultHandshakeTimeout = 10 * time.Second

type conn struct {
	// tls is the state of the connection underneath, when there is one. It exists for
	// channel binding: internal/handshake mixes RFC 5705 exported keying material into
	// what the device signs, so a middlebox that terminates TLS and relays the handshake
	// signs over one channel and is verified over another.
	//
	// Held rather than fetched because there is nowhere to fetch it from later: on the
	// client side it arrives on the dial's *http.Response and on the server side on the
	// *http.Request, and both are gone by the time the handshake runs.
	tlsState *tls.ConnectionState

	c    *ws.Conn
	addr string
}

var _ transport.Conn = (*conn)(nil)

func (c *conn) Recv(ctx context.Context) ([]byte, error) {
	typ, b, err := c.c.Read(ctx)
	if err != nil {
		// Two ways an oversize message surfaces, and both must translate to the
		// same thing: ErrMessageTooBig when *our* read limit stopped the read, and
		// close status 1009 when the peer tore the connection down for the same
		// reason. Matching only the close status was a bug — the local read limit
		// never produces one, so an oversize message read as a generic failure.
		if errors.Is(err, ws.ErrMessageTooBig) || ws.CloseStatus(err) == ws.StatusMessageTooBig {
			return nil, transport.ErrTooLarge
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", transport.ErrClosed, err)
	}
	if typ != ws.MessageBinary {
		// Every Oarlock frame is binary. A text frame is not something to coerce
		// into one; it means the peer is speaking a different protocol.
		_ = c.Close(transport.CloseProtocolError, "text message")
		return nil, transport.ErrTextMessage
	}
	return b, nil
}

func (c *conn) Send(ctx context.Context, b []byte) error {
	if err := c.c.Write(ctx, ws.MessageBinary, b); err != nil {
		return fmt.Errorf("%w: %v", transport.ErrClosed, err)
	}
	return nil
}

func (c *conn) Close(code transport.CloseCode, reason string) error {
	// WebSocket close reasons are capped at 123 bytes; a longer one makes Close
	// fail, which would turn a tidy shutdown into an abort.
	if len(reason) > 120 {
		reason = reason[:120]
	}
	err := c.c.Close(status(code), reason)
	if err != nil && (ws.CloseStatus(err) != -1 || errors.Is(err, net.ErrClosed)) {
		return nil
	}
	return err
}

func (c *conn) RemoteAddr() string { return c.addr }

func status(code transport.CloseCode) ws.StatusCode {
	switch code {
	case transport.CloseNormal:
		return ws.StatusNormalClosure
	case transport.CloseGoingAway:
		return ws.StatusGoingAway
	case transport.CloseProtocolError:
		return ws.StatusProtocolError
	case transport.ClosePolicyViolation:
		return ws.StatusPolicyViolation
	case transport.CloseTooLarge:
		return ws.StatusMessageTooBig
	default:
		return ws.StatusInternalError
	}
}

func readLimit(opts transport.Options) int64 {
	if opts.MaxMessageBytes > 0 {
		return int64(opts.MaxMessageBytes)
	}
	return frame.MaxFrame
}

// Dialer dials outbound WebSocket connections.
type Dialer struct{}

var _ transport.Dialer = Dialer{}

func (Dialer) Dial(ctx context.Context, url string, opts transport.Options) (transport.Conn, error) {
	timeout := opts.HandshakeTimeout
	if timeout <= 0 {
		timeout = defaultHandshakeTimeout
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	sub := opts.Subprotocol
	if sub == "" {
		sub = Subprotocol
	}

	do := &ws.DialOptions{
		Subprotocols: []string{sub},
		HTTPHeader:   opts.Header,
	}
	if len(opts.PinSHA256) > 0 {
		do.HTTPClient = &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
					// Additive: normal chain verification still runs. Pinning
					// narrows what is acceptable, it does not replace the checks.
					VerifyPeerCertificate: pinVerifier(opts.PinSHA256),
				},
			},
		}
	}

	c, resp, err := ws.Dial(dctx, url, do)
	if err != nil {
		return nil, fmt.Errorf("websocket: dial %s: %w", url, err)
	}
	if resp != nil && resp.Body != nil {
		// The TLS state is read from resp below; closing the body does not invalidate it.
		_ = resp.Body.Close()
	}
	if got := c.Subprotocol(); got != sub {
		_ = c.Close(ws.StatusProtocolError, "subprotocol")
		return nil, fmt.Errorf("websocket: server negotiated subprotocol %q, want %q", got, sub)
	}
	c.SetReadLimit(readLimit(opts))
	var state *tls.ConnectionState
	if resp != nil {
		state = resp.TLS
	}
	return &conn{c: c, addr: url, tlsState: state}, nil
}

// Upgrader accepts inbound WebSocket connections.
type Upgrader struct {
	// OriginPatterns restricts the browser Origin header. Empty means same-origin
	// only, which is the safe default: the browser leg is authenticated by a
	// ticket in the OPEN frame, and an unrestricted origin would let any page
	// start the handshake before that ticket is ever checked.
	OriginPatterns []string
}

var _ transport.Upgrader = Upgrader{}

func (u Upgrader) Upgrade(w http.ResponseWriter, r *http.Request, opts transport.Options) (transport.Conn, error) {
	sub := opts.Subprotocol
	if sub == "" {
		sub = Subprotocol
	}
	c, err := ws.Accept(w, r, &ws.AcceptOptions{
		Subprotocols:   []string{sub},
		OriginPatterns: u.OriginPatterns,
		// Compression stays off. Terminal output is highly compressible, and
		// compressing attacker-influenced plaintext next to secrets is the shape
		// of every CRIME-family problem. The bandwidth is not worth the class.
		CompressionMode: ws.CompressionDisabled,
	})
	if err != nil {
		return nil, fmt.Errorf("websocket: accept: %w", err)
	}
	if got := c.Subprotocol(); got != sub {
		_ = c.Close(ws.StatusProtocolError, "subprotocol")
		return nil, fmt.Errorf("websocket: client did not offer %q", sub)
	}
	c.SetReadLimit(readLimit(opts))
	return &conn{c: c, addr: r.RemoteAddr, tlsState: r.TLS}, nil
}

// pinVerifier matches the leaf's SubjectPublicKeyInfo against a pin set.
//
// SPKI rather than the whole certificate, so a renewal that keeps the key does
// not invalidate every agent's pin — which is what makes pinning survivable to
// operate rather than an outage waiting for a certificate to expire.
func pinVerifier(pins []string) func([][]byte, [][]*x509.Certificate) error {
	want := make(map[string]struct{}, len(pins))
	for _, p := range pins {
		want[p] = struct{}{}
	}
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("websocket: no certificate to pin against")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("websocket: parse leaf: %w", err)
		}
		sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		if _, ok := want[base64.StdEncoding.EncodeToString(sum[:])]; ok {
			return nil
		}
		return errors.New("websocket: server key does not match any pin")
	}
}

// Pin computes the pin for a certificate, so an operator can produce the value
// to configure without hand-running openssl.
func Pin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// ChannelBinding returns RFC 5705 exported keying material for this connection.
//
// # When this legitimately fails
//
// `ws://` has nothing to bind to, so a development gateway gets ErrNoChannelBinding and
// the caller's policy decides what that means.
//
// It also fails on a TLS 1.2 session resumed without extended master secret, because the
// exporter would not be tied to *this* handshake — Go refuses rather than returning
// something that looks bound and is not, which is the right refusal. TLS 1.3 always
// exports. A deployment that requires binding and hits this is running an old TLS stack
// somewhere in the path, and the refusal says so rather than quietly downgrading.
func (c *conn) ChannelBinding(label string, length int) ([]byte, error) {
	if c.tlsState == nil {
		return nil, transport.ErrNoChannelBinding
	}
	ekm, err := c.tlsState.ExportKeyingMaterial(label, nil, length)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", transport.ErrNoChannelBinding, err)
	}
	return ekm, nil
}

var _ transport.ChannelBound = (*conn)(nil)
