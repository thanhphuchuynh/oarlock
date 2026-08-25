package agent

// The `tcp` profile: carry one TCP connection to a device-local port.
//
// This is what makes `ssh -L 8080:localhost:3000 device@gateway` work — a web UI, a
// database, an `adb` daemon, anything that speaks TCP on a machine that cannot be dialled
// from the operator's network. The gateway terminates the operator's SSH and opens one
// Oarlock session per forwarded connection (ADR-024: a connection is one session, and
// nothing here multiplexes).
//
// # Loopback only, from an allow-list the device holds
//
// The invitation names a port and never a host, and this file dials 127.0.0.1. Both
// halves matter. A device that dialled a *host* the gateway named would be an open proxy
// into whatever network it sits on — and that network is, by construction, the one nobody
// outside can reach, which is why the device is behind Oarlock in the first place. The
// port allow-list is the same bargain the exec allow-list makes: the gateway authorises
// the action, the device decides what is actually reachable on it. Without it, `tcp` on
// any device means every listening socket on that device, including the ones bound to
// loopback precisely because they have no authentication of their own.
//
// # Not recorded
//
// ARCHITECTURE § 9.4: `tcp` is not recorded. A recording is an asciicast — a terminal
// replay — and a TLS handshake streamed into one produces something nobody can watch and
// a second copy of every byte in a store with its own retention. The session row still
// says `not_recorded`, so it is a queryable fact rather than an absence to notice.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/oarlock/oarlock/pkg/frame"
)

// DefaultDialTimeout bounds connecting to the device-local port.
//
// Short on purpose: the target is on loopback, so anything that is going to answer
// answers immediately. A long timeout here is an operator watching a hung terminal for a
// service that is simply not running.
const DefaultDialTimeout = 5 * time.Second

// ErrPortNotAllowed means the gateway asked for a port this device does not offer.
var ErrPortNotAllowed = errors.New("agent: that port is not forwardable on this device")

// DialRequest is one forwarded connection, as the gateway asked for it.
type DialRequest struct {
	SessionID string
	// Principal is for the agent's own log only; never an authorisation input. The
	// agent trusts the gateway completely and cannot check anything itself.
	Principal string
	// Port is the device-local TCP port. Untrusted until it is matched against the
	// allow-list.
	Port int
}

// DialFunc opens one connection to a device-local port.
//
// A hook like ShellFunc and FileFunc, for the same reason: which ports a device is
// willing to expose is a deployment's choice, and a build with nothing worth forwarding
// should leave "tcp" out of Caps so the gateway refuses at open time rather than after a
// round trip.
type DialFunc func(ctx context.Context, req DialRequest) (net.Conn, error)

// DialOption configures Dial.
type DialOption func(*dialOptions)

type dialOptions struct {
	timeout time.Duration
	host    string
}

// DialTimeout bounds connecting to the device-local port.
func DialTimeout(d time.Duration) DialOption {
	return func(o *dialOptions) { o.timeout = d }
}

// Dial builds a DialFunc that will connect to 127.0.0.1 on an allow-listed port.
//
// An empty allow-list returns nil rather than a function that refuses everything: nil is
// what the caller checks to decide whether to advertise "tcp" at all, and a device that
// advertises a capability it will refuse for every port costs a round trip to say no.
func Dial(allow []int, opts ...DialOption) DialFunc {
	o := dialOptions{timeout: DefaultDialTimeout, host: "127.0.0.1"}
	for _, apply := range opts {
		apply(&o)
	}

	// A set rather than a slice scan: the list is short either way, but building it
	// once also collapses duplicates in a hand-written config.
	allowed := make(map[int]struct{}, len(allow))
	for _, port := range allow {
		if port > 0 && port < 65536 {
			allowed[port] = struct{}{}
		}
	}
	if len(allowed) == 0 {
		return nil
	}

	return func(ctx context.Context, req DialRequest) (net.Conn, error) {
		if _, ok := allowed[req.Port]; !ok {
			// The port is named back. It came from this device's own operator via the
			// gateway, so it is not a secret, and "port 5432 is not forwardable" tells
			// somebody what to put in the config file where "denied" does not.
			return nil, fmt.Errorf("%w: %d", ErrPortNotAllowed, req.Port)
		}
		d := net.Dialer{Timeout: o.timeout}
		addr := net.JoinHostPort(o.host, strconv.Itoa(req.Port))
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("agent: dialling %s: %w", addr, err)
		}
		return conn, nil
	}
}

// runTCP joins a device-local connection to the session.
//
// # Half-close is not represented
//
// TCP lets one side finish sending while the other keeps going, and SSH's direct-tcpip
// channel carries that as EOF. Oarlock's frame vocabulary has no half-close: CLOSE means
// the session is over. So a peer's EOF ends the whole forward rather than half of it.
//
// That is correct for everything a forward is normally for — HTTP keeps the connection
// open across a response, and so do Postgres, Redis and adb — and wrong for the protocols
// that signal end-of-request by shutting down the write side, which is mostly `nc` and
// HTTP/1.0. Adding a half-close frame is a protocol change; it is written down here
// rather than half-implemented, because a forward that silently truncates one direction
// is worse than one that documents what it does not do.
func (s *session) runTCP(ctx context.Context, dial DialFunc, inv frame.Invitation) error {
	if dial == nil {
		err := errors.New("agent: no Dial configured, but a tcp session was requested")
		_ = s.send(ctx, frame.TypeError, frame.Error{
			Code: "profile_unsupported", Message: err.Error()})
		return err
	}
	if inv.TCP == nil {
		err := errors.New("agent: a tcp session carried no target port")
		_ = s.send(ctx, frame.TypeError, frame.Error{
			Code: "protocol_error", Message: err.Error()})
		return err
	}

	conn, err := dial(ctx, DialRequest{
		SessionID: inv.SessionID, Principal: inv.Principal, Port: inv.TCP.Port,
	})
	if err != nil {
		// A refused port and an unreachable one are different things and get different
		// codes: the first is policy on this device and will never succeed, the second
		// is a service that is not running yet and might.
		code := "internal"
		if errors.Is(err, ErrPortNotAllowed) {
			code = "not_authorized"
		}
		_ = s.send(ctx, frame.TypeError, frame.Error{Code: code, Message: err.Error()})
		_ = s.send(ctx, frame.TypeClose, frame.Close{Reason: "device_close"})
		return err
	}
	defer conn.Close()

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Device → gateway. io.Copy's 32 KiB reads sit an order of magnitude under
	// frame.MaxFrame, so a full read is always one frame.
	copyDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(&frameWriter{s: s, ctx: runCtx, kind: frame.TypeData}, conn)
		copyDone <- err
		// The local service hung up, or the copy failed. Either way this forward is
		// over: unblock the receive loop below rather than leaving it waiting on an
		// operator who is waiting on bytes that will never come.
		cancel()
	}()

	recvErr := s.tcpFromGateway(runCtx, conn)

	// Closing the local connection stops the copier, whichever side finished first.
	_ = conn.Close()
	copyErr := <-copyDone

	// Reported before CLOSE, and only for a genuine failure. A peer that hung up is how
	// a forwarded connection normally ends — every closed browser tab is one — and an
	// ERROR frame for it would put a red line in front of an operator for whom nothing
	// went wrong.
	err = firstRealError(recvErr, copyErr)
	if err != nil {
		_ = s.send(ctx, frame.TypeError, frame.Error{Code: "internal", Message: err.Error()})
	} else {
		_ = s.send(ctx, frame.TypeExit, frame.Exit{Code: 0})
	}
	_ = s.send(ctx, frame.TypeClose, frame.Close{Reason: "device_close"})
	return err
}

// tcpFromGateway writes operator bytes to the device-local connection until either end
// stops. A nil return means an ordinary end, not an error.
func (s *session) tcpFromGateway(ctx context.Context, conn net.Conn) error {
	for {
		msg, err := s.conn.Recv(ctx)
		if err != nil {
			if ctx.Err() != nil {
				// The copier cancelled us because the local service hung up. That is
				// this forward ending normally, not a transport failure.
				return nil
			}
			return err
		}
		f, err := s.codec.Decode(msg)
		if err != nil {
			return err
		}
		if frame.Expect(frame.ScopeSession, f) != nil {
			return errors.New("agent: an out-of-scope frame on a tcp session")
		}
		switch f.Type {
		case frame.TypeData:
			if _, err := conn.Write(f.Payload); err != nil {
				return err
			}
		case frame.TypeClose:
			// The operator closed their end of the forward.
			return nil
		default:
			// RESIZE and SIGNAL belong to a terminal and there is not one here.
			// Ignored rather than fatal: a future frame type must not break a forward
			// that has nothing to do with it.
		}
	}
}

// firstRealError picks the failure worth reporting, treating an ordinary hang-up as none.
func firstRealError(errs ...error) error {
	for _, err := range errs {
		switch {
		case err == nil, errors.Is(err, io.EOF), errors.Is(err, net.ErrClosed):
		case errors.Is(err, io.ErrClosedPipe):
		default:
			return err
		}
	}
	return nil
}
