package sshsrv

// `direct-tcpip`: local port forwarding through the gateway.
//
// This is what makes `ssh -L 8080:localhost:3000 treadmill-4821@gw -N` reach a web UI,
// a database or an adb daemon on a machine that cannot be dialled from the operator's
// network. The operator's own `ssh` is the client — there is nothing else to install,
// and `scp`, `rsync` and everything else that rides an SSH channel come along with it.
//
// # One connection is one session
//
// Every forwarded TCP connection opens its own Oarlock session: its own row, its own
// invitation, its own websocket from the device. That is ADR-024 applied rather than
// worked around, and it is the reason a forward is revocable, killable and auditable
// with exactly the machinery a shell already has.
//
// It is also not free. A browser opens up to six connections for one page, and each one
// costs a TLS handshake to the device. ADR-024 accepted that cost for sessions that are
// "rare and short"; forwarded connections are neither, and that is the honest price of
// not multiplexing. The per-device cap for forwards is separate and larger for exactly
// this reason (sessions.HoldsDevice).
//
// # The target is a port, never a host
//
// `-L 8080:localhost:3000` is honoured; `-L 8080:10.0.0.5:3000` is refused. The device
// dials its own loopback and nothing else, so a compromised gateway cannot turn a fleet
// of agents into proxies into the networks they sit on — which is the whole reason those
// devices are behind Oarlock.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	gssh "github.com/gliderlabs/ssh"
	xssh "golang.org/x/crypto/ssh"

	"github.com/oarlock/oarlock/internal/invite"
	"github.com/oarlock/oarlock/internal/sessionrun"
	"github.com/oarlock/oarlock/internal/sessions"
	"github.com/oarlock/oarlock/pkg/condition"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
	"github.com/oarlock/oarlock/pkg/transport"
)

// directTCPIP is the channel-open payload for direct-tcpip, RFC 4254 § 7.2.
// gliderlabs keeps its own copy unexported, and its handler dials locally, which is
// exactly what must not happen here.
type directTCPIP struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

// loopbackNames are the destinations an operator may write in `-L`. The device always
// dials 127.0.0.1; these are the ways of asking for it that mean the same thing.
func isLoopbackTarget(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1", "":
		return true
	}
	// A client that resolved the name before sending it — some do — still has to land
	// on loopback.
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// handleDirectTCPIP forwards one TCP connection to a device-local port.
//
// Every string handed to newChan.Reject reaches the operator through their own ssh,
// which escapes anything outside ASCII: an em dash arrives as `\200\224` in the middle
// of the sentence. Keep these messages ASCII — the house style elsewhere in this repo
// will not survive the trip. (OpenSSH also only prints them under `ssh -v`; the
// gateway log carries the same reason for anyone not running verbose.)
func (s *Server) handleDirectTCPIP(_ *gssh.Server, _ *xssh.ServerConn,
	newChan xssh.NewChannel, ctx gssh.Context) {

	var d directTCPIP
	if err := xssh.Unmarshal(newChan.ExtraData(), &d); err != nil {
		_ = newChan.Reject(xssh.ConnectionFailed, "oarlock: malformed forward request")
		return
	}

	deviceID := ctx.User()
	p, _ := ctx.Value(principalKey{}).(*plugin.Principal)
	if p == nil {
		// Cannot happen with PublicKeyHandler set, but an unattributed forward is
		// worse than no forward.
		_ = newChan.Reject(xssh.Prohibited, "oarlock: no authenticated principal")
		return
	}
	log := s.log.With("principal", p.ID, "device", deviceID, "profile", "tcp",
		"port", d.DestPort)

	if !isLoopbackTarget(d.DestAddr) {
		// Named explicitly, because the operator's next move is to retype the command
		// and they need to know which half was wrong.
		log.Warn("forward refused: non-loopback destination", "dest", d.DestAddr)
		_ = newChan.Reject(xssh.Prohibited, fmt.Sprintf(
			"oarlock: only the device's own loopback can be forwarded, not %q. "+
				"Use -L <local>:localhost:%d", d.DestAddr, d.DestPort))
		return
	}
	if d.DestPort == 0 || d.DestPort > 65535 {
		_ = newChan.Reject(xssh.ConnectionFailed, "oarlock: that is not a port")
		return
	}

	dev, err := s.o.Registry.Get(ctx, deviceID)
	if err != nil || dev.Disabled {
		// The same sentence whether the device is unknown or invisible to this
		// operator: a valid key must not enumerate the fleet by trying usernames.
		log.Warn("device lookup failed", "error", err)
		_ = newChan.Reject(xssh.Prohibited,
			"oarlock: no such device, or you don't have access")
		return
	}
	if !dev.Supports(sessions.ProfileTCP) {
		log.Warn("forward refused: device does not offer tcp")
		_ = newChan.Reject(xssh.Prohibited,
			"oarlock: this device does not offer port forwarding")
		return
	}

	// Authorisation before anything is created or anybody is woken. `tcp` is its own
	// action: a grant to open a shell is not a grant to reach every listening socket on
	// the device, and several of those are bound to loopback precisely because they
	// have no authentication of their own.
	if verdict := s.o.Authz.AtOpen(ctx, p, dev, plugin.ActionTCP); !verdict.Allow() {
		c, _ := condition.Lookup(verdict.Code)
		text := c.Text()
		if verdict.Reason != "" {
			text = verdict.Reason
		}
		log.Warn("forward refused by authorization",
			"outcome", verdict.Outcome, "code", verdict.Code, "error", verdict.Err)
		s.audit(ctx, plugin.AuditEvent{
			Kind: plugin.AuditSessionRejected, DeviceID: dev.ID, Principal: p.ID,
			Surface: "ssh", Code: verdict.Code, Reason: verdict.Reason,
			Action: string(plugin.ActionTCP),
		})
		_ = newChan.Reject(xssh.Prohibited, "oarlock: "+text)
		return
	}

	sessionID := s.o.NewSessionID()

	// The row exists before the device is asked to dial, so a forward that never opens
	// is still something you can query for afterwards.
	//
	// RecordInput is not resolved: `tcp` is never recorded (ARCHITECTURE § 9.4), so a
	// keystroke-recording policy has nothing to attach to, and running the resolver
	// anyway could refuse a forward over a conflict that could not have applied to it.
	row := &sessions.Session{
		ID: sessionID, DeviceID: dev.ID, Profile: sessions.ProfileTCP,
		Mode: string(dev.ResolvedMode()), Principal: p.ID,
		State: sessions.StateWaking, RecordingState: sessions.NotRecorded,
	}
	if err := s.o.Sessions.Create(ctx, row); err != nil {
		if errors.Is(err, sessions.ErrLimit) {
			log.Warn("forward refused by a concurrency limit", "error", err)
			_ = newChan.Reject(xssh.ResourceShortage,
				"oarlock: too many forwarded connections are open on this device")
		} else {
			log.Error("could not create a session row", "error", err)
			_ = newChan.Reject(xssh.ConnectionFailed, "oarlock: could not open a session")
		}
		return
	}

	pending, err := s.o.Inviter.Invite(ctx, dev, invite.Request{
		SessionID: sessionID,
		Profile:   sessions.ProfileTCP,
		Principal: p.ID,
		TCP:       &frame.TCPTarget{Port: int(d.DestPort)},
	})
	if err != nil {
		var f *invite.Failure
		if errors.As(err, &f) {
			log.Warn("could not invite the device", "code", f.Code, "error", err)
			_ = newChan.Reject(xssh.ConnectionFailed, "oarlock: "+operatorText(f))
		} else {
			log.Error("invite failed", "error", err)
			_ = newChan.Reject(xssh.ConnectionFailed, "oarlock: could not open a session")
		}
		s.reject(ctx, sessionID, closeReason(err, "device_offline"))
		return
	}

	att, err := pending.Wait(ctx)
	if err != nil {
		s.o.Inviter.Cancel(ctx, sessionID, "operator_gave_up")
		var f *invite.Failure
		if errors.As(err, &f) {
			log.Warn("device did not attach", "code", f.Code)
			_ = newChan.Reject(xssh.ConnectionFailed, "oarlock: "+operatorText(f))
		} else {
			_ = newChan.Reject(xssh.ConnectionFailed, "oarlock: session setup failed")
		}
		s.reject(ctx, sessionID, closeReason(err, "device_offline"))
		return
	}
	defer att.Done()

	// Accepted only now. Everything above can still be reported as a channel-open
	// failure, which the operator's ssh prints with our sentence attached; after the
	// accept the only way to say anything is to close the connection silently.
	ch, reqs, err := newChan.Accept()
	if err != nil {
		s.o.Inviter.Cancel(ctx, sessionID, "operator_gave_up")
		s.reject(ctx, sessionID, "transport_error")
		return
	}
	go xssh.DiscardRequests(reqs)

	_ = s.o.Sessions.Update(ctx, sessionID, func(row *sessions.Session) error {
		row.State = sessions.StateAttached
		row.AttachedAt = time.Now()
		return nil
	})

	log.Info("forward open", "session", sessionID, "origin",
		net.JoinHostPort(d.OriginAddr, strconv.FormatUint(uint64(d.OriginPort), 10)))

	runner := &sessionrun.Runner{
		Sessions: s.o.Sessions, Live: s.o.Live, Recorder: s.o.Recorder,
		Limits: s.o.Limits, Deadlines: s.o.Deadlines, Log: s.log,
		Authz: s.o.AuthzSupervisor,
	}
	opConn := newForwardConn(ch, ctx.RemoteAddr().String(), s.log.With("session", sessionID))
	defer opConn.Close(transport.CloseNormal, "forward over")

	params := sessionrun.Params{
		SessionID: sessionID, DeviceID: dev.ID, Profile: sessions.ProfileTCP,
		Principal: p.ID, Action: plugin.ActionTCP,
		Surface: "ssh", Grantee: p,
		Device: att.Conn,
		// No PTY, no reattach: a forwarded connection has no terminal and no second
		// chance. If the operator's TCP connection goes, the thing on the other end
		// has already lost its peer, so waiting for a replacement would hold the
		// device open for a conversation that cannot be resumed.
		Operator: opConn,
	}

	// Prepare skips the recorder for `tcp` and marks the row attached. It is still
	// called, because it is also what emits the session-opened audit event: a forward
	// nobody can find in the audit trail is worse than no forward.
	rw, _, startedAt, err := runner.Prepare(ctx, params)
	if err != nil {
		log.Error("could not prepare the forward", "session", sessionID, "error", err)
		runner.Reject(ctx, sessionID, "internal")
		_ = ch.Close()
		return
	}

	out := runner.Run(ctx, params, rw, startedAt)
	log.Info("forward closed", "session", sessionID, "reason", out.Result.Reason,
		"bytes_in", out.Result.Stats.BytesIn, "bytes_out", out.Result.Stats.BytesOut)
	_ = ch.Close()
}

// forwardConn adapts an SSH direct-tcpip channel to transport.Conn.
//
// Simpler than sshConn: a forwarded channel has no window changes, no signals and no
// stderr worth writing to, and its EOF means something different — see readChannel.
type forwardConn struct {
	ch     xssh.Channel
	remote string
	log    logger

	frames  chan []byte
	closeCh chan struct{}
	once    sync.Once

	wmu sync.Mutex
}

// logger is the slice of *slog.Logger this file uses, so a test can drop in a quiet one.
type logger interface {
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

var _ transport.Conn = (*forwardConn)(nil)

func newForwardConn(ch xssh.Channel, remote string, log logger) *forwardConn {
	c := &forwardConn{
		ch: ch, remote: remote, log: log,
		frames:  make(chan []byte, 8),
		closeCh: make(chan struct{}),
	}
	go c.readChannel()
	return c
}

// readChannel turns the operator's bytes into DATA frames.
func (c *forwardConn) readChannel() {
	// 32 KiB sits an order of magnitude under frame.MaxFrame, so a full read is always
	// one frame.
	buf := make([]byte, 32<<10)
	for {
		n, err := c.ch.Read(buf)
		if n > 0 {
			if !c.offer(frame.Data(buf[:n])) {
				return
			}
		}
		if err != nil {
			// EOF ends the forward, and this is where it differs from a shell.
			//
			// On a session channel, EOF on stdin means "no more input" and the session
			// keeps running — `ssh host < script` depends on it. On a forwarded
			// connection it means the operator's local socket closed. Oarlock's frame
			// vocabulary has no half-close, so there is no way to pass "I am done
			// sending" through and keep the other direction alive: the choice is to end
			// the forward or to hold a device slot open for a connection nobody is on.
			c.offerClose("operator_close")
			return
		}
	}
}

func (c *forwardConn) offer(f frame.Frame) bool {
	wire, err := frame.Codec{}.Encode(nil, f)
	if err != nil {
		return false
	}
	select {
	case c.frames <- wire:
		return true
	case <-c.closeCh:
		return false
	}
}

func (c *forwardConn) offerClose(reason string) {
	if f, err := frame.Marshal(frame.TypeClose, frame.Close{Reason: reason}); err == nil {
		c.offer(f)
	}
}

// Recv hands the next operator-side frame to the pump.
func (c *forwardConn) Recv(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closeCh:
		return nil, transport.ErrClosed
	case b := <-c.frames:
		return b, nil
	}
}

// Send writes the device's bytes to the operator's channel.
func (c *forwardConn) Send(_ context.Context, b []byte) error {
	f, err := frame.Codec{}.Decode(b)
	if err != nil {
		return err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()

	switch f.Type {
	case frame.TypeData:
		_, err := c.ch.Write(f.Payload)
		return err
	case frame.TypeError:
		// There is nowhere on a forwarded channel to render this — a byte written here
		// is a byte in the operator's TCP stream, and injecting a sentence into somebody's
		// HTTP response or Postgres wire protocol corrupts it. So it goes to the log and
		// the connection closes, which is what the peer will interpret correctly.
		var e frame.Error
		_ = frame.Unmarshal(f, &e)
		c.log.Warn("forward failed", "code", e.Code, "message", e.Message)
		return transport.ErrClosed
	case frame.TypeThrottle:
		// `tcp` is a backpressure profile: dropping bytes out of a forwarded stream is
		// corruption, not degradation. A THROTTLE arriving here means the policy engine
		// disagrees with pump.PolicyFor, which is a bug and not a condition to render.
		c.log.Error("THROTTLE reached a forwarded connection — " +
			"tcp must backpressure, never drop")
		return nil
	case frame.TypeDataErr:
		// No stderr on a byte pipe. A device sending one on `tcp` is a device bug.
		c.log.Warn("DATA_ERR on a forwarded connection; dropped")
		return nil
	case frame.TypeExit, frame.TypeReady, frame.TypePing, frame.TypePong:
		return nil
	default:
		return fmt.Errorf("sshsrv: cannot render %s to a forwarded connection", f.Type)
	}
}

func (c *forwardConn) Close(transport.CloseCode, string) error {
	c.once.Do(func() {
		close(c.closeCh)
		_ = c.ch.Close()
	})
	return nil
}

func (c *forwardConn) RemoteAddr() string { return c.remote }
