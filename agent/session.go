package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/transport"
)

// ResizeInterval is how often a window change is actually applied.
//
// Dragging a browser window edge generates hundreds of events and the PTY only
// needs the last one. Applying every one means hundreds of ioctls and hundreds of
// SIGWINCHs delivered to whatever is running.
const ResizeInterval = 100 * time.Millisecond

// ReadBuffer is how much the agent reads from the PTY at once.
//
// Sized to the gateway's batch ceiling: reading more would only produce a frame the
// gateway has to split. Coalescing proper happens at the gateway, which is the side
// that knows how fast the operator is consuming.
const ReadBuffer = 64 << 10

// HandleInvitation dials a session connection and serves it.
//
// Use it as Config.OnInvitation to get the default behaviour. It is the same
// function for both reachability modes, because after ADR-024 an invitation from a
// DIAL frame and one from a doorbell are the same payload.
func (c *Control) HandleInvitation(ctx context.Context, inv frame.Invitation) {
	if err := c.Serve(ctx, inv); err != nil {
		c.log.Warn("session ended with an error",
			"session", inv.SessionID, "profile", inv.Profile, "error", err)
	}
}

// Serve dials the invitation's URL, presents the ticket, and runs the profile.
func (c *Control) Serve(ctx context.Context, inv frame.Invitation) error {
	if inv.URL == "" || inv.Ticket == "" {
		return errors.New("agent: invitation is missing a URL or ticket")
	}
	log := c.log.With("session", inv.SessionID, "profile", inv.Profile)

	conn, err := c.cfg.Dialer.Dial(ctx, inv.URL, transport.Options{
		PinSHA256:       c.cfg.PinSHA256,
		MaxMessageBytes: frame.MaxFrame,
	})
	if err != nil {
		return fmt.Errorf("agent: dialing the session: %w", err)
	}
	defer conn.Close(transport.CloseNormal, "session over")

	s := &session{
		conn:    conn,
		codec:   frame.Codec{},
		log:     log,
		timeout: c.cfg.WriteTimeout,
	}

	// The ticket rides in the OPEN frame body, never in the URL: a query string
	// ends up in ingress logs, load-balancer logs and browser history, and a
	// single-use ticket sitting in a log file is still a ticket until it is spent.
	if err := s.send(ctx, frame.TypeOpen, frame.Open{
		Ticket:   inv.Ticket,
		DeviceID: c.cfg.DeviceID,
		Profile:  inv.Profile,
		PTY:      inv.PTY,
		Agent:    c.cfg.Info,
	}); err != nil {
		return err
	}

	var ready frame.Ready
	if err := s.recvInto(ctx, frame.TypeReady, &ready); err != nil {
		return err
	}
	log.Info("session open", "recording", ready.Recording, "mode", ready.Mode)

	switch inv.Profile {
	case "shell":
		return s.runShell(ctx, c.cfg.Shell, inv)
	case "exec":
		return s.runExec(ctx, c.cfg.Exec, inv)
	case "file":
		return s.runFile(ctx, c.cfg.File, inv)
	case "tcp":
		return s.runTCP(ctx, c.cfg.Dial, inv)
	default:
		// log and sshpass land later in E5. Refusing clearly beats
		// pretending: the gateway already knows what this build advertised.
		err := fmt.Errorf("profile %q is not implemented by this build", inv.Profile)
		_ = s.send(ctx, frame.TypeError, frame.Error{
			Code: "profile_unsupported", Message: err.Error()})
		return err
	}
}

type session struct {
	conn    transport.Conn
	codec   frame.Codec
	log     *slog.Logger
	timeout time.Duration

	mu  sync.Mutex
	buf []byte
}

// runShell wires a PTY to the session connection.
func (s *session) runShell(ctx context.Context, shell ShellFunc, inv frame.Invitation) error {
	if shell == nil {
		err := errors.New("agent: no Shell configured, but a shell was requested")
		_ = s.send(ctx, frame.TypeError, frame.Error{
			Code: "profile_unsupported", Message: err.Error()})
		return err
	}
	req := ShellRequest{SessionID: inv.SessionID, Principal: inv.Principal,
		Profile: inv.Profile}
	if inv.PTY != nil {
		req.Term, req.Cols, req.Rows = inv.PTY.Term, inv.PTY.Cols, inv.PTY.Rows
	}

	p, err := shell(ctx, req)
	if err != nil {
		_ = s.send(ctx, frame.TypeError, frame.Error{
			Code: "internal", Message: "could not start a shell"})
		return fmt.Errorf("agent: starting the shell: %w", err)
	}
	defer p.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	rs := newResizer(p, ResizeInterval)
	defer rs.stop()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		s.ptyToGateway(ctx, p)
	}()

	err = s.gatewayToPTY(ctx, p, rs)
	cancel()
	wg.Wait()
	return err
}

// ptyToGateway forwards output. It sends what it reads: the gateway coalesces,
// because the gateway is the side that knows how fast the operator is consuming.
func (s *session) ptyToGateway(ctx context.Context, p PTY) {
	buf := make([]byte, ReadBuffer)
	for {
		n, err := p.Read(buf)
		if n > 0 {
			if serr := s.sendFrame(ctx, frame.Data(buf[:n])); serr != nil {
				return
			}
		}
		if err != nil {
			// The PTY closing is how a shell exits: the read fails with EIO once the
			// child is gone, which is normal and not worth logging as an error.
			code, werr := p.Wait()
			if werr != nil {
				s.log.Warn("waiting for the shell", "error", werr)
			}
			_ = s.send(ctx, frame.TypeExit, frame.Exit{Code: code})
			_ = s.send(ctx, frame.TypeClose, frame.Close{Reason: "device_close"})
			return
		}
	}
}

// gatewayToPTY applies input, resizes and signals.
func (s *session) gatewayToPTY(ctx context.Context, p PTY, rs *resizer) error {
	for {
		msg, err := s.conn.Recv(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		f, err := s.codec.Decode(msg)
		if err != nil {
			return s.protocolError(ctx, err)
		}
		if err := frame.Expect(frame.ScopeSession, f); err != nil {
			return s.protocolError(ctx, err)
		}
		if f.Type.Disposition() == frame.Ignore {
			continue
		}

		switch f.Type {
		case frame.TypeData:
			if _, err := p.Write(f.Payload); err != nil {
				return fmt.Errorf("agent: writing to the pty: %w", err)
			}
		case frame.TypeResize:
			var r frame.Resize
			if err := frame.Unmarshal(f, &r); err != nil {
				return s.protocolError(ctx, err)
			}
			rs.want(r.Cols, r.Rows)
		case frame.TypeSignal:
			var sig frame.Signal
			if err := frame.Unmarshal(f, &sig); err != nil {
				return s.protocolError(ctx, err)
			}
			if err := p.Signal(sig.Signal); err != nil {
				s.log.Warn("could not deliver a signal", "signal", sig.Signal, "error", err)
			}
		case frame.TypeClose:
			var cl frame.Close
			_ = frame.Unmarshal(f, &cl)
			s.log.Info("gateway closed the session", "reason", cl.Reason)
			return nil
		case frame.TypeError:
			var e frame.Error
			_ = frame.Unmarshal(f, &e)
			return fmt.Errorf("agent: gateway error %s: %s", e.Code, e.Message)
		case frame.TypePing:
			stamp, err := frame.ReadStamp(f)
			if err != nil {
				return s.protocolError(ctx, err)
			}
			pong, _ := frame.Stamp(frame.TypePong, stamp)
			if err := s.sendFrame(ctx, pong); err != nil {
				return err
			}
		case frame.TypePong:
		default:
			// READY twice, OPEN, EXIT, DATA_ERR, THROTTLE from the gateway.
			return s.protocolError(ctx,
				fmt.Errorf("%s is not valid from a gateway mid-session", f.Type))
		}
	}
}

// resizer applies at most one window change per interval, keeping the latest.
type resizer struct {
	p        PTY
	interval time.Duration

	mu      sync.Mutex
	pending bool
	cols    int
	rows    int
	timer   *time.Timer
	stopped bool
}

func newResizer(p PTY, interval time.Duration) *resizer {
	return &resizer{p: p, interval: interval}
}

func (r *resizer) want(cols, rows int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return
	}
	r.cols, r.rows = cols, rows
	if r.pending {
		return // a flush is already scheduled; it will pick up the latest values
	}
	// Apply the first one immediately — a resize that waits 100 ms on a fresh
	// terminal is a visible flash of the wrong geometry — then coalesce the rest.
	r.applyLocked()
	r.pending = true
	r.timer = time.AfterFunc(r.interval, r.flush)
}

func (r *resizer) flush() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pending = false
	if r.stopped {
		return
	}
	r.applyLocked()
}

func (r *resizer) applyLocked() {
	if r.cols <= 0 || r.rows <= 0 {
		return
	}
	_ = r.p.Resize(r.cols, r.rows)
}

func (r *resizer) stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopped = true
	if r.timer != nil {
		r.timer.Stop()
	}
}

// ── plumbing ────────────────────────────────────────────────────────────────────

func (s *session) send(ctx context.Context, t frame.Type, v any) error {
	f, err := frame.Marshal(t, v)
	if err != nil {
		return err
	}
	return s.sendFrame(ctx, f)
}

func (s *session) sendFrame(ctx context.Context, f frame.Frame) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	wire, err := s.codec.Encode(s.buf[:0], f)
	if err != nil {
		return err
	}
	s.buf = wire
	timeout := s.timeout
	if timeout <= 0 {
		timeout = DefaultWriteTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := s.conn.Send(ctx, wire); err != nil {
		return fmt.Errorf("agent: sending %s: %w", f.Type, err)
	}
	return nil
}

func (s *session) recvInto(ctx context.Context, want frame.Type, v any) error {
	msg, err := s.conn.Recv(ctx)
	if err != nil {
		return fmt.Errorf("agent: waiting for %s: %w", want, err)
	}
	f, err := s.codec.Decode(msg)
	if err != nil {
		return err
	}
	if err := frame.Expect(frame.ScopeSession, f); err != nil {
		return err
	}
	if f.Type == frame.TypeError && want != frame.TypeError {
		var e frame.Error
		if uerr := frame.Unmarshal(f, &e); uerr == nil {
			return fmt.Errorf("agent: gateway refused the session: %s: %s", e.Code, e.Message)
		}
	}
	if f.Type != want {
		return fmt.Errorf("agent: got %s, want %s", f.Type, want)
	}
	return frame.Unmarshal(f, v)
}

func (s *session) protocolError(ctx context.Context, cause error) error {
	_ = s.send(ctx, frame.TypeError, frame.Error{
		Code: frame.ErrorCode(cause), Message: cause.Error()})
	_ = s.conn.Close(transport.CloseProtocolError, "protocol error")
	return fmt.Errorf("agent: %w", cause)
}
