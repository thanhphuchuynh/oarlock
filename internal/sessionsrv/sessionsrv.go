// Package sessionsrv is the /ws/session endpoint: where an agent dials in and
// presents its ticket.
//
// It is the same endpoint in both reachability modes (ADR-024). Nothing here knows
// or cares whether the invitation arrived as a DIAL frame down a held control
// channel or through a doorbell, which is the entire return on not multiplexing.
package sessionsrv

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/oarlock/oarlock/internal/invite"
	"github.com/oarlock/oarlock/internal/ticket"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/transport"
)

// OpenBudget is how long an agent has to send its OPEN frame.
//
// Short on purpose: until OPEN arrives this is an unauthenticated socket, and the
// only thing holding it is somebody's claim that they are about to identify
// themselves.
const OpenBudget = 5 * time.Second

// Attacher is the part of the Inviter this package needs.
type Attacher interface {
	Attach(ctx context.Context, token string, want ticket.Want,
		conn transport.Conn) (*invite.Attachment, error)
}

// Server handles inbound session connections.
type Server struct {
	Upgrader transport.Upgrader
	Inviter  Attacher
	Log      *slog.Logger

	// Ready is sent to the agent once it is paired. Leave nil for the default,
	// which reports the session id and nothing else; the operator's side fills in
	// scrollback and recording state.
	Ready func(claims *ticket.Claims) frame.Ready
}

var _ http.Handler = (*Server)(nil)

func (s *Server) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// ServeHTTP upgrades, reads OPEN, redeems the ticket, and holds the connection open
// for the life of the session.
//
// The handler must not return early: returning tears down the socket, and the
// operator's side is the one that knows when the session is over. So it waits on the
// attachment.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := s.Upgrader.Upgrade(w, r, transport.Options{MaxMessageBytes: frame.MaxFrame})
	if err != nil {
		s.log().Warn("session upgrade failed", "remote", r.RemoteAddr, "error", err)
		return
	}

	ctx := r.Context()
	open, err := readOpen(ctx, conn)
	if err != nil {
		s.refuse(ctx, conn, "protocol_error", err)
		return
	}

	att, err := s.Inviter.Attach(ctx, open.Ticket, ticket.Want{
		DeviceID: open.DeviceID,
		Profile:  open.Profile,
		Kind:     ticket.KindDevice,
	}, conn)
	if err != nil {
		// Deliberately coarse on the wire. An agent that presented a spent, expired,
		// wrong-scope or unwanted ticket learns only that it was refused; telling it
		// which would let an attacker probe for live sessions. The reason is logged.
		s.log().Warn("session attach refused",
			"device", open.DeviceID, "profile", open.Profile,
			"remote", conn.RemoteAddr(), "reason", err)
		s.refuse(ctx, conn, "ticket_invalid", errors.New("ticket refused"))
		return
	}

	ready := frame.Ready{SessionID: att.Claims.SessionID, Mode: "gateway", Recording: false}
	if s.Ready != nil {
		ready = s.Ready(att.Claims)
	}
	if err := send(ctx, conn, frame.TypeReady, ready); err != nil {
		s.log().Warn("could not send READY", "session", att.Claims.SessionID, "error", err)
		att.Done()
		return
	}

	s.log().Info("device attached",
		"device", att.Claims.DeviceID, "session", att.Claims.SessionID,
		"profile", att.Claims.Profile, "principal", att.Claims.Principal)

	// Hold the socket open until the pump says the session is over.
	if err := att.Wait(ctx); err != nil {
		att.Done() // the request was cancelled; release the operator's side too
	}
	_ = conn.Close(transport.CloseNormal, "session over")
}

func readOpen(ctx context.Context, conn transport.Conn) (frame.Open, error) {
	ctx, cancel := context.WithTimeout(ctx, OpenBudget)
	defer cancel()

	msg, err := conn.Recv(ctx)
	if err != nil {
		return frame.Open{}, err
	}
	f, err := frame.Codec{}.Decode(msg)
	if err != nil {
		return frame.Open{}, err
	}
	if err := frame.Expect(frame.ScopeSession, f); err != nil {
		return frame.Open{}, err
	}
	if f.Type != frame.TypeOpen {
		return frame.Open{}, errors.New("sessionsrv: first frame must be OPEN")
	}
	var open frame.Open
	if err := frame.Unmarshal(f, &open); err != nil {
		return frame.Open{}, err
	}
	if open.Ticket == "" {
		return frame.Open{}, errors.New("sessionsrv: OPEN carries no ticket")
	}
	return open, nil
}

func (s *Server) refuse(ctx context.Context, conn transport.Conn, code string, cause error) {
	_ = send(ctx, conn, frame.TypeError, frame.Error{Code: code, Message: cause.Error()})
	_ = conn.Close(transport.ClosePolicyViolation, code)
}

func send(ctx context.Context, conn transport.Conn, t frame.Type, v any) error {
	f, err := frame.Marshal(t, v)
	if err != nil {
		return err
	}
	wire, err := frame.Codec{}.Encode(nil, f)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return conn.Send(ctx, wire)
}
