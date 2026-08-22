// Package attachsrv is /ws/attach: where a browser operator arrives.
//
// It is the mirror of sessionsrv — that endpoint takes the device's connection, this
// one takes the operator's — and between them they replace what the SSH front door
// does in a single goroutine. The asymmetry is worth naming: over SSH one request
// owns both waits, and here the two ends arrive on two different requests, possibly
// seconds apart, so the device parks its connection and this handler collects it.
package attachsrv

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/oarlock/oarlock/internal/invite"
	"github.com/oarlock/oarlock/internal/pump"
	"github.com/oarlock/oarlock/internal/ring"
	"github.com/oarlock/oarlock/internal/sessionrun"
	"github.com/oarlock/oarlock/internal/sessions"
	"github.com/oarlock/oarlock/internal/ticket"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/transport"
)

// OpenBudget is how long the browser has to send its OPEN frame. Short, because until
// it arrives this is an unauthenticated socket.
const OpenBudget = 5 * time.Second

// Collector is the part of the Inviter this package needs.
type Collector interface {
	Redeem(ctx context.Context, token string, want ticket.Want) (*ticket.Claims, error)
	Collect(ctx context.Context, sessionID string) (*invite.Attachment, error)
}

// Server handles inbound operator connections.
type Server struct {
	Upgrader transport.Upgrader
	Inviter  Collector
	Runner   *sessionrun.Runner
	// Live is the node's live-session registry, which is how a *reattaching* operator
	// finds the pump that is already running their session. Without it every attach is
	// treated as a first attach, and a reconnecting browser waits for a device that has
	// been paired for ten minutes.
	Live *sessions.Registry
	Log  *slog.Logger
}

var _ http.Handler = (*Server)(nil)

func (s *Server) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// ServeHTTP upgrades, redeems the attach ticket, collects the device, and runs the
// session for the life of the request.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := s.Upgrader.Upgrade(w, r, transport.Options{MaxMessageBytes: frame.MaxFrame})
	if err != nil {
		s.log().Warn("attach upgrade failed", "remote", r.RemoteAddr, "error", err)
		return
	}
	defer conn.Close(transport.CloseNormal, "attach over")

	ctx := r.Context()
	open, err := readOpen(ctx, conn)
	if err != nil {
		s.refuse(ctx, conn, "protocol_error", err)
		return
	}

	// Either kind: the two legs arrive on the same endpoint and the ticket says which
	// one this is. A device ticket is still refused — Want checks that below.
	claims, err := s.Inviter.Redeem(ctx, open.Ticket, ticket.Want{})
	if err == nil && claims.Kind != ticket.KindAttach && claims.Kind != ticket.KindObserve {
		// A device's ticket presented on the operator endpoint. Coarse on the wire,
		// like every other ticket refusal.
		s.log().Warn("attach refused: wrong ticket kind",
			"kind", claims.Kind, "remote", conn.RemoteAddr())
		s.refuse(ctx, conn, "ticket_invalid", errors.New("ticket refused"))
		return
	}
	if err != nil {
		// Coarse on the wire: a browser presenting a spent, expired or wrong-kind
		// ticket learns only that it was refused. Telling it which would let a
		// caller probe for live sessions.
		s.log().Warn("attach refused", "remote", conn.RemoteAddr(), "reason", err)
		s.refuse(ctx, conn, "ticket_invalid", errors.New("ticket refused"))
		return
	}
	log := s.log().With("session", claims.SessionID, "device", claims.DeviceID,
		"principal", claims.Principal)

	// A live session on this node means this is a reattach or an observation, not a
	// first attach: the device is already paired and pumping, and what the arriving
	// connection needs is the scrollback plus the live stream, not a device connection
	// of its own.
	if s.Live != nil {
		if h, err := s.Live.Get(claims.SessionID); err == nil {
			if claims.Kind == ticket.KindObserve {
				s.observe(ctx, conn, h, claims, log)
			} else {
				s.reattach(ctx, conn, h, open, log)
			}
			return
		} else if !errors.Is(err, sessions.ErrNotLive) {
			log.Warn("could not check the live registry", "error", err)
		}
	}
	if claims.Kind == ticket.KindObserve {
		// A watch ticket for a session that is not running here. There is nothing to
		// observe, and pairing a device for a watcher would be opening a session on
		// somebody else's behalf.
		s.refuse(ctx, conn, "session_closed", errors.New("that session is not running here"))
		return
	}

	att, err := s.Inviter.Collect(ctx, claims.SessionID)
	if err != nil {
		// The device has not arrived yet, gave up, or somebody else is already
		// attached. These are different facts and the operator-facing text differs;
		// the wire code comes from the failure itself.
		var f *invite.Failure
		code, detail := "device_offline", "the device has not attached"
		if errors.As(err, &f) {
			code, detail = f.Code, f.Operator
		}
		log.Warn("nothing to attach to", "code", code, "error", err)
		s.refuse(ctx, conn, code, errors.New(detail))
		return
	}
	defer att.Done()

	params := sessionrun.Params{
		SessionID:   claims.SessionID,
		DeviceID:    claims.DeviceID,
		Profile:     claims.Profile,
		Principal:   claims.Principal,
		OpenedBy:    claims.OpenedBy,
		Unattended:  claims.Unattended,
		RecordInput: claims.RecordInput,
		Surface:     "browser",
		Device:      att.Conn,
		Operator:    conn,
		PTY:         open.PTY,
		// A browser can come back. Operators lose wifi constantly, and a shell that
		// dies with it is a shell nobody trusts with a long command.
		Reattachable: true,
	}

	rw, recording, startedAt, err := s.Runner.Prepare(ctx, params)
	if err != nil {
		// A recorder that cannot start fails the session: one that looks recorded and
		// is not is worse than one that never opened.
		log.Error("could not start recording", "error", err)
		s.Runner.Reject(ctx, claims.SessionID, "recorder_failed")
		s.refuse(ctx, conn, "recorder_failed",
			errors.New("could not start recording; refusing the session"))
		return
	}

	// READY carries the disclosure the browser has no banner channel for. `recording`
	// and `mode` are how the status bar tells the truth, and a client that renders a
	// terminal without reading them is the risk the component is designed to refuse.
	if err := send(ctx, conn, frame.TypeReady, frame.Ready{
		SessionID:     claims.SessionID,
		Recording:     recording,
		Mode:          "gateway",
		ScrollbackLen: 0, // a first attach has nothing to replay
		Limits: &frame.Limits{
			Frame: frame.MaxFrame, Batch: frame.MaxBatch, PingInterval: 30,
		},
	}); err != nil {
		log.Warn("could not send READY", "error", err)
		return
	}
	log.Info("operator attached", "recording", recording)

	out := s.Runner.Run(ctx, params, rw, startedAt)

	// Said again as the session ends, at a point no prefix-truncation attack can
	// reach — the same reasoning as the SSH closing disclosure, and the same reason
	// it carries the session id.
	_ = send(ctx, conn, frame.TypeClose, frame.Close{Reason: out.Result.Reason})
}

// observe attaches a read-only watcher to a live session (FR13).
//
// The watcher's connection is *read* here, and everything on it is discarded. The pump
// never reads it, so read-only is structural rather than enforced — there is no code path
// from a watcher's socket to the device. This loop exists for two other reasons: to
// notice promptly when a watcher leaves, so the operator's indicator clears rather than
// waiting for the session's next output byte, and so that a keystroke from a watcher is
// *counted* rather than vanishing. The component disables input, so a counted keystroke
// means either an old client or somebody probing, and both are worth being able to see.
func (s *Server) observe(ctx context.Context, conn transport.Conn, h *sessions.Handle,
	claims *ticket.Claims, log *slog.Logger) {
	recording := s.Runner != nil && s.Runner.Recorder != nil

	greet := func(list []frame.Observer) (frame.Frame, error) {
		return frame.Marshal(frame.TypeReady, frame.Ready{
			SessionID: h.ID,
			Recording: recording,
			Mode:      "gateway",
			// The two fields that make a watcher's client visibly different: input
			// disabled, and whose session this is.
			ReadOnly:  true,
			Watching:  h.Principal,
			Observers: list,
			Limits: &frame.Limits{
				Frame: frame.MaxFrame, Batch: frame.MaxBatch, PingInterval: 30,
			},
		})
	}

	watcher, err := h.Observe(ctx, claims.Principal, conn, greet)
	if err != nil {
		switch {
		case errors.Is(err, sessions.ErrNoObserve):
			s.refuse(ctx, conn, "protocol_error",
				errors.New("that session cannot be observed"))
		case errors.Is(err, pump.ErrTooManyObservers):
			s.refuse(ctx, conn, "session_limit",
				errors.New("that session already has as many watchers as it allows"))
		case errors.Is(err, sessions.ErrNotLive):
			s.refuse(ctx, conn, "session_closed", errors.New("that session has ended"))
		default:
			log.Warn("could not observe", "error", err)
			s.refuse(ctx, conn, "internal", errors.New("could not observe"))
		}
		return
	}
	log.Info("session is being watched", "observer", claims.Principal,
		"watching", h.Principal)
	defer watcher.Leave()

	// Drain and discard. Nothing here forwards.
	var dropped int
	for {
		select {
		case <-watcher.Gone():
			log.Info("watcher left", "observer", claims.Principal, "dropped_input", dropped)
			return
		case <-h.Done():
			return
		case <-ctx.Done():
			return
		default:
		}

		msg, rerr := conn.Recv(ctx)
		if rerr != nil {
			log.Info("watcher disconnected", "observer", claims.Principal,
				"dropped_input", dropped)
			return
		}
		f, derr := frame.Codec{}.Decode(msg)
		if derr != nil {
			continue
		}
		switch f.Type {
		case frame.TypeClose:
			log.Info("watcher closed", "observer", claims.Principal, "dropped_input", dropped)
			return
		case frame.TypeData, frame.TypeResize, frame.TypeSignal:
			// Counted, never forwarded. The component disables input, so anything here
			// is an old client or somebody trying.
			dropped++
			log.Warn("discarded input from a read-only watcher",
				"observer", claims.Principal, "type", f.Type)
		}
	}
}

// reattach hands this connection to the pump already running the session.
//
// The greeting is built by the pump, under its write lock, from the very snapshot it is
// about to replay — which is what makes READY's scrollback_len exact and stops a DATA
// frame produced a microsecond later from overtaking the scrollback and assembling the
// screen in the wrong order.
func (s *Server) reattach(ctx context.Context, conn transport.Conn, h *sessions.Handle,
	open frame.Open, log *slog.Logger) {
	recording := s.Runner != nil && s.Runner.Recorder != nil

	greet := func(snap ring.Snapshot) (frame.Frame, error) {
		return frame.Marshal(frame.TypeReady, frame.Ready{
			SessionID: h.ID,
			// What the operator is about to be sent, exactly. A reattaching browser
			// uses it to say "replaying 12 KiB" rather than looking frozen.
			ScrollbackLen: len(snap.Replay),
			Recording:     recording,
			Mode:          "gateway",
			Limits: &frame.Limits{
				Frame: frame.MaxFrame, Batch: frame.MaxBatch, PingInterval: 30,
			},
		})
	}

	// The handler has to outlive the attach: the pump writes to this connection until
	// the session ends or the operator drops again, and returning here would close the
	// socket underneath it.
	if err := h.Reattach(ctx, conn, greet); err != nil {
		switch {
		case errors.Is(err, sessions.ErrNoReattach):
			// An SSH session. There is nothing to reattach to, and saying so beats a
			// browser waiting for a device that is already busy.
			log.Warn("a browser tried to reattach to a session that cannot take one")
			s.refuse(ctx, conn, "protocol_error",
				errors.New("that session cannot be reattached to"))
		case errors.Is(err, pump.ErrOperatorPresent):
			// Somebody is already there. Two operators writing into one shell would
			// interleave their keystrokes; watching one is a different feature (FR13).
			s.refuse(ctx, conn, "session_limit",
				errors.New("that session already has an operator"))
		case errors.Is(err, sessions.ErrNotLive):
			s.refuse(ctx, conn, "device_offline", errors.New("that session has ended"))
		default:
			log.Warn("reattach failed", "error", err)
			s.refuse(ctx, conn, "internal", errors.New("could not reattach"))
		}
		return
	}
	log.Info("operator reattached")

	// Block until the session ends. The pump owns the connection now; this handler
	// exists only to keep it — and therefore the socket — alive. Waiting on the
	// request context alone would hold a goroutine and a socket after the session was
	// over, until the browser happened to give up.
	select {
	case <-h.Done():
	case <-ctx.Done():
	}
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
		return frame.Open{}, errors.New("attachsrv: first frame must be OPEN")
	}
	var open frame.Open
	if err := frame.Unmarshal(f, &open); err != nil {
		return frame.Open{}, err
	}
	if open.Ticket == "" {
		return frame.Open{}, errors.New("attachsrv: OPEN carries no ticket")
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
