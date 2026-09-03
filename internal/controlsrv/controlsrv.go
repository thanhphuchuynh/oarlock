// Package controlsrv is the /ws/control endpoint: where a persistent-mode agent
// holds a channel open.
//
// It is three lines of orchestration — upgrade, handshake, serve — and it is a
// separate package so that the handshake's rules and the hub's rules stay
// independently testable.
package controlsrv

import (
	"log/slog"
	"net/http"

	"github.com/oarlock/oarlock/internal/handshake"
	"github.com/oarlock/oarlock/internal/hub"
	"github.com/oarlock/oarlock/internal/ownership"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/transport"
)

// Server accepts control channels.
type Server struct {
	Upgrader  transport.Upgrader
	Handshake *handshake.Gateway
	Hub       *hub.Hub
	Log       *slog.Logger

	// Owners records which node is holding this channel, for a deployment with more
	// than one replica. Nil is a single-node gateway and costs a nil check.
	Owners *ownership.Keeper
}

var _ http.Handler = (*Server)(nil)

func (s *Server) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// ServeHTTP upgrades, authenticates the device, and serves the channel until it
// ends.
//
// The handler stays for the life of the channel, which is the point: a control
// channel is long-lived by definition, and returning would close the socket the
// gateway needs in order to reach the device later.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := s.Upgrader.Upgrade(w, r, transport.Options{MaxMessageBytes: frame.MaxFrame})
	if err != nil {
		s.log().Warn("control upgrade failed", "remote", r.RemoteAddr, "error", err)
		return
	}

	ctx := r.Context()
	res, err := s.Handshake.Accept(ctx, conn)
	if err != nil {
		// The handshake has already told the peer what it is going to tell it —
		// deliberately just auth_failed, so an unauthenticated caller cannot probe
		// for which devices exist.
		s.log().Warn("control handshake failed", "remote", r.RemoteAddr, "error", err)
		_ = conn.Close(transport.ClosePolicyViolation, "handshake failed")
		return
	}

	s.log().Info("control channel up",
		"device", res.Device.ID, "mode", res.Device.ResolvedMode(),
		"caps", res.Caps, "agent", res.Agent.Version)

	// Bracket the channel's whole lifetime, which is exactly Serve's: this handler
	// stays for as long as the device is reachable through this node, so it is the one
	// place where "held here" begins and ends.
	//
	// A claim that fails is logged and not fatal. The device is dialled in and
	// reachable through this node whatever the registry believes, and refusing the
	// channel would turn a registry outage into a fleet outage.
	release, err := s.Owners.Hold(ctx, res.Device.ID)
	if err != nil {
		s.log().Error("could not record which node holds this device",
			"device", res.Device.ID, "error", err)
	}
	defer release()

	if err := s.Hub.Serve(ctx, conn, res); err != nil {
		s.log().Info("control channel ended", "device", res.Device.ID, "error", err)
	}
	_ = conn.Close(transport.CloseNormal, "channel over")
}
