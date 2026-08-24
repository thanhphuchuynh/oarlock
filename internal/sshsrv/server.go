// Package sshsrv is the SSH front door: where an operator with a terminal arrives.
//
// # The SSH user is the device, not the operator
//
// `ssh treadmill-4821@gw.example.org` names the *device*. The operator comes from
// their key or certificate. This is the one piece of SSH convention Oarlock breaks,
// and it earns it: an operator addresses a fleet of thousands with one set of
// credentials, so the addressable thing in the connection string has to be the
// device.
package sshsrv

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"time"

	gssh "github.com/gliderlabs/ssh"
	xssh "golang.org/x/crypto/ssh"

	"github.com/oarlock/oarlock/internal/authz"
	"github.com/oarlock/oarlock/internal/invite"
	"github.com/oarlock/oarlock/internal/pump"
	"github.com/oarlock/oarlock/internal/recordpolicy"
	"github.com/oarlock/oarlock/internal/sessionrun"
	"github.com/oarlock/oarlock/internal/sessions"
	"github.com/oarlock/oarlock/pkg/condition"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
	"github.com/oarlock/oarlock/pkg/transport"
)

// principalKey is where the authenticated operator is stashed between
// PublicKeyHandler and the session handler. gliderlabs' auth callback returns a
// bool, so the principal has to travel through the connection context.
type principalKey struct{}

// ptyKey carries the PTY request captured on the request loop's goroutine.
type ptyKey struct{}

type capturedPty struct {
	req gssh.Pty
	win <-chan gssh.Window
	ok  bool
}

// Inviter is the part of internal/invite this package needs.
type Inviter interface {
	Invite(ctx context.Context, dev *plugin.Device, req invite.Request) (*invite.Pending, error)
	Cancel(ctx context.Context, sessionID, reason string)
}

// Options configure the front door.
type Options struct {
	Addr          string
	Authenticator plugin.Authenticator
	// Authz decides whether this operator may open this session. Nil allows
	// everything, which is what a deployment with no authorizer gets — authentication
	// still applies, and internal/safety refuses to boot production without one.
	Authz *authz.Checker
	// AuthzSupervisor re-checks live sessions and closes the ones that lose their
	// grant. Nil checks at open and never again — which means an operator whose access
	// is withdrawn keeps their shell until they close it.
	AuthzSupervisor *authz.Supervisor
	Registry        plugin.DeviceRegistry
	Inviter         Inviter
	Sessions        sessions.Store
	// Live registers running sessions so they can be ended from outside: the API's
	// admin kill (FR19), authorisation withdrawal (E4.S5), and drain (E6.S3).
	Live   *sessions.Registry
	Limits pump.Limits

	// Deadlines bound a session in time. The zero value is replaced with
	// pump.DefaultDeadlines: a caller who forgets to configure timers should get
	// bounded sessions, not unbounded ones.
	Deadlines pump.Deadlines

	// Recorder records sessions. Nil records nothing — and says so in the banner
	// and in the session row, because an unrecorded session must be a fact you can
	// query for rather than an absence somebody has to notice.
	Recorder plugin.Recorder
	// RecordInput resolves whether the session recording captures keystrokes.
	RecordInput recordpolicy.RecordInput
	// Audit receives SSH open/refusal events. Nil disables audit emission.
	Audit plugin.AuditSink

	// HostKey is the gateway's SSH identity. **Every replica must present the same
	// one.** If they do not, operators get a host-key-mismatch warning on every
	// reconnect and learn to ignore it — which is the precise failure the warning
	// exists to prevent. E4.S8 owns making that configurable and rotatable; leaving
	// this nil generates an ephemeral key and says so, loudly.
	HostKey xssh.Signer

	// NewSessionID mints session ids. Injectable so tests are deterministic.
	NewSessionID func() string

	Banner func(dev *plugin.Device, p *plugin.Principal, recording bool) string
	Log    *slog.Logger
}

// Server is the SSH front door.
type Server struct {
	o   Options
	srv *gssh.Server
	log *slog.Logger
}

// New builds the server.
func New(o Options) (*Server, error) {
	switch {
	case o.Authenticator == nil:
		return nil, errors.New("sshsrv: Authenticator is required")
	case o.Registry == nil:
		return nil, errors.New("sshsrv: Registry is required")
	case o.Inviter == nil:
		return nil, errors.New("sshsrv: Inviter is required")
	case o.Sessions == nil:
		return nil, errors.New("sshsrv: Sessions is required")
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.NewSessionID == nil {
		o.NewSessionID = randomSessionID
	}
	if o.Deadlines == (pump.Deadlines{}) {
		o.Deadlines = pump.DefaultDeadlines()
	}
	if o.Live == nil {
		o.Live = sessions.NewRegistry()
	}

	s := &Server{o: o, log: o.Log}
	s.srv = &gssh.Server{
		Addr:             o.Addr,
		Handler:          s.handleSession,
		PublicKeyHandler: s.handlePublicKey,
		Version:          "Oarlock",
		// Capture the PTY here rather than in the handler, because
		// gliderlabs/ssh v0.3.8 has a data race between Session.Pty(), which copies
		// the pty struct, and its own request loop, which writes pty.Window when a
		// "window-change" arrives. OpenSSH sends one immediately, so the race is not
		// theoretical — the race detector catches it on an ordinary connection.
		//
		// This callback runs *on the request loop's own goroutine*, so a copy taken
		// here is serialised with that write. The handler then reads our copy and
		// never touches sess.Pty() at all. An initial size that a window-change
		// superseded in between is corrected by the same change arriving on the
		// window channel.
		SessionRequestCallback: func(sess gssh.Session, requestType string) bool {
			switch requestType {
			case "shell", "exec":
				req, win, ok := sess.Pty()
				sess.Context().SetValue(ptyKey{}, &capturedPty{req: req, win: win, ok: ok})
			}
			return true
		},
	}

	// Advertised only when the backend can answer it, so a key-only deployment does not
	// list keyboard-interactive among its methods. That is cosmetic — the handler asserts
	// again before challenging, so nobody is ever prompted for something it cannot check —
	// but it is the difference between `Permission denied (publickey)` and a message that
	// names a method the server was never going to honour.
	if _, ok := o.Authenticator.(plugin.InteractiveAuthenticator); ok {
		s.srv.KeyboardInteractiveHandler = s.handleKeyboardInteractive
	}

	hk := o.HostKey
	if hk == nil {
		var err error
		if hk, err = ephemeralHostKey(); err != nil {
			return nil, err
		}
		s.log.Warn("no SSH host key configured — generated an ephemeral one. " +
			"Operators will see a host-key-mismatch warning after every restart, " +
			"and an operator trained to click through those is the failure the " +
			"warning exists to prevent. Configure a persistent key, shared by " +
			"every replica, before anyone else uses this.")
	}
	s.srv.AddHostKey(hk)
	return s, nil
}

// Handler exposes the underlying server, for tests and for an embedder that wants
// to own the listener.
func (s *Server) Handler() *gssh.Server { return s.srv }

// ListenAndServe serves until it fails.
func (s *Server) ListenAndServe() error {
	s.log.Info("ssh front door listening", "addr", s.o.Addr)
	return s.srv.ListenAndServe()
}

// Close stops the server.
func (s *Server) Close() error { return s.srv.Close() }

// handleKeyboardInteractive authenticates by conversation, when the backend can.
//
// This is how an operator logs in with no key and no password: the backend prints a URL
// and a code, they approve in a browser that already holds their session and their second
// factor, and the shell opens. Neither this process nor the terminal ever sees a secret.
//
// Offered only when the authenticator implements the optional interface. Enabling it means
// an operator may use either method, which is worth being deliberate about: withdrawing
// somebody's access means withdrawing it at the identity provider or in the authorizer,
// not deleting a line from authorized_keys.
func (s *Server) handleKeyboardInteractive(ctx gssh.Context,
	challenger xssh.KeyboardInteractiveChallenge) bool {

	interactive, ok := s.o.Authenticator.(plugin.InteractiveAuthenticator)
	if !ok {
		return false
	}
	ask := func(instruction string, questions []string, echos []bool) ([]string, error) {
		// The name field is empty: clients render it inconsistently — some as a title,
		// some not at all — and anything an operator has to read belongs in the
		// instruction, which every client shows.
		return challenger("", instruction, questions, echos)
	}
	p, err := interactive.AuthInteractive(ctx, ctx.User(), ask)
	if err != nil || p == nil {
		// The reason stays in the log. On the wire an unauthenticated peer learns only
		// that it failed — and in particular does not learn whether the device in the
		// username exists, which would be a fleet enumeration oracle over SSH.
		s.log.Warn("ssh keyboard-interactive auth failed",
			"user", ctx.User(), "remote", ctx.RemoteAddr().String(), "error", err)
		return false
	}
	ctx.SetValue(principalKey{}, p)
	s.log.Info("ssh keyboard-interactive auth succeeded",
		"principal", p.ID, "remote", ctx.RemoteAddr().String())
	return true
}

// handlePublicKey authenticates the operator and stashes the principal.
func (s *Server) handlePublicKey(ctx gssh.Context, key gssh.PublicKey) bool {
	p, err := s.o.Authenticator.AuthPublicKey(ctx, ctx.User(), key)
	if err != nil || p == nil {
		// No detail on the wire. An unauthenticated peer learns only that it failed,
		// and in particular does not learn whether the *device* in the username
		// exists — that would be a fleet enumeration oracle over SSH.
		s.log.Warn("ssh auth failed",
			"user", ctx.User(), "remote", ctx.RemoteAddr().String(),
			"key_type", key.Type(), "error", err)
		return false
	}
	ctx.SetValue(principalKey{}, p)
	return true
}

func (s *Server) handleSession(sess gssh.Session) {
	ctx := sess.Context()
	deviceID := sess.User()

	p, _ := ctx.Value(principalKey{}).(*plugin.Principal)
	if p == nil {
		// Cannot happen with PublicKeyHandler set, but a nil principal would mean an
		// unattributed session, and an unattributed session is worse than no session.
		fmt.Fprintln(sess.Stderr(), "oarlock: no authenticated principal")
		_ = sess.Exit(1)
		return
	}
	log := s.log.With("principal", p.ID, "device", deviceID)

	if len(sess.Command()) > 0 || sess.Subsystem() != "" {
		// exec and sftp are E5. Refusing clearly beats half-running something.
		fmt.Fprintln(sess.Stderr(), "oarlock: only interactive shells are supported yet")
		_ = sess.Exit(1)
		return
	}

	dev, err := s.o.Registry.Get(ctx, deviceID)
	if err != nil || dev.Disabled {
		// Deliberately the same message whether the device is unknown or the caller
		// may not see it: an operator with a valid key must not be able to enumerate
		// the fleet by trying usernames.
		log.Warn("device lookup failed", "error", err)
		fmt.Fprintf(sess.Stderr(), "oarlock: no such device, or you don't have access\r\n")
		_ = sess.Exit(1)
		return
	}

	// Our own copy, taken on the request loop's goroutine by SessionRequestCallback —
	// see the comment there. Calling sess.Pty() from this goroutine races the library's
	// own write to the same struct.
	captured, _ := ctx.Value(ptyKey{}).(*capturedPty)
	if captured == nil {
		// No callback ran, which means this build wired the server differently. Fall
		// back rather than refuse: the race is a bug in a dependency, not a reason to
		// drop a session.
		req, win, ok := sess.Pty()
		captured = &capturedPty{req: req, win: win, ok: ok}
	}
	ptyReq, winCh, isPty := captured.req, captured.win, captured.ok
	if !isPty {
		fmt.Fprintln(sess.Stderr(), "oarlock: this needs a terminal (try without -T)")
		_ = sess.Exit(1)
		return
	}

	// Authorisation, before anything is created or anybody is woken.
	//
	// A denial produces no session row at all — ARCHITECTURE § 7.1 is explicit that a
	// refused-at-open session is a 403 and not a row — while an *outage* refuses too,
	// but says something different, because "you don't have access" and "we couldn't
	// check" send somebody to entirely different places.
	if verdict := s.o.Authz.AtOpen(ctx, p, dev, plugin.ActionShell); !verdict.Allow() {
		c, _ := condition.Lookup(verdict.Code)
		text := c.Text()
		if verdict.Reason != "" {
			// The backend's own sentence, when it gave one: "not in the on-call group"
			// is worth more than the generic copy, and it is what the rules file
			// author wrote for exactly this moment.
			text = verdict.Reason
		}
		log.Warn("session refused by authorization",
			"outcome", verdict.Outcome, "code", verdict.Code, "error", verdict.Err)
		fmt.Fprintf(sess.Stderr(), "oarlock: %s\r\n", text)
		_ = sess.Exit(1)
		return
	}
	recordInput, err := s.o.RecordInput.Resolve(p, dev)
	if err != nil {
		log.Warn("session refused by record_input policy", "error", err)
		s.audit(ctx, plugin.AuditEvent{
			Kind: plugin.AuditSessionRejected, DeviceID: dev.ID, Principal: p.ID,
			Surface: "ssh", Code: "policy_conflict", Reason: err.Error(),
			Action: string(plugin.ActionShell),
		})
		fmt.Fprintf(sess.Stderr(), "oarlock: record_input policy conflict: %s\r\n", err)
		_ = sess.Exit(1)
		return
	}

	sessionID := s.o.NewSessionID()

	// The row exists before the device is asked to dial, so a session that never
	// opens is still accounted for. A refusal with no row is a refusal nobody can
	// query for later.
	row := &sessions.Session{
		ID: sessionID, DeviceID: dev.ID, Profile: "shell",
		Mode: string(dev.ResolvedMode()), Principal: p.ID,
		RecordInput: recordInput,
		State:       sessions.StateWaking, RecordingState: sessions.NotRecorded,
	}
	if err := s.o.Sessions.Create(ctx, row); err != nil {
		if errors.Is(err, sessions.ErrLimit) {
			log.Warn("session refused by a concurrency limit", "error", err)
			fmt.Fprintf(sess.Stderr(),
				"oarlock: this device already has a session open\r\n")
		} else {
			log.Error("could not create a session row", "error", err)
			fmt.Fprintln(sess.Stderr(), "oarlock: could not open a session")
		}
		_ = sess.Exit(1)
		return
	}

	pending, err := s.o.Inviter.Invite(ctx, dev, invite.Request{
		SessionID:   sessionID,
		Profile:     "shell",
		Principal:   p.ID,
		RecordInput: recordInput,
		PTY: &frame.PTY{
			Cols: ptyReq.Window.Width,
			Rows: ptyReq.Window.Height,
			Term: ptyReq.Term,
		},
	})
	if err != nil {
		// The operator sees the sentence written for them, not a wire code.
		var f *invite.Failure
		if errors.As(err, &f) {
			log.Warn("could not invite the device", "code", f.Code, "error", err)
			fmt.Fprintf(sess.Stderr(), "oarlock: %s\r\n", operatorText(f))
		} else {
			log.Error("invite failed", "error", err)
			fmt.Fprintln(sess.Stderr(), "oarlock: could not open a session")
		}
		s.reject(ctx, sessionID, closeReason(err, "device_offline"))
		_ = sess.Exit(1)
		return
	}

	// Progress only. Deliberately carries no security-relevant claim: this *is* in
	// the window a truncation attack could reach, so nothing an operator needs to
	// make a decision on may live here. The disclosure comes after pairing.
	fmt.Fprintf(sess, "oarlock: waking %s…\r\n", dev.ID)
	att, err := pending.Wait(ctx)
	if err != nil {
		s.o.Inviter.Cancel(ctx, sessionID, "operator_gave_up")
		var f *invite.Failure
		if errors.As(err, &f) {
			log.Warn("device did not attach", "code", f.Code)
			fmt.Fprintf(sess.Stderr(), "oarlock: %s\r\n", operatorText(f))
		} else {
			fmt.Fprintln(sess.Stderr(), "oarlock: session setup failed")
		}
		s.reject(ctx, sessionID, closeReason(err, "device_offline"))
		_ = sess.Exit(1)
		return
	}
	defer att.Done()

	_ = s.o.Sessions.Update(ctx, sessionID, func(row *sessions.Session) error {
		row.State = sessions.StateAttached
		row.AttachedAt = time.Now()
		return nil
	})

	runner := &sessionrun.Runner{
		Sessions: s.o.Sessions, Live: s.o.Live, Recorder: s.o.Recorder,
		Limits: s.o.Limits, Deadlines: s.o.Deadlines, Log: s.log,
		Authz: s.o.AuthzSupervisor,
	}
	params := sessionrun.Params{
		SessionID: sessionID, DeviceID: dev.ID, Profile: "shell", Principal: p.ID,
		Surface: "ssh", Grantee: p, Device: att.Conn, RecordInput: recordInput,
		PTY: &frame.PTY{
			Cols: ptyReq.Window.Width, Rows: ptyReq.Window.Height, Term: ptyReq.Term,
		},
	}

	// Recording starts before the operator sees a prompt. If it cannot start, the
	// session does not open: a session that looks recorded and is not is worse than
	// one that never happened.
	rw, recording, startedAt, err := runner.Prepare(ctx, params)
	if err != nil {
		log.Error("could not start recording", "session", sessionID, "error", err)
		fmt.Fprintln(sess.Stderr(), "oarlock: could not start recording; refusing the session")
		runner.Reject(ctx, sessionID, "recorder_failed")
		_ = sess.Exit(1)
		return
	}

	banner := defaultBanner
	if s.o.Banner != nil {
		banner = s.o.Banner
	}
	// After the channel is established and the session is paired — never as an
	// unauthenticated early message that a prefix-truncation attack could remove
	// (NFR7, and the reason Terrapin matters to a custom SSH server).
	fmt.Fprint(sess, banner(dev, p, recording))

	opConn := newSSHConn(sess, winCh)
	defer opConn.Close(transport.CloseNormal, "session over")
	params.Operator = opConn

	out := runner.Run(ctx, params, rw, startedAt)
	res := out.Result
	code := out.ExitCode

	if opConn.sawThrottle() {
		// A shell must never drop. If one was announced, the policy engine is wrong.
		log.Error("THROTTLE reached an SSH operator on a shell session — "+
			"shell must backpressure, never drop", "session", sessionID)
	}

	// Said again, at a point no prefix-truncation attack can reach.
	fmt.Fprint(sess.Stderr(), closingDisclosure(dev, sessionID, res.Reason, recording))
	_ = sess.Exit(code)
}

func (s *Server) audit(ctx context.Context, e plugin.AuditEvent) {
	if s.o.Audit != nil {
		s.o.Audit.Emit(ctx, e)
	}
}

// reject marks a session that never opened. The row keeps the reason, so "why did
// nobody get a shell on that treadmill" has an answer that does not require the
// logs to still exist.
func (s *Server) reject(ctx context.Context, id, reason string) {
	_ = s.o.Sessions.Update(ctx, id, func(row *sessions.Session) error {
		row.State = sessions.StateRejected
		row.CloseReason = reason
		row.ClosedAt = time.Now()
		return nil
	})
}

// operatorText is what an operator with no components is told.
//
// The headline *and* the next action, from the same table the browser renders screens
// from. Printing only the headline — which this used to do — meant the two surfaces said
// different things about the same condition: a browser operator was told what to do about
// a sleeping device and an ssh operator was told only that it was asleep.
func operatorText(f *invite.Failure) string {
	if c, ok := condition.Lookup(f.Code); ok {
		return c.Text()
	}
	// A code with no entry is a bug, caught by pkg/condition's source scan. Falling back
	// to whatever the failure carried beats printing nothing.
	return f.Operator
}

func closeReason(err error, fallback string) string {
	var f *invite.Failure
	if errors.As(err, &f) {
		return f.Code
	}
	return fallback
}

func defaultBanner(dev *plugin.Device, p *plugin.Principal, recording bool) string {
	// The operator is told what they are in *before* they type. Discovering which
	// mode you were in from the absence of a recording six weeks later is not a
	// disclosure.
	return fmt.Sprintf("oarlock: %s · gateway-terminated · this session is %s\r\n",
		dev.ID, recordingWord(recording))
}

func recordingWord(recording bool) string {
	if recording {
		return "recorded"
	}
	return "not recorded"
}

// closingDisclosure repeats the mode and recording state as the session ends.
//
// # Why it is said twice
//
// Terrapin (CVE-2023-48795) lets an attacker who can modify traffic delete a bounded
// number of packets **immediately after** the channel is established. Strict key
// exchange removes that primitive and CI pins the x/crypto version that implements
// it — that is the actual defence, and NFR6 owns it.
//
// This is the structural half. A disclosure carried by a single early message is one
// deletion away from never having been said; a disclosure repeated minutes later, at
// a point no truncation attack can reach, cannot be suppressed by deleting a prefix.
// It also happens to be the more useful placement: it carries the session id, which
// is what somebody needs in order to go and find the recording.
func closingDisclosure(dev *plugin.Device, sessionID, reason string, recording bool) string {
	return fmt.Sprintf(
		"\r\noarlock: session %s on %s ended (%s) · gateway-terminated · was %s\r\n",
		sessionID, dev.ID, reason, recordingWord(recording))
}

func ephemeralHostKey() (xssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("sshsrv: generating a host key: %w", err)
	}
	signer, err := xssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("sshsrv: wrapping the host key: %w", err)
	}
	return signer, nil
}

func randomSessionID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("sess_%d", time.Now().UnixNano())
	}
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
	out := make([]byte, len(b))
	for i, v := range b {
		out[i] = alphabet[int(v)%len(alphabet)]
	}
	return "sess_" + string(out)
}
