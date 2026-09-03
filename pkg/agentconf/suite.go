package agentconf

// The battery.
//
// Every case is one control channel and one question, and every question comes from a
// paragraph of docs/protocol.md rather than from this implementation's behaviour. Where
// the two disagree the document is right and this is a bug — a conformance suite written
// against the reference implementation is a suite that certifies agreement with a bug.

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/oarlock/oarlock/internal/handshake"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/transport"
)

// Options configure a run.
type Options struct {
	// DeviceID is the device the agent under test will identify as.
	DeviceID string
	// PublicKey is that device's registered Ed25519 public key. The suite verifies the
	// agent's signature against it, which is the case everything else rests on.
	PublicKey ed25519.PublicKey
	// GatewayID is what the suite calls itself in CHALLENGE. It is inside the signed
	// input, so an agent that ignores it fails.
	GatewayID string

	// SessionURL is what the suite puts in an invitation's `url`, so it can watch the
	// agent dial back. Empty disables the cases that need it.
	SessionURL string

	// CaseTimeout bounds how long one case waits for the agent. Zero means
	// DefaultCaseTimeout.
	CaseTimeout time.Duration
	// ConnectTimeout bounds how long the suite waits for the agent to (re)connect
	// between cases. Zero means DefaultConnectTimeout — generously more than the
	// documented backoff, because an agent that is backing off correctly is not failing.
	ConnectTimeout time.Duration
}

// DefaultCaseTimeout bounds one exchange.
const DefaultCaseTimeout = 10 * time.Second

// DefaultConnectTimeout bounds waiting for a reconnect.
//
// Thirty seconds, because the documented backoff is base 1 s × 1.6 capped at 60 s with
// ±25 % jitter, and an agent on its fourth attempt is inside its rights to be four seconds
// away. A suite that timed out faster than the protocol permits would fail correct agents.
const DefaultConnectTimeout = 30 * time.Second

// Suite runs cases against whatever connects.
//
// It is not an http.Handler by accident: the implementer points their agent at a URL, and
// how that URL is served — plain HTTP for a first run, TLS once the channel-binding cases
// matter — is theirs to choose.
type Suite struct {
	o   Options
	rec *recorder

	// conns carries each accepted control channel to the case runner. Buffered, because
	// an agent that reconnects while a case is still finishing should not be dropped.
	conns chan accepted

	// sessions carries connections the agent made to the session endpoint, for the
	// cases that watch it dial back.
	sessions chan sessionDial

	upgrader transport.Upgrader
	once     sync.Once
	done     chan struct{}
}

type sessionDial struct {
	conn transport.Conn
	url  string
	done chan struct{}
}

// accepted is a connection handed from an HTTP handler to the case runner.
//
// `done` is the whole point. An HTTP handler that returns closes its socket, so the
// handler has to stay until the case is finished with the connection — and the obvious way
// to arrange that, reading until the read fails, is wrong: it puts a second Recv on a
// transport.Conn, which allows Send concurrent with Recv but not two Recvs. The first
// version of this file did exactly that and stole the agent's HELLO out from under the
// handshake.
type accepted struct {
	conn transport.Conn
	done chan struct{}
}

// New returns a suite. The upgrader is passed in so this package names no transport:
// pkg/transport exists so that everything above it can be tested without a WebSocket, and
// the suite's own tests use the in-memory pair.
func New(o Options, up transport.Upgrader) (*Suite, error) {
	switch {
	case o.DeviceID == "":
		return nil, errors.New("agentconf: DeviceID is required")
	case len(o.PublicKey) != ed25519.PublicKeySize:
		return nil, errors.New("agentconf: PublicKey must be an Ed25519 public key")
	case up == nil:
		return nil, errors.New("agentconf: an Upgrader is required")
	}
	if o.GatewayID == "" {
		o.GatewayID = "conformance-suite"
	}
	if o.CaseTimeout <= 0 {
		o.CaseTimeout = DefaultCaseTimeout
	}
	if o.ConnectTimeout <= 0 {
		o.ConnectTimeout = DefaultConnectTimeout
	}
	return &Suite{
		o: o, rec: &recorder{}, upgrader: up,
		conns:    make(chan accepted, 4),
		sessions: make(chan sessionDial, 8),
		done:     make(chan struct{}),
	}, nil
}

// Control is the handler for the control-channel URL the agent dials.
func (s *Suite) Control(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, transport.Options{MaxMessageBytes: frame.MaxFrame})
	if err != nil {
		return
	}
	release := make(chan struct{})
	select {
	case s.conns <- accepted{conn: conn, done: release}:
	case <-s.done:
		_ = conn.Close(transport.CloseGoingAway, "suite over")
		return
	}
	// Held until the case says it is finished. Returning here would close the socket the
	// runner is about to speak on — and reading it to find out when it closed would be a
	// second concurrent Recv, which is what this replaced.
	select {
	case <-release:
	case <-s.done:
	}
}

// Session is the handler for the session URL an invitation names.
func (s *Suite) Session(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, transport.Options{MaxMessageBytes: frame.MaxFrame})
	if err != nil {
		return
	}
	release := make(chan struct{})
	select {
	case s.sessions <- sessionDial{conn: conn, url: r.URL.String(), done: release}:
	case <-s.done:
		_ = conn.Close(transport.CloseGoingAway, "suite over")
		return
	}
	select {
	case <-release:
	case <-s.done:
	}
}

// Run executes the battery and returns the report.
func (s *Suite) Run(ctx context.Context) Report {
	defer s.once.Do(func() { close(s.done) })

	for _, n := range alwaysNotes {
		s.rec.note("%s", n)
	}

	// The first case is reconnect, and it runs first for a reason: everything after it
	// depends on the agent coming back, and an agent that does not should be told that
	// once rather than nine times.
	if !s.caseFirstConnection(ctx) {
		s.rec.note("the remaining cases did not run: the agent never completed a first " +
			"handshake, so there was nothing to drive")
		return s.rec.report()
	}

	for _, c := range []struct {
		name, req string
		run       func(context.Context, *channel) (Status, string)
	}{
		{"ping is echoed verbatim", "§ 4.5", s.casePing},
		{"a session frame on the control channel ends it", "§ 2.3, § 4", s.caseWrongScope},
		{"an unknown connection-scoped frame ends it", "§ 2.3", s.caseUnknownConnFrame},

		{"a dial is answered, with the ticket in the OPEN body", "§ 3.2, § 4.7", s.caseDial},
		{"a cancelled invitation is not dialled", "§ 4.8", s.caseCancel},
		{"goaway's reconnect delay is honoured", "§ 4.9", s.caseGoAwayDelay},
		{"a text websocket message is refused", "§ 2.1", s.caseTextFrame},
		{"an oversized frame is refused", "§ 2.2", s.caseOversized},
	} {
		if c.run == nil {
			// Named so the report shows what is not covered rather than leaving a hole
			// somebody has to notice. This one needs the suite to lie about the version
			// in CHALLENGE, which the handshake helper does not expose yet.
			s.rec.add(Result{Name: c.name, Requirement: c.req, Status: Skip,
				Detail: "not implemented by this release of the suite"})
			continue
		}
		s.runCase(ctx, c.name, c.req, c.run)
	}
	// Driven by hand: it needs the suite to send a CHALLENGE a correct gateway never
	// would, so it cannot go through the shared handshake helper.
	s.caseUnofferedVersion(ctx)
	return s.rec.report()
}

// runCase waits for a connection, completes the handshake, and hands the live channel to
// one case.
func (s *Suite) runCase(ctx context.Context, name, req string,
	f func(context.Context, *channel) (Status, string)) {

	started := time.Now()
	add := func(st Status, detail string) {
		s.rec.add(Result{Name: name, Requirement: req, Status: st, Detail: detail,
			Elapsed: time.Since(started)})
	}

	ch, err := s.accept(ctx)
	if err != nil {
		add(Timeout, fmt.Sprintf("no connection within %s: %v", s.o.ConnectTimeout, err))
		return
	}
	defer ch.close()

	if err := s.handshake(ctx, ch); err != nil {
		add(Fail, "the handshake did not complete: "+err.Error())
		return
	}
	cctx, cancel := context.WithTimeout(ctx, s.o.CaseTimeout)
	defer cancel()
	st, detail := f(cctx, ch)
	add(st, detail)
}

// accept waits for the agent to connect.
func (s *Suite) accept(ctx context.Context) (*channel, error) {
	ctx, cancel := context.WithTimeout(ctx, s.o.ConnectTimeout)
	defer cancel()
	select {
	case a := <-s.conns:
		return &channel{conn: a.conn, codec: frame.Codec{}, release: a.done}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ── the handshake, as the gateway ───────────────────────────────────────────────

// handshake runs the gateway side and verifies the agent's signature.
//
// It uses internal/handshake rather than a second implementation. That is deliberate: the
// suite's job is to check the *agent* against the document, and a hand-rolled gateway here
// would mean two implementations of the signing input that could drift apart — with the
// suite becoming the thing that certifies the drift.
func (s *Suite) handshake(ctx context.Context, ch *channel) error {
	g := &handshake.Gateway{
		Registry:  oneDevice{id: s.o.DeviceID, key: s.o.PublicKey},
		GatewayID: s.o.GatewayID,
		Log:       discardLogger(),
		Resume:    ch.resume,
	}
	ctx, cancel := context.WithTimeout(ctx, s.o.CaseTimeout)
	defer cancel()
	res, err := g.Accept(ctx, ch.conn)
	if err != nil {
		return err
	}
	ch.result = res
	return nil
}

// caseFirstConnection is case zero: the agent connects and its signature verifies.
func (s *Suite) caseFirstConnection(ctx context.Context) bool {
	started := time.Now()
	add := func(st Status, detail string) {
		s.rec.add(Result{
			Name:        "the handshake completes and the signature verifies",
			Requirement: "§ 3.1",
			Status:      st, Detail: detail, Elapsed: time.Since(started),
		})
	}

	ch, err := s.accept(ctx)
	if err != nil {
		add(Timeout, fmt.Sprintf("no connection within %s. Point your agent at this "+
			"suite's control URL and make sure it is running.", s.o.ConnectTimeout))
		return false
	}
	defer ch.close()

	if err := s.handshake(ctx, ch); err != nil {
		add(Fail, err.Error())
		return false
	}
	// The version tells the implementer which half of § 3.1 they landed on, and whether
	// the channel-binding cases were even possible.
	detail := fmt.Sprintf("negotiated protocol v%d, caps %v",
		ch.result.Version, ch.result.Caps)
	if ch.result.Version < handshake.Version {
		bound, berr := transport.Binding(ch.conn, handshake.ChannelBindingLabel,
			handshake.ChannelBindingLen)
		switch {
		case berr != nil:
			s.rec.note("channel binding (protocol v1) was not exercised: this connection " +
				"has no TLS channel to bind to. Serve the suite over wss:// to check it")
		case len(bound) > 0:
			// The connection *could* have been bound and the agent chose v0. That is
			// legal and it is also the downgrade, so it is worth naming.
			s.rec.note("this connection supports channel binding and your agent " +
				"negotiated v0. That is permitted, and it means a TLS-terminating " +
				"middlebox could relay your handshake — see docs/protocol.md § 3.1")
		}
	}
	add(Pass, detail)
	return true
}

// ── cases ───────────────────────────────────────────────────────────────────────

func (s *Suite) casePing(ctx context.Context, ch *channel) (Status, string) {
	const stamp = uint64(0x0123456789abcdef)
	ping, err := frame.Stamp(frame.TypePing, stamp)
	if err != nil {
		return Fail, "the suite could not build a PING: " + err.Error()
	}
	if err := ch.send(ctx, ping); err != nil {
		return Fail, "sending PING: " + err.Error()
	}
	f, err := ch.recvType(ctx, frame.TypePong)
	if err != nil {
		return statusFor(err), err.Error()
	}
	got, err := frame.ReadStamp(f)
	if err != nil {
		return Fail, "PONG's payload is not eight bytes: " + err.Error()
	}
	if got != stamp {
		return Fail, fmt.Sprintf("PONG echoed %#x, want %#x echoed verbatim — the stamp "+
			"is the gateway's round-trip clock, not a timestamp to regenerate", got, stamp)
	}
	return Pass, ""
}

func (s *Suite) caseWrongScope(ctx context.Context, ch *channel) (Status, string) {
	// DATA is session-scoped. On a control channel it means the peer has confused two
	// connections, and § 2.3 says a connection-scoped mistake is not recoverable
	// per-frame.
	if err := ch.send(ctx, frame.Data([]byte("this belongs on a session"))); err != nil {
		return Fail, "sending DATA: " + err.Error()
	}
	if closed, detail := ch.expectClose(ctx); !closed {
		return Fail, "the channel stayed open after a session-scoped frame arrived on " +
			"it: " + detail
	}
	return Pass, ""
}

func (s *Suite) caseUnknownConnFrame(ctx context.Context, ch *channel) (Status, string) {
	// 0x1F is connection-scoped and unassigned. § 2.3: an unknown connection-scoped
	// frame must close the connection, because the scope nibble is what lets a receiver
	// decide that without knowing the type.
	if err := ch.send(ctx, frame.Frame{Type: frame.Type(0x1F), Payload: []byte("{}")}); err != nil {
		return Fail, "sending an unknown connection-scoped frame: " + err.Error()
	}
	if closed, detail := ch.expectClose(ctx); !closed {
		return Fail, "the channel stayed open after an unknown connection-scoped frame. " +
			"An unknown *session*-scoped frame may be skipped; a connection-scoped one " +
			"carries the state the connection runs on: " + detail
	}
	return Pass, ""
}

func (s *Suite) caseDial(ctx context.Context, ch *channel) (Status, string) {
	if s.o.SessionURL == "" {
		return Skip, "no SessionURL configured, so there is nowhere to watch the agent dial"
	}
	const ticket = "conformance-single-use-ticket"
	inv := frame.Invitation{
		SessionID: "conf-dial-1", Ticket: ticket, URL: s.o.SessionURL,
		Profile: "shell", PTY: &frame.PTY{Cols: 80, Rows: 24, Term: "xterm-256color"},
	}
	if err := ch.sendJSON(ctx, frame.TypeDial, inv); err != nil {
		return Fail, "sending DIAL: " + err.Error()
	}

	select {
	case d := <-s.sessions:
		defer func() {
			_ = d.conn.Close(transport.CloseNormal, "case over")
			close(d.done)
		}()
		// The ticket must not be in the URL. § 3.2 is explicit, and the reason is that a
		// query string lands in every log between the device and here.
		if strings.Contains(d.url, ticket) {
			return Fail, "the ticket appeared in the session URL (" + d.url + "). It " +
				"belongs in the OPEN frame body: a query string ends up in ingress logs, " +
				"load-balancer logs and browser history"
		}
		sc := &channel{conn: d.conn, codec: frame.Codec{}}
		f, err := sc.recvType(ctx, frame.TypeOpen)
		if err != nil {
			return statusFor(err), "after dialling, the first frame must be OPEN: " + err.Error()
		}
		var open frame.Open
		if err := frame.Unmarshal(f, &open); err != nil {
			return Fail, "OPEN did not decode: " + err.Error()
		}
		switch {
		case open.Ticket != ticket:
			return Fail, fmt.Sprintf("OPEN carried ticket %q, want the one from the "+
				"invitation", open.Ticket)
		case open.Profile != "shell":
			return Fail, fmt.Sprintf("OPEN carried profile %q, want the invitation's", open.Profile)
		case open.PTY == nil || open.PTY.Cols != 80:
			return Fail, "OPEN did not carry the invitation's pty geometry"
		}
		return Pass, ""
	case <-ctx.Done():
		return Timeout, "the agent did not dial the invitation's URL within " +
			s.o.CaseTimeout.String()
	}
}

func (s *Suite) caseCancel(ctx context.Context, ch *channel) (Status, string) {
	if s.o.SessionURL == "" {
		return Skip, "no SessionURL configured, so a dial cannot be observed"
	}
	// Drain anything left from an earlier case, so this one cannot pass on somebody
	// else's connection.
	for {
		select {
		case d := <-s.sessions:
			_ = d.conn.Close(transport.CloseNormal, "stale")
			close(d.done)
			continue
		default:
		}
		break
	}

	inv := frame.Invitation{
		SessionID: "conf-cancel-1", Ticket: "cancelled-ticket", URL: s.o.SessionURL,
		Profile: "shell", PTY: &frame.PTY{Cols: 80, Rows: 24},
	}
	if err := ch.sendJSON(ctx, frame.TypeDial, inv); err != nil {
		return Fail, "sending DIAL: " + err.Error()
	}
	if err := ch.sendJSON(ctx, frame.TypeCancel, frame.Cancel{
		SessionID: inv.SessionID, Reason: "operator_gave_up",
	}); err != nil {
		return Fail, "sending CANCEL: " + err.Error()
	}

	// This case is inherently a race: an agent that dialled instantly and correctly is
	// not wrong, it just did not see the CANCEL in time. So a dial for the cancelled
	// session is reported as a skip with the reason, not a failure — and an agent that
	// dials *after* seeing CANCEL is the actual bug, which this cannot distinguish.
	select {
	case d := <-s.sessions:
		_ = d.conn.Close(transport.CloseNormal, "case over")
		close(d.done)
		return Skip, "the agent dialled before the CANCEL could arrive, which is not a " +
			"conformance failure — this case cannot distinguish that from ignoring CANCEL"
	case <-time.After(2 * time.Second):
		return Pass, ""
	case <-ctx.Done():
		return Pass, ""
	}
}

func (s *Suite) caseGoAwayDelay(ctx context.Context, ch *channel) (Status, string) {
	// Derived rather than fixed: the case has to wait out the delay it asks for, plus the
	// reconnect, inside its own timeout. A hard-coded 3 s failed a correct agent the
	// moment CaseTimeout was set to 3 s — which is a suite bug that reads exactly like an
	// agent bug, and is the reason this is computed.
	delay := s.o.CaseTimeout / 3
	if delay < 500*time.Millisecond {
		delay = 500 * time.Millisecond
	}
	delayMS := int(delay / time.Millisecond)

	if err := ch.sendJSON(ctx, frame.TypeGoAway, frame.GoAway{
		Reason: "draining", ReconnectAfterMS: delayMS,
	}); err != nil {
		return Fail, "sending GOAWAY: " + err.Error()
	}
	sent := time.Now()
	ch.close()

	// Its own budget: waiting for a reconnect the suite just asked to be delayed cannot
	// share a deadline with the delay.
	wctx, wcancel := context.WithTimeout(context.WithoutCancel(ctx), delay+s.o.ConnectTimeout)
	defer wcancel()
	next, err := s.accept(wctx)
	if err != nil {
		return Timeout, "the agent did not reconnect after GOAWAY: " + err.Error()
	}
	gap := time.Since(sent)
	// Handed back so the next case gets this connection rather than waiting for another.
	s.push(next)

	// A little slack: the measurement includes the agent noticing the close, and an
	// agent is not wrong for being 50 ms early on a 3 s delay.
	if floor := delay - delay/4; gap < floor {
		return Fail, fmt.Sprintf("reconnected after %s; GOAWAY asked for %dms. During a "+
			"drain the gateway is the only party that can see the whole fleet, so its "+
			"delay has to win over local backoff", gap.Round(time.Millisecond), delayMS)
	}
	return Pass, ""
}

func (s *Suite) caseTextFrame(ctx context.Context, ch *channel) (Status, string) {
	if err := ch.sendText(ctx, []byte(`{"type":"hello"}`)); err != nil {
		if errors.Is(err, errNoTextSupport) {
			return Skip, "this transport cannot send a text message, so the binary-only " +
				"rule could not be checked"
		}
		return Fail, "sending a text message: " + err.Error()
	}
	if closed, detail := ch.expectClose(ctx); !closed {
		return Fail, "the channel stayed open after a text message. Every Oarlock frame " +
			"is binary; a text frame is a protocol error, not something to coerce: " + detail
	}
	return Pass, ""
}

func (s *Suite) caseOversized(ctx context.Context, ch *channel) (Status, string) {
	// One byte over the ceiling. § 2.2: the limit is a defence against an allocation, so
	// it must be refused *without* buffering — which the suite cannot observe, but the
	// refusal it can.
	//
	// Built by hand rather than through the codec, because the codec refuses to encode an
	// oversized frame. That refusal is correct and it is also the wrong side of the wire:
	// an attacker is not using our encoder.
	if err := ch.sendRaw(ctx, oversizedWire()); err != nil {
		return Skip, "the suite could not put an oversized message on the wire (" +
			err.Error() + "), so the agent's read limit was not exercised"
	}
	if closed, detail := ch.expectClose(ctx); !closed {
		return Fail, "the channel stayed open after a frame over the ceiling: " + detail
	}
	return Pass, ""
}

func (s *Suite) push(ch *channel) {
	select {
	case s.conns <- accepted{conn: ch.conn, done: ch.release}:
	default:
		ch.close()
	}
}

func statusFor(err error) Status {
	if errors.Is(err, context.DeadlineExceeded) {
		return Timeout
	}
	return Fail
}

// oversizedWire builds a message one byte past the frame ceiling.
//
// The header shape is docs/protocol.md § 2.2 as the codec writes it: the type byte and
// whatever padding frame.HeaderLen accounts for. Built here rather than encoded because
// frame.Codec refuses to produce one — correctly, and on the wrong side of the wire.
func oversizedWire() []byte {
	b := make([]byte, frame.HeaderLen+frame.MaxFrame+1)
	b[0] = byte(frame.TypePing)
	return b
}

// caseUnofferedVersion checks that an agent refuses a version it did not offer.
//
// Driven by hand rather than through internal/handshake, because the point is to do
// something a correct gateway never does. That is also why it is worth checking: the
// version selects the domain separator and whether the channel binding is signed over, so
// an agent that signs whatever version it is handed can be steered onto a handshake it did
// not agree to.
func (s *Suite) caseUnofferedVersion(ctx context.Context) {
	const (
		name = "a challenge naming an unoffered version is refused"
		req  = "§ 3.1"
	)
	started := time.Now()
	add := func(st Status, detail string) {
		s.rec.add(Result{Name: name, Requirement: req, Status: st, Detail: detail,
			Elapsed: time.Since(started)})
	}

	ch, err := s.accept(ctx)
	if err != nil {
		add(Timeout, "no connection: "+err.Error())
		return
	}
	defer ch.close()

	cctx, cancel := context.WithTimeout(ctx, s.o.CaseTimeout)
	defer cancel()

	f, err := ch.recvType(cctx, frame.TypeHello)
	if err != nil {
		add(statusFor(err), "waiting for HELLO: "+err.Error())
		return
	}
	var hello frame.Hello
	if err := frame.Unmarshal(f, &hello); err != nil {
		add(Fail, "HELLO did not decode: "+err.Error())
		return
	}

	// A version nobody offers. 99 is not in SupportedVersions and will not become one.
	const bogus = 99
	for _, v := range hello.Versions {
		if v == bogus {
			add(Skip, "the agent offered v99, which this case uses as a version nobody "+
				"offers. Nothing is wrong; the case cannot run.")
			return
		}
	}
	if err := ch.sendJSON(cctx, frame.TypeChallenge, frame.Challenge{
		NonceS:    strings.Repeat("A", 43), // 32 bytes, base64url, unpadded
		GatewayID: s.o.GatewayID,
		Version:   bogus,
	}); err != nil {
		add(Fail, "sending CHALLENGE: "+err.Error())
		return
	}

	// The agent must not sign for it. An AUTH here is the failure.
	if closed, detail := ch.expectClose(cctx); !closed {
		add(Fail, "the agent did not refuse a CHALLENGE naming v99, which it never "+
			"offered. The version selects the domain separator and whether the channel "+
			"binding is signed over, so signing for one you did not offer means signing "+
			"something you did not agree to: "+detail)
		return
	}
	add(Pass, "")
}
