package attachsrv_test

// The operator's end of the browser leg.
//
// Three properties are worth more than the rest of this file put together:
//
//   - A device's ticket presented here must not open an operator's session. The two
//     legs share a ticket store and differ only by Kind, so the check is one comparison
//     and the consequence of losing it is that anyone holding a device credential —
//     which every device on the fleet holds — becomes an operator.
//   - A watcher's keystrokes must never reach the device. FR13 says observation is
//     read-only, and this is where that is either true or a comment.
//   - A recorder that cannot start must fail the session. A session that looks recorded
//     and is not is worse than one that never opened.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/attachsrv"
	"github.com/oarlock/oarlock/internal/invite"
	"github.com/oarlock/oarlock/internal/pump"
	"github.com/oarlock/oarlock/internal/ring"
	"github.com/oarlock/oarlock/internal/sessionrun"
	"github.com/oarlock/oarlock/internal/sessions"
	"github.com/oarlock/oarlock/internal/ticket"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
	"github.com/oarlock/oarlock/pkg/transport"
	"github.com/oarlock/oarlock/pkg/transport/memory"
)

const nodeURL = "wss://gw-a.example.org/ws/session"

// ── doubles ─────────────────────────────────────────────────────────────────────

type upgrader struct {
	conn transport.Conn
	err  error
}

func (u upgrader) Upgrade(http.ResponseWriter, *http.Request, transport.Options) (transport.Conn, error) {
	if u.err != nil {
		return nil, u.err
	}
	return u.conn, nil
}

type reacher struct {
	mu      sync.Mutex
	invited []frame.Invitation
}

func (r *reacher) Connected(string) bool { return true }
func (r *reacher) Invite(_ context.Context, _ string, inv frame.Invitation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.invited = append(r.invited, inv)
	return nil
}
func (r *reacher) Cancel(context.Context, string, string, string) error { return nil }

func (r *reacher) lastTicket() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.invited) == 0 {
		return ""
	}
	return r.invited[len(r.invited)-1].Ticket
}

// refusingRecorder is a recorder that cannot start. The point of the type is the
// property below it: this failure must end the session, not be logged and continued.
type refusingRecorder struct{ err error }

func (r refusingRecorder) Open(context.Context, *plugin.SessionMeta) (plugin.RecordingWriter, error) {
	return nil, r.err
}
func (refusingRecorder) Get(context.Context, string) (io.ReadCloser, error) {
	return nil, plugin.ErrUnsupported
}
func (refusingRecorder) URL(context.Context, string, time.Duration) (string, error) {
	return "", plugin.ErrUnsupported
}

// watcher is a live observation the test controls.
type watcher struct {
	gone chan struct{}
	once sync.Once
}

func newWatcher() *watcher { return &watcher{gone: make(chan struct{})} }

func (w *watcher) Gone() <-chan struct{} { return w.gone }
func (w *watcher) Leave()                { w.once.Do(func() { close(w.gone) }) }

// syncBuffer is a log sink a test can read while the handler is still writing to it.
// bytes.Buffer is not, and -race is right to say so.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// ── harness ─────────────────────────────────────────────────────────────────────

type harness struct {
	srv     *attachsrv.Server
	inviter *invite.Inviter
	tickets *ticket.Memory
	live    *sessions.Registry
	hub     *reacher
	device  *plugin.Device
	logs    *syncBuffer

	client transport.Conn
	done   chan struct{}
	cancel context.CancelFunc
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{
		tickets: ticket.NewMemory(nil),
		live:    sessions.NewRegistry(),
		hub:     &reacher{},
		device:  &plugin.Device{ID: "treadmill-4821", Platform: plugin.PlatformAndroid},
		logs:    &syncBuffer{},
		done:    make(chan struct{}),
	}
	log := slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h.inviter = &invite.Inviter{
		Tickets:        h.tickets,
		Hub:            h.hub,
		NodeURL:        nodeURL,
		AnswerDeadline: 2 * time.Second,
		Log:            log,
	}

	server, client := memory.Pair(0)
	h.client = client
	h.srv = &attachsrv.Server{
		Upgrader: upgrader{conn: server},
		Inviter:  h.inviter,
		Live:     h.live,
		Runner: &sessionrun.Runner{
			Sessions: sessions.NewMemory(sessions.Limits{}, nil),
			Live:     h.live,
			Log:      log,
		},
		Log: log,
	}
	return h
}

func (h *harness) serve(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	req := httptest.NewRequest(http.MethodGet, "/ws/attach", nil).WithContext(ctx)
	go func() {
		defer close(h.done)
		h.srv.ServeHTTP(httptest.NewRecorder(), req)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-h.done:
		case <-time.After(3 * time.Second):
			t.Error("the handler did not return after the request was cancelled")
		}
	})
}

// invite mints both halves for one session and returns (deviceTicket, attachTicket).
func (h *harness) invite(t *testing.T, sessionID, profile string) (string, string) {
	t.Helper()
	p, err := h.inviter.Invite(context.Background(), h.device, invite.Request{
		SessionID: sessionID, Profile: profile,
		Principal: "ops@example.org", AttachTicket: true,
	})
	if err != nil {
		t.Fatalf("inviting: %v", err)
	}
	return h.hub.lastTicket(), p.Attach
}

// mint issues a ticket of any kind directly, for the cases where no real invitation
// should exist.
func (h *harness) mint(t *testing.T, sessionID string, kind ticket.Kind) string {
	t.Helper()
	tok, err := h.tickets.Mint(context.Background(), ticket.Claims{
		SessionID: sessionID, DeviceID: h.device.ID, Profile: "shell",
		Principal: "ops@example.org", Kind: kind,
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// ── wire helpers ────────────────────────────────────────────────────────────────

func send(t *testing.T, conn transport.Conn, typ frame.Type, v any) {
	t.Helper()
	f, err := frame.Marshal(typ, v)
	if err != nil {
		t.Fatalf("marshalling %s: %v", typ, err)
	}
	sendFrame(t, conn, f)
}

func sendFrame(t *testing.T, conn transport.Conn, f frame.Frame) {
	t.Helper()
	wire, err := frame.Codec{}.Encode(nil, f)
	if err != nil {
		t.Fatalf("encoding %s: %v", f.Type, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := conn.Send(ctx, wire); err != nil {
		t.Fatalf("sending %s: %v", f.Type, err)
	}
}

func recv(t *testing.T, conn transport.Conn) frame.Frame {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	msg, err := conn.Recv(ctx)
	if err != nil {
		t.Fatalf("receiving: %v", err)
	}
	f, err := frame.Codec{}.Decode(msg)
	if err != nil {
		t.Fatalf("decoding: %v", err)
	}
	return f.Clone()
}

func recvError(t *testing.T, conn transport.Conn) frame.Error {
	t.Helper()
	f := recv(t, conn)
	if f.Type != frame.TypeError {
		t.Fatalf("got %s, want ERROR", f.Type)
	}
	var e frame.Error
	if err := frame.Unmarshal(f, &e); err != nil {
		t.Fatalf("unmarshalling ERROR: %v", err)
	}
	return e
}

func recvReady(t *testing.T, conn transport.Conn) frame.Ready {
	t.Helper()
	f := recv(t, conn)
	if f.Type != frame.TypeReady {
		t.Fatalf("got %s, want READY", f.Type)
	}
	var r frame.Ready
	if err := frame.Unmarshal(f, &r); err != nil {
		t.Fatalf("unmarshalling READY: %v", err)
	}
	return r
}

// ── the ticket kind ─────────────────────────────────────────────────────────────

// TestADeviceTicketCannotOpenAnOperatorSession.
//
// The security property this endpoint exists to hold. Both legs redeem from one ticket
// store and the only thing separating them is Kind, so a device credential — held by
// every device on the fleet, and by anyone who has compromised one — must be inert here.
func TestADeviceTicketCannotOpenAnOperatorSession(t *testing.T) {
	h := newHarness(t)
	deviceTicket, _ := h.invite(t, "s-kind", "shell")
	h.serve(t)

	send(t, h.client, frame.TypeOpen, frame.Open{Ticket: deviceTicket})

	if e := recvError(t, h.client); e.Code != "ticket_invalid" {
		t.Fatalf("a device ticket got %q on the operator endpoint, want ticket_invalid", e.Code)
	}
	if !strings.Contains(h.logs.String(), "wrong ticket kind") {
		t.Fatalf("the refusal was not logged as a kind confusion:\n%s", h.logs.String())
	}
}

// TestAttachRefusalsAreIndistinguishable. Same reasoning as the device leg: a caller who
// can tell "that ticket is spent" from "that session is not yours" can enumerate.
func TestAttachRefusalsAreIndistinguishable(t *testing.T) {
	cases := map[string]func(t *testing.T, h *harness) string{
		"a token that was never minted": func(*testing.T, *harness) string {
			return "not-a-real-ticket"
		},
		"a token already spent": func(t *testing.T, h *harness) string {
			tok := h.mint(t, "s-spent", ticket.KindAttach)
			if _, err := h.tickets.Redeem(context.Background(), tok); err != nil {
				t.Fatalf("priming the replay: %v", err)
			}
			return tok
		},
		"a device's ticket": func(t *testing.T, h *harness) string {
			return h.mint(t, "s-device", ticket.KindDevice)
		},
	}

	var first frame.Error
	var firstName string
	for name, build := range cases {
		h := newHarness(t)
		tok := build(t, h)
		h.serve(t)

		send(t, h.client, frame.TypeOpen, frame.Open{Ticket: tok})
		got := recvError(t, h.client)

		if got.Code != "ticket_invalid" {
			t.Errorf("%s: code = %q, want ticket_invalid", name, got.Code)
		}
		if firstName == "" {
			first, firstName = got, name
			continue
		}
		if got != first {
			t.Errorf("a caller can tell these apart:\n  %s: %+v\n  %s: %+v",
				firstName, first, name, got)
		}
	}
}

// ── the OPEN frame ──────────────────────────────────────────────────────────────

func TestTheFirstFrameMustBeOpen(t *testing.T) {
	h := newHarness(t)
	h.serve(t)

	sendFrame(t, h.client, frame.Data([]byte("ls\n")))

	if e := recvError(t, h.client); e.Code != "protocol_error" {
		t.Fatalf("code = %q, want protocol_error", e.Code)
	}
}

func TestAnOpenWithNoTicketIsRefused(t *testing.T) {
	h := newHarness(t)
	h.serve(t)

	send(t, h.client, frame.TypeOpen, frame.Open{Profile: "shell"})

	e := recvError(t, h.client)
	if e.Code != "protocol_error" {
		t.Fatalf("code = %q, want protocol_error", e.Code)
	}
	if !strings.Contains(e.Message, "no ticket") {
		t.Fatalf("message = %q; it should say the ticket is missing", e.Message)
	}
}

// TestTheOpenBudgetIsShort. Until OPEN arrives this socket is unauthenticated, and this
// constant is the only thing bounding how long somebody may hold one.
func TestTheOpenBudgetIsShort(t *testing.T) {
	if attachsrv.OpenBudget > 10*time.Second {
		t.Fatalf("OpenBudget is %v; an unauthenticated socket may be held that long",
			attachsrv.OpenBudget)
	}
}

// ── watching ────────────────────────────────────────────────────────────────────

// live registers a session on this node with the reattach and observe hooks the test
// wants, standing in for a running pump.
func (h *harness) liveSession(id, principal string, obs sessions.ObserveFunc,
	re sessions.ReattachFunc) *sessions.Handle {

	hd := &sessions.Handle{ID: id, DeviceID: h.device.ID, Principal: principal, Profile: "shell"}
	if obs != nil {
		hd.SetObserve(obs)
	}
	if re != nil {
		hd.SetReattach(re)
	}
	return h.live.Add(hd, func(string) {})
}

// TestAWatcherIsToldItIsReadOnlyAndWhoTheyAreWatching.
//
// Two fields, and both are load-bearing rather than cosmetic: ReadOnly is what makes the
// watcher's client disable input rather than accept keystrokes it will silently drop,
// and Watching is the operator's entitlement to know observation is not anonymous.
func TestAWatcherIsToldItIsReadOnlyAndWhoTheyAreWatching(t *testing.T) {
	h := newHarness(t)
	tok := h.mint(t, "s-watch", ticket.KindObserve)
	w := newWatcher()
	h.liveSession("s-watch", "alice@example.org",
		func(_ context.Context, _ string, conn transport.Conn,
			greet func([]frame.Observer) (frame.Frame, error)) (sessions.Watcher, error) {
			f, err := greet([]frame.Observer{{Principal: "alice@example.org"}})
			if err != nil {
				return nil, err
			}
			sendFrame(t, conn, f)
			return w, nil
		}, nil)
	h.serve(t)

	send(t, h.client, frame.TypeOpen, frame.Open{Ticket: tok})

	ready := recvReady(t, h.client)
	if !ready.ReadOnly {
		t.Fatal("a watcher was not told the connection is read-only")
	}
	if ready.Watching != "alice@example.org" {
		t.Fatalf("watching = %q, want alice@example.org", ready.Watching)
	}
	w.Leave()
}

// TestAWatchersKeystrokesNeverReachTheDevice is FR13's actual guarantee.
//
// Read-only is structural here: there is no code path from a watcher's socket to the
// device, because the handler never hands that socket to a pump. What could undo it is
// one line — an observe ticket falling through to the reattach path, which exists a few
// lines away and *does* hand the connection to a pump that forwards. So the assertion is
// that reattach is never reached, plus that the input was recognised and counted rather
// than silently ignored.
//
// Asserting "nothing arrived on a device connection" would be worse than useless: no
// device connection is wired to this handler at all, so that assertion holds however the
// code is written.
func TestAWatchersKeystrokesNeverReachTheDevice(t *testing.T) {
	h := newHarness(t)
	tok := h.mint(t, "s-noinput", ticket.KindObserve)

	var reattached atomic.Bool
	var observed transport.Conn
	w := newWatcher()
	h.liveSession("s-noinput", "alice@example.org",
		func(_ context.Context, _ string, conn transport.Conn,
			greet func([]frame.Observer) (frame.Frame, error)) (sessions.Watcher, error) {
			observed = conn
			f, err := greet(nil)
			if err != nil {
				return nil, err
			}
			sendFrame(t, conn, f)
			return w, nil
		},
		func(context.Context, transport.Conn, func(ring.Snapshot) (frame.Frame, error)) error {
			// The pump door. A watcher's connection arriving here is the bug.
			reattached.Store(true)
			return nil
		})
	h.serve(t)

	send(t, h.client, frame.TypeOpen, frame.Open{Ticket: tok})
	_ = recvReady(t, h.client)
	if observed == nil {
		t.Fatal("the watcher never reached the read-only door")
	}

	// Everything a watcher's client could put on the wire.
	sendFrame(t, h.client, frame.Data([]byte("rm -rf /\n")))
	send(t, h.client, frame.TypeResize, frame.Resize{Cols: 200, Rows: 50})
	send(t, h.client, frame.TypeSignal, frame.Signal{Signal: "INT"})

	// Counted rather than silently dropped: a keystroke here means either an old client
	// or somebody probing, and both are worth being able to see. Waiting on the log is
	// also what synchronises this test with the handler's drain loop.
	waitFor(t, func() bool {
		return strings.Count(h.logs.String(), "discarded input from a read-only watcher") == 3
	}, "the watcher's three input frames were not all counted")

	if reattached.Load() {
		t.Fatal("a watcher's connection was handed to the pump, which forwards to the device")
	}
	w.Leave()
}

// waitFor polls until cond holds, so a test does not race the handler's own goroutine.
func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal(msg)
}

// TestAWatchTicketForASessionThatIsNotRunningHereDoesNotPairADevice.
//
// The tempting bug is to fall through to Collect. That would open a session on somebody
// else's behalf using a ticket that only ever entitled its holder to watch one.
func TestAWatchTicketForASessionThatIsNotRunningHereDoesNotPairADevice(t *testing.T) {
	h := newHarness(t)
	tok := h.mint(t, "s-elsewhere", ticket.KindObserve)
	h.serve(t)

	send(t, h.client, frame.TypeOpen, frame.Open{Ticket: tok})

	if e := recvError(t, h.client); e.Code != "session_closed" {
		t.Fatalf("code = %q, want session_closed", e.Code)
	}
}

// TestObserveFailuresGetTheirOwnCode. Each of these sends an operator to a different
// place, and collapsing them into one code is how somebody ends up looking at hardware
// when the session simply already has as many watchers as it allows.
func TestObserveFailuresGetTheirOwnCode(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		code string
	}{
		{"a session that cannot be observed", sessions.ErrNoObserve, "protocol_error"},
		{"a session at its watcher limit", pump.ErrTooManyObservers, "session_limit"},
		{"a session that just ended", sessions.ErrNotLive, "session_closed"},
		{"anything else", errors.New("boom"), "internal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			tok := h.mint(t, "s-obs", ticket.KindObserve)
			h.liveSession("s-obs", "alice@example.org",
				func(context.Context, string, transport.Conn,
					func([]frame.Observer) (frame.Frame, error)) (sessions.Watcher, error) {
					return nil, tc.err
				}, nil)
			h.serve(t)

			send(t, h.client, frame.TypeOpen, frame.Open{Ticket: tok})
			if e := recvError(t, h.client); e.Code != tc.code {
				t.Fatalf("code = %q, want %q", e.Code, tc.code)
			}
		})
	}
}

// ── reattaching ─────────────────────────────────────────────────────────────────

// TestAReattachingOperatorIsHandedToTheRunningPump.
//
// Without the live-registry lookup every attach is treated as a first attach, and a
// browser that lost wifi waits for a device that has been paired for ten minutes.
func TestAReattachingOperatorIsHandedToTheRunningPump(t *testing.T) {
	h := newHarness(t)
	tok := h.mint(t, "s-reattach", ticket.KindAttach)

	var handed transport.Conn
	hd := h.liveSession("s-reattach", "ops@example.org", nil,
		func(_ context.Context, conn transport.Conn,
			greet func(ring.Snapshot) (frame.Frame, error)) error {
			handed = conn
			f, err := greet(ring.Snapshot{Replay: []byte("previous output")})
			if err != nil {
				return err
			}
			sendFrame(t, conn, f)
			return nil
		})
	h.serve(t)

	send(t, h.client, frame.TypeOpen, frame.Open{Ticket: tok})

	ready := recvReady(t, h.client)
	if handed == nil {
		t.Fatal("the operator's connection never reached the pump")
	}
	// The count comes from the very snapshot about to be replayed, which is what lets a
	// browser say "replaying 15 bytes" instead of looking frozen.
	if ready.ScrollbackLen != len("previous output") {
		t.Fatalf("scrollback_len = %d, want %d", ready.ScrollbackLen, len("previous output"))
	}

	// The handler stays until the session ends: the pump owns the socket now.
	select {
	case <-h.done:
		t.Fatal("the handler returned and closed the socket the pump is writing to")
	case <-time.After(100 * time.Millisecond):
	}
	hd.Kill("test over")
	h.live.Remove("s-reattach")
}

// TestReattachFailuresGetTheirOwnCode.
func TestReattachFailuresGetTheirOwnCode(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		code string
	}{
		// An SSH session. There is nothing to reattach to, and saying so beats a
		// browser waiting for a device that is already busy.
		{"a session that cannot be reattached to", sessions.ErrNoReattach, "protocol_error"},
		// Two operators writing into one shell would interleave their keystrokes.
		{"a session that already has an operator", pump.ErrOperatorPresent, "session_limit"},
		{"a session that just ended", sessions.ErrNotLive, "device_offline"},
		{"anything else", errors.New("boom"), "internal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			tok := h.mint(t, "s-re", ticket.KindAttach)
			h.liveSession("s-re", "ops@example.org", nil,
				func(context.Context, transport.Conn,
					func(ring.Snapshot) (frame.Frame, error)) error {
					return tc.err
				})
			h.serve(t)

			send(t, h.client, frame.TypeOpen, frame.Open{Ticket: tok})
			if e := recvError(t, h.client); e.Code != tc.code {
				t.Fatalf("code = %q, want %q", e.Code, tc.code)
			}
		})
	}
}

// ── first attach ────────────────────────────────────────────────────────────────

// TestNothingToAttachToReportsWhy.
//
// "The device has not connected", "the agent did not answer" and "somebody is already
// attached" are three different facts with three different next steps, and the operator
// text is not interchangeable. Unlike a ticket refusal there is nothing to hide here:
// the caller has already proved they hold a valid ticket for this session.
func TestNothingToAttachToReportsWhy(t *testing.T) {
	h := newHarness(t)
	// A valid attach ticket for a session no device ever dialled for.
	tok := h.mint(t, "s-nodevice", ticket.KindAttach)
	h.serve(t)

	send(t, h.client, frame.TypeOpen, frame.Open{Ticket: tok})

	e := recvError(t, h.client)
	if e.Code != "device_offline" {
		t.Fatalf("code = %q, want device_offline", e.Code)
	}
	if e.Message == "" {
		t.Fatal("the operator was given no sentence to act on")
	}
}

// TestARecorderThatCannotStartFailsTheSession.
//
// Fail closed. A session that looks recorded and is not is worse than one that never
// opened, because an audit trail with silent holes is one nobody can rely on — and the
// operator has no way to notice from inside the session.
func TestARecorderThatCannotStartFailsTheSession(t *testing.T) {
	h := newHarness(t)
	h.srv.Runner.Recorder = refusingRecorder{err: errors.New("object store is unreachable")}

	deviceTicket, attachTicket := h.invite(t, "s-rec", "shell")

	// The device dials in and parks its connection, as sessionsrv would.
	deviceConn, _ := memory.Pair(0)
	if _, err := h.inviter.Attach(context.Background(), deviceTicket, ticket.Want{
		DeviceID: h.device.ID, Profile: "shell", Kind: ticket.KindDevice,
	}, deviceConn); err != nil {
		t.Fatalf("the device could not attach: %v", err)
	}

	h.serve(t)
	send(t, h.client, frame.TypeOpen, frame.Open{Ticket: attachTicket})

	e := recvError(t, h.client)
	if e.Code != "recorder_failed" {
		t.Fatalf("code = %q, want recorder_failed", e.Code)
	}
	// READY must never have gone out: a client that saw one would have drawn a terminal.
	if !strings.Contains(h.logs.String(), "could not start recording") {
		t.Fatalf("the recorder failure was not logged:\n%s", h.logs.String())
	}
}

// TestAFailedUpgradeIsNotAPanic.
func TestAFailedUpgradeIsNotAPanic(t *testing.T) {
	logs := &bytes.Buffer{}
	srv := &attachsrv.Server{
		Upgrader: upgrader{err: errors.New("not a websocket request")},
		Inviter:  &invite.Inviter{},
		Log:      slog.New(slog.NewTextHandler(logs, nil)),
	}
	srv.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/ws/attach", nil))

	if !strings.Contains(logs.String(), "attach upgrade failed") {
		t.Fatalf("a failed upgrade was not logged:\n%s", logs.String())
	}
}
