package sessionsrv_test

// The device's end of the session leg.
//
// This endpoint is the second half of the claim the whole product rests on: the device
// dials out, presents a single-use ticket, and gets a session. Until the ticket is
// redeemed the socket is unauthenticated, so what these tests are actually about is what
// an unauthenticated peer can learn and how long it can hold on.
//
// The refusal tests matter more than the happy path. A ticket can be refused for six
// genuinely different reasons, and the gateway must be unable to tell a caller which —
// otherwise the endpoint is an oracle for which sessions are live and which devices
// exist, answerable by anyone who can open a socket.

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/invite"
	"github.com/oarlock/oarlock/internal/sessionsrv"
	"github.com/oarlock/oarlock/internal/ticket"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
	"github.com/oarlock/oarlock/pkg/transport"
	"github.com/oarlock/oarlock/pkg/transport/memory"
)

const nodeURL = "wss://gw-a.example.org/ws/session"

// ── doubles ─────────────────────────────────────────────────────────────────────

// upgrader hands the handler one end of an in-memory pair.
//
// No WebSocket anywhere in this file, deliberately: pkg/transport exists so that
// everything above it can be tested without one, and a test that stood up a real socket
// would be testing coder/websocket rather than this package.
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

// reacher is the hub as far as the Inviter is concerned: a device that is connected and
// accepts whatever it is sent. The delivery route is not what is under test here.
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
	srv     *sessionsrv.Server
	inviter *invite.Inviter
	tickets *ticket.Memory
	device  *plugin.Device
	logs    *syncBuffer

	client transport.Conn // the agent's end
	done   chan struct{}  // closed when ServeHTTP returns
	cancel context.CancelFunc
}

// newHarness builds a server around a *real* Inviter rather than a fake one.
//
// That is the point of the refusal tests below: a stub returning a canned error could
// only prove the handler forwards whatever it is given. Refusals have to come from the
// real ticket store and the real scope check, or "every refusal looks the same" is a
// claim about the double instead of about the gateway.
func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{
		tickets: ticket.NewMemory(nil),
		device:  &plugin.Device{ID: "treadmill-4821", Platform: plugin.PlatformAndroid},
		logs:    &syncBuffer{},
		done:    make(chan struct{}),
	}
	h.inviter = &invite.Inviter{
		Tickets:        h.tickets,
		Hub:            &reacher{},
		NodeURL:        nodeURL,
		AnswerDeadline: 2 * time.Second,
		Log:            slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}

	server, client := memory.Pair(0)
	h.client = client
	h.srv = &sessionsrv.Server{
		Upgrader: upgrader{conn: server},
		Inviter:  h.inviter,
		Log:      slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	return h
}

// serve runs the handler on its own goroutine, as net/http would.
func (h *harness) serve(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	req := httptest.NewRequest(http.MethodGet, "/ws/session", nil).WithContext(ctx)
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

// invited mints a real device ticket for a session an operator is waiting on.
func (h *harness) invited(t *testing.T, sessionID, profile string) string {
	t.Helper()
	p, err := h.inviter.Invite(context.Background(), h.device, invite.Request{
		SessionID: sessionID, Profile: profile, Principal: "ops@example.org",
	})
	if err != nil {
		t.Fatalf("inviting: %v", err)
	}
	r, _ := h.inviter.Hub.(*reacher)
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.invited) == 0 {
		t.Fatal("the invitation was never delivered")
	}
	_ = p
	return r.invited[len(r.invited)-1].Ticket
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

// recv reads one frame and clones it: Decode aliases the read buffer, which a
// transport is entitled to recycle on the next Recv.
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

// ── the OPEN frame ──────────────────────────────────────────────────────────────

// TestTheFirstFrameMustBeOpen. Anything else is a peer that has not identified itself
// trying to do something, and the socket is still unauthenticated at that point.
func TestTheFirstFrameMustBeOpen(t *testing.T) {
	h := newHarness(t)
	h.serve(t)

	sendFrame(t, h.client, frame.Data([]byte("id\n")))

	if e := recvError(t, h.client); e.Code != "protocol_error" {
		t.Fatalf("code = %q, want protocol_error", e.Code)
	}
}

// TestAnOpenWithNoTicketIsRefused. An empty ticket must not reach the store, where an
// empty-string key could match an empty-string entry.
func TestAnOpenWithNoTicketIsRefused(t *testing.T) {
	h := newHarness(t)
	h.serve(t)

	send(t, h.client, frame.TypeOpen, frame.Open{DeviceID: "treadmill-4821", Profile: "shell"})

	e := recvError(t, h.client)
	if e.Code != "protocol_error" {
		t.Fatalf("code = %q, want protocol_error", e.Code)
	}
	if !strings.Contains(e.Message, "no ticket") {
		t.Fatalf("message = %q; it should say the ticket is missing", e.Message)
	}
}

// TestAControlChannelFrameIsRefusedOnTheSessionEndpoint.
//
// Scope is checked before type. A HELLO here is either a confused agent that has dialled
// the wrong URL or somebody trying to run the control-channel handshake against an
// endpoint that does not authenticate — and the second is worth refusing loudly.
func TestAControlChannelFrameIsRefusedOnTheSessionEndpoint(t *testing.T) {
	h := newHarness(t)
	h.serve(t)

	send(t, h.client, frame.TypeHello, frame.Hello{
		DeviceID: "treadmill-4821", Versions: []int{0}, NonceC: "AAAA",
	})

	if e := recvError(t, h.client); e.Code != "protocol_error" {
		t.Fatalf("code = %q, want protocol_error", e.Code)
	}
}

// ── the refusal oracle ──────────────────────────────────────────────────────────

// TestEveryTicketRefusalIsIndistinguishable is the security property this endpoint
// exists to hold.
//
// Six causes, all real, all produced by the actual ticket store and scope check:
// a token that never existed, one already spent, one for another device, one for another
// profile, one of the wrong kind, and a valid one for a session nobody is waiting on.
// If any of them produced a distinguishable ERROR, an unauthenticated caller could ask
// this endpoint which devices exist and which of their sessions are live — one socket
// per question, no credential needed.
//
// The assertion is on the whole payload, not just the code, because the coarseness is
// easy to lose in `message`: a maintainer adding %w to that string would reopen the
// oracle while leaving every code-only assertion passing.
func TestEveryTicketRefusalIsIndistinguishable(t *testing.T) {
	ctx := context.Background()

	// Each case returns the OPEN that should be refused, given a freshly built harness.
	cases := map[string]func(t *testing.T, h *harness) frame.Open{
		"a token that was never minted": func(t *testing.T, h *harness) frame.Open {
			return frame.Open{Ticket: "not-a-real-ticket", DeviceID: h.device.ID, Profile: "shell"}
		},
		"a token already spent": func(t *testing.T, h *harness) frame.Open {
			tok := h.invited(t, "s-spent", "shell")
			if _, err := h.tickets.Redeem(ctx, tok); err != nil {
				t.Fatalf("priming the replay: %v", err)
			}
			return frame.Open{Ticket: tok, DeviceID: h.device.ID, Profile: "shell"}
		},
		"a token for another device": func(t *testing.T, h *harness) frame.Open {
			tok := h.invited(t, "s-device", "shell")
			return frame.Open{Ticket: tok, DeviceID: "some-other-device", Profile: "shell"}
		},
		"a token for another profile": func(t *testing.T, h *harness) frame.Open {
			tok := h.invited(t, "s-profile", "shell")
			return frame.Open{Ticket: tok, DeviceID: h.device.ID, Profile: "exec"}
		},
		"an operator's ticket on the device endpoint": func(t *testing.T, h *harness) frame.Open {
			tok, err := h.tickets.Mint(ctx, ticket.Claims{
				SessionID: "s-kind", DeviceID: h.device.ID,
				Profile: "shell", Kind: ticket.KindAttach,
			}, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			return frame.Open{Ticket: tok, DeviceID: h.device.ID, Profile: "shell"}
		},
		"a valid ticket for a session nobody is waiting on": func(t *testing.T, h *harness) frame.Open {
			tok, err := h.tickets.Mint(ctx, ticket.Claims{
				SessionID: "s-nopending", DeviceID: h.device.ID,
				Profile: "shell", Kind: ticket.KindDevice,
			}, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			return frame.Open{Ticket: tok, DeviceID: h.device.ID, Profile: "shell"}
		},
	}

	var first frame.Error
	var firstName string
	for name, build := range cases {
		h := newHarness(t)
		open := build(t, h)
		h.serve(t)

		send(t, h.client, frame.TypeOpen, open)
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

	// And the sentence itself must carry nothing. "ticket refused" is the whole of it.
	if strings.Contains(strings.ToLower(first.Message), "device") ||
		strings.Contains(strings.ToLower(first.Message), "session") ||
		strings.Contains(strings.ToLower(first.Message), "profile") {
		t.Fatalf("the refusal names what was wrong: %q", first.Message)
	}
}

// TestTheRealReasonIsLogged is the other half of the bargain above. Telling the peer
// nothing is only defensible if the operator can still find out.
func TestTheRealReasonIsLogged(t *testing.T) {
	h := newHarness(t)
	tok := h.invited(t, "s-1", "shell")
	h.serve(t)

	send(t, h.client, frame.TypeOpen, frame.Open{
		Ticket: tok, DeviceID: "some-other-device", Profile: "shell",
	})
	_ = recvError(t, h.client)

	logs := h.logs.String()
	for _, want := range []string{"some-other-device", "session attach refused"} {
		if !strings.Contains(logs, want) {
			t.Fatalf("the log does not mention %q:\n%s", want, logs)
		}
	}
}

// TestASpentTicketCannotBeReplayed. Redemption is a compare-and-delete in the store; this
// is the same property observed from the wire, where an attacker who captured a ticket
// would be racing the real agent for it.
func TestASpentTicketCannotBeReplayed(t *testing.T) {
	h := newHarness(t)
	tok := h.invited(t, "s-replay", "shell")
	h.serve(t)

	send(t, h.client, frame.TypeOpen, frame.Open{
		Ticket: tok, DeviceID: h.device.ID, Profile: "shell",
	})
	if f := recv(t, h.client); f.Type != frame.TypeReady {
		t.Fatalf("the first use got %s, want READY", f.Type)
	}

	// A second connection, same ticket.
	h2 := newHarness(t)
	h2.tickets = h.tickets
	h2.inviter.Tickets = h.tickets
	h2.serve(t)

	send(t, h2.client, frame.TypeOpen, frame.Open{
		Ticket: tok, DeviceID: h.device.ID, Profile: "shell",
	})
	if e := recvError(t, h2.client); e.Code != "ticket_invalid" {
		t.Fatalf("the replay got %q, want ticket_invalid", e.Code)
	}
}

// ── the paired session ──────────────────────────────────────────────────────────

// TestAPairedDeviceIsToldTheSessionID. READY is how the agent learns which session it is
// on, which is what every log line it writes afterwards is keyed by.
func TestAPairedDeviceIsToldTheSessionID(t *testing.T) {
	h := newHarness(t)
	tok := h.invited(t, "s-ready", "shell")
	h.serve(t)

	send(t, h.client, frame.TypeOpen, frame.Open{
		Ticket: tok, DeviceID: h.device.ID, Profile: "shell",
	})

	f := recv(t, h.client)
	if f.Type != frame.TypeReady {
		t.Fatalf("got %s, want READY", f.Type)
	}
	var ready frame.Ready
	if err := frame.Unmarshal(f, &ready); err != nil {
		t.Fatal(err)
	}
	if ready.SessionID != "s-ready" {
		t.Fatalf("session = %q, want s-ready", ready.SessionID)
	}
	if ready.Mode != "gateway" {
		t.Fatalf("mode = %q, want gateway", ready.Mode)
	}
}

// TestTheReadyHookOwnsWhatTheDeviceIsTold. The default reports the session id and
// nothing else; the operator's side is what knows about scrollback and recording, so it
// gets to fill READY in.
func TestTheReadyHookOwnsWhatTheDeviceIsTold(t *testing.T) {
	h := newHarness(t)
	tok := h.invited(t, "s-hook", "shell")

	var seen *ticket.Claims
	h.srv.Ready = func(c *ticket.Claims) frame.Ready {
		seen = c
		return frame.Ready{SessionID: c.SessionID, Recording: true, Mode: "gateway"}
	}
	h.serve(t)

	send(t, h.client, frame.TypeOpen, frame.Open{
		Ticket: tok, DeviceID: h.device.ID, Profile: "shell",
	})

	var ready frame.Ready
	if err := frame.Unmarshal(recv(t, h.client), &ready); err != nil {
		t.Fatal(err)
	}
	if !ready.Recording {
		t.Fatal("the hook's READY did not reach the wire")
	}
	if seen == nil || seen.Principal != "ops@example.org" {
		t.Fatalf("the hook was given %+v; it needs the redeemed claims", seen)
	}
}

// TestTheHandlerHoldsTheSocketUntilTheSessionEnds.
//
// Returning from ServeHTTP closes the socket, and the operator's side is the one that
// knows when the session is over. A handler that returned after READY would tear down
// every session the moment it opened.
func TestTheHandlerHoldsTheSocketUntilTheSessionEnds(t *testing.T) {
	h := newHarness(t)
	tok := h.invited(t, "s-hold", "shell")
	h.serve(t)

	send(t, h.client, frame.TypeOpen, frame.Open{
		Ticket: tok, DeviceID: h.device.ID, Profile: "shell",
	})
	if f := recv(t, h.client); f.Type != frame.TypeReady {
		t.Fatalf("got %s, want READY", f.Type)
	}

	select {
	case <-h.done:
		t.Fatal("the handler returned while the session was still open")
	case <-time.After(100 * time.Millisecond):
	}

	// The operator's side finishing is what releases it.
	att, err := h.inviter.Collect(context.Background(), "s-hold")
	if err != nil {
		t.Fatalf("collecting: %v", err)
	}
	att.Done()

	select {
	case <-h.done:
	case <-time.After(3 * time.Second):
		t.Fatal("the handler did not return after the session ended")
	}
}

// TestACancelledRequestReleasesTheOperatorsSide.
//
// The device dropping is not the same as the session ending, and the handler is the only
// thing that knows it happened. Without the Done() on that path the operator waits on a
// device that is already gone until a timer fires.
func TestACancelledRequestReleasesTheOperatorsSide(t *testing.T) {
	h := newHarness(t)
	tok := h.invited(t, "s-drop", "shell")
	h.serve(t)

	send(t, h.client, frame.TypeOpen, frame.Open{
		Ticket: tok, DeviceID: h.device.ID, Profile: "shell",
	})
	if f := recv(t, h.client); f.Type != frame.TypeReady {
		t.Fatalf("got %s, want READY", f.Type)
	}

	att, err := h.inviter.Collect(context.Background(), "s-drop")
	if err != nil {
		t.Fatalf("collecting: %v", err)
	}

	h.cancel() // the device's request goes away

	if err := att.Wait(context.Background()); err != nil {
		t.Fatalf("waiting on the attachment: %v", err)
	}
}

// ── the socket before anyone has identified themselves ──────────────────────────

// TestASilentPeerDoesNotHoldTheHandlerForever.
//
// Until OPEN arrives this is an unauthenticated socket held open on somebody's promise
// that they are about to say who they are. OpenBudget is the ceiling; this covers the
// other way out, a request that goes away, which is what actually happens when a load
// balancer drops a half-open connection.
func TestASilentPeerDoesNotHoldTheHandlerForever(t *testing.T) {
	h := newHarness(t)
	h.serve(t)

	// Nothing is sent. The handler is sitting in readOpen.
	select {
	case <-h.done:
		t.Fatal("the handler gave up before the budget")
	case <-time.After(50 * time.Millisecond):
	}

	h.cancel()
	select {
	case <-h.done:
	case <-time.After(3 * time.Second):
		t.Fatal("a cancelled request left the handler holding an unauthenticated socket")
	}
}

// TestTheOpenBudgetIsShort guards the constant itself.
//
// It is the only thing bounding how long an unauthenticated peer may hold a socket, and
// it is the sort of number that gets raised to "be safe" during an unrelated timeout
// investigation. Raising it is a decision, not a tweak.
func TestTheOpenBudgetIsShort(t *testing.T) {
	if sessionsrv.OpenBudget > 10*time.Second {
		t.Fatalf("OpenBudget is %v; an unauthenticated socket may be held that long",
			sessionsrv.OpenBudget)
	}
}

// TestAFailedUpgradeIsNotAPanic. The upgrader has already written its own response by
// then, so there is nothing left to do but leave.
func TestAFailedUpgradeIsNotAPanic(t *testing.T) {
	logs := &bytes.Buffer{}
	srv := &sessionsrv.Server{
		Upgrader: upgrader{err: errors.New("not a websocket request")},
		Inviter:  &invite.Inviter{},
		Log:      slog.New(slog.NewTextHandler(logs, nil)),
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ws/session", nil))

	if !strings.Contains(logs.String(), "session upgrade failed") {
		t.Fatalf("a failed upgrade was not logged:\n%s", logs.String())
	}
}
