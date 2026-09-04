package invite_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/invite"
	"github.com/oarlock/oarlock/internal/ticket"
	"github.com/oarlock/oarlock/pkg/condition"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
	"github.com/oarlock/oarlock/pkg/transport/memory"
)

const nodeURL = "wss://gw-a.example.org/ws/session"

// ── doubles ─────────────────────────────────────────────────────────────────────

type fakeHub struct {
	mu        sync.Mutex
	connected bool
	sendErr   error
	invited   []frame.Invitation
	cancelled []string
}

func (h *fakeHub) Connected(string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.connected
}
func (h *fakeHub) Invite(_ context.Context, _ string, inv frame.Invitation) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.sendErr != nil {
		return h.sendErr
	}
	h.invited = append(h.invited, inv)
	return nil
}
func (h *fakeHub) Cancel(_ context.Context, _, sessionID, _ string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cancelled = append(h.cancelled, sessionID)
	return nil
}
func (h *fakeHub) last() (frame.Invitation, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.invited) == 0 {
		return frame.Invitation{}, false
	}
	return h.invited[len(h.invited)-1], true
}

func persistentDevice() *plugin.Device {
	return &plugin.Device{ID: "build-runner-2", Platform: plugin.PlatformLinux}
}
func dispatchDevice() *plugin.Device {
	return &plugin.Device{ID: "treadmill-4821", Platform: plugin.PlatformAndroid}
}

type harness struct {
	inv     *invite.Inviter
	hub     *fakeHub
	tickets *ticket.Memory
	logbuf  *bytes.Buffer
}

func newHarness(t *testing.T, d plugin.Dispatcher) *harness {
	t.Helper()
	h := &harness{
		hub:     &fakeHub{connected: true},
		tickets: ticket.NewMemory(nil),
		logbuf:  &bytes.Buffer{},
	}
	h.inv = &invite.Inviter{
		Tickets:        h.tickets,
		Hub:            h.hub,
		Dispatcher:     d,
		NodeURL:        nodeURL,
		AnswerDeadline: 150 * time.Millisecond,
		Log: slog.New(slog.NewTextHandler(h.logbuf,
			&slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	return h
}

func req() invite.Request {
	return invite.Request{
		SessionID: "sess_1", Profile: "shell", Principal: "admin@mail.com",
		PTY: &frame.PTY{Cols: 132, Rows: 38, Term: "xterm-256color"},
	}
}

// ── both modes converge ─────────────────────────────────────────────────────────

// TestBothModesProduceTheSameInvitation is the return on not multiplexing: one
// payload, two delivery paths, one handler downstream.
func TestBothModesProduceTheSameInvitation(t *testing.T) {
	ctx := context.Background()

	viaHub := newHarness(t, nil)
	if _, err := viaHub.inv.Invite(ctx, persistentDevice(), req()); err != nil {
		t.Fatal(err)
	}
	fromDial, ok := viaHub.last()
	if !ok {
		t.Fatal("nothing was delivered down the control channel")
	}

	var fromDoorbell frame.Invitation
	viaDoorbell := newHarness(t, plugin.DispatcherFunc(
		func(_ context.Context, _ *plugin.Device, i frame.Invitation) error {
			fromDoorbell = i
			return nil
		}))
	// No control channel, or the doorbell never rings: a held channel is now used
	// whatever the mode says, so a dispatch device with a live channel is delivered
	// through it. This test is about the two *delivery paths* producing the same
	// invitation, so it has to actually take the doorbell path.
	viaDoorbell.hub.connected = false
	if _, err := viaDoorbell.inv.Invite(ctx, dispatchDevice(), req()); err != nil {
		t.Fatal(err)
	}

	// Everything but the ticket must match: same session, same node URL, same
	// profile, same pty.
	if fromDial.SessionID != fromDoorbell.SessionID ||
		fromDial.URL != fromDoorbell.URL ||
		fromDial.Profile != fromDoorbell.Profile ||
		fromDial.Principal != fromDoorbell.Principal {
		t.Errorf("the two paths differ:\n dial:     %+v\n doorbell: %+v", fromDial, fromDoorbell)
	}
	if *fromDial.PTY != *fromDoorbell.PTY {
		t.Errorf("pty differs: %+v vs %+v", fromDial.PTY, fromDoorbell.PTY)
	}
	if fromDial.Ticket == fromDoorbell.Ticket {
		t.Error("two invitations shared a ticket")
	}
	if fromDial.URL != nodeURL {
		t.Errorf("URL %q must name this node, not a load balancer", fromDial.URL)
	}
	if fromDial.ExpiresAt == "" {
		t.Error("no expiry on the invitation")
	}
}

func (h *harness) last() (frame.Invitation, bool) { return h.hub.last() }

// ── the failure distinction ─────────────────────────────────────────────────────

// TestFailuresAreDistinguishable is FR5. Getting this wrong wastes an on-call hour:
// "device offline" sends someone to a gym, "the wake-up service isn't responding"
// sends them to the broker.
func TestFailuresAreDistinguishable(t *testing.T) {
	ctx := context.Background()

	t.Run("persistent with no channel", func(t *testing.T) {
		h := newHarness(t, nil)
		h.hub.connected = false
		_, err := h.inv.Invite(ctx, persistentDevice(), req())
		assertFailure(t, err, invite.ErrNotConnected, "device_not_connected")
	})

	t.Run("doorbell says the device is unreachable", func(t *testing.T) {
		h := newHarness(t, plugin.DispatcherFunc(
			func(context.Context, *plugin.Device, frame.Invitation) error {
				return plugin.ErrDeviceUnreachable
			}))
		// No control channel: a held one is used whatever the mode says, so a
		// doorbell outcome only happens when there is no channel to prefer.
		h.hub.connected = false
		_, err := h.inv.Invite(ctx, dispatchDevice(), req())
		assertFailure(t, err, invite.ErrUnreachable, "device_unreachable")
	})

	t.Run("doorbell itself is broken", func(t *testing.T) {
		h := newHarness(t, plugin.DispatcherFunc(
			func(context.Context, *plugin.Device, frame.Invitation) error {
				return errors.New("mqtt: connection refused")
			}))
		// No control channel: a held one is used whatever the mode says, so a
		// doorbell outcome only happens when there is no channel to prefer.
		h.hub.connected = false
		_, err := h.inv.Invite(ctx, dispatchDevice(), req())
		assertFailure(t, err, invite.ErrDoorbellFailed, "doorbell_failed")
		// The cause survives, because whoever is paged needs it.
		if !strings.Contains(err.Error(), "connection refused") {
			t.Errorf("the cause was swallowed: %v", err)
		}
	})

	t.Run("no dispatcher configured", func(t *testing.T) {
		h := newHarness(t, nil)
		// No control channel: a held one is used whatever the mode says, so a
		// doorbell outcome only happens when there is no channel to prefer.
		h.hub.connected = false
		_, err := h.inv.Invite(ctx, dispatchDevice(), req())
		assertFailure(t, err, invite.ErrNoRoute, "no_wake_method")
		// A deployment mistake must not be reported as the device's problem.
		if strings.Contains(strings.ToLower(err.(*invite.Failure).Operator), "offline") {
			t.Error("a configuration error is being blamed on the device")
		}
	})

	t.Run("hub send fails after the check", func(t *testing.T) {
		h := newHarness(t, nil)
		h.hub.sendErr = errors.New("write timeout")
		_, err := h.inv.Invite(ctx, persistentDevice(), req())
		// The channel died between the check and the send: the device is gone, not
		// the doorbell.
		assertFailure(t, err, invite.ErrNotConnected, "device_not_connected")
	})

	// The name of this test was already a claim it could not check: three of these
	// conditions used to share the code `device_offline`, with the distinguishing
	// sentence in ERROR's `message` — which the protocol says is for humans and is never
	// parsed. A browser could render one screen for all three, or break the contract to
	// tell them apart. Now the codes are distinct, so the claim is checkable.
	t.Run("the codes themselves are distinct", func(t *testing.T) {
		seen := map[string]string{}
		for _, f := range []*invite.Failure{
			invite.ErrNotConnected, invite.ErrUnreachable, invite.ErrNoAnswer,
			invite.ErrDoorbellFailed, invite.ErrAlreadyAttached, invite.ErrNoRoute,
		} {
			if prev, dup := seen[f.Code]; dup {
				t.Errorf("%q and %q share the code %q — one screen for two conditions",
					prev, f.Operator, f.Code)
			}
			seen[f.Code] = f.Operator
			// And each one is in the table the browser renders from, so none of them
			// can reach an operator as a code with no screen behind it.
			if _, ok := condition.Lookup(f.Code); !ok {
				t.Errorf("%q has no entry in pkg/condition", f.Code)
			}
		}
	})
}

// TestEveryFailureHasItsOwnWords: three of these share a wire code, and an operator
// shown the wrong one goes to the wrong place.
func TestEveryFailureHasItsOwnWords(t *testing.T) {
	all := []*invite.Failure{
		invite.ErrNotConnected, invite.ErrUnreachable, invite.ErrNoAnswer,
		invite.ErrDoorbellFailed, invite.ErrNoRoute,
	}
	seen := map[string]bool{}
	for _, f := range all {
		if f.Operator == "" {
			t.Errorf("%s has no operator text", f.Code)
		}
		if seen[f.Operator] {
			t.Errorf("duplicate operator text: %q", f.Operator)
		}
		seen[f.Operator] = true
	}
	// And the code that must never be confused with the others really is distinct.
	if invite.ErrDoorbellFailed.Code == invite.ErrNotConnected.Code {
		t.Error("a broken doorbell reports the same code as an absent device")
	}
}

// ── lifecycle ───────────────────────────────────────────────────────────────────

func TestPendingResolvesWhenTheAgentDialsIn(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, nil)
	p, err := h.inv.Invite(ctx, persistentDevice(), req())
	if err != nil {
		t.Fatal(err)
	}
	inv, _ := h.last()

	type waited struct {
		a   *invite.Attachment
		err error
	}
	done := make(chan waited, 1)
	go func() { a, err := p.Wait(ctx); done <- waited{a, err} }()

	devConn, _ := memory.Pair(0)
	att, err := h.inv.Attach(ctx, inv.Ticket, ticket.Want{
		DeviceID: "build-runner-2", Profile: "shell", Kind: ticket.KindDevice}, devConn)
	if err != nil {
		t.Fatal(err)
	}
	if att.Claims.SessionID != "sess_1" || att.Claims.Principal != "admin@mail.com" {
		t.Errorf("claims: %+v", att.Claims)
	}
	select {
	case w := <-done:
		if w.err != nil {
			t.Fatalf("Wait returned %v", w.err)
		}
		// The waiter must receive the very connection the device arrived on.
		if w.a.Conn != devConn {
			t.Error("the waiter got a different connection")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("attaching did not resolve the pending session")
	}
	if h.inv.Outstanding() != 0 {
		t.Error("the pending entry survived the answer")
	}
}

func TestAnswerDeadline(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, nil)
	p, err := h.inv.Invite(ctx, persistentDevice(), req())
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Wait(ctx)
	assertFailure(t, err, invite.ErrNoAnswer, "device_offline")
	if !strings.Contains(err.(*invite.Failure).Operator, "didn’t answer") {
		t.Errorf("operator text: %q", err.(*invite.Failure).Operator)
	}
}

// TestFailedDeliveryRevokesTheTicket: leaving a spendable ticket behind is how a
// device that wakes up late opens a shell nobody is attached to.
func TestFailedDeliveryRevokesTheTicket(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, plugin.DispatcherFunc(
		func(context.Context, *plugin.Device, frame.Invitation) error {
			return errors.New("broker down")
		}))
	// No control channel, so delivery has to go through the doorbell — and fail there.
	h.hub.connected = false
	if _, err := h.inv.Invite(ctx, dispatchDevice(), req()); err == nil {
		t.Fatal("expected a failure")
	}
	if n := h.tickets.Outstanding(); n != 0 {
		t.Errorf("%d tickets left spendable after a failed delivery", n)
	}
	if h.inv.Outstanding() != 0 {
		t.Errorf("%d pending entries left behind", h.inv.Outstanding())
	}
}

func TestCancelRevokesAndTellsTheDevice(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, nil)
	if _, err := h.inv.Invite(ctx, persistentDevice(), req()); err != nil {
		t.Fatal(err)
	}
	inv, _ := h.last()

	h.inv.Cancel(ctx, "sess_1", "operator_gave_up")

	if _, err := h.tickets.Redeem(ctx, inv.Ticket); !errors.Is(err, ticket.ErrInvalid) {
		t.Errorf("the ticket survived the cancel: %v", err)
	}
	h.hub.mu.Lock()
	cancelled := append([]string(nil), h.hub.cancelled...)
	h.hub.mu.Unlock()
	if len(cancelled) != 1 || cancelled[0] != "sess_1" {
		t.Errorf("the device was not told: %v", cancelled)
	}
	// Cancelling twice, or cancelling something unknown, must be quiet.
	h.inv.Cancel(ctx, "sess_1", "again")
	h.inv.Cancel(ctx, "never-existed", "x")
}

// TestTicketOutlivesTheAnswerDeadline: a device answering just inside the deadline
// must not find its credential already expired.
func TestTicketOutlivesTheAnswerDeadline(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, nil)
	h.inv.AnswerDeadline = 90 * time.Second
	h.inv.TicketTTL = 10 * time.Second // deliberately shorter than the deadline

	p, err := h.inv.Invite(ctx, persistentDevice(), req())
	if err != nil {
		t.Fatal(err)
	}
	inv, _ := h.last()
	if !p.Deadline.After(time.Now().Add(80 * time.Second)) {
		t.Fatalf("deadline is %v", p.Deadline)
	}
	// The ticket's own expiry must sit beyond the wait, or the two timers combine
	// into a session that can never be opened.
	expires, err := time.Parse(time.RFC3339, inv.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if !expires.After(p.Deadline) {
		t.Errorf("ticket expires at %v, before the answer deadline %v", expires, p.Deadline)
	}
}

// TestTheTicketIsNeverLogged: a doorbell payload is a credential, and a log line is
// where a single-use secret becomes multi-use.
func TestTheTicketIsNeverLogged(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, nil)
	if _, err := h.inv.Invite(ctx, persistentDevice(), req()); err != nil {
		t.Fatal(err)
	}
	inv, _ := h.last()
	h.inv.Cancel(ctx, "sess_1", "done")

	logs := h.logbuf.String()
	if logs == "" {
		t.Fatal("nothing was logged at all; this test would pass vacuously")
	}
	if strings.Contains(logs, inv.Ticket) {
		t.Fatalf("the ticket was logged:\n%s", logs)
	}
	// The useful fields are there, so the assertion above is not passing because we
	// log nothing.
	for _, want := range []string{"build-runner-2", "sess_1", "shell"} {
		if !strings.Contains(logs, want) {
			t.Errorf("log is missing %q:\n%s", want, logs)
		}
	}
}

func TestRedeemWithTheWrongScopeDoesNotAnswer(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, nil)
	p, err := h.inv.Invite(ctx, persistentDevice(), req())
	if err != nil {
		t.Fatal(err)
	}
	inv, _ := h.last()

	// A ticket minted for `shell` must not open a `log` stream.
	devConn, _ := memory.Pair(0)
	if _, err := h.inv.Attach(ctx, inv.Ticket, ticket.Want{Profile: "log"}, devConn); !errors.Is(err, ticket.ErrScope) {
		t.Fatalf("got %v, want ErrScope", err)
	}
	// The ticket is spent either way — but the session was never answered, so it
	// still times out rather than being treated as attached.
	if _, err := p.Wait(ctx); !errors.Is(err, invite.ErrNoAnswer) {
		t.Errorf("Wait returned %v, want ErrNoAnswer", err)
	}
}

func TestInviteValidates(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, nil)
	if _, err := h.inv.Invite(ctx, nil, req()); err == nil {
		t.Error("a nil device was accepted")
	}
	if _, err := h.inv.Invite(ctx, persistentDevice(), invite.Request{Profile: "shell"}); err == nil {
		t.Error("a request with no session id was accepted")
	}
	if _, err := h.inv.Invite(ctx, persistentDevice(), invite.Request{SessionID: "s"}); err == nil {
		t.Error("a request with no profile was accepted")
	}
	noURL := &invite.Inviter{Tickets: h.tickets, Hub: h.hub}
	if _, err := noURL.Invite(ctx, persistentDevice(), req()); err == nil {
		t.Error("an Inviter with no NodeURL was accepted")
	}
}

func assertFailure(t *testing.T, err error, want *invite.Failure, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got nil", want.Code)
	}
	if !errors.Is(err, want) {
		t.Fatalf("got %v, want %s (%q)", err, want.Code, want.Operator)
	}
	var f *invite.Failure
	if !errors.As(err, &f) {
		t.Fatalf("%v is not a *Failure", err)
	}
	if f.Code != code {
		t.Errorf("code %q, want %q", f.Code, code)
	}
	if f.Operator == "" {
		t.Error("no operator-facing text")
	}
}

// TestAttachWithNobodyWaitingIsRefused: a valid ticket whose operator has gone —
// they gave up, or this is a replay arriving after the real attach — must not be
// paired with nothing. A shell running with no operator on the other end is worse
// than a refused connection.
func TestAttachWithNobodyWaitingIsRefused(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, nil)
	p, err := h.inv.Invite(ctx, persistentDevice(), req())
	if err != nil {
		t.Fatal(err)
	}
	inv, _ := h.last()

	// The operator gives up.
	h.inv.Cancel(ctx, "sess_1", "operator_gave_up")
	_ = p

	devConn, _ := memory.Pair(0)
	if _, err := h.inv.Attach(ctx, inv.Ticket, ticket.Want{}, devConn); err == nil {
		t.Fatal("a device attached to a session nobody was waiting for")
	}
}

// TestAttachmentDoneUnblocksTheHandler covers the two-goroutine split: the handler
// holding the device connection must stay alive until the side running the pump
// says the session is over.
func TestAttachmentDoneUnblocksTheHandler(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, nil)
	p, err := h.inv.Invite(ctx, persistentDevice(), req())
	if err != nil {
		t.Fatal(err)
	}
	inv, _ := h.last()
	devConn, _ := memory.Pair(0)
	att, err := h.inv.Attach(ctx, inv.Ticket, ticket.Want{}, devConn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Wait(ctx); err != nil {
		t.Fatal(err)
	}

	waiting := make(chan error, 1)
	go func() { waiting <- att.Wait(ctx) }()
	select {
	case <-waiting:
		t.Fatal("Wait returned before Done")
	case <-time.After(50 * time.Millisecond):
	}
	att.Done()
	select {
	case err := <-waiting:
		if err != nil {
			t.Fatalf("Wait returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Done did not unblock Wait")
	}
	att.Done() // idempotent
}

// TestCollectWaitsForASlowDevice is the regression test for the race the browser flow
// exposed: `POST /sessions` returns as soon as the invitation is *delivered*, so the
// operator's connection routinely arrives before the device has dialled in. A Collect
// that failed in that window reported "the agent didn't answer" for sessions that were
// perfectly fine — intermittently, depending on which round trip won.
func TestCollectWaitsForASlowDevice(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, nil)
	h.inv.AnswerDeadline = 3 * time.Second
	if _, err := h.inv.Invite(ctx, persistentDevice(), req()); err != nil {
		t.Fatal(err)
	}
	inv, _ := h.last()

	// The operator collects *first*, while the device is still waking.
	type res struct {
		a   *invite.Attachment
		err error
	}
	got := make(chan res, 1)
	go func() {
		a, err := h.inv.Collect(ctx, "sess_1")
		got <- res{a, err}
	}()

	select {
	case r := <-got:
		t.Fatalf("Collect returned before the device arrived: %v / %v", r.a, r.err)
	case <-time.After(150 * time.Millisecond):
		// Still waiting, which is the point.
	}

	devConn, _ := memory.Pair(0)
	if _, err := h.inv.Attach(ctx, inv.Ticket, ticket.Want{}, devConn); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-got:
		if r.err != nil {
			t.Fatalf("Collect returned %v after the device arrived", r.err)
		}
		if r.a.Conn != devConn {
			t.Error("the collector got a different connection")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Collect did not wake when the device arrived")
	}
}

func TestCollectGivesUpAtTheDeadline(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, nil)
	h.inv.AnswerDeadline = 120 * time.Millisecond
	if _, err := h.inv.Invite(ctx, persistentDevice(), req()); err != nil {
		t.Fatal(err)
	}
	_, err := h.inv.Collect(ctx, "sess_1")
	assertFailure(t, err, invite.ErrNoAnswer, "device_offline")
}

// TestOnlyOneCollectorWins: two pumps on one device connection would interleave
// keystrokes into a single shell.
func TestOnlyOneCollectorWins(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, nil)
	if _, err := h.inv.Invite(ctx, persistentDevice(), req()); err != nil {
		t.Fatal(err)
	}
	inv, _ := h.last()
	devConn, _ := memory.Pair(0)
	if _, err := h.inv.Attach(ctx, inv.Ticket, ticket.Want{}, devConn); err != nil {
		t.Fatal(err)
	}

	var wins, refused atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			a, err := h.inv.Collect(ctx, "sess_1")
			switch {
			case err == nil && a != nil:
				wins.Add(1)
			case errors.Is(err, invite.ErrAlreadyAttached), errors.Is(err, invite.ErrNoAnswer):
				refused.Add(1)
			default:
				t.Errorf("unexpected: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d collectors won, want exactly 1", wins.Load())
	}
	if refused.Load() != 7 {
		t.Errorf("%d refusals, want 7", refused.Load())
	}
}

// TestUncollectedAttachmentIsReleased: a device that dials in and is never collected is
// a shell running with nobody on the other end.
func TestUncollectedAttachmentIsReleased(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, nil)
	h.inv.CollectDeadline = 120 * time.Millisecond
	if _, err := h.inv.Invite(ctx, persistentDevice(), req()); err != nil {
		t.Fatal(err)
	}
	inv, _ := h.last()
	devConn, _ := memory.Pair(0)
	att, err := h.inv.Attach(ctx, inv.Ticket, ticket.Want{}, devConn)
	if err != nil {
		t.Fatal(err)
	}

	// The handler holding the device connection is released, so it can close the
	// socket instead of holding it open for an operator who never came.
	if err := att.Wait(ctx); err != nil {
		t.Fatalf("the attachment was never released: %v", err)
	}
	if att.Collected() {
		t.Error("it reports as collected")
	}
	if h.inv.AwaitingCollection() != 0 {
		t.Errorf("%d attachments still parked", h.inv.AwaitingCollection())
	}
}

// TestAHeldChannelIsUsedWhateverTheModeSays.
//
// This is the failure a first-time deployment actually hits. `examples/devices.yaml`
// describes an appliance on the `android` platform, which resolves to dispatch because the
// platform *resists* a held connection — it does not forbid one. An agent run on a desk
// holds one perfectly well, and the gateway refused the session with
// "no wake-up method is configured for it" while holding that device's control channel.
//
// The mode describes how to reach a device that is not connected. A connected device is
// reachable.
func TestAHeldChannelIsUsedWhateverTheModeSays(t *testing.T) {
	ctx := context.Background()

	// No dispatcher at all: the configuration that used to fail.
	h := newHarness(t, nil)
	h.hub.connected = true

	if _, err := h.inv.Invite(ctx, dispatchDevice(), req()); err != nil {
		t.Fatalf("a dispatch-mode device with a live control channel was refused: %v", err)
	}
	if _, ok := h.last(); !ok {
		t.Error("nothing was delivered down the control channel")
	}
}

func TestWithNoChannelAndNoDoorbellItStillSaysSo(t *testing.T) {
	// The other half: a dispatch device that is genuinely unreachable, in a deployment
	// that configured no way to reach it. That is ours to answer for, and the condition
	// says so rather than blaming the device.
	h := newHarness(t, nil)
	h.hub.connected = false
	_, err := h.inv.Invite(context.Background(), dispatchDevice(), req())
	assertFailure(t, err, invite.ErrNoRoute, "no_wake_method")
}

// TestADeadChannelFallsBackToTheDoorbell: the channel is the preference, not a commitment.
func TestADeadChannelFallsBackToTheDoorbell(t *testing.T) {
	var rang bool
	h := newHarness(t, plugin.DispatcherFunc(
		func(context.Context, *plugin.Device, frame.Invitation) error {
			rang = true
			return nil
		}))
	// Connected as far as the check can tell, and broken by the time the send happens —
	// which is the ordinary race, not an exotic one.
	h.hub.connected = true
	h.hub.sendErr = errors.New("write timeout")

	if _, err := h.inv.Invite(context.Background(), dispatchDevice(), req()); err != nil {
		t.Fatalf("a dispatch device with a dead channel and a working doorbell failed: %v", err)
	}
	if !rang {
		t.Error("the doorbell was never rung")
	}
}

// TestAPersistentDeviceWithADeadChannelIsGone: no fallback exists for it, and inventing one
// would mean reporting a device as reachable when nothing can reach it.
func TestAPersistentDeviceWithADeadChannelIsGone(t *testing.T) {
	h := newHarness(t, plugin.DispatcherFunc(
		func(context.Context, *plugin.Device, frame.Invitation) error {
			t.Error("a persistent device must not be delivered through the doorbell")
			return nil
		}))
	h.hub.connected = true
	h.hub.sendErr = errors.New("write timeout")
	_, err := h.inv.Invite(context.Background(), persistentDevice(), req())
	assertFailure(t, err, invite.ErrNotConnected, "device_not_connected")
}
