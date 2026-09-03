package agent_test

// The session leg: what happens after the doorbell rings.
//
// The agent dials the URL the invitation named, presents the ticket, and runs one
// profile. Two things here are worth more than the rest:
//
//   - The ticket travels in the OPEN frame body and never in the URL. A query string
//     ends up in ingress logs, load-balancer logs and browser history, and a single-use
//     ticket sitting in a log file is still a ticket until it is spent.
//   - A profile this build cannot serve is refused with a reason. The gateway already
//     knows what was advertised, so the failure should name the disagreement rather than
//     hanging or dying silently on a device nobody can reach.

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oarlock/oarlock/agent"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/transport"
)

const sessionURL = "wss://gw-a.example.org/ws/session"

// ── a pty the test drives ───────────────────────────────────────────────────────

// fakePTY is a shell without a shell: output is whatever the test queues, and every
// write, resize and signal is recorded.
type fakePTY struct {
	out chan []byte // queued output; close to end the session

	// dead is closed by Close, and Read selects on it.
	//
	// Modelling this matters more than it looks. A real pty's Read is unblocked by
	// closing the master descriptor and by nothing else — not by a context, not by a
	// cancel — and a fake whose Read could be abandoned some other way would have hidden
	// the deadlock this file exists to have caught.
	dead      chan struct{}
	closeOnce sync.Once

	mu       sync.Mutex
	written  []byte
	resizes  [][2]int
	signals  []string
	closed   bool
	exitCode int
	waitErr  error
}

func newFakePTY() *fakePTY {
	return &fakePTY{out: make(chan []byte, 8), dead: make(chan struct{})}
}

func (p *fakePTY) Read(b []byte) (int, error) {
	select {
	case <-p.dead:
		return 0, io.ErrClosedPipe
	case chunk, ok := <-p.out:
		if !ok {
			// How a shell exits: the read fails once the child is gone.
			return 0, io.EOF
		}
		return copy(b, chunk), nil
	}
}

func (p *fakePTY) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.written = append(p.written, b...)
	return len(b), nil
}

func (p *fakePTY) Close() error {
	p.closeOnce.Do(func() { close(p.dead) })
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	return nil
}

func (p *fakePTY) Resize(cols, rows int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.resizes = append(p.resizes, [2]int{cols, rows})
	return nil
}

func (p *fakePTY) Signal(name string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.signals = append(p.signals, name)
	return nil
}

func (p *fakePTY) Wait() (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exitCode, p.waitErr
}

func (p *fakePTY) wrote() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return string(p.written)
}

func (p *fakePTY) resized() [][2]int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([][2]int(nil), p.resizes...)
}

func (p *fakePTY) signalled() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.signals...)
}

// ── harness ─────────────────────────────────────────────────────────────────────

// sessionHarness runs Serve against a gateway the test plays by hand. Unlike the control
// channel there is no handshake here: the ticket in OPEN is the whole authentication.
type sessionHarness struct {
	ctrl   *agent.Control
	dialer *dialer
	pty    *fakePTY

	served chan error
	cancel context.CancelFunc
}

func newSessionHarness(t *testing.T, tweak func(*agent.Config)) *sessionHarness {
	t.Helper()
	h := &sessionHarness{
		dialer: newDialer(),
		pty:    newFakePTY(),
		served: make(chan error, 1),
	}
	inner := newControlHarness(t, func(c *agent.Config) {
		c.Dialer = h.dialer
		c.Shell = func(context.Context, agent.ShellRequest) (agent.PTY, error) {
			return h.pty, nil
		}
		if tweak != nil {
			tweak(c)
		}
	})
	h.ctrl = inner.ctrl
	return h
}

// serve runs one invitation and returns the gateway's end of its connection.
func (h *sessionHarness) serve(t *testing.T, inv frame.Invitation) transport.Conn {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() { h.served <- h.ctrl.Serve(ctx, inv) }()
	t.Cleanup(cancel)
	return h.dialer.gateway(t)
}

// openFrom reads the OPEN the agent sent.
func openFrom(t *testing.T, conn transport.Conn) frame.Open {
	t.Helper()
	f := recv(t, conn)
	if f.Type != frame.TypeOpen {
		t.Fatalf("the agent's first frame was %s, want OPEN", f.Type)
	}
	var open frame.Open
	if err := frame.Unmarshal(f, &open); err != nil {
		t.Fatal(err)
	}
	return open
}

func shellInvitation() frame.Invitation {
	return frame.Invitation{
		SessionID: "s-1", Ticket: "single-use-secret", URL: sessionURL,
		Profile: "shell", Principal: "ops@example.org",
		PTY: &frame.PTY{Cols: 80, Rows: 24, Term: "xterm-256color"},
	}
}

// ── the ticket ──────────────────────────────────────────────────────────────────

// TestTheTicketTravelsInTheOpenBodyAndNotTheURL.
//
// The URL the agent dials is the one the gateway named, verbatim. Anything appended to
// it — a query string in particular — is written to every log between here and the
// gateway, and a spent-once credential in a log file is still a credential right up
// until it is spent.
func TestTheTicketTravelsInTheOpenBodyAndNotTheURL(t *testing.T) {
	h := newSessionHarness(t, nil)
	inv := shellInvitation()
	conn := h.serve(t, inv)

	dialled := h.dialer.at(0).url
	if dialled != sessionURL {
		t.Fatalf("dialled %q, want the invitation's URL verbatim", dialled)
	}
	if strings.Contains(dialled, inv.Ticket) {
		t.Fatalf("the ticket is in the URL: %s", dialled)
	}

	open := openFrom(t, conn)
	if open.Ticket != inv.Ticket {
		t.Fatalf("OPEN carried ticket %q, want %q", open.Ticket, inv.Ticket)
	}
	if open.Profile != "shell" {
		t.Fatalf("OPEN carried profile %q", open.Profile)
	}
	if open.PTY == nil || open.PTY.Cols != 80 || open.PTY.Term != "xterm-256color" {
		t.Fatalf("OPEN carried pty %+v; the gateway's geometry did not survive", open.PTY)
	}
}

// TestAnInvitationMissingItsUrlOrTicketIsRefusedBeforeDialling. Dialling first would
// spend a socket, and on a metered radio that is not free.
func TestAnInvitationMissingItsUrlOrTicketIsRefusedBeforeDialling(t *testing.T) {
	for _, tc := range []struct {
		name string
		inv  frame.Invitation
	}{
		{"no url", frame.Invitation{SessionID: "s", Ticket: "t", Profile: "shell"}},
		{"no ticket", frame.Invitation{SessionID: "s", URL: sessionURL, Profile: "shell"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newSessionHarness(t, nil)
			err := h.ctrl.Serve(context.Background(), tc.inv)
			if err == nil {
				t.Fatal("an incomplete invitation was accepted")
			}
			if h.dialer.count() != 0 {
				t.Fatal("the agent dialled anyway")
			}
		})
	}
}

// ── profiles this build cannot serve ────────────────────────────────────────────

// TestAnUnknownProfileIsRefusedWithAReason.
//
// Refusing clearly beats pretending. The gateway already knows what this build
// advertised, so a disagreement is a configuration error somebody can fix — but only if
// the refusal says which profile.
func TestAnUnknownProfileIsRefusedWithAReason(t *testing.T) {
	h := newSessionHarness(t, nil)
	inv := shellInvitation()
	inv.Profile = "log"
	conn := h.serve(t, inv)

	_ = openFrom(t, conn)
	send(t, conn, frame.TypeReady, frame.Ready{SessionID: "s-1", Mode: "gateway"})

	f := recv(t, conn)
	if f.Type != frame.TypeError {
		t.Fatalf("got %s, want ERROR", f.Type)
	}
	var e frame.Error
	if err := frame.Unmarshal(f, &e); err != nil {
		t.Fatal(err)
	}
	if e.Code != "profile_unsupported" {
		t.Fatalf("code = %q, want profile_unsupported", e.Code)
	}
	// Quoted, so this does not pass on the word "log" appearing incidentally.
	if !strings.Contains(e.Message, `profile "log"`) {
		t.Fatalf("the refusal does not name the profile: %q", e.Message)
	}

	select {
	case err := <-h.served:
		if err == nil {
			t.Fatal("Serve returned nil for a profile it cannot run")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return")
	}
}

// TestAShellProfileOnABuildWithNoShellIsRefused.
//
// A build with no PTY is meant to leave "shell" out of Caps, and then the gateway refuses
// at open time. This is the belt to that braces: if a shell is asked for anyway, the
// device says so rather than hanging with a session the operator is staring at.
func TestAShellProfileOnABuildWithNoShellIsRefused(t *testing.T) {
	h := newSessionHarness(t, func(c *agent.Config) { c.Shell = nil })
	conn := h.serve(t, shellInvitation())

	_ = openFrom(t, conn)
	send(t, conn, frame.TypeReady, frame.Ready{SessionID: "s-1", Mode: "gateway"})

	f := recv(t, conn)
	var e frame.Error
	if err := frame.Unmarshal(f, &e); err != nil {
		t.Fatal(err)
	}
	if e.Code != "profile_unsupported" {
		t.Fatalf("code = %q, want profile_unsupported", e.Code)
	}
}

// TestAGatewayRefusalIsSurfacedRatherThanTreatedAsReady.
//
// The gateway can answer OPEN with ERROR instead of READY — a spent ticket, most often.
// An agent that ignored it would sit waiting for a READY that is never coming.
func TestAGatewayRefusalIsSurfacedRatherThanTreatedAsReady(t *testing.T) {
	h := newSessionHarness(t, nil)
	conn := h.serve(t, shellInvitation())

	_ = openFrom(t, conn)
	send(t, conn, frame.TypeError, frame.Error{Code: "ticket_invalid", Message: "ticket refused"})

	select {
	case err := <-h.served:
		if err == nil {
			t.Fatal("Serve returned nil after the gateway refused the session")
		}
		if !strings.Contains(err.Error(), "ticket_invalid") {
			t.Fatalf("the error does not carry the gateway's code: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after the gateway refused")
	}
}

// ── the shell, once it is running ───────────────────────────────────────────────

// ready brings a shell session up and returns the gateway's end.
func (h *sessionHarness) ready(t *testing.T) transport.Conn {
	t.Helper()
	conn := h.serve(t, shellInvitation())
	_ = openFrom(t, conn)
	send(t, conn, frame.TypeReady, frame.Ready{SessionID: "s-1", Mode: "gateway", Recording: true})
	return conn
}

// TestOperatorInputReachesThePTY.
func TestOperatorInputReachesThePTY(t *testing.T) {
	h := newSessionHarness(t, nil)
	conn := h.ready(t)

	sendFrame(t, conn, frame.Data([]byte("uname -a\n")))

	waitFor(t, func() bool { return h.pty.wrote() == "uname -a\n" },
		"the operator's keystrokes never reached the pty")
}

// TestPTYOutputReachesTheGateway. The agent sends what it reads; coalescing is the
// gateway's job, because the gateway is the side that knows how fast the operator is
// consuming.
func TestPTYOutputReachesTheGateway(t *testing.T) {
	h := newSessionHarness(t, nil)
	conn := h.ready(t)

	h.pty.out <- []byte("Linux build-runner-2\n")

	f := recv(t, conn)
	if f.Type != frame.TypeData {
		t.Fatalf("got %s, want DATA", f.Type)
	}
	if string(f.Payload) != "Linux build-runner-2\n" {
		t.Fatalf("the gateway received %q", f.Payload)
	}
}

// TestAShellExitingSendsExitThenClose.
//
// Both, and in that order. EXIT is what makes the exec profile mean anything, and CLOSE
// is what tells the gateway the session is over rather than the socket having dropped —
// which are different facts with different consequences for a reattachable session.
func TestAShellExitingSendsExitThenClose(t *testing.T) {
	h := newSessionHarness(t, nil)
	h.pty.mu.Lock()
	h.pty.exitCode = 7
	h.pty.mu.Unlock()
	conn := h.ready(t)

	close(h.pty.out) // the shell is gone; the next read fails

	f := recv(t, conn)
	if f.Type != frame.TypeExit {
		t.Fatalf("got %s, want EXIT", f.Type)
	}
	var exit frame.Exit
	if err := frame.Unmarshal(f, &exit); err != nil {
		t.Fatal(err)
	}
	if exit.Code != 7 {
		t.Fatalf("exit code = %d, want 7", exit.Code)
	}

	if f := recv(t, conn); f.Type != frame.TypeClose {
		t.Fatalf("got %s, want CLOSE after EXIT", f.Type)
	}
}

// TestASignalIsDeliveredByName. Not interactive Ctrl-C — that is byte 0x03 inside DATA,
// interpreted by the device's line discipline. This is the browser's stop button.
func TestASignalIsDeliveredByName(t *testing.T) {
	h := newSessionHarness(t, nil)
	conn := h.ready(t)

	send(t, conn, frame.TypeSignal, frame.Signal{Signal: "INT"})

	waitFor(t, func() bool {
		s := h.pty.signalled()
		return len(s) == 1 && s[0] == "INT"
	}, "the signal never reached the pty")
}

// TestTheGatewayClosingEndsTheSessionCleanly.
func TestTheGatewayClosingEndsTheSessionCleanly(t *testing.T) {
	h := newSessionHarness(t, nil)
	conn := h.ready(t)

	send(t, conn, frame.TypeClose, frame.Close{Reason: "operator_close"})

	select {
	case err := <-h.served:
		if err != nil {
			t.Fatalf("Serve returned %v; the gateway closing is not an error", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return when the gateway closed the session")
	}
}

// TestAPingMidSessionIsAnswered. A session where nobody is typing still has to be known
// to be alive, or the gateway cannot tell a quiet operator from a dead device.
func TestAPingMidSessionIsAnswered(t *testing.T) {
	h := newSessionHarness(t, nil)
	conn := h.ready(t)

	const stamp = uint64(0xfeedface)
	ping, err := frame.Stamp(frame.TypePing, stamp)
	if err != nil {
		t.Fatal(err)
	}
	sendFrame(t, conn, ping)

	f := recv(t, conn)
	if f.Type != frame.TypePong {
		t.Fatalf("got %s, want PONG", f.Type)
	}
	if got, _ := frame.ReadStamp(f); got != stamp {
		t.Fatalf("stamp came back as %#x, want %#x", got, stamp)
	}
}

// TestAFrameThatIsNotValidFromAGatewayEndsTheSession.
//
// OPEN, READY-twice and EXIT all come *from* the device. Arriving from the gateway they
// mean the two ends disagree about who is who, and continuing would mean guessing.
func TestAFrameThatIsNotValidFromAGatewayEndsTheSession(t *testing.T) {
	h := newSessionHarness(t, nil)
	conn := h.ready(t)

	send(t, conn, frame.TypeExit, frame.Exit{Code: 0})

	f := recv(t, conn)
	if f.Type != frame.TypeError {
		t.Fatalf("got %s, want ERROR", f.Type)
	}
	select {
	case err := <-h.served:
		if err == nil {
			t.Fatal("Serve returned nil after a protocol error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after a protocol error")
	}
}

// TestAConnectionScopedFrameMidSessionIsRefused. Scope is checked before type: a DIAL on
// a session connection is the gateway confusing this socket for a control channel.
func TestAConnectionScopedFrameMidSessionIsRefused(t *testing.T) {
	h := newSessionHarness(t, nil)
	conn := h.ready(t)

	send(t, conn, frame.TypeDial, frame.Invitation{SessionID: "s-2", Ticket: "t", URL: "u"})

	if f := recv(t, conn); f.Type != frame.TypeError {
		t.Fatalf("got %s, want ERROR", f.Type)
	}
}

// ── resizing ────────────────────────────────────────────────────────────────────

// TestTheFirstResizeIsAppliedImmediately.
//
// A resize that waits for the coalescing window is a visible flash of the wrong geometry
// on a terminal that has just opened — which is the one moment the operator is looking
// straight at it.
func TestTheFirstResizeIsAppliedImmediately(t *testing.T) {
	h := newSessionHarness(t, nil)
	conn := h.ready(t)

	send(t, conn, frame.TypeResize, frame.Resize{Cols: 120, Rows: 40})

	waitFor(t, func() bool {
		r := h.pty.resized()
		return len(r) >= 1 && r[0] == [2]int{120, 40}
	}, "the first resize was not applied promptly")
}

// TestABurstOfResizesIsCoalescedToTheLastOne.
//
// Dragging a browser window edge generates hundreds of events and the PTY needs only the
// last. Applying every one means hundreds of ioctls and hundreds of SIGWINCHs delivered
// to whatever is running — which is how `less` ends up redrawing instead of scrolling.
func TestABurstOfResizesIsCoalescedToTheLastOne(t *testing.T) {
	h := newSessionHarness(t, nil)
	conn := h.ready(t)

	for _, cols := range []int{100, 101, 102, 103, 104, 105} {
		send(t, conn, frame.TypeResize, frame.Resize{Cols: cols, Rows: 40})
	}

	// The last one must arrive, and long after the window has closed the total must be
	// far short of one per frame.
	waitFor(t, func() bool {
		r := h.pty.resized()
		return len(r) > 0 && r[len(r)-1] == [2]int{105, 40}
	}, "the final geometry never reached the pty")

	time.Sleep(3 * agent.ResizeInterval)
	if n := len(h.pty.resized()); n > 3 {
		t.Fatalf("%d resizes reached the pty for a burst of 6; they are not being coalesced", n)
	}
	// And the terminal ends up the size the operator actually chose.
	last := h.pty.resized()
	if last[len(last)-1] != [2]int{105, 40} {
		t.Fatalf("the pty settled at %v, want 105x40", last[len(last)-1])
	}
}

// TestAnImpossibleGeometryIsNotAppliedToThePTY. A 0x0 window reaches an ioctl on a real
// terminal, and a terminal that believes it is zero columns wide wraps every line.
func TestAnImpossibleGeometryIsNotAppliedToThePTY(t *testing.T) {
	h := newSessionHarness(t, nil)
	conn := h.ready(t)

	send(t, conn, frame.TypeResize, frame.Resize{Cols: 0, Rows: 0})
	send(t, conn, frame.TypeResize, frame.Resize{Cols: -1, Rows: 24})

	time.Sleep(3 * agent.ResizeInterval)
	for _, r := range h.pty.resized() {
		if r[0] <= 0 || r[1] <= 0 {
			t.Fatalf("an impossible geometry reached the pty: %v", r)
		}
	}
}

// TestTheSessionClosingClosesThePTY. A device that leaks a shell per session runs out of
// processes, and the leak is invisible until it is not.
func TestTheSessionClosingClosesThePTY(t *testing.T) {
	h := newSessionHarness(t, nil)
	conn := h.ready(t)

	send(t, conn, frame.TypeClose, frame.Close{Reason: "operator_close"})
	select {
	case <-h.served:
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return")
	}

	h.pty.mu.Lock()
	defer h.pty.mu.Unlock()
	if !h.pty.closed {
		t.Fatal("the session ended without closing the pty")
	}
}

// TestADialFailureIsReported. The gateway named a node; if it cannot be reached the
// operator needs the reason, not a session that never opens.
func TestADialFailureIsReported(t *testing.T) {
	h := newSessionHarness(t, nil)
	h.dialer.mu.Lock()
	h.dialer.err = errors.New("connection refused")
	h.dialer.mu.Unlock()

	err := h.ctrl.Serve(context.Background(), shellInvitation())
	if err == nil {
		t.Fatal("Serve returned nil when the session could not be dialled")
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("the error does not carry the cause: %v", err)
	}
}

// TestAGatewayCloseOnAnIdleShellDoesNotLeakTheSession is a regression test, and it uses a
// real /bin/sh rather than the fake above on purpose.
//
// The bug it guards was invisible to a fake whose Read could be abandoned: ptyToGateway
// blocks in p.Read on the pty master, and a blocking read on a file descriptor is not
// unblocked by cancelling a context. runShell closed the terminal in a defer — which
// could not run until runShell returned, which could not happen until the wait for that
// very goroutine was satisfied.
//
// So every session ended by the *gateway* on a shell that happened to be idle parked a
// goroutine, a pty and a live shell process on the device, permanently. An operator
// closing a browser tab was enough to do it, and nothing on the device reported it.
func TestAGatewayCloseOnAnIdleShellDoesNotLeakTheSession(t *testing.T) {
	h := newSessionHarness(t, func(c *agent.Config) {
		c.Shell = agent.Forkpty([]string{"/bin/sh"})
	})
	conn := h.serve(t, shellInvitation())
	_ = openFrom(t, conn)
	send(t, conn, frame.TypeReady, frame.Ready{SessionID: "s-1", Mode: "gateway"})

	// Let the shell reach its prompt, and drain whatever it printed so the agent is not
	// blocked writing to a connection nobody is reading.
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			_, err := conn.Recv(ctx)
			cancel()
			if err != nil {
				return
			}
		}
	}()
	time.Sleep(300 * time.Millisecond)

	send(t, conn, frame.TypeClose, frame.Close{Reason: "operator_close"})

	select {
	case err := <-h.served:
		if err != nil {
			t.Fatalf("Serve returned %v; the gateway closing is not an error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return: the session, its pty and its shell are leaked")
	}
	<-drained
}

// TestTheDefaultInvitationHandlerDialsAndLogsItsFailures.
//
// NewControl installs HandleInvitation when the embedder sets no OnInvitation, so this is
// what every default agent does with a DIAL. Leaving it nil and dropping invitations
// silently would make a correctly configured device look unreachable, so the wrapper
// exists — and its whole job is to run the session and turn an error into a log line
// rather than a lost invitation.
func TestTheDefaultInvitationHandlerDialsAndLogsItsFailures(t *testing.T) {
	h := newControlHarness(t, nil) // no OnInvitation: the default is installed
	h.run(t)
	conn := h.up(t)

	// A profile no build serves, so the session fails and the wrapper has something to
	// report. What matters is that it dialled at all.
	inv := shellInvitation()
	inv.Profile = "log"
	send(t, conn, frame.TypeDial, inv)

	waitFor(t, func() bool { return h.dialer.count() >= 2 },
		"the default handler never dialled the session")

	session := h.dialer.gateway(t)
	_ = openFrom(t, session)
	send(t, session, frame.TypeReady, frame.Ready{SessionID: "s-1", Mode: "gateway"})

	waitFor(t, func() bool {
		return strings.Contains(h.logs.String(), "session ended with an error")
	}, "the default handler swallowed the session's failure")
	// The slog attribute, not the bare word: "log" appears in every line of a log.
	if !strings.Contains(h.logs.String(), "profile=log") {
		t.Fatalf("the log does not name the profile:\n%s", h.logs.String())
	}
}
