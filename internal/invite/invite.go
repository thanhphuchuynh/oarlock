// Package invite asks a device to dial back for one session.
//
// It is where the two reachability modes converge. Both mint the same ticket and
// build the same frame.Invitation; the only difference is delivery — a DIAL frame
// down a held control channel, or a Dispatcher over a doorbell the fleet already
// has. Downstream of arrival there is one code path (ADR-024).
package invite

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oarlock/oarlock/internal/ticket"
	"github.com/oarlock/oarlock/pkg/condition"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
	"github.com/oarlock/oarlock/pkg/transport"
)

// DefaultAnswerDeadline is how long the gateway waits for an agent to dial in.
//
// **This number is a guess and should be treated as one.** Thirty seconds is
// generous for a warm control channel and quite possibly too tight for an Android
// device waking from doze, where push delivery is routinely measured in minutes.
// E1.S9 measures it on real hardware; until then, expect to change it.
const DefaultAnswerDeadline = 30 * time.Second

// Failure carries both halves of what a failed invitation means: the machine code
// the API and the wire report, and the sentence an operator is shown.
//
// They are separate fields because they are separate audiences, and because two
// failures can share a code and still need different words. "This device isn't
// connected" and "The agent didn't answer" are both device_offline, and sending an
// operator to the wrong one of those is an hour of somebody's evening.
type Failure struct {
	Code      string
	Operator  string
	Retryable bool
	Cause     error
}

func (f *Failure) Error() string {
	if f.Cause != nil {
		return fmt.Sprintf("invite: %s: %v", f.Code, f.Cause)
	}
	return "invite: " + f.Code
}

func (f *Failure) Unwrap() error { return f.Cause }

// Is lets errors.Is match on the code, so callers compare against the sentinels
// below rather than string-matching a message.
func (f *Failure) Is(target error) bool {
	t, ok := target.(*Failure)
	return ok && t.Code == f.Code && t.Operator == f.Operator
}

// The failure set. Note that three of these share a wire code and none share
// operator text — which is the whole point of separating them.
var (
	// The codes come from pkg/condition, which is the closed set both surfaces render
	// from. They used to be three different sentences behind one code, `device_offline`,
	// with the distinguishing text in ERROR's `message` — a field the protocol says is
	// for humans and is never parsed. A browser could therefore render one screen for
	// all three, or break the contract to tell them apart. Now each condition has its
	// own code and its own screen.

	// ErrNotConnected: persistent mode, no control channel. The device is not there.
	ErrNotConnected = of("device_not_connected")
	// ErrUnreachable: the doorbell rang and reported the device is not reachable.
	ErrUnreachable = of("device_unreachable")
	// ErrNoAnswer: the invitation was delivered and nobody dialled in.
	ErrNoAnswer = of("device_offline")
	// ErrDoorbellFailed: *our* fault, not the device's. Saying "offline" here sends
	// someone to look at hardware in a gym when the broker is what is broken.
	ErrDoorbellFailed = of("doorbell_failed")
	// ErrAlreadyAttached: something already collected this session's device. Two
	// operators pumping one connection would interleave keystrokes into one shell.
	ErrAlreadyAttached = of("already_attached")
	// ErrNoRoute: a dispatch-mode device with no Dispatcher configured. A deployment
	// mistake, and it must not be reported as the device's problem.
	ErrNoRoute = of("no_wake_method")
	// ErrElsewhere: the device is connected, to another replica of this gateway. Only
	// reachable in a multi-replica deployment, and until the forwarding hop exists it
	// is the difference between sending somebody to check a treadmill and telling them
	// what actually happened.
	ErrElsewhere = of("device_on_another_node")
)

// of builds a Failure from the canonical condition table, so the code, the retryability
// and the operator-facing sentence cannot disagree with what the browser renders.
func of(id string) *Failure {
	c, ok := condition.Lookup(id)
	if !ok {
		// A programming error, and one worth being loud about: a code with no entry in
		// the table is a code with no screen behind it.
		panic("invite: no condition registered for " + id)
	}
	return &Failure{Code: c.ID, Operator: c.Headline, Retryable: c.Retryable}
}

func failure(base *Failure, cause error) *Failure {
	f := *base
	f.Cause = cause
	return &f
}

// Locator is the part of the ownership registry this package needs: which *other*
// replica is holding a device's control channel, or "" for nobody this node knows of.
//
// Deliberately a single string rather than a lease: this package decides where to send
// an invitation, and everything else on the record is somebody else's question.
type Locator interface {
	Elsewhere(ctx context.Context, deviceID string) string
}

// Reacher is the part of the hub this package needs: whether a device is holding a
// control channel, and how to send it a frame.
type Reacher interface {
	Connected(deviceID string) bool
	Invite(ctx context.Context, deviceID string, inv frame.Invitation) error
	Cancel(ctx context.Context, deviceID, sessionID, reason string) error
}

// Request is what an operator asked for.
type Request struct {
	SessionID   string
	Profile     string
	Principal   string
	OpenedBy    string
	Unattended  bool
	RecordInput bool
	PTY         *frame.PTY
	Exec        []string
	File        *frame.FileOp
	TCP         *frame.TCPTarget
	Log         *frame.LogSource

	// AttachTicket asks for an operator-side ticket as well as the device's.
	//
	// Only the browser flow needs one. The SSH path does not, and minting one anyway
	// would leave a spendable credential lying around for a connection nobody is
	// going to make.
	AttachTicket bool
}

// Inviter mints, delivers and tracks invitations.
type Inviter struct {
	Tickets    ticket.Store
	Hub        Reacher
	Dispatcher plugin.Dispatcher

	// Owners answers which other replica holds a device. Nil on a single-node
	// gateway, where the question has one answer and it is always this node.
	Owners Locator

	// NodeURL is the session endpoint on **this** node, e.g.
	// wss://gw-a.example.org/ws/session. Not a load balancer: the agent must land
	// on the replica the operator is waiting on (ADR-025).
	NodeURL string

	// AttachURL is the operator endpoint on this node, e.g.
	// wss://gw-a.example.org/ws/attach. Same reasoning: the browser has to reach the
	// replica holding the device, not whichever one a load balancer picks.
	AttachURL string

	TicketTTL      time.Duration
	AnswerDeadline time.Duration
	Now            func() time.Time
	Log            *slog.Logger

	// CollectDeadline is how long a device that has dialled in waits for an operator
	// to collect it. Zero means AnswerDeadline. A parked attachment nobody collects
	// is a shell running with nobody attached.
	CollectDeadline time.Duration

	mu          sync.Mutex
	pending     map[string]*Pending
	attachments map[string]*Attachment

	// attachTokens is the outstanding operator ticket per session, so renewing one
	// revokes its predecessor. Without it a page that reloads three times leaves
	// three spendable credentials for one session lying around; only one of them can
	// ever collect the device, but the other two are still credentials, and a
	// credential nobody needs is a credential nobody notices being used.
	attachTokens map[string]string
}

// Pending is a session waiting for its agent to dial in.
type Pending struct {
	SessionID string
	DeviceID  string
	Deadline  time.Time

	// Attach is the operator-side ticket, when one was asked for.
	Attach          string
	AttachExpiresAt time.Time

	token    string
	answered chan struct{}
	once     sync.Once
	inviter  *Inviter
}

// Attachment is a device that has dialled in and presented its ticket.
//
// It carries the connection *and* a completion signal, because two goroutines own
// different halves of the same session: the HTTP handler that upgraded the device's
// connection must stay alive until the session ends, while the operator's side is
// the one that knows when that is.
//
// # Why it is collected rather than handed over
//
// Over SSH one goroutine owns both waits: it invites the device and then blocks until
// the device arrives. The browser flow is two-sided and asynchronous — `POST
// /sessions` returns immediately with an attach ticket, and the operator's connection
// arrives on a *different* request, possibly seconds later. So an arriving device
// parks its attachment for collection instead of handing it to whoever happens to be
// blocked, and both paths collect through the same door.
//
// A parked attachment that nobody collects is a device holding a shell with no
// operator on the other end, so it expires.
type Attachment struct {
	Claims *ticket.Claims
	Conn   transport.Conn

	once      sync.Once
	done      chan struct{}
	collected atomic.Bool

	// timerMu guards timer. time.AfterFunc arms the timer *before* the assignment
	// storing it completes, so the callback and the assignment are two unsynchronised
	// accesses to one field — a real race, not a theoretical one, and the sort that
	// surfaces as a corrupt pointer under load rather than as a clean failure.
	timerMu sync.Mutex
	timer   *time.Timer
}

func (a *Attachment) setTimer(t *time.Timer) {
	a.timerMu.Lock()
	a.timer = t
	a.timerMu.Unlock()
}

// stopTimer disarms the release timer, if it is armed. Safe to call from the timer's
// own callback, where it finds nothing to stop.
func (a *Attachment) stopTimer() {
	a.timerMu.Lock()
	t := a.timer
	a.timer = nil
	a.timerMu.Unlock()
	if t != nil {
		t.Stop()
	}
}

// Done says the session is over. Called by whichever side ran the pump.
func (a *Attachment) Done() {
	a.once.Do(func() {
		a.stopTimer()
		close(a.done)
	})
}

// Collected reports whether an operator took this attachment.
func (a *Attachment) Collected() bool { return a.collected.Load() }

// Wait blocks until Done. Called by the handler holding the device's connection
// open, so returning from it does not tear the socket down mid-session.
func (a *Attachment) Wait(ctx context.Context) error {
	select {
	case <-a.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Wait blocks until the agent dials in, the deadline passes, or ctx ends, and
// collects the attachment.
//
// This is the SSH path: one goroutine invites and then waits. The browser path calls
// Collect on a later request instead, and both end up in the same place.
func (p *Pending) Wait(ctx context.Context) (*Attachment, error) {
	timer := time.NewTimer(time.Until(p.Deadline))
	defer timer.Stop()
	select {
	case <-p.answered:
		return p.inviter.Collect(ctx, p.SessionID)
	case <-timer.C:
		return nil, failure(ErrNoAnswer, fmt.Errorf("no OPEN within the answer deadline"))
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (i *Inviter) now() time.Time {
	if i.Now != nil {
		return i.Now()
	}
	return time.Now()
}

func (i *Inviter) log() *slog.Logger {
	if i.Log != nil {
		return i.Log
	}
	return slog.Default()
}

// Invite mints a ticket, delivers an invitation by whichever route the device uses,
// and returns a handle to wait on.
//
// A failed delivery revokes the ticket before returning. Leaving a spendable ticket
// behind for a session nobody is waiting on is how a device that wakes up late
// spends a credential on a shell with no operator attached.
func (i *Inviter) Invite(ctx context.Context, dev *plugin.Device, req Request) (*Pending, error) {
	switch {
	case dev == nil:
		return nil, errors.New("invite: device is required")
	case req.SessionID == "" || req.Profile == "":
		return nil, errors.New("invite: SessionID and Profile are required")
	case i.NodeURL == "":
		return nil, errors.New("invite: NodeURL is required")
	}

	ttl := i.TicketTTL
	if ttl <= 0 {
		ttl = ticket.DefaultTTL
	}
	deadline := i.AnswerDeadline
	if deadline <= 0 {
		deadline = DefaultAnswerDeadline
	}
	// The ticket must outlive the wait, or a device that answers just inside the
	// deadline finds its credential already expired.
	if ttl < deadline {
		ttl = deadline + 5*time.Second
	}

	token, err := i.Tickets.Mint(ctx, ticket.Claims{
		SessionID:   req.SessionID,
		DeviceID:    dev.ID,
		Profile:     req.Profile,
		Principal:   req.Principal,
		OpenedBy:    req.OpenedBy,
		Unattended:  req.Unattended,
		RecordInput: req.RecordInput,
		Kind:        ticket.KindDevice,
	}, ttl)
	if err != nil {
		return nil, fmt.Errorf("invite: minting a ticket: %w", err)
	}

	now := i.now()
	inv := frame.Invitation{
		SessionID: req.SessionID,
		Ticket:    token,
		URL:       i.NodeURL,
		Profile:   req.Profile,
		PTY:       req.PTY,
		Exec:      req.Exec,
		File:      req.File,
		TCP:       req.TCP,
		Log:       req.Log,
		Principal: req.Principal,
		ExpiresAt: now.Add(ttl).UTC().Format(time.RFC3339),
	}

	p := &Pending{
		SessionID: req.SessionID,
		DeviceID:  dev.ID,
		Deadline:  now.Add(deadline),
		token:     token,
		answered:  make(chan struct{}),
		inviter:   i,
	}

	if req.AttachTicket {
		attachTTL := ttl
		attach, err := i.Tickets.Mint(ctx, ticket.Claims{
			SessionID:   req.SessionID,
			DeviceID:    dev.ID,
			Profile:     req.Profile,
			Principal:   req.Principal,
			OpenedBy:    req.OpenedBy,
			Unattended:  req.Unattended,
			RecordInput: req.RecordInput,
			Kind:        ticket.KindAttach,
		}, attachTTL)
		if err != nil {
			_ = i.Tickets.Revoke(ctx, token)
			return nil, fmt.Errorf("invite: minting an attach ticket: %w", err)
		}
		p.Attach, p.AttachExpiresAt = attach, now.Add(attachTTL)
		i.rememberAttachToken(req.SessionID, attach)
	}

	i.register(p)

	if err := i.deliver(ctx, dev, inv); err != nil {
		i.drop(p)
		_ = i.Tickets.Revoke(ctx, token)
		if p.Attach != "" {
			// Both halves go, or a failed invite leaves an attach ticket for a
			// session that will never exist.
			_ = i.Tickets.Revoke(ctx, p.Attach)
			i.forgetAttachToken(p.SessionID)
		}
		return nil, err
	}

	// Deliberately not logging the ticket. A doorbell payload is a credential, and
	// a log line is the one place a single-use secret becomes multi-use.
	i.log().Info("invited a device to dial",
		"device", dev.ID, "session", req.SessionID, "profile", req.Profile,
		"mode", dev.ResolvedMode(), "deadline", p.Deadline)
	return p, nil
}

func (i *Inviter) deliver(ctx context.Context, dev *plugin.Device, inv frame.Invitation) error {
	// A held control channel is used whatever the configured mode says.
	//
	// The mode describes how to reach a device that is *not* connected. A device holding
	// a channel right now is reachable through it, and branching on the mode alone made
	// the gateway refuse a session with `no_wake_method` — "no wake-up method is
	// configured for this device" — while it was holding that very device's control
	// channel. Which is the gateway declining to use a connection it already has,
	// because a doorbell it does not need is not configured.
	//
	// That is not a hypothetical: a device on the `android` platform resolves to
	// dispatch, because the platform resists a held connection. It does not forbid one.
	// An agent that manages to hold one anyway — a foreground service, a device on
	// mains power, anything running on a desk during development — should be reached
	// through it, and using it is strictly better where it applies: no doorbell
	// latency and no external dependency.
	if i.Hub != nil && i.Hub.Connected(dev.ID) {
		err := i.Hub.Invite(ctx, dev.ID, inv)
		if err == nil {
			return nil
		}
		// The channel died between the check and the send. For a persistent device that
		// is the device being gone. For a dispatch device there is still a doorbell to
		// try, and trying it is the whole point of having one.
		if dev.ResolvedMode() == plugin.ModePersistent {
			return failure(ErrNotConnected, err)
		}
		i.log().Warn("the device's control channel failed; falling back to the doorbell",
			"device", dev.ID, "session", inv.SessionID, "error", err)
	}

	switch dev.ResolvedMode() {
	case plugin.ModePersistent:
		// Not on this node, and persistent mode has no doorbell to fall back to. Before
		// concluding the device is not there, ask whether another replica is holding
		// it — "isn't connected" and "is connected to the node next door" send an
		// operator to different places, and only one of those places has anything
		// wrong with it.
		//
		// Only here, and deliberately not before the switch: a dispatch-mode device
		// that happens to hold a channel to another node is still wakeable by *this*
		// node's doorbell, and answering with the owner would refuse a session that
		// would have worked.
		//
		// This is where E6.S2's forwarding hop goes: with the owner in hand the
		// invitation can be handed to that node instead of to the operator.
		if i.Owners != nil {
			if node := i.Owners.Elsewhere(ctx, dev.ID); node != "" {
				i.log().Info("the device is held by another node",
					"device", dev.ID, "session", inv.SessionID, "node", node)
				return failure(ErrElsewhere, fmt.Errorf("held by %s", node))
			}
		}
		return failure(ErrNotConnected, nil)

	case plugin.ModeDispatch:
		if i.Dispatcher == nil {
			return failure(ErrNoRoute, nil)
		}
		err := i.Dispatcher.Wake(ctx, dev, inv)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, plugin.ErrDeviceUnreachable):
			return failure(ErrUnreachable, err)
		default:
			return failure(ErrDoorbellFailed, err)
		}

	default:
		return failure(ErrNoRoute, fmt.Errorf("unknown mode %q", dev.ResolvedMode()))
	}
}

// Attach spends a ticket and hands the connection to whoever is waiting.
//
// One entry point, so redeeming a ticket and "stop waiting" cannot drift apart. A
// ticket that is valid but has no waiter — the operator gave up, or this is a
// replay arriving after a legitimate attach — is refused: the connection has
// nowhere to go, and pairing it with nothing would leave a shell running with no
// operator on the other end.
func (i *Inviter) Attach(ctx context.Context, token string, want ticket.Want,
	conn transport.Conn) (*Attachment, error) {

	claims, err := i.Tickets.Redeem(ctx, token)
	if err != nil {
		return nil, err
	}
	if err := claims.Check(want); err != nil {
		return nil, err
	}

	a := &Attachment{Claims: claims, Conn: conn, done: make(chan struct{})}

	i.mu.Lock()
	p := i.pending[claims.SessionID]
	if p != nil {
		delete(i.pending, claims.SessionID)
		if i.attachments == nil {
			i.attachments = make(map[string]*Attachment)
		}
		i.attachments[claims.SessionID] = a
	}
	i.mu.Unlock()

	if p == nil {
		return nil, failure(ErrNoAnswer,
			fmt.Errorf("no operator is waiting for session %s", claims.SessionID))
	}

	// A device that arrives and is never collected holds a shell with nobody on the
	// other end. Park it, but not forever.
	collectBy := i.CollectDeadline
	if collectBy <= 0 {
		collectBy = deadlineOr(i.AnswerDeadline)
	}
	a.setTimer(time.AfterFunc(collectBy, func() {
		i.mu.Lock()
		still := i.attachments[claims.SessionID] == a
		if still {
			delete(i.attachments, claims.SessionID)
		}
		i.mu.Unlock()
		if still && !a.collected.Load() {
			i.log().Warn("no operator collected an attached device; releasing it",
				"session", claims.SessionID, "device", claims.DeviceID, "after", collectBy)
			a.Done()
		}
	}))

	p.once.Do(func() { close(p.answered) })
	return a, nil
}

// MintAttach issues an operator-side ticket for a session that already exists,
// revoking any outstanding one.
//
// This is the other half of single-use. A browser spends its ticket on connect, so a
// page that reloads, a handshake that fails, or a ticket that ages past 60 s leaves the
// operator with a live session and no way back into it. Renewing is not a weakening of
// NFR8 — the new ticket is scoped and short-lived exactly like the first — and it is
// the moment authorisation gets re-checked for free, which is why the caller does that
// check before calling this.
func (i *Inviter) MintAttach(ctx context.Context, c ticket.Claims, ttl time.Duration) (string, time.Time, error) {
	if c.SessionID == "" || c.DeviceID == "" {
		return "", time.Time{}, errors.New("invite: SessionID and DeviceID are required")
	}
	if ttl <= 0 {
		ttl = ticket.DefaultTTL
	}
	c.Kind = ticket.KindAttach
	token, err := i.Tickets.Mint(ctx, c, ttl)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("invite: minting an attach ticket: %w", err)
	}

	prev := i.rememberAttachToken(c.SessionID, token)

	// Best effort, and after the new one exists: failing to revoke the old ticket is
	// worth a log line, not a failed renewal that leaves the operator locked out.
	if prev != "" && prev != token {
		if err := i.Tickets.Revoke(ctx, prev); err != nil {
			i.log().Warn("could not revoke a replaced attach ticket",
				"session", c.SessionID, "error", err)
		}
	}
	return token, i.now().Add(ttl).UTC(), nil
}

// rememberAttachToken records the outstanding operator ticket and returns the one it
// replaced, if any.
func (i *Inviter) rememberAttachToken(sessionID, token string) string {
	i.mu.Lock()
	defer i.mu.Unlock()
	prev := i.attachTokens[sessionID]
	if i.attachTokens == nil {
		i.attachTokens = make(map[string]string)
	}
	i.attachTokens[sessionID] = token
	return prev
}

// MintObserve issues a read-only watch ticket for a live session (FR13).
//
// Not tracked in attachTokens and not revoking anything: several people may watch one
// session at once, so a new watch ticket is not a replacement for an old one. That is the
// difference from MintAttach, where exactly one credential should be live at a time
// because exactly one person can hold the keyboard.
func (i *Inviter) MintObserve(ctx context.Context, c ticket.Claims, ttl time.Duration) (string, time.Time, error) {
	if c.SessionID == "" || c.DeviceID == "" {
		return "", time.Time{}, errors.New("invite: SessionID and DeviceID are required")
	}
	if ttl <= 0 {
		ttl = ticket.DefaultTTL
	}
	c.Kind = ticket.KindObserve
	token, err := i.Tickets.Mint(ctx, c, ttl)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("invite: minting a watch ticket: %w", err)
	}
	return token, i.now().Add(ttl).UTC(), nil
}

// forgetAttachToken drops the bookkeeping for a spent or dead session.
func (i *Inviter) forgetAttachToken(sessionID string) {
	i.mu.Lock()
	delete(i.attachTokens, sessionID)
	i.mu.Unlock()
}

// Collect takes the attachment for a session, once — **waiting** for the device if it
// has not arrived yet.
//
// The waiting is the whole point, and getting it wrong is a real bug rather than a
// nicety. Over SSH one goroutine invites and then blocks, so the device is always
// there by the time anything collects. In the browser flow `POST /sessions` returns as
// soon as the invitation is *delivered*, and the operator's connection arrives on a
// separate request — often faster than the device can wake, dial, and present its
// ticket. A Collect that failed when the device had not arrived yet reported
// "the agent didn't answer" for sessions that were perfectly fine, intermittently,
// depending on which of two network round trips won.
//
// Atomic by construction: a second caller gets ErrAlreadyAttached rather than a second
// reference to the same connection. Two pumps on one device connection would interleave
// keystrokes into one shell.
func (i *Inviter) Collect(ctx context.Context, sessionID string) (*Attachment, error) {
	// Already parked: the common case once a device is quick or the operator is slow.
	if a, err := i.take(sessionID); a != nil || err != nil {
		return a, err
	}

	i.mu.Lock()
	p := i.pending[sessionID]
	i.mu.Unlock()
	if p == nil {
		// Never invited, expired, or already collected by somebody else. The last of
		// those is the interesting one, and take() below distinguishes it.
		return nil, failure(ErrNoAnswer,
			fmt.Errorf("nothing is pending for session %s", sessionID))
	}

	timer := time.NewTimer(time.Until(p.Deadline))
	defer timer.Stop()
	select {
	case <-p.answered:
		a, err := i.take(sessionID)
		if err != nil {
			return nil, err
		}
		if a == nil {
			// Answered, but the attachment is gone: another collector won.
			return nil, ErrAlreadyAttached
		}
		return a, nil
	case <-timer.C:
		return nil, failure(ErrNoAnswer,
			fmt.Errorf("no OPEN within the answer deadline"))
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// take removes a parked attachment, or returns nil if there is none.
func (i *Inviter) take(sessionID string) (*Attachment, error) {
	i.mu.Lock()
	a := i.attachments[sessionID]
	if a != nil {
		delete(i.attachments, sessionID)
	}
	i.mu.Unlock()

	if a == nil {
		return nil, nil
	}
	if !a.collected.CompareAndSwap(false, true) {
		return nil, ErrAlreadyAttached
	}
	a.stopTimer()
	// The ticket that got somebody here is spent, so there is nothing left to revoke
	// on the next renewal.
	i.forgetAttachToken(sessionID)
	return a, nil
}

// AwaitingCollection is how many devices have dialled in with no operator yet, for
// metrics.
func (i *Inviter) AwaitingCollection() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return len(i.attachments)
}

func deadlineOr(d time.Duration) time.Duration {
	if d <= 0 {
		return DefaultAnswerDeadline
	}
	return d
}

// Redeem spends a ticket and returns its claims, without collecting anything.
//
// The operator side uses this: an attach ticket proves who is arriving and for which
// session, and the device's connection is then collected separately. Splitting the two
// means a valid ticket with no device parked is reported as "the device has not
// attached" rather than as a bad ticket — different facts, different remedies.
func (i *Inviter) Redeem(ctx context.Context, token string, want ticket.Want) (*ticket.Claims, error) {
	claims, err := i.Tickets.Redeem(ctx, token)
	if err != nil {
		return nil, err
	}
	if err := claims.Check(want); err != nil {
		return nil, err
	}
	return claims, nil
}

// Cancel withdraws an invitation: the ticket is revoked, and a persistent-mode
// device is told not to bother dialling.
//
// Without the second half, a device that woke slowly dials for a session nobody is
// waiting on, spends a ticket, and is told to go away — which looks like a bug from
// the device's side and costs a handshake for nothing.
func (i *Inviter) Cancel(ctx context.Context, sessionID, reason string) {
	i.mu.Lock()
	p := i.pending[sessionID]
	if p != nil {
		delete(i.pending, sessionID)
	}
	i.mu.Unlock()
	if p == nil {
		return
	}
	_ = i.Tickets.Revoke(ctx, p.token)
	if p.Attach != "" {
		_ = i.Tickets.Revoke(ctx, p.Attach)
	}
	i.forgetAttachToken(sessionID)
	if p.Attach != "" {
		_ = i.Tickets.Revoke(ctx, p.Attach)
	}
	if i.Hub != nil && i.Hub.Connected(p.DeviceID) {
		_ = i.Hub.Cancel(ctx, p.DeviceID, sessionID, reason)
	}
	i.log().Info("withdrew an invitation",
		"device", p.DeviceID, "session", sessionID, "reason", reason)
}

// Outstanding is the number of invitations awaiting an answer, for metrics.
func (i *Inviter) Outstanding() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return len(i.pending)
}

func (i *Inviter) register(p *Pending) {
	i.mu.Lock()
	if i.pending == nil {
		i.pending = make(map[string]*Pending)
	}
	i.pending[p.SessionID] = p
	i.mu.Unlock()
}

func (i *Inviter) drop(p *Pending) {
	i.mu.Lock()
	if i.pending[p.SessionID] == p {
		delete(i.pending, p.SessionID)
	}
	i.mu.Unlock()
}
