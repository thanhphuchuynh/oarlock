package invite_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/ticket"
	"github.com/oarlock/oarlock/pkg/transport/memory"
)

// The other half of releasing an uncollected attachment, and the half that was missing.
//
// Releasing the device closes its socket; it does not touch the session row, and this
// package deliberately cannot — it knows nothing about the ledger. So the row went on
// saying `waking` for the life of the process while nothing ran, and at the default
// `sessions_per_device: 1` that device could never be used again. Found by running the
// gateway locally: POST answered session_limit and DELETE answered wrong_node, forever.
func TestAnUncollectedAttachmentReportsItselfAbandoned(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, nil)
	h.inv.CollectDeadline = 120 * time.Millisecond

	type call struct{ session, device, reason string }
	abandoned := make(chan call, 4)
	h.inv.OnAbandoned = func(sessionID, deviceID, reason string) {
		abandoned <- call{sessionID, deviceID, reason}
	}

	if _, err := h.inv.Invite(ctx, persistentDevice(), req()); err != nil {
		t.Fatal(err)
	}
	inv, _ := h.last()
	devConn, _ := memory.Pair(0)
	if _, err := h.inv.Attach(ctx, inv.Ticket, ticket.Want{}, devConn); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-abandoned:
		if got.session != inv.SessionID {
			t.Errorf("session %q, want %q", got.session, inv.SessionID)
		}
		if got.device != persistentDevice().ID {
			t.Errorf("device %q, want %q", got.device, persistentDevice().ID)
		}
		// The same code every other site that withdraws an uncollected invitation
		// uses, so one screen covers all of them.
		if got.reason != "operator_gave_up" {
			t.Errorf("reason %q, want operator_gave_up", got.reason)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("an uncollected attachment was released without reporting it")
	}
}

// A collected attachment is a session somebody is using, and reporting it abandoned
// would close the row out from under a live shell.
func TestACollectedAttachmentIsNotReportedAbandoned(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, nil)
	h.inv.CollectDeadline = 120 * time.Millisecond

	var abandoned atomic.Int64
	h.inv.OnAbandoned = func(string, string, string) { abandoned.Add(1) }

	if _, err := h.inv.Invite(ctx, persistentDevice(), req()); err != nil {
		t.Fatal(err)
	}
	inv, _ := h.last()
	devConn, _ := memory.Pair(0)
	if _, err := h.inv.Attach(ctx, inv.Ticket, ticket.Want{}, devConn); err != nil {
		t.Fatal(err)
	}
	if _, err := h.inv.Collect(ctx, inv.SessionID); err != nil {
		t.Fatalf("could not collect the attachment: %v", err)
	}

	// Well past the collect deadline: the timer has fired and found it collected.
	time.Sleep(400 * time.Millisecond)
	if n := abandoned.Load(); n != 0 {
		t.Fatalf("a collected attachment was reported abandoned %d times", n)
	}
}
