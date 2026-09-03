package invite_test

import (
	"context"
	"testing"

	"github.com/oarlock/oarlock/internal/invite"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
)

// locator is a fixed answer to "which other node holds this device".
type locator struct{ node string }

func (l locator) Elsewhere(context.Context, string) string { return l.node }

const otherNode = "wss://gw-b.example.org"

// The diagnosis this whole story is for. A persistent device that is not on this node
// used to be reported as not connected, which sends somebody to look at a machine that
// is fine.
func TestAPersistentDeviceHeldElsewhereIsReportedAsSuch(t *testing.T) {
	h := newHarness(t, nil)
	h.hub.connected = false
	h.inv.Owners = locator{node: otherNode}

	_, err := h.inv.Invite(context.Background(), persistentDevice(), req())
	assertFailure(t, err, invite.ErrElsewhere, "device_on_another_node")
}

// And when nobody else holds it, the answer is unchanged: the device really is not
// there. A locator that is configured but has nothing to say must not colour the
// ordinary case.
func TestAPersistentDeviceNobodyHoldsIsStillNotConnected(t *testing.T) {
	h := newHarness(t, nil)
	h.hub.connected = false
	h.inv.Owners = locator{node: ""}

	_, err := h.inv.Invite(context.Background(), persistentDevice(), req())
	assertFailure(t, err, invite.ErrNotConnected, "device_not_connected")
}

// The regression this placement exists to avoid. A dispatch-mode device holding a
// channel to another replica is still wakeable by *this* node's doorbell — the
// doorbell is not per-node. Answering with the owner instead would refuse a session
// that works, in exactly the multi-replica deployment the ownership record is for.
func TestADispatchDeviceHeldElsewhereStillRingsTheDoorbell(t *testing.T) {
	rang := 0
	h := newHarness(t, plugin.DispatcherFunc(
		func(context.Context, *plugin.Device, frame.Invitation) error {
			rang++
			return nil
		}))
	h.hub.connected = false
	h.inv.Owners = locator{node: otherNode}

	if _, err := h.inv.Invite(context.Background(), dispatchDevice(), req()); err != nil {
		t.Fatalf("a dispatch device held elsewhere was refused: %v", err)
	}
	if rang != 1 {
		t.Fatalf("the doorbell rang %d times, want 1", rang)
	}
}
