package plugin

import (
	"context"
	"errors"

	"github.com/oarlock/oarlock/pkg/frame"
)

// ErrDeviceUnreachable means the doorbell worked and the *device* is not there —
// not subscribed, not registered for push, known to be off.
//
// Distinguishing this from a delivery failure matters more than it sounds. "Device
// is offline" sends someone to look at hardware in a gym. "I couldn't deliver the
// wake-up" sends someone to look at the broker. Returning the wrong one wastes an
// on-call hour, and the operator-facing text differs accordingly.
var ErrDeviceUnreachable = errors.New("plugin: device is not reachable")

// Dispatcher is the doorbell: how the gateway asks a device to dial back when it is
// not holding a control channel.
//
// It carries exactly the same frame.Invitation that a DIAL frame carries down a
// control channel, which is the return on not multiplexing (ADR-024) — downstream
// of arrival there is one code path, not two.
type Dispatcher interface {
	// Wake delivers an invitation. It must be fast, and it must distinguish
	// ErrDeviceUnreachable from every other error.
	//
	// The invitation's URL names a specific gateway node, so the agent connects to
	// the replica the operator is waiting on rather than to whatever a load
	// balancer picks. Do not rewrite it.
	Wake(ctx context.Context, dev *Device, inv frame.Invitation) error
}

// DispatcherFunc adapts a function to Dispatcher.
type DispatcherFunc func(ctx context.Context, dev *Device, inv frame.Invitation) error

// Wake implements Dispatcher.
func (f DispatcherFunc) Wake(ctx context.Context, dev *Device, inv frame.Invitation) error {
	return f(ctx, dev, inv)
}
