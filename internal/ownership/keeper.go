package ownership

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// releaseTimeout bounds the release that runs as a control channel ends.
//
// Short on purpose. Release is cleanup on a path that is already unwinding, and a
// registry that has stopped answering must not hold a handler goroutine open — the
// lease expires by itself, which is the whole reason it has a clock on it.
const releaseTimeout = 5 * time.Second

// Keeper holds this node's claim on a device for as long as its control channel is up.
//
// One per gateway process, shared by every channel. A nil *Keeper is a working
// single-node gateway: Hold does nothing and returns no error, so the caller needs no
// branch and the multi-replica code path costs a nil check when it is not configured.
type Keeper struct {
	// Registry is the shared record. Nil disables the keeper.
	Registry Registry

	// Node identifies this process. Use the node's own externally reachable URL: it
	// is unique per replica by construction, it is already configured (`url`), and it
	// is what a peer needs in order to reach this node — so the identity and the
	// address cannot drift apart the way two separate settings would.
	Node string

	// RenewInterval and TTL default to DefaultRenewInterval and LeaseMultiple times
	// whatever the interval is, so setting only the interval keeps the ratio.
	RenewInterval time.Duration
	TTL           time.Duration

	Log *slog.Logger
}

func (k *Keeper) log() *slog.Logger {
	if k != nil && k.Log != nil {
		return k.Log
	}
	return slog.Default()
}

func (k *Keeper) renewInterval() time.Duration {
	if k.RenewInterval > 0 {
		return k.RenewInterval
	}
	return DefaultRenewInterval
}

func (k *Keeper) ttl() time.Duration {
	if k.TTL > 0 {
		return k.TTL
	}
	return k.renewInterval() * LeaseMultiple
}

// Enabled reports whether this keeper records anything.
func (k *Keeper) Enabled() bool { return k != nil && k.Registry != nil && k.Node != "" }

// Hold claims deviceID for this node and keeps the claim fresh until release is
// called.
//
// **The returned release is always non-nil, including when Hold returns an error.**
// The caller's shape is then `release, err := Hold(...)`, log the error, `defer
// release()` — with no branch that could skip the cleanup, which is the branch that
// eventually gets it wrong.
//
// A failure to claim is reported and not fatal. The device is dialled into this node
// and reachable through it whether or not the registry agrees, so refusing the channel
// would convert a registry outage into a fleet outage — see the package comment.
func (k *Keeper) Hold(ctx context.Context, deviceID string) (release func(), err error) {
	if !k.Enabled() || deviceID == "" {
		return func() {}, nil
	}

	// A claim failure is returned, not logged here, so it is reported once by the
	// caller that has the connection's context to report it with. The renew loop
	// starts either way: the registry may be back before the channel ends, and a
	// device whose channel outlives a brief outage should end up recorded rather than
	// invisible until it happens to reconnect.
	_, claimErr := k.Registry.Claim(ctx, deviceID, k.Node, k.ttl())

	// The loop's context is deliberately detached from the caller's. ctx here is the
	// request context of the device's connection, and by the time release runs it is
	// usually already cancelled — so a release that borrowed it would be a release
	// that never reached the registry.
	loopCtx, stop := context.WithCancel(context.WithoutCancel(ctx))
	done := make(chan struct{})
	go func() {
		defer close(done)
		k.renew(loopCtx, deviceID)
	}()

	var once sync.Once
	release = func() {
		once.Do(func() {
			stop()
			<-done
			rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), releaseTimeout)
			defer cancel()
			switch err := k.Registry.Release(rctx, deviceID, k.Node); {
			case err == nil, errors.Is(err, ErrHeldByAnother):
				// ErrHeldByAnother is the expected end of a device that moved to
				// another replica while this node's socket was still half-open. The
				// check is what stops this release from deleting the new owner's
				// lease, so arriving here means it did its job.
			default:
				k.log().Warn("could not release an ownership lease",
					"device", deviceID, "node", k.Node, "error", err)
			}
		})
	}
	return release, claimErr
}

// renew keeps the lease fresh until the context ends.
func (k *Keeper) renew(ctx context.Context, deviceID string) {
	t := time.NewTicker(k.renewInterval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		switch _, err := k.Registry.Renew(ctx, deviceID, k.Node, k.ttl()); {
		case err == nil:

		case errors.Is(err, ErrHeldByAnother):
			// The device reconnected somewhere else. That replica has the live
			// channel; this one has a socket that has not noticed yet, and the hub's
			// own liveness check will close it. Stop renewing rather than fight for a
			// device that is no longer here — a keeper that re-claimed on this error
			// would make two replicas take turns owning a device forever.
			k.log().Info("another node has taken over this device",
				"device", deviceID, "node", k.Node)
			return

		case errors.Is(err, ErrNotHeld):
			// The lease lapsed — a slow registry, or this node was paused past the
			// TTL. The channel is still here, so this node is still the right answer.
			if _, err := k.Registry.Claim(ctx, deviceID, k.Node, k.ttl()); err != nil {
				k.log().Warn("could not reclaim a lapsed ownership lease",
					"device", deviceID, "node", k.Node, "error", err)
			}

		default:
			// Transient. Keep the loop: the lease has room for LeaseMultiple of these
			// before another node may take over, which is what the multiple is for.
			k.log().Warn("renewing an ownership lease failed",
				"device", deviceID, "node", k.Node, "error", err)
		}
	}
}

// Elsewhere answers which *other* node holds the device.
//
// It is the read side, and it exists so the gateway can stop telling an operator that
// a device is not connected when it is connected to the replica next door. Empty
// string means "nobody else" — unheld, held by this node, or a registry that could not
// answer. All three collapse deliberately: the caller's next move is the same in every
// case, and a lookup failure must not become a different answer to the operator.
func (k *Keeper) Elsewhere(ctx context.Context, deviceID string) string {
	if !k.Enabled() || deviceID == "" {
		return ""
	}
	l, err := k.Registry.Lookup(ctx, deviceID)
	if err != nil {
		if !errors.Is(err, ErrNotHeld) {
			k.log().Warn("looking up which node holds a device failed",
				"device", deviceID, "error", err)
		}
		return ""
	}
	if l.Node == k.Node {
		return ""
	}
	return l.Node
}
