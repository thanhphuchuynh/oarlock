package plugin

import (
	"context"
	"errors"
	"path/filepath"
	"time"
)

var (
	ErrNoPermission     = errors.New("plugin: no such permission")
	ErrPermissionExists = errors.New("plugin: permission already exists")
)

// Permission is one durable authorization rule managed through the admin API.
type Permission struct {
	ID          string
	Name        string
	Principals  []string
	Devices     []string
	Tags        map[string]string
	Actions     []string
	Deny        bool
	Reason      string
	Priority    int
	Enabled     bool
	MaxDuration time.Duration
	Idle        time.Duration
	TTL         time.Duration
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// AppliesTo reports whether this permission is written about this device.
//
// Device and tag matching only — no principal, no action. So it answers "which rules
// mention this device", which is the question a fleet view asks when it shows who can
// reach something, and deliberately not "may this operator do this now", which is
// Authorize's job and needs the whole decision.
//
// It lives here, on the type, because the authorisation backend and the admin API both
// need this exact predicate. A second copy of glob-and-tag matching written in the
// console — or in TypeScript, one network hop from the real one — would drift, and the
// direction it drifts is a UI that says somebody cannot reach a device they can.
func (p *Permission) AppliesTo(dev *Device) bool {
	if p == nil || dev == nil {
		return false
	}
	// An empty device list is every device. Written this way round because `devices:` is
	// the optional half of a rule and `principals:` is not.
	if len(p.Devices) > 0 && !matchesAny(p.Devices, dev.ID) {
		return false
	}
	// Every listed tag must match. A rule scoped to PCI *and* the EU does not apply to a
	// device that is only one of them.
	for key, value := range p.Tags {
		if dev.Tags[key] != value {
			return false
		}
	}
	return true
}

// matchesAny is glob matching with an exact-match and "*" fast path.
func matchesAny(patterns []string, value string) bool {
	for _, pattern := range patterns {
		if pattern == "*" || pattern == value {
			return true
		}
		if ok, err := filepath.Match(pattern, value); err == nil && ok {
			return true
		}
	}
	return false
}

// MatchesPrincipal reports whether this permission is written about this principal id.
func (p *Permission) MatchesPrincipal(id string) bool {
	return p != nil && matchesAny(p.Principals, id)
}

// Grants reports whether this permission lists the action, `"*"` included. It says
// nothing about effect: a deny that grants an action is a deny of that action.
func (p *Permission) Grants(action Action) bool {
	if p == nil {
		return false
	}
	for _, candidate := range p.Actions {
		if candidate == "*" || candidate == string(action) {
			return true
		}
	}
	return false
}

type PermissionAdmin interface {
	ListPermissions(ctx context.Context) ([]*Permission, error)
	GetPermission(ctx context.Context, id string) (*Permission, error)
	CreatePermission(ctx context.Context, permission *Permission) error
	UpdatePermission(ctx context.Context, permission *Permission) error
	DeletePermission(ctx context.Context, id string) error
}
