// Package plugin holds the interfaces Oarlock is extended through, and the types
// they exchange. It is public API: an integration compiled out of tree imports
// this and nothing else from the module.
//
// Every interface here has a working default somewhere under internal/ or
// plugins/, because `go run` must need no external service — and scale must not
// need a fork.
package plugin

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Errors a DeviceRegistry returns.
var (
	ErrNoDevice = errors.New("plugin: no such device")
	// ErrUnsupported is the honest answer for an optional capability a backend does
	// not have. It is never a security failure: the gateway falls back to whatever
	// the interface documents.
	ErrUnsupported = errors.New("plugin: not supported by this backend")
)

// Platform is what a device runs. It exists to pick the reachability default,
// because the right default differs by platform rather than by deployment.
type Platform string

const (
	PlatformAndroid   Platform = "android"
	PlatformLinux     Platform = "linux"
	PlatformContainer Platform = "container"
	PlatformOther     Platform = "other"
)

// Mode is how the gateway reaches a device.
type Mode string

const (
	// ModePersistent: the agent holds a control channel open. No doorbell needed.
	ModePersistent Mode = "persistent"
	// ModeDispatch: the gateway rings a doorbell and the agent dials per session.
	ModeDispatch Mode = "dispatch"
)

// deviceIDRe keeps ids to something safe to put in a log line, a metric label, a
// filesystem path and an SSH username — because a device id ends up in all four.
var deviceIDRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

// ValidDeviceID reports whether id is acceptable.
func ValidDeviceID(id string) bool { return deviceIDRe.MatchString(id) }

// Device is what the gateway knows about a device. It is read-only: Oarlock does
// not enroll devices, name them, or own their lifecycle — it reads from whatever
// already does.
type Device struct {
	ID       string
	Platform Platform

	// Mode overrides the platform default. Empty means resolve from Platform.
	Mode Mode

	// Keys are the device's control-channel identity keys.
	//
	// A list, not a key, and that is the whole rotation story: publish the new key
	// alongside the old, let devices roll over, then retire the old one. A single
	// key would make rotation a flag day.
	Keys []ed25519.PublicKey

	// AllowPassthrough enables mode A for this device. Off by default: an
	// unrecorded session must never be an accident.
	AllowPassthrough bool

	// Tags are what Authorizer selectors and record_input policy selectors match
	// on. Doing double duty is deliberate — it means compliance scope and
	// jurisdiction ride the mechanism that already exists, and no tenancy concept
	// has to be invented to carry them.
	Tags map[string]string

	// Profiles is what this device may be asked to do. Empty means the gateway's
	// default set.
	Profiles []string
}

// ResolvedMode returns the reachability mode to use.
//
// Android resolves to dispatch because the platform actively resists a held
// connection: apps are bucketed into standby tiers, persistent connections can be
// flagged as excessive, and a dataSync foreground service cannot be started from
// BOOT_COMPLETED — which is exactly when a rebooted device needs to be reachable.
// Everything else resolves to persistent, because nothing there objects and it
// needs no doorbell.
func (d Device) ResolvedMode() Mode {
	if d.Mode != "" {
		return d.Mode
	}
	switch d.Platform {
	case PlatformAndroid:
		return ModeDispatch
	default:
		return ModePersistent
	}
}

// ModeWasDefaulted reports whether ResolvedMode came from the platform rather than
// from configuration, so the gateway can log a surprising default once at
// registration instead of never.
func (d Device) ModeWasDefaulted() bool { return d.Mode == "" }

// Supports reports whether this device may be asked for a profile. An empty
// Profiles list means "the gateway's defaults", which the caller applies.
func (d Device) Supports(profile string) bool {
	if len(d.Profiles) == 0 {
		return true
	}
	for _, p := range d.Profiles {
		if p == profile {
			return true
		}
	}
	return false
}

// HasKey reports whether pub is one of this device's identity keys.
func (d Device) HasKey(pub ed25519.PublicKey) bool {
	for _, k := range d.Keys {
		if k.Equal(pub) {
			return true
		}
	}
	return false
}

// DeviceQuery filters a List.
type DeviceQuery struct {
	Platform Platform
	Mode     Mode
	Tags     map[string]string
	Limit    int
	After    string // cursor: the last id from the previous page
}

// DeviceRegistry is where device identity comes from. Read-only by design.
type DeviceRegistry interface {
	// Get returns the device, or an error wrapping ErrNoDevice.
	Get(ctx context.Context, id string) (*Device, error)
	// List returns a page of devices and the cursor for the next one.
	List(ctx context.Context, q DeviceQuery) (devices []*Device, next string, err error)
}

// ── key encoding ────────────────────────────────────────────────────────────────

const sshEd25519Prefix = "ssh-ed25519"

// ParseDeviceKey accepts either of the two forms a person or a provisioning system
// is likely to have:
//
//	ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA… optional comment
//	<base64 of the raw 32-byte key>
//
// The OpenSSH form is supported because it is what `ssh-keygen -t ed25519`
// produces, and requiring a bespoke encoding for no reason is how a registry file
// becomes something only a script can write.
func ParseDeviceKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("plugin: empty key")
	}
	if strings.HasPrefix(s, sshEd25519Prefix) {
		fields := strings.Fields(s)
		if len(fields) < 2 {
			return nil, errors.New("plugin: ssh-ed25519 key has no body")
		}
		blob, err := base64.StdEncoding.DecodeString(fields[1])
		if err != nil {
			return nil, fmt.Errorf("plugin: ssh-ed25519 body is not base64: %w", err)
		}
		return parseSSHEd25519(blob)
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		if raw, err = base64.RawStdEncoding.DecodeString(s); err != nil {
			return nil, fmt.Errorf("plugin: key is not base64: %w", err)
		}
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("plugin: key is %d bytes, want %d",
			len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// parseSSHEd25519 reads the SSH public-key wire format: a length-prefixed
// algorithm name followed by a length-prefixed key. Thirty lines here beats a
// dependency on an SSH library the gateway does not otherwise need at this layer.
func parseSSHEd25519(blob []byte) (ed25519.PublicKey, error) {
	name, rest, err := sshString(blob)
	if err != nil {
		return nil, fmt.Errorf("plugin: ssh key algorithm: %w", err)
	}
	if string(name) != sshEd25519Prefix {
		return nil, fmt.Errorf("plugin: key algorithm is %q, want %q", name, sshEd25519Prefix)
	}
	key, rest, err := sshString(rest)
	if err != nil {
		return nil, fmt.Errorf("plugin: ssh key body: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("plugin: %d trailing bytes after the key", len(rest))
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("plugin: ssh key is %d bytes, want %d",
			len(key), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(key), nil
}

func sshString(b []byte) (val, rest []byte, err error) {
	if len(b) < 4 {
		return nil, nil, errors.New("truncated length prefix")
	}
	n := binary.BigEndian.Uint32(b[:4])
	// Bound before slicing: a 4-byte length from an untrusted file must not become
	// an index into nothing.
	if uint64(n) > uint64(len(b)-4) {
		return nil, nil, fmt.Errorf("length %d exceeds the %d bytes available", n, len(b)-4)
	}
	return b[4 : 4+n], b[4+n:], nil
}

// EncodeDeviceKey renders a key in the raw base64 form, for writing a registry
// file or logging a fingerprint-adjacent value.
func EncodeDeviceKey(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}
