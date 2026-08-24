package main

// Configuration from a file, for the deployments where flags are the wrong shape.
//
// An `init` service on Android is the case that forced this. Its argv is fixed at build
// time in an `.rc` file that lives in a system image, so anything an operator might want
// to change — the gateway, the pins, which user a session runs as — has to come from
// somewhere writable. Flags stay authoritative when both are given, because a flag is
// something somebody typed just now.

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/oarlock/oarlock/agent"
)

// Config is the agent's file configuration. Every field has a flag equivalent except
// Sessions and DNS, which are deployment concerns rather than things to type.
type Config struct {
	Gateway string `yaml:"gateway"`
	Device  string `yaml:"device"`
	// DeviceFile reads the id from a file instead of naming it here.
	//
	// It exists because the id is usually per-device and the config is usually not:
	// one image, one config, ten thousand machines. `init` cannot reliably expand a
	// property into a service argument, so provisioning — or an `exec` line running
	// `getprop ro.serialno` — writes the id once and the agent reads it.
	DeviceFile string `yaml:"device_file"`

	Key             string   `yaml:"key"`
	Shell           string   `yaml:"shell"`
	Pins            []string `yaml:"pins"`
	InsecureSkipPin bool     `yaml:"insecure_skip_pin"`

	// DNS names resolvers explicitly.
	//
	// Android has no /etc/resolv.conf, so a CGO-free build falls back to 127.0.0.1:53
	// where nothing is listening, and a gateway URL with a hostname never resolves at
	// all. An address without a port gets :53.
	DNS []string `yaml:"dns"`

	Sessions Sessions `yaml:"sessions"`

	// Exec is the allow-list for the `exec` profile: complete argvs, matched element for
	// element. Empty — the default — means this device does not offer `exec` at all, and
	// the gateway then refuses such a session at open time rather than after a round trip.
	//
	// Exact argvs rather than a list of programs with free arguments. See agent.Exec for
	// why: `tail` with a caller-chosen path reads any file, `find -exec` runs anything,
	// and deciding which flags of which binary are safe is a per-binary research project.
	Exec [][]string `yaml:"exec"`
	// ExecTimeout bounds one command. Zero uses the agent default.
	ExecTimeout time.Duration `yaml:"exec_timeout"`
}

// Sessions says what OS identity a session's shell runs as.
//
// The gateway decides who may open a shell. Only the agent can decide what that shell
// can touch, and if it decides nothing then every operator gets whatever the agent
// process is — which for a service started by `init` is root, for everybody.
type Sessions struct {
	// User is the identity for any profile without its own entry. Empty inherits the
	// agent's own identity, which is right when `init` already starts it as the user
	// you want and wrong the moment the agent runs as root.
	User string `yaml:"user"`
	// Groups are the supplementary groups a dropped session holds. Empty drops all of
	// them. On Android you generally want 1007 (log) and 3003 (inet), or the session
	// cannot write a log line or open a socket.
	Groups []uint32 `yaml:"groups"`
	// PerProfile overrides User for one profile. This is where two privilege tiers on
	// one device live: `exec` for field service, `shell` for on-call.
	PerProfile map[string]string `yaml:"per_profile"`
}

// LoadConfig reads a config file. A missing path is not an error — the caller decides
// whether it had to be there.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	// Unknown keys are refused rather than ignored, for the same reason the gateway
	// refuses them: `insecure_skip_pen: true` that quietly stays false is a security
	// setting somebody believes they set.
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("agent config %s: %w", path, err)
	}
	if c.Device != "" && c.DeviceFile != "" {
		return nil, fmt.Errorf("agent config %s: set device or device_file, not both", path)
	}
	if c.DeviceFile != "" {
		raw, err := os.ReadFile(c.DeviceFile)
		if err != nil {
			return nil, fmt.Errorf("agent config %s: reading device_file: %w", path, err)
		}
		c.Device = strings.TrimSpace(string(raw))
		if c.Device == "" {
			return nil, fmt.Errorf("agent config %s: device_file %s is empty",
				path, c.DeviceFile)
		}
	}
	return &c, nil
}

// identities turns the configured users into the hook the agent asks per session.
//
// Returns nil when nothing is configured, which means "inherit the agent's identity" —
// distinct from an identity of uid 0, and the distinction matters enough to be a nil
// rather than a zero value.
func (s Sessions) identities() (func(profile string) *agent.Identity, error) {
	if s.User == "" && len(s.PerProfile) == 0 {
		if len(s.Groups) > 0 {
			return nil, errors.New("sessions.groups is set but no sessions.user is: " +
				"supplementary groups only apply to a session that changes user")
		}
		return nil, nil
	}
	fallback, err := parseIdentity(s.User, s.Groups)
	if err != nil {
		return nil, fmt.Errorf("sessions.user: %w", err)
	}
	byProfile := make(map[string]*agent.Identity, len(s.PerProfile))
	for profile, spec := range s.PerProfile {
		id, err := parseIdentity(spec, s.Groups)
		if err != nil {
			return nil, fmt.Errorf("sessions.per_profile[%s]: %w", profile, err)
		}
		if id == nil {
			return nil, fmt.Errorf("sessions.per_profile[%s] is empty: remove the entry "+
				"to inherit sessions.user, rather than writing a blank one", profile)
		}
		byProfile[profile] = id
	}
	// Changing identity at all — even to the identity we already hold — goes through
	// setgroups, which needs CAP_SETGID. So "run sessions as the user we already are"
	// is not a cheap no-op: asking for it unprivileged fails at exec with `operation
	// not permitted`, which reads like a broken shell path rather than a permissions
	// decision. There is nothing to drop in that case, so don't.
	privileged := os.Geteuid() == 0
	self := uint32(os.Geteuid())
	return func(profile string) *agent.Identity {
		id, ok := byProfile[profile]
		if !ok {
			id = fallback
		}
		if id == nil {
			return nil
		}
		if !privileged && id.UID == self {
			return nil
		}
		return id
	}, nil
}

// parseIdentity accepts "uid", "uid:gid" or a user name.
//
// Numeric is the documented form for Android, which has no passwd file at all: uid 2000
// is AID_SHELL, the identity `adb shell` runs as and the one whose SELinux policy has
// been hardened for a decade. A name is a convenience for a laptop.
func parseIdentity(spec string, groups []uint32) (*agent.Identity, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	uidPart, gidPart, hasGID := strings.Cut(spec, ":")

	uid, err := strconv.ParseUint(strings.TrimSpace(uidPart), 10, 32)
	if err != nil {
		// Not numeric: try it as a name, and say plainly why that may not work here.
		u, lookupErr := user.Lookup(strings.TrimSpace(uidPart))
		if lookupErr != nil {
			return nil, fmt.Errorf("%q is neither a uid nor a user this system can look "+
				"up (Android has no passwd file — use a number, e.g. 2000 for shell): %w",
				uidPart, lookupErr)
		}
		if uid, err = strconv.ParseUint(u.Uid, 10, 32); err != nil {
			return nil, fmt.Errorf("user %q has a non-numeric uid %q", uidPart, u.Uid)
		}
		if !hasGID {
			gid, gerr := strconv.ParseUint(u.Gid, 10, 32)
			if gerr != nil {
				return nil, fmt.Errorf("user %q has a non-numeric gid %q", uidPart, u.Gid)
			}
			return &agent.Identity{UID: uint32(uid), GID: uint32(gid), Groups: groups}, nil
		}
	}

	gid := uid // A bare uid takes the matching gid, which is the Android convention.
	if hasGID {
		parsed, err := strconv.ParseUint(strings.TrimSpace(gidPart), 10, 32)
		if err != nil {
			g, lookupErr := user.LookupGroup(strings.TrimSpace(gidPart))
			if lookupErr != nil {
				return nil, fmt.Errorf("group %q is neither a gid nor a group this "+
					"system can look up: %w", gidPart, lookupErr)
			}
			if parsed, err = strconv.ParseUint(g.Gid, 10, 32); err != nil {
				return nil, fmt.Errorf("group %q has a non-numeric gid %q", gidPart, g.Gid)
			}
		}
		gid = parsed
	}
	if uid == 0 {
		// Not a hard refusal — a deployment may genuinely want a root session and say
		// so — but it is the one value worth naming out loud, because it is also what
		// you get by accident from an unset field somewhere upstream.
		return &agent.Identity{UID: 0, GID: uint32(gid), Groups: groups}, nil
	}
	return &agent.Identity{UID: uint32(uid), GID: uint32(gid), Groups: groups}, nil
}

// canDropTo checks up front whether the configured drops are possible.
//
// A session that fails at exec time is a session an operator watches fail for no
// legible reason, thirty seconds after they asked for it. Changing uid needs root, so
// this is knowable at boot: refuse to start instead.
func canDropTo(identities func(string) *agent.Identity, profiles []string) error {
	if identities == nil {
		return nil
	}
	euid := os.Geteuid()
	if euid == 0 {
		return nil
	}
	seen := map[uint32]bool{}
	for _, profile := range append([]string{""}, profiles...) {
		id := identities(profile)
		if id == nil || id.UID == uint32(euid) || seen[id.UID] {
			continue
		}
		seen[id.UID] = true
		return fmt.Errorf("configured to run sessions as uid %d but this process is "+
			"uid %d and not root, so the change would be refused at exec time. Either "+
			"start the agent as root and let it drop, or remove sessions.user and let "+
			"sessions inherit uid %d", id.UID, euid, euid)
	}
	return nil
}
