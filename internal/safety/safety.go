// Package safety is the boot gate: the checks that run before the gateway serves
// anything.
//
// # Why a gate rather than documentation
//
// Every setting here has a safe value and a tempting one. `allow_unrecorded` makes a
// stubborn session work; `record_input` satisfies an auditor; a static token gets you
// past a login screen. Each is defensible somewhere and dangerous by default, and the
// gap between "we documented the default" and "the default is what is running" is
// where incidents live.
//
// So the checks are code, they run at boot, and the dangerous combinations refuse to
// start rather than warn. A warning at startup is a line in a log nobody reads until
// afterwards.
package safety

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
)

// Env is the deployment environment. It is not decoration: several checks are
// relaxed in development precisely so that they can be strict everywhere else.
type Env string

const (
	Dev  Env = "dev"
	Test Env = "test"
	Prod Env = "prod"
)

// Production reports whether this environment gets the strict checks. Anything that
// is not explicitly dev or test does — an unset or misspelled environment must fail
// safe, not open.
func (e Env) Production() bool {
	switch e {
	case Dev, Test:
		return false
	default:
		return true
	}
}

// Settings is the subset of configuration the gate has opinions about.
//
// Deliberately a flat struct rather than a reference to the whole config: a gate that
// reaches into everything ends up asserting things it does not understand.
type Settings struct {
	Env Env

	// AuthenticatorKind is the operator authentication backend in use.
	AuthenticatorKind string
	// AllowUnrecorded permits sessions the gateway cannot read (mode A).
	AllowUnrecorded bool
	// RecordInputDefault is the fallback when no policy rule matches.
	RecordInputDefault bool
	// RecorderConfigured says whether recordings are being written at all.
	RecorderConfigured bool
	// RecordingStoreProtected is whether the store can enforce immutability, as
	// *reported by the store* rather than declared in configuration. A guarantee an
	// operator types into a config file is a guarantee nobody checked.
	RecordingStoreProtected bool
	// RecordingStoreMode is what it reported, for the message.
	RecordingStoreMode string
	// TCPAllowlist and FileRoots are the device-side profile allow-lists.
	TCPAllowlist []string
	FileRoots    []string
	// DevicesAllowingPassthrough is how many devices are flagged for mode A.
	DevicesAllowingPassthrough int
	// SSHHostKeyConfigured says whether a persistent host key was supplied.
	SSHHostKeyConfigured bool
	// AuthzGrace is how many failed re-checks a live session survives.
	AuthzGrace int
	// AuthzKind is the authorisation backend.
	AuthzKind string
}

// Problem is one finding. Fatal problems refuse the boot; the rest are warnings that
// deserve to be loud but not fatal.
type Problem struct {
	Fatal   bool
	Setting string
	Message string
}

func (p Problem) String() string {
	kind := "warning"
	if p.Fatal {
		kind = "refused"
	}
	return fmt.Sprintf("%s: %s: %s", kind, p.Setting, p.Message)
}

// Check runs the gate. It returns every problem it found, and an error if any is
// fatal — every problem at once, because a deployment with three unsafe settings
// should take one edit to fix, not three boots.
func Check(s Settings, log *slog.Logger) ([]Problem, error) {
	if log == nil {
		log = slog.Default()
	}
	var ps []Problem
	add := func(fatal bool, setting, msg string) {
		ps = append(ps, Problem{Fatal: fatal, Setting: setting, Message: msg})
	}
	prod := s.Env.Production()

	if s.Env == "" {
		add(true, "env", "not set. An unset environment gets the strict checks, and "+
			"has to be named explicitly so nobody gets production rules by accident "+
			"or development rules by omission")
	}

	// Static tokens are long-lived shared secrets. Fine on a laptop.
	if s.AuthenticatorKind == "static" && prod {
		add(true, "authenticator", "static tokens cannot be revoked without a config "+
			"push and never expire; use oidc or sshca outside development")
	}
	if s.AuthenticatorKind == "authorized_keys" && prod {
		add(false, "authenticator", "authorized_keys means revoking an operator is a "+
			"file edit on every replica; sshca or oidc scale, this does not")
	}

	// An unrecorded session must be a deliberate, narrow choice.
	if s.AllowUnrecorded && prod {
		add(false, "allow_unrecorded", "sessions the gateway cannot read are permitted. "+
			"Every one of them is unauditable by construction — keep this off unless "+
			"there is a written reason")
	}
	if !s.RecorderConfigured && prod {
		add(false, "recorder", "no recorder is configured, so no session is recorded. "+
			"A chosen absence is legitimate; an accidental one is discovered during an "+
			"incident")
	}
	if s.RecorderConfigured && !s.RecordingStoreProtected && prod {
		add(false, "recording_store", fmt.Sprintf(
			"the recording store reports %q: tampering is detectable but not "+
				"impossible, because anything with write access can alter a recording "+
				"and only the signature would show it. Object lock or retention is "+
				"what makes it impossible; see docs/plugins.md § 4.2",
			orUnknown(s.RecordingStoreMode)))
	}
	if s.AllowUnrecorded && s.DevicesAllowingPassthrough == 0 {
		add(false, "allow_unrecorded", "enabled, but no device is flagged for "+
			"passthrough — the policy is doing nothing except widening what a "+
			"misconfigured device could do")
	}

	// record_input turns recordings into a credential store.
	if s.RecordInputDefault {
		add(false, "record_input", "defaulting to on. Echo is suppressed on the "+
			"device, so the gateway sees whatever is typed into a password prompt: "+
			"recordings become a credential store and must be handled as one")
	}

	// Device-side allow-lists.
	for _, entry := range s.TCPAllowlist {
		if strings.HasPrefix(entry, "0.0.0.0") || strings.HasPrefix(entry, "*") ||
			strings.HasPrefix(entry, "[::]") {
			add(true, "tcp_allowlist", fmt.Sprintf(
				"%q is not loopback. A tcp forward to a non-local address turns the "+
					"device into a pivot into the network it sits on", entry))
		}
	}
	for _, root := range s.FileRoots {
		if root == "/" {
			add(true, "file_roots", "a root of \"/\" makes the whole device filesystem "+
				"readable through the file profile")
		}
	}

	// Multi-replica SSH identity.
	if !s.SSHHostKeyConfigured && prod {
		add(true, "ssh_host_key", "no persistent host key. Every restart changes the "+
			"gateway's identity, operators are shown a mismatch warning, and an "+
			"operator trained to click through those is the failure the warning exists "+
			"to prevent")
	}

	// Authorisation degradation.
	if s.AuthzGrace < 0 {
		add(true, "authz_grace", "negative, which has no meaning. Zero is strict "+
			"fail-closed — an authorisation error ends live sessions immediately — "+
			"and a positive value is how many failed re-checks a live session "+
			"survives before closing as authz_unavailable")
	}
	if s.AuthzKind == "" && prod {
		add(true, "authorizer", "not configured. With no authorizer there is nothing "+
			"deciding who may open a shell on which device")
	}

	for _, p := range ps {
		if p.Fatal {
			log.Error("boot gate refused a setting", "setting", p.Setting, "detail", p.Message)
		} else {
			log.Warn("boot gate warning", "setting", p.Setting, "detail", p.Message)
		}
	}

	var fatal []string
	for _, p := range ps {
		if p.Fatal {
			fatal = append(fatal, p.Setting+": "+p.Message)
		}
	}
	if len(fatal) > 0 {
		return ps, fmt.Errorf("safety: refusing to start, %d unsafe setting(s):\n  %s",
			len(fatal), strings.Join(fatal, "\n  "))
	}
	return ps, nil
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// ErrRefused is returned wrapped by Check when a fatal problem is found.
var ErrRefused = errors.New("safety: refusing to start")
