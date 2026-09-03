package safety_test

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/oarlock/oarlock/internal/safety"
)

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func safeProd() safety.Settings {
	return safety.Settings{
		Env:                  safety.Prod,
		AuthenticatorKind:    "oidc",
		AuthzKind:            "webhook",
		RecorderConfigured:   true,
		SSHHostKeyConfigured: true,
		AuthzGrace:           3,
		// A safe production baseline stores recordings somewhere that can enforce
		// immutability. Anything less is a warning, not a refusal — a lab has no
		// WORM storage and must still be able to record.
		RecordingStoreProtected: true,
		RecordingStoreMode:      "compliance",
		// And it binds the control-channel handshake to the connection it runs on, so a
		// TLS-terminating middlebox cannot relay a device's handshake and keep the
		// channel. Pinning does not cover a certificate the device already trusts.
		ChannelBindingRequired: true,
	}
}

func TestSafeProductionPasses(t *testing.T) {
	problems, err := safety.Check(safeProd(), quiet())
	if err != nil {
		t.Fatalf("a safe configuration was refused: %v", err)
	}
	for _, p := range problems {
		t.Errorf("unexpected finding: %s", p)
	}
}

// TestEachUnsafeSettingIsCaught: every one of these has a tempting value and a safe
// one, and the gap between "we documented the default" and "the default is what is
// running" is where incidents live.
func TestEachUnsafeSettingIsCaught(t *testing.T) {
	tests := map[string]struct {
		mutate  func(*safety.Settings)
		setting string
		fatal   bool
	}{
		"unset environment": {
			func(s *safety.Settings) { s.Env = "" }, "env", true,
		},
		"static tokens in production": {
			func(s *safety.Settings) { s.AuthenticatorKind = "static" }, "authenticator", true,
		},
		"authorized_keys in production": {
			func(s *safety.Settings) { s.AuthenticatorKind = "authorized_keys" }, "authenticator", false,
		},
		"unrecorded sessions permitted": {
			func(s *safety.Settings) {
				s.AllowUnrecorded = true
				s.DevicesAllowingPassthrough = 1
			}, "allow_unrecorded", false,
		},
		"no recorder": {
			func(s *safety.Settings) { s.RecorderConfigured = false }, "recorder", false,
		},
		"metrics served to anybody": {
			func(s *safety.Settings) { s.MetricsPublic = true }, "listen.metrics", false,
		},
		"an unbound control-channel handshake": {
			func(s *safety.Settings) { s.ChannelBindingRequired = false },
			"listen.require_channel_binding", false,
		},
		"mutable recording store": {
			func(s *safety.Settings) {
				s.RecordingStoreProtected = false
				s.RecordingStoreMode = "mutable"
			}, "recording_store", false,
		},
		"store that reports nothing": {
			func(s *safety.Settings) {
				s.RecordingStoreProtected = false
				s.RecordingStoreMode = ""
			}, "recording_store", false,
		},
		"record_input defaulting on": {
			func(s *safety.Settings) { s.RecordInputDefault = true }, "record_input", false,
		},
		"tcp allowlist beyond loopback": {
			func(s *safety.Settings) { s.TCPAllowlist = []string{"0.0.0.0:8080"} }, "tcp_allowlist", true,
		},
		"tcp allowlist wildcard": {
			func(s *safety.Settings) { s.TCPAllowlist = []string{"*:22"} }, "tcp_allowlist", true,
		},
		"file root at /": {
			func(s *safety.Settings) { s.FileRoots = []string{"/"} }, "file_roots", true,
		},
		"no persistent host key": {
			func(s *safety.Settings) { s.SSHHostKeyConfigured = false }, "ssh_host_key", true,
		},
		"no authorizer": {
			func(s *safety.Settings) { s.AuthzKind = "" }, "authorizer", true,
		},
		"negative authz grace": {
			func(s *safety.Settings) { s.AuthzGrace = -1 }, "authz_grace", true,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			s := safeProd()
			tc.mutate(&s)
			problems, err := safety.Check(s, quiet())

			var found *safety.Problem
			for i := range problems {
				if problems[i].Setting == tc.setting {
					found = &problems[i]
				}
			}
			if found == nil {
				t.Fatalf("%q was not caught; findings: %v", tc.setting, problems)
			}
			if found.Fatal != tc.fatal {
				t.Errorf("fatal=%v, want %v (%s)", found.Fatal, tc.fatal, found.Message)
			}
			if tc.fatal && err == nil {
				t.Error("a fatal finding did not refuse the boot")
			}
			if !tc.fatal && err != nil {
				t.Errorf("a warning refused the boot: %v", err)
			}
			// The message has to say *why*, or the operator changes the setting back.
			if len(found.Message) < 40 {
				t.Errorf("message is too terse to act on: %q", found.Message)
			}
		})
	}
}

// TestEveryProblemIsReportedAtOnce: a deployment with three unsafe settings should
// take one edit to fix, not three boots.
func TestEveryProblemIsReportedAtOnce(t *testing.T) {
	s := safeProd()
	s.AuthenticatorKind = "static"
	s.SSHHostKeyConfigured = false
	s.FileRoots = []string{"/"}
	s.RecordInputDefault = true

	problems, err := safety.Check(s, quiet())
	if err == nil {
		t.Fatal("an unsafe configuration started")
	}
	if len(problems) < 4 {
		t.Fatalf("%d findings, want at least 4: %v", len(problems), problems)
	}
	msg := err.Error()
	for _, want := range []string{"authenticator", "ssh_host_key", "file_roots"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not mention %q:\n%s", want, msg)
		}
	}
}

// TestDevelopmentIsRelaxedDeliberately: several checks are loose in development
// precisely so they can be strict everywhere else.
func TestDevelopmentIsRelaxedDeliberately(t *testing.T) {
	s := safety.Settings{
		Env:               safety.Dev,
		AuthenticatorKind: "static",
		AuthzKind:         "",
		AuthzGrace:        3,
	}
	if _, err := safety.Check(s, quiet()); err != nil {
		t.Fatalf("a development configuration was refused: %v", err)
	}

	// But the checks that are about the *device* rather than the deployment apply
	// everywhere: a laptop can still be pointed at real hardware.
	s.TCPAllowlist = []string{"0.0.0.0:9000"}
	if _, err := safety.Check(s, quiet()); err == nil {
		t.Error("a non-loopback tcp allowlist was accepted in development")
	}
}

// TestUnknownEnvironmentIsTreatedAsProduction: a misspelled environment must fail
// safe, not open.
func TestUnknownEnvironmentIsTreatedAsProduction(t *testing.T) {
	for _, env := range []safety.Env{"prod", "production", "staging", "Dev", "DEV", "live"} {
		if !env.Production() {
			t.Errorf("env %q is not treated as production", env)
		}
	}
	for _, env := range []safety.Env{safety.Dev, safety.Test} {
		if env.Production() {
			t.Errorf("env %q is treated as production", env)
		}
	}
}

// TestPointlessPolicyIsFlagged: allow_unrecorded with no device flagged for it is
// doing nothing except widening what a misconfigured device could do.
func TestPointlessPolicyIsFlagged(t *testing.T) {
	s := safeProd()
	s.AllowUnrecorded = true
	s.DevicesAllowingPassthrough = 0
	problems, err := safety.Check(s, quiet())
	if err != nil {
		t.Fatalf("this should warn, not refuse: %v", err)
	}
	var found bool
	for _, p := range problems {
		if p.Setting == "allow_unrecorded" && strings.Contains(p.Message, "no device") {
			found = true
		}
	}
	if !found {
		t.Errorf("a policy doing nothing was not flagged: %v", problems)
	}
}

// TestNoRecorderDoesNotAlsoWarnAboutStorage: a gateway recording nothing has no
// storage guarantee to complain about, and two warnings for one decision is how a
// warning stops being read.
func TestNoRecorderDoesNotAlsoWarnAboutStorage(t *testing.T) {
	s := safeProd()
	s.RecorderConfigured = false
	s.RecordingStoreProtected = false
	problems, err := safety.Check(s, quiet())
	if err != nil {
		t.Fatalf("this should warn, not refuse: %v", err)
	}
	for _, p := range problems {
		if p.Setting == "recording_store" {
			t.Errorf("warned about the store with no recorder configured: %s", p)
		}
	}
}

// TestCompositeAuthenticatorKindsAreMatched.
//
// The kind a deployment reports is usually a composite — "authorized_keys+static_token",
// "oidc+authorized_keys" — and these checks were equality comparisons against "static"
// and "authorized_keys". The first matched nothing at all, because the daemon reports
// "static_token"; the second missed every deployment that also had tokens. A gate that
// silently matches nothing reads like coverage and is not.
func TestCompositeAuthenticatorKindsAreMatched(t *testing.T) {
	for _, tc := range []struct {
		kind  string
		fatal bool // refuses to boot
		warns bool
	}{
		{kind: "oidc"},
		{kind: "static_token", fatal: true},
		{kind: "authorized_keys", warns: true},
		{kind: "authorized_keys+static_token", fatal: true, warns: true},
		{kind: "oidc+authorized_keys", warns: true},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			s := safeProd()
			s.AuthenticatorKind = tc.kind
			problems, err := safety.Check(s, quiet())

			var sawFatal, sawWarning bool
			for _, p := range problems {
				if p.Setting != "authenticator" {
					continue
				}
				if p.Fatal {
					sawFatal = true
				} else {
					sawWarning = true
				}
			}
			if sawFatal != tc.fatal {
				t.Errorf("fatal = %v, want %v (problems: %v, err: %v)",
					sawFatal, tc.fatal, problems, err)
			}
			if sawWarning != tc.warns {
				t.Errorf("warned = %v, want %v (problems: %v)", sawWarning, tc.warns, problems)
			}
			// A fatal finding must actually stop the boot, not merely be reported.
			if tc.fatal && err == nil {
				t.Error("a fatal authenticator finding did not refuse the boot")
			}
		})
	}
}
