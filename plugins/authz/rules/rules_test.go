package rules_test

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oarlock/oarlock/pkg/plugin"
	"github.com/oarlock/oarlock/pkg/plugin/plugintest"
	"github.com/oarlock/oarlock/plugins/authz/rules"
)

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func write(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func open(t *testing.T, content string) *rules.Authorizer {
	t.Helper()
	a, err := rules.Open(write(t, content), quiet())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

func dev(id string, tags map[string]string) *plugin.Device {
	return &plugin.Device{ID: id, Tags: tags}
}

func who(id string) *plugin.Principal { return &plugin.Principal{ID: id} }

const basic = `
rules:
  - principals: ["admin@mail.com"]
    devices: ["treadmill-*"]
    actions: ["shell", "exec"]
  - principals: ["auditor@example.com"]
    actions: ["replay", "observe"]
`

func TestGrantsWhatItSays(t *testing.T) {
	a := open(t, basic)
	ctx := context.Background()

	for _, tc := range []struct {
		p     string
		d     string
		act   plugin.Action
		allow bool
	}{
		{"admin@mail.com", "treadmill-4821", plugin.ActionShell, true},
		{"admin@mail.com", "treadmill-4821", plugin.ActionExec, true},
		// exec does not imply shell and shell does not imply file access: the actions
		// are coarse but they are not a hierarchy.
		{"admin@mail.com", "treadmill-4821", plugin.ActionFileRead, false},
		{"admin@mail.com", "treadmill-4821", plugin.ActionPassthrough, false},
		{"admin@mail.com", "rower-7", plugin.ActionShell, false},
		{"someone@example.com", "treadmill-4821", plugin.ActionShell, false},
		// No devices: means every device.
		{"auditor@example.com", "rower-7", plugin.ActionReplay, true},
		{"auditor@example.com", "rower-7", plugin.ActionShell, false},
	} {
		d, err := a.Authorize(ctx, who(tc.p), dev(tc.d, nil), tc.act, plugin.Target{})
		if err != nil {
			t.Fatalf("%s/%s/%s: %v", tc.p, tc.d, tc.act, err)
		}
		if d.Allow != tc.allow {
			t.Errorf("%s on %s for %s: allow=%v, want %v (%s)",
				tc.act, tc.d, tc.p, d.Allow, tc.allow, d.Reason)
		}
	}
}

func TestADenialNamesWhatItRefused(t *testing.T) {
	a := open(t, basic)
	d, _ := a.Authorize(context.Background(), who("nobody@example.com"),
		dev("treadmill-4821", nil), plugin.ActionShell, plugin.Target{})
	// "denied" tells an operator nothing they can take to whoever manages access.
	for _, want := range []string{"shell", "treadmill-4821", "nobody@example.com"} {
		if !strings.Contains(d.Reason, want) {
			t.Errorf("the reason %q does not name %q", d.Reason, want)
		}
	}
}

func TestTagSelectors(t *testing.T) {
	a := open(t, `
rules:
  - principals: ["pci-team@example.com"]
    tags: {scope: "pci", region: "eu"}
    actions: ["shell"]
`)
	ctx := context.Background()
	cases := []struct {
		tags  map[string]string
		allow bool
	}{
		{map[string]string{"scope": "pci", "region": "eu"}, true},
		// Every listed tag must match: a rule scoped to PCI *and* the EU must not grant
		// on a device that is only one of them.
		{map[string]string{"scope": "pci"}, false},
		{map[string]string{"scope": "pci", "region": "us"}, false},
		{map[string]string{"scope": "pci", "region": "eu", "extra": "x"}, true},
		{nil, false},
	}
	for _, tc := range cases {
		d, _ := a.Authorize(ctx, who("pci-team@example.com"), dev("d1", tc.tags), plugin.ActionShell, plugin.Target{})
		if d.Allow != tc.allow {
			t.Errorf("tags %v: allow=%v, want %v", tc.tags, d.Allow, tc.allow)
		}
	}
}

// TestADenyBeatsEveryAllow: a broad grant should be carveable without rewriting it, and
// adding a deny must not be defeatable by rule ordering somebody else controls.
func TestADenyBeatsEveryAllow(t *testing.T) {
	for _, order := range []string{"deny first", "deny last"} {
		allow := `  - principals: ["*"]
    actions: ["shell"]
`
		deny := `  - principals: ["*"]
    tags: {scope: "pci"}
    actions: ["*"]
    deny: true
    reason: "PCI devices need a change ticket"
`
		body := "rules:\n" + allow + deny
		if order == "deny first" {
			body = "rules:\n" + deny + allow
		}
		a := open(t, body)
		ctx := context.Background()

		d, _ := a.Authorize(ctx, who("admin@mail.com"),
			dev("pos-1", map[string]string{"scope": "pci"}), plugin.ActionShell, plugin.Target{})
		if d.Allow {
			t.Errorf("%s: a deny was overridden by an allow", order)
		}
		if d.Reason != "PCI devices need a change ticket" {
			t.Errorf("%s: the deny's reason was lost: %q", order, d.Reason)
		}
		// And the broad grant still works everywhere else.
		if d, _ := a.Authorize(ctx, who("admin@mail.com"), dev("treadmill-4821", nil),
			plugin.ActionShell, plugin.Target{}); !d.Allow {
			t.Errorf("%s: the carve-out removed the grant entirely", order)
		}
	}
}

func TestLimitsAndTTLRideTheGrant(t *testing.T) {
	a := open(t, `
rules:
  - principals: ["contractor@example.com"]
    actions: ["shell"]
    max_duration: 15m
    idle: 2m
    ttl: 10s
`)
	d, _ := a.Authorize(context.Background(), who("contractor@example.com"),
		dev("treadmill-4821", nil), plugin.ActionShell, plugin.Target{})
	if !d.Allow {
		t.Fatal("denied")
	}
	if d.Limits == nil || d.Limits.MaxDuration == nil || *d.Limits.MaxDuration != 15*time.Minute {
		t.Errorf("max duration %v", d.Limits)
	}
	if d.Limits.Idle == nil || *d.Limits.Idle != 2*time.Minute {
		t.Errorf("idle %v", d.Limits.Idle)
	}
	if d.TTL != 10*time.Second {
		t.Errorf("ttl %v", d.TTL)
	}
}

// TestAnEmptyActionListIsRefused: far more likely to be an unfinished rule than an intent
// to grant the fleet.
func TestAnEmptyActionListIsRefused(t *testing.T) {
	_, err := rules.Open(write(t, `
rules:
  - principals: ["admin@mail.com"]
    actions: []
`), quiet())
	if err == nil {
		t.Fatal("a rule with no actions loaded")
	}
	if !strings.Contains(err.Error(), `actions: ["*"]`) {
		t.Errorf("the error does not say how to grant everything: %v", err)
	}
}

func TestInvalidFilesAreRefusedAtOpen(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"unknown key", "rules:\n  - principals: [\"a\"]\n    actions: [\"shell\"]\n    typo: 1\n", "typo"},
		{"unknown action", "rules:\n  - principals: [\"a\"]\n    actions: [\"root\"]\n", "not an action"},
		{"no principals", "rules:\n  - actions: [\"shell\"]\n", "no principals"},
		{"negative duration", "rules:\n  - principals: [\"a\"]\n    actions: [\"shell\"]\n    idle: -1m\n", "negative"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := rules.Open(write(t, tc.body), quiet()); err == nil {
				t.Fatal("it loaded")
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the error does not mention %q: %v", tc.want, err)
			}
		})
	}
}

// TestABrokenReloadKeepsTheOldRules is the property that makes this a safe default.
//
// Somebody saves a file with a syntax error in it. Dropping to no rules would deny
// everybody, instantly, because of a typo — and it would look exactly like a mass
// revocation to every operator it hit.
func TestABrokenReloadKeepsTheOldRules(t *testing.T) {
	path := write(t, basic)
	a, err := rules.Open(path, quiet())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })

	if err := os.WriteFile(path, []byte("rules:\n  - this is not: valid: yaml:\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.Reload(); err == nil {
		t.Fatal("a broken file reloaded successfully")
	}

	d, err := a.Authorize(context.Background(), who("admin@mail.com"),
		dev("treadmill-4821", nil), plugin.ActionShell, plugin.Target{})
	if err != nil {
		t.Fatalf("Authorize failed after a broken reload: %v", err)
	}
	if !d.Allow {
		t.Error("a syntax error revoked everybody's access")
	}
}

func TestADeletedFileKeepsTheOldRules(t *testing.T) {
	path := write(t, basic)
	a, err := rules.Open(path, quiet())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	// A deleted file is far more likely to be a deployment mid-flight than an intent to
	// revoke everybody.
	if err := a.Reload(); err == nil {
		t.Error("reloading a deleted file succeeded")
	}
	if d, _ := a.Authorize(context.Background(), who("admin@mail.com"),
		dev("treadmill-4821", nil), plugin.ActionShell, plugin.Target{}); !d.Allow {
		t.Error("deleting the file revoked everybody's access")
	}
}

func TestAGoodReloadTakesEffect(t *testing.T) {
	path := write(t, basic)
	a, err := rules.Open(path, quiet())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })

	if err := os.WriteFile(path, []byte(`
rules:
  - principals: ["newcomer@example.com"]
    actions: ["shell"]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.Reload(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if d, _ := a.Authorize(ctx, who("newcomer@example.com"), dev("d", nil), plugin.ActionShell, plugin.Target{}); !d.Allow {
		t.Error("the new rule did not take effect")
	}
	if d, _ := a.Authorize(ctx, who("admin@mail.com"), dev("treadmill-4821", nil),
		plugin.ActionShell, plugin.Target{}); d.Allow {
		t.Error("the old rule survived the reload")
	}
}

// TestConformance runs the default authorizer through the suite every backend runs.
func TestConformance(t *testing.T) {
	path := write(t, basic)
	plugintest.Authorizer(t, plugintest.AuthorizerHarness{
		New: func(t *testing.T) plugin.Authorizer {
			a, err := rules.Open(path, quiet())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = a.Close() })
			return a
		},
		Allowed: func() (*plugin.Principal, *plugin.Device, plugin.Action) {
			return who("admin@mail.com"), dev("treadmill-4821", nil), plugin.ActionShell
		},
		Denied: func() (*plugin.Principal, *plugin.Device, plugin.Action) {
			return who("nobody@example.com"), dev("treadmill-4821", nil), plugin.ActionShell
		},
		// The claim, and the reason this backend is a safe default: its source of truth
		// is a file already in memory, so there is no outage in which it starts denying
		// people. The suite checks the checkable part — that it answers, consistently.
		NoDependencyToBreak: true,
	})
}
