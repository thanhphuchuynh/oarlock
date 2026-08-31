package rules_test

import (
	"context"
	"testing"

	"github.com/oarlock/oarlock/pkg/plugin"
)

const targeted = `
rules:
  # Narrowed: this operator may forward the app port and nothing else.
  - principals: ["support@example.com"]
    actions: ["tcp"]
    ports: [3000, 8080]
  # Unconstrained: the shape every rule written before targets existed has.
  - principals: ["oncall@example.com"]
    actions: ["tcp"]
  # Narrowed by path, and separately by command.
  - principals: ["support@example.com"]
    actions: ["file:read"]
    paths: ["logs/*"]
  - principals: ["support@example.com"]
    actions: ["exec"]
    commands: ["/bin/echo", "/usr/bin/*"]
`

func allows(t *testing.T, content, principal string, act plugin.Action, tgt plugin.Target) bool {
	t.Helper()
	a := open(t, content)
	d, err := a.Authorize(context.Background(), who(principal), dev("treadmill-4821", nil), act, tgt)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	return d.Allow
}

// TestPortsNarrowAGrant is the feature: `tcp` stops being all-or-nothing on a device.
func TestPortsNarrowAGrant(t *testing.T) {
	for _, tc := range []struct {
		name      string
		principal string
		port      int
		want      bool
	}{
		{"a listed port is granted", "support@example.com", 3000, true},
		{"the other listed port too", "support@example.com", 8080, true},
		{"an unlisted port is not", "support@example.com", 22, false},
		{"nor a neighbouring one", "support@example.com", 3001, false},
		{"an unconstrained rule still grants any port", "oncall@example.com", 22, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := allows(t, targeted, tc.principal, plugin.ActionTCP, plugin.Target{Port: tc.port})
			if got != tc.want {
				t.Errorf("port %d: allow = %v, want %v", tc.port, got, tc.want)
			}
		})
	}
}

// TestAPortConstrainedRuleDoesNotGrantAnActionWithNoPort is the trap in the design.
//
// `actions: ["*"]` beside `ports: [3000]` is written by somebody scoping a rule down, and
// it must not read as a grant of `shell` — which names no port and would otherwise sail
// past a constraint that had nothing to say about it.
func TestAPortConstrainedRuleDoesNotGrantAnActionWithNoPort(t *testing.T) {
	const everything = `
rules:
  - principals: ["support@example.com"]
    actions: ["*"]
    ports: [3000]
`
	if allows(t, everything, "support@example.com", plugin.ActionShell, plugin.Target{}) {
		t.Error("a port-constrained rule granted a shell, which names no port")
	}
	if !allows(t, everything, "support@example.com", plugin.ActionTCP, plugin.Target{Port: 3000}) {
		t.Error("the same rule did not grant the port it names")
	}
}

// TestADenyNarrowsToItsOwnTargets pins the reading of a constrained deny.
//
// `deny ... ports: [22]` means "not port 22". Reading it as "deny everything, and 22 is
// also mentioned" would turn a carve-out into a fleet-wide refusal the author never wrote.
func TestADenyNarrowsToItsOwnTargets(t *testing.T) {
	const carveOut = `
rules:
  - principals: ["oncall@example.com"]
    actions: ["tcp"]
  - principals: ["oncall@example.com"]
    actions: ["tcp"]
    ports: [22]
    deny: true
    reason: "ssh to the device's own sshd is not a forward"
`
	if allows(t, carveOut, "oncall@example.com", plugin.ActionTCP, plugin.Target{Port: 22}) {
		t.Error("the denied port was allowed")
	}
	if !allows(t, carveOut, "oncall@example.com", plugin.ActionTCP, plugin.Target{Port: 3000}) {
		t.Error("the deny for port 22 swallowed every other port")
	}
}

// TestPathsAndCommandsNarrowToo covers the other two target kinds, including that the
// globs are globs.
func TestPathsAndCommandsNarrowToo(t *testing.T) {
	for _, tc := range []struct {
		name string
		act  plugin.Action
		tgt  plugin.Target
		want bool
	}{
		{"a path under the granted prefix", plugin.ActionFileRead, plugin.Target{Path: "logs/app.log"}, true},
		{"a path outside it", plugin.ActionFileRead, plugin.Target{Path: "secrets/key.pem"}, false},
		{"an exactly-listed command", plugin.ActionExec, plugin.Target{Argv: []string{"/bin/echo", "hi"}}, true},
		{"a command matching the glob", plugin.ActionExec, plugin.Target{Argv: []string{"/usr/bin/uptime"}}, true},
		{"a command matching neither", plugin.ActionExec, plugin.Target{Argv: []string{"/bin/sh", "-c", "id"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := allows(t, targeted, "support@example.com", tc.act, tc.tgt); got != tc.want {
				t.Errorf("%s: allow = %v, want %v", tc.tgt, got, tc.want)
			}
		})
	}
}

// TestRulesWrittenBeforeTargetsAreUnchanged is the compatibility guarantee.
//
// Adding the parameter must not have narrowed anybody's existing policy: a rule with no
// target fields answers for every target, exactly as it did when it could not see one.
func TestRulesWrittenBeforeTargetsAreUnchanged(t *testing.T) {
	for _, tc := range []struct {
		act plugin.Action
		tgt plugin.Target
	}{
		{plugin.ActionShell, plugin.Target{}},
		{plugin.ActionExec, plugin.Target{Argv: []string{"/bin/sh", "-c", "anything"}}},
	} {
		if !allows(t, basic, "phuc@example.com", tc.act, tc.tgt) {
			t.Errorf("%s %s: an unconstrained rule stopped granting it", tc.act, tc.tgt)
		}
	}
}
