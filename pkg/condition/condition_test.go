package condition_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/oarlock/oarlock/pkg/condition"
)

func TestEveryConditionIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range condition.All() {
		if c.ID == "" {
			t.Error("a condition with no id")
		}
		if seen[c.ID] {
			t.Errorf("%q appears twice", c.ID)
		}
		seen[c.ID] = true

		if c.Kind == 0 {
			t.Errorf("%s: no kind — nothing says where it appears on the wire", c.ID)
		}
		if c.Audience == condition.Operator {
			// The two rules from the UX spec, as assertions: name the thing, and give
			// the next action. A headline that is a code, or prose that apologises, is
			// what this stops.
			if c.Headline == "" {
				t.Errorf("%s: an operator-facing condition with no headline", c.ID)
			}
			if strings.Contains(strings.ToLower(c.Headline), "error") {
				t.Errorf("%s: headline says %q — never 'Error' as the headline", c.ID, c.Headline)
			}
			// A code as the headline, rather than the word that happens to be in it:
			// "Your access was revoked." is prose; "revoked" and "device_offline" are
			// codes leaking into the interface.
			if c.Headline == c.ID || strings.Contains(c.Headline, "_") {
				t.Errorf("%s: the headline reads as a code: %q", c.ID, c.Headline)
			}
			for _, sorry := range []string{"sorry", "oops", "unfortunately", "whoops"} {
				if strings.Contains(strings.ToLower(c.Text()), sorry) {
					t.Errorf("%s: %q — flat and specific, no apologies", c.ID, c.Text())
				}
			}
		}
		if c.Text() == "" {
			t.Errorf("%s: nothing to print", c.ID)
		}
	}
	if len(seen) < 20 {
		t.Errorf("only %d conditions — the wire's closed sets are bigger than that", len(seen))
	}
}

// TestRevokedAndUnavailableAreNotTheSameScreen is the acceptance criterion for E3.S4,
// and the reason this package exists.
//
// "Your access was removed" and "we could not check your access" send somebody to
// entirely different places. An operator told the first when the second happened goes and
// asks a manager about a permission that was never taken away, during the incident that
// put them on the device in the first place.
func TestRevokedAndUnavailableAreNotTheSameScreen(t *testing.T) {
	revoked, ok := condition.Lookup("revoked")
	if !ok {
		t.Fatal("revoked is missing")
	}
	unavailable, ok := condition.Lookup("authz_unavailable")
	if !ok {
		t.Fatal("authz_unavailable is missing")
	}

	if revoked.Headline == unavailable.Headline {
		t.Error("the two share a headline")
	}
	if revoked.Fault == unavailable.Fault {
		t.Errorf("both blame %s — one is the operator's access, one is our dependency",
			revoked.Fault)
	}
	if !unavailable.Retryable {
		t.Error("authz_unavailable must be retryable: nothing about the operator changed")
	}
	if revoked.Retryable {
		t.Error("revoked must not be retryable: trying again cannot restore a withdrawn grant")
	}
	// The strongest form of the requirement: an operator reading the unavailable screen
	// must not be able to conclude that their access was taken away.
	lower := strings.ToLower(unavailable.Text())
	for _, forbidden := range []string{"revoked", "withdrawn", "removed", "no longer have"} {
		if strings.Contains(lower, forbidden) {
			t.Errorf("authz_unavailable says %q, which reads as a revocation", unavailable.Text())
		}
	}
	// And it says so positively, because silence on the point is what people fill in
	// with the worst reading.
	if !strings.Contains(lower, "hasn’t changed") && !strings.Contains(lower, "hasn't changed") {
		t.Errorf("authz_unavailable does not say the operator's access is unchanged: %q",
			unavailable.Text())
	}
}

// TestABrokenDoorbellIsNotTheDevicesFault: saying "offline" here sends an engineer to
// look at hardware in a gym when the push broker is what is down.
func TestABrokenDoorbellIsNotTheDevicesFault(t *testing.T) {
	c, ok := condition.Lookup("doorbell_failed")
	if !ok {
		t.Fatal("doorbell_failed is missing")
	}
	if c.Fault != condition.FaultGateway {
		t.Errorf("doorbell_failed blames %s, want the gateway", c.Fault)
	}
	if strings.Contains(strings.ToLower(c.Text()), "offline") {
		t.Errorf("doorbell_failed says %q", c.Text())
	}
	offline, _ := condition.Lookup("device_offline")
	if c.Headline == offline.Headline {
		t.Error("a broken doorbell and an offline device share a headline")
	}
}

// TestTheThreeDeviceConditionsAreDistinguishable.
//
// They used to be three different sentences behind one wire code, `device_offline`, with
// the distinguishing text in ERROR's `message` — a field the protocol says is for humans
// and is never parsed. A browser could therefore render only one screen for all three,
// or break the contract to tell them apart.
func TestTheThreeDeviceConditionsAreDistinguishable(t *testing.T) {
	ids := []string{"device_not_connected", "device_offline", "device_unreachable"}
	heads := map[string]string{}
	for _, id := range ids {
		c, ok := condition.Lookup(id)
		if !ok {
			t.Fatalf("%s is missing", id)
		}
		if prev, dup := heads[c.Headline]; dup {
			t.Errorf("%s and %s share the headline %q", prev, id, c.Headline)
		}
		heads[c.Headline] = id
	}
}

func TestAnUnknownCodeRendersAsUnknown(t *testing.T) {
	// A gateway newer than this client, which the versioning rules allow. It has to
	// render as "we don't recognise this" rather than as a blank screen or as whatever
	// the first row of the table happens to be.
	c := condition.Get("something_invented_next_year")
	if c.ID != "something_invented_next_year" {
		t.Errorf("id %q", c.ID)
	}
	if c.Audience != condition.Integrator {
		t.Error("an unknown code is not something an operator can act on")
	}
	if c.Text() == "" {
		t.Error("an unknown code renders as nothing")
	}
	if _, known := condition.Lookup("something_invented_next_year"); known {
		t.Error("Lookup claims to know it")
	}
}

// TestNoCodeIsEmittedThatHasNoScreen is the anti-drift mechanism.
//
// The codes reach the wire as bare string literals, so nothing but a test can tell that
// somebody added a new one without a screen to render it. It scans every snake_case
// string literal in the packages that emit session conditions and demands that each one
// is either in the set or in the allowlist below — which turns out to be entirely
// practical, because those packages contain about a dozen such literals in total.
//
// A narrower version of this test, matching only `Code:` and `Reason:` shapes, missed a
// reason assigned to a local variable — and the broad version immediately found
// `operator_gave_up`, emitted by the SSH surface with no screen behind it. Which is the
// argument for the broad version.
func TestNoCodeIsEmittedThatHasNoScreen(t *testing.T) {
	dirs := []string{
		"../../internal/invite", "../../internal/pump", "../../internal/attachsrv",
		"../../internal/sshsrv", "../../internal/sessionsrv", "../../internal/controlsrv",
		"../../internal/sessionrun",
	}
	literal := regexp.MustCompile(`"([a-z][a-z0-9]*(?:_[a-z0-9]+)+)"`)

	// Structured-log field names and JSON keys, which share the shape and are not
	// conditions. Kept short on purpose: every addition here is a chance to silence a
	// real finding, so a new entry should be obviously not a code.
	notCodes := map[string]bool{
		"bytes_out": true, "bytes_in": true, "key_type": true,
		"skipped_for_safety": true, "dropped_bytes": true, "bytes_dropped": true,
		"session_id":     true,
		"scrollback_len": true, "max_frame": true, "ping_interval": true,
		"dropped_input": true, "read_only": true,
		// A log field on the SSH door's rate-limit refusal, not a wire code: the peer
		// is told nothing at all, it is simply hung up on.
		"connections_this_minute": true,
	}

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") ||
				strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range literal.FindAllStringSubmatch(string(src), -1) {
				id := m[1]
				if notCodes[id] {
					continue
				}
				if _, ok := condition.Lookup(id); !ok {
					t.Errorf("%s contains %q, which has no screen.\n"+
						"Add it to pkg/condition, or add it to notCodes if it is a log "+
						"field rather than a condition — but check which it is first.",
						path, id)
				}
			}
		}
	}
}
