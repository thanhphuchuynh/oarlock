package app_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/config"
	"github.com/oarlock/oarlock/internal/safety"
)

// These tests are about one sentence: the gateway reports the guarantee the *store*
// gives, and refuses to start when that is less than the guarantee the operator asked
// for.
//
// They go through app.Build rather than calling the store directly, because the two
// defects they pin both lived in the wiring. One was a string comparison that counted
// "the store could not answer" as "the store is protected"; the other was that no
// configuration could ask for a lock at all, so nothing ever noticed the difference
// between an unlocked bucket and an unlocked bucket somebody had promised was locked.
//
// Nothing here carries a credential that means anything: the fake accepts whatever
// signature arrives, and real credentials come from the environment or the config file.

// lockOracle is a fake S3 that answers exactly one question — what does this bucket's
// object lock configuration say — because that is the only request building a gateway
// makes of the store. record.New asks for immutability once, at construction.
type lockOracle struct {
	srv    *httptest.Server
	status int
	body   string
}

func newLockOracle(t *testing.T, status int, body string) *lockOracle {
	t.Helper()
	o := &lockOracle{status: status, body: body}
	o.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !r.URL.Query().Has("object-lock") {
			http.Error(w, "the fake answers object-lock queries and nothing else",
				http.StatusNotImplemented)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(o.status)
		_, _ = w.Write([]byte(o.body))
	}))
	t.Cleanup(o.srv.Close)
	return o
}

func (o *lockOracle) host() string { return strings.TrimPrefix(o.srv.URL, "http://") }

// The three answers a bucket can give, in the wire form real S3 gives them.
const (
	// A bucket that was never created with Object Lock. It cannot be turned on
	// afterwards, which is the single most common way this gets missed.
	unlockedBucket = `<?xml version="1.0" encoding="UTF-8"?>` +
		`<Error><Code>ObjectLockConfigurationNotFoundError</Code>` +
		`<Message>Object Lock configuration does not exist for this bucket</Message></Error>`

	// A bucket the gateway can write to but cannot interrogate — no
	// s3:GetObjectLockConfiguration grant. This is the answer that used to read as a
	// guarantee.
	unreadableBucket = `<?xml version="1.0" encoding="UTF-8"?>` +
		`<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`

	lockedBucket = `<?xml version="1.0" encoding="UTF-8"?>` +
		`<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">` +
		`<ObjectLockEnabled>Enabled</ObjectLockEnabled>` +
		`<Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>365</Days>` +
		`</DefaultRetention></Rule></ObjectLockConfiguration>`
)

// bucketGateway builds a real gateway recording to the fake bucket.
func bucketGateway(t *testing.T, o *lockOracle, lockMode string) *deployment {
	t.Helper()
	withConfig(t, func(c *config.Config) {
		// dir and s3 are mutually exclusive, so the directory the harness configured
		// has to go.
		c.Recorder.Dir = ""
		c.Recorder.S3 = &config.S3{
			Bucket:    "oarlock-recordings",
			Region:    "us-east-1",
			Endpoint:  o.host(),
			Prefix:    "recordings",
			AccessKey: "fake-access-key",
			SecretKey: "fake-secret-key",
			LockMode:  lockMode,
			RetainFor: 2160 * time.Hour,
		}
	})
	return deploy(t, quiet())
}

// TestAStoreThatCannotAnswerIsNotProtected is the pin on cmd/oarlockd/app's own
// defect.
//
// The check used to read `imm.Mode != "mutable"`, and record reports ModeUnknown when
// a store's Immutability call *fails*. So a bucket the gateway could not interrogate
// came out as protected, the boot gate said nothing, and the deployment that most
// needed to be told something was the one told nothing.
//
// record.Mode.Protected() deliberately excludes ModeUnknown: a guarantee nobody can
// describe is not one.
func TestAStoreThatCannotAnswerIsNotProtected(t *testing.T) {
	o := newLockOracle(t, http.StatusForbidden, unreadableBucket)
	// No lock requested, so this is purely about how the answer is classified.
	d := bucketGateway(t, o, "")

	if got := d.gw.Settings.RecordingStoreMode; got != "unknown" {
		t.Fatalf("mode = %q, want %q — the store could not read the bucket", got, "unknown")
	}
	if d.gw.Settings.RecordingStoreProtected {
		t.Fatal("a store that could not read its own bucket reported as protected")
	}
	if d.gw.Settings.RecordingStoreDetail == "" {
		t.Error("no detail: \"unknown\" on its own tells an operator nothing to do")
	}

	// And the consequence: the gate is no longer quiet about it in production.
	s := d.gw.Settings
	s.Env = safety.Prod
	problems, _ := safety.Check(s, quiet())
	var found *safety.Problem
	for i := range problems {
		if problems[i].Setting == "recording_store" {
			found = &problems[i]
		}
	}
	if found == nil {
		t.Fatalf("the gate said nothing about an unverified store: %v", problems)
	}
	if found.Fatal {
		t.Errorf("an unverified store with no lock requested refused the boot; "+
			"nobody promised anything, so this is a warning: %s", found)
	}
}

// TestAskingForALockTheBucketDoesNotGiveRefusesTheBoot is the point of the feature.
//
// An operator who wrote lock_mode: compliance asked for a guarantee, and every
// manifest written afterwards records the storage claim in its own signed JSON. Booting
// anyway signs a claim nobody checked into every piece of evidence.
//
// The two rows cover both ways the bucket can fail to deliver. "unknown" is the one the
// old string comparison hid completely — and it is also the one only the boot gate can
// ever catch, because the store is asked for its immutability once, at construction, so
// a bucket unreachable at boot answers "unknown" for the lifetime of the process.
func TestAskingForALockTheBucketDoesNotGiveRefusesTheBoot(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   int
		body     string
		wantMode string
	}{
		{"a bucket with no object lock", http.StatusNotFound, unlockedBucket, "mutable"},
		{"a bucket the gateway cannot interrogate", http.StatusForbidden, unreadableBucket, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := newLockOracle(t, tc.status, tc.body)
			d := bucketGateway(t, o, "compliance")

			if got := d.gw.Settings.RecordingStoreMode; got != tc.wantMode {
				t.Fatalf("reported mode = %q, want %q", got, tc.wantMode)
			}
			if got := d.gw.Settings.RecordingStoreRequested; got != "compliance" {
				t.Fatalf("requested mode = %q, want compliance", got)
			}

			// env is dev in the harness, and this still refuses. A check relaxed in
			// development is a check about a dangerous *default*; this one is about an
			// explicit request the deployment cannot honour, which is the same lie in a
			// lab as in production.
			problems, err := safety.Check(d.gw.Settings, quiet())
			if err == nil {
				t.Fatalf("compliance was promised against a %s bucket and the gateway "+
					"started: %v", tc.wantMode, problems)
			}
			var fatal []safety.Problem
			for _, p := range problems {
				if p.Fatal {
					fatal = append(fatal, p)
				}
			}
			if len(fatal) != 1 || fatal[0].Setting != "recorder.s3.lock_mode" {
				t.Fatalf("want exactly one fatal finding on recorder.s3.lock_mode, got %v", fatal)
			}
			// The one line that has to teach the fix.
			t.Logf("operator sees:\n%s", fatal[0])
			for _, want := range []string{"compliance", tc.wantMode, "lock_mode: none",
				"docs/plugins.md § 4.2"} {
				if !strings.Contains(fatal[0].Message, want) {
					t.Errorf("the refusal does not mention %q:\n%s", want, fatal[0].Message)
				}
			}
		})
	}
}

// TestAskingForNothingKeepsTheWarning: a lab has no WORM storage and must still be
// able to record. Nobody promised anything, so nothing is refused.
func TestAskingForNothingKeepsTheWarning(t *testing.T) {
	for _, mode := range []string{"", "none"} {
		t.Run(fmt.Sprintf("lock_mode %q", mode), func(t *testing.T) {
			o := newLockOracle(t, http.StatusNotFound, unlockedBucket)
			d := bucketGateway(t, o, mode)

			if got := d.gw.Settings.RecordingStoreMode; got != "mutable" {
				t.Fatalf("reported mode = %q, want mutable", got)
			}
			if got := d.gw.Settings.RecordingStoreRequested; got != "" {
				t.Fatalf("requested = %q; \"none\" and \"\" both mean no lock was asked for", got)
			}
			if _, err := safety.Check(d.gw.Settings, quiet()); err != nil {
				t.Fatalf("a mutable store nobody promised anything about refused the boot: %v", err)
			}
		})
	}
}

// TestALockedBucketIsReportedAsLocked: the other side of the gate, so the fatal above
// is evidence of a check and not of a store that can only say no.
func TestALockedBucketIsReportedAsLocked(t *testing.T) {
	o := newLockOracle(t, http.StatusOK, lockedBucket)
	d := bucketGateway(t, o, "compliance")

	if got := d.gw.Settings.RecordingStoreMode; got != "compliance" {
		t.Fatalf("reported mode = %q, want compliance", got)
	}
	if !d.gw.Settings.RecordingStoreProtected {
		t.Fatal("a compliance-locked bucket did not report as protected")
	}
	problems, err := safety.Check(d.gw.Settings, quiet())
	if err != nil {
		t.Fatalf("a locked bucket refused the boot: %v", err)
	}
	for _, p := range problems {
		if p.Setting == "recording_store" || p.Setting == "recorder.s3.lock_mode" {
			t.Errorf("unexpected finding against a locked bucket: %s", p)
		}
	}
}
