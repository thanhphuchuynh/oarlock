package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/config"
)

func TestWebhookAuthorizerConfig(t *testing.T) {
	cfg, err := config.Parse([]byte(`
env: dev
url: ws://127.0.0.1:8443
devices: devices.yaml
ssh:
  host_key: hostkey
authorizer:
  kind: webhook
  url: http://127.0.0.1:9000/authorize
  watch_url: http://127.0.0.1:9000/watch
  token: dev-secret
  timeout: 2s
  cache_ttl: 5s
  recheck_interval: 30s
recorder:
  dir: recordings
  signing_key: recording.key
`), "test.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Authz.Kind != "webhook" || cfg.Authz.URL == "" || cfg.Authz.WatchURL == "" {
		t.Fatalf("authz config = %+v", cfg.Authz)
	}
}

func TestLegacyDevicePathDoesNotOptIntoStore(t *testing.T) {
	cfg, err := config.Parse([]byte(`
env: dev
url: ws://127.0.0.1:8443
devices: devices.yaml
ssh:
  host_key: hostkey
authorizer:
  kind: none
`), "test.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Devices.Kind != "file" || cfg.Devices.Path != "devices.yaml" {
		t.Fatalf("devices = %+v", cfg.Devices)
	}
	if cfg.Store.Kind != "" || cfg.Store.Path != "" {
		t.Fatalf("legacy config unexpectedly selected store = %+v", cfg.Store)
	}
}

func TestSQLiteDeviceRegistryDefaultsStore(t *testing.T) {
	cfg, err := config.Parse([]byte(`
env: dev
url: ws://127.0.0.1:8443
devices:
  kind: sqlite
ssh:
  host_key: hostkey
authorizer:
  kind: none
`), "test.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Devices.Kind != "sqlite" {
		t.Fatalf("devices = %+v", cfg.Devices)
	}
	if cfg.Store.Kind != "sqlite" || cfg.Store.Path != "./oarlock.db" {
		t.Fatalf("store = %+v", cfg.Store)
	}
	if cfg.Store.Migrate == nil || !*cfg.Store.Migrate {
		t.Fatalf("migrate = %v", cfg.Store.Migrate)
	}
}

func TestSQLiteAuthorizerUsesOperationalStore(t *testing.T) {
	cfg, err := config.Parse([]byte(`
env: dev
url: ws://127.0.0.1:8443
store:
  kind: sqlite
  path: ./operations.db
devices:
  kind: sqlite
ssh:
  host_key: hostkey
authorizer:
  kind: sqlite
`), "test.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Authz.Kind != "sqlite" || cfg.Store.Path != "./operations.db" {
		t.Fatalf("config = %+v / %+v", cfg.Authz, cfg.Store)
	}
}

func TestAuditConfigDefaultsAndValidation(t *testing.T) {
	cfg, err := config.Parse([]byte(`
env: dev
url: ws://127.0.0.1:8443
devices: devices.yaml
ssh:
  host_key: hostkey
authorizer:
  kind: none
recorder:
  dir: recordings
  signing_key: recording.key
`), "test.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Audit.Kind != "stderr" || cfg.Audit.Buffer != 1024 {
		t.Fatalf("audit config = %+v", cfg.Audit)
	}

	_, err = config.Parse([]byte(`
env: dev
url: ws://127.0.0.1:8443
devices: devices.yaml
ssh:
  host_key: hostkey
authorizer:
  kind: none
audit:
  kind: kafka
recorder:
  dir: recordings
  signing_key: recording.key
`), "test.yaml")
	if err == nil {
		t.Fatal("expected audit.kind validation error")
	}
	if !strings.Contains(err.Error(), "audit.kind") {
		t.Fatalf("error = %v", err)
	}
}

func TestMQTTDispatcherConfigDefaults(t *testing.T) {
	cfg, err := config.Parse([]byte(`
env: dev
url: ws://127.0.0.1:8443
devices: devices.yaml
ssh:
  host_key: hostkey
authorizer:
  kind: none
dispatcher:
  kind: mqtt
  url: mqtt://127.0.0.1:1883
  client_id: gateway-a
  username: doorbell
  password: secret
  timeout: 2s
recorder:
  dir: recordings
  signing_key: recording.key
`), "test.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Dispatch.Topic != "oarlock/devices/{device_id}/wake" {
		t.Fatalf("topic = %q", cfg.Dispatch.Topic)
	}
	if cfg.Dispatch.QoS == nil || *cfg.Dispatch.QoS != 1 {
		t.Fatalf("qos = %v", cfg.Dispatch.QoS)
	}
}

func TestMQTTDispatcherQoSZeroIsPreserved(t *testing.T) {
	cfg, err := config.Parse([]byte(`
env: dev
url: ws://127.0.0.1:8443
devices: devices.yaml
ssh:
  host_key: hostkey
authorizer:
  kind: none
dispatcher:
  kind: mqtt
  url: mqtt://127.0.0.1:1883
  qos: 0
recorder:
  dir: recordings
  signing_key: recording.key
`), "test.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Dispatch.QoS == nil || *cfg.Dispatch.QoS != 0 {
		t.Fatalf("qos = %v", cfg.Dispatch.QoS)
	}
}

func TestDispatcherConfigValidation(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "unknown kind",
			body: "dispatcher:\n  kind: kafka\n",
			want: "dispatcher.kind",
		},
		{
			name: "exec command required",
			body: "dispatcher:\n  kind: exec\n",
			want: "dispatcher.command",
		},
		{
			name: "webhook URL required",
			body: "dispatcher:\n  kind: webhook\n",
			want: "dispatcher.url",
		},
		{
			name: "mqtt URL required",
			body: "dispatcher:\n  kind: mqtt\n",
			want: "dispatcher.url",
		},
		{
			name: "mqtt topic per device",
			body: "dispatcher:\n  kind: mqtt\n  url: mqtt://127.0.0.1:1883\n  topic: fleet/wake\n",
			want: "{device_id}",
		},
		{
			name: "mqtt qos",
			body: "dispatcher:\n  kind: mqtt\n  url: mqtt://127.0.0.1:1883\n  qos: 2\n",
			want: "dispatcher.qos",
		},
		{
			name: "mqtt password needs username",
			body: "dispatcher:\n  kind: mqtt\n  url: mqtt://127.0.0.1:1883\n  password: secret\n",
			want: "dispatcher.username",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := config.Parse([]byte(`
env: dev
url: ws://127.0.0.1:8443
devices: devices.yaml
ssh:
  host_key: hostkey
authorizer:
  kind: none
recorder:
  dir: recordings
  signing_key: recording.key
`+tc.body), "test.yaml")
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestWebhookCacheTTLIsShorterThanRecheckInterval(t *testing.T) {
	_, err := config.Parse([]byte(`
env: dev
url: ws://127.0.0.1:8443
devices: devices.yaml
ssh:
  host_key: hostkey
authorizer:
  kind: webhook
  url: http://127.0.0.1:9000/authorize
  cache_ttl: 30s
  recheck_interval: 30s
recorder:
  dir: recordings
  signing_key: recording.key
`), "test.yaml")
	if err == nil {
		t.Fatal("expected cache_ttl validation error")
	}
	if !strings.Contains(err.Error(), "cache_ttl") {
		t.Fatalf("error = %v", err)
	}
}

func TestWebhookDefaultCacheTTLIsCheckedAgainstRecheckInterval(t *testing.T) {
	_, err := config.Parse([]byte(`
env: dev
url: ws://127.0.0.1:8443
devices: devices.yaml
ssh:
  host_key: hostkey
authorizer:
  kind: webhook
  url: http://127.0.0.1:9000/authorize
  recheck_interval: 1s
recorder:
  dir: recordings
  signing_key: recording.key
`), "test.yaml")
	if err == nil {
		t.Fatal("expected default cache_ttl validation error")
	}
	if !strings.Contains(err.Error(), "cache_ttl") {
		t.Fatalf("error = %v", err)
	}
}

func TestDelegationSecretMustBeLongEnough(t *testing.T) {
	_, err := config.Parse([]byte(`
env: dev
url: ws://127.0.0.1:8443
devices: devices.yaml
ssh:
  host_key: hostkey
authorizer:
  kind: none
api:
  delegation_secret: short
recorder:
  dir: recordings
  signing_key: recording.key
`), "test.yaml")
	if err == nil {
		t.Fatal("expected delegation_secret validation error")
	}
	if !strings.Contains(err.Error(), "delegation_secret") {
		t.Fatalf("error = %v", err)
	}
}

func TestRecordInputPolicyConfig(t *testing.T) {
	cfg, err := config.Parse([]byte(`
env: dev
url: ws://127.0.0.1:8443
devices: devices.yaml
ssh:
  host_key: hostkey
authorizer:
  kind: none
policy:
  record_input:
    default: false
    rules:
      - name: pci capture
        when:
          device_tags: {pci_scope: "true"}
        value: true
      - authority: employment-law
        when:
          principal_groups: ["eu-*"]
        value: false
recorder:
  dir: recordings
  signing_key: recording.key
`), "test.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Policy.RecordInput.Rules) != 2 {
		t.Fatalf("rules = %d", len(cfg.Policy.RecordInput.Rules))
	}
}

func TestRecordInputPolicyInvalidPatternIsRejected(t *testing.T) {
	_, err := config.Parse([]byte(`
env: dev
url: ws://127.0.0.1:8443
devices: devices.yaml
ssh:
  host_key: hostkey
authorizer:
  kind: none
policy:
  record_input:
    rules:
      - when:
          principals: ["["]
        value: true
recorder:
  dir: recordings
  signing_key: recording.key
`), "test.yaml")
	if err == nil {
		t.Fatal("expected invalid pattern error")
	}
	if !strings.Contains(err.Error(), "recordpolicy") {
		t.Fatalf("error = %v", err)
	}
}

// TestAdminsAreExactPrincipalIds. `authorizer.admins` is the one field in the file that
// outranks the policy store, so a pattern there would be a break-glass for a whole
// domain. Grants take patterns; this does not.
func TestAdminsAreExactPrincipalIds(t *testing.T) {
	base := `
env: dev
url: ws://127.0.0.1:8443
devices: devices.yaml
ssh:
  host_key: hostkey
recorder:
  dir: recordings
  signing_key: recording.key
authorizer:
  kind: none
`
	c, err := config.Parse([]byte(base+"  admins:\n    - root@example.com\n"), "test.yaml")
	if err != nil {
		t.Fatalf("an exact id was refused: %v", err)
	}
	if len(c.Authz.Admins) != 1 || c.Authz.Admins[0] != "root@example.com" {
		t.Fatalf("admins = %#v", c.Authz.Admins)
	}

	for _, tc := range []struct{ name, value, want string }{
		{"a glob", `"*@example.com"`, "looks like a pattern"},
		{"a single-character wildcard", `"root?@example.com"`, "looks like a pattern"},
		{"a character class", `"root[12]@example.com"`, "looks like a pattern"},
		{"an empty entry", `""`, "is empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := config.Parse([]byte(base+"  admins:\n    - "+tc.value+"\n"), "test.yaml")
			if err == nil {
				t.Fatalf("%s was accepted", tc.value)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

// ── recording to a bucket ───────────────────────────────────────────────────────

// TestS3RecorderConfig covers the block and the two validations that used to key off
// recorder.dir alone.
//
// Both were wrong the moment a second store existed: an S3-only deployment was told
// "nothing is recorded", and an S3 bucket with no signing key sailed through — an
// unsigned manifest being a chain anyone with write access can recompute, which is the
// thing record.New refuses to construct.
func TestS3RecorderConfig(t *testing.T) {
	base := `
env: dev
url: ws://127.0.0.1:8443
devices: devices.yaml
ssh:
  host_key: hostkey
authorizer:
  kind: none
`
	t.Run("a bucket is a recorder", func(t *testing.T) {
		c, err := config.Parse([]byte(base+`recorder:
  signing_key: recording.key
  key_id: prod-recording-key
  s3:
    bucket: oarlock-recordings
    region: eu-west-1
    endpoint: ""
    prefix: recordings
    lock_mode: compliance
    retain_for: 2160h
`), "test.yaml")
		if err != nil {
			t.Fatalf("an s3-only recorder was refused: %v", err)
		}
		if c.Recorder.S3 == nil {
			t.Fatal("recorder.s3 did not decode")
		}
		if got := c.Recorder.S3.Bucket; got != "oarlock-recordings" {
			t.Errorf("bucket = %q", got)
		}
		if got := c.Recorder.S3.RetainFor; got != 2160*time.Hour {
			t.Errorf("retain_for = %v, want 2160h", got)
		}
		if got := c.Recorder.S3.RequestedLockMode(); got != "compliance" {
			t.Errorf("requested lock mode = %q", got)
		}
		if !c.Recorder.Recording() {
			t.Error("a configured bucket does not count as recording, so the " +
				"signing-key checks and the operator's banner would both be wrong")
		}
	})

	t.Run("none and absent both mean no lock was asked for", func(t *testing.T) {
		for _, line := range []string{"    lock_mode: none\n", ""} {
			c, err := config.Parse([]byte(base+`recorder:
  signing_key: recording.key
  s3:
    bucket: oarlock-recordings
`+line), "test.yaml")
			if err != nil {
				t.Fatalf("%q was refused: %v", line, err)
			}
			if got := c.Recorder.S3.RequestedLockMode(); got != "" {
				t.Errorf("%q gave a requested mode of %q, want empty — the boot gate "+
					"refuses a requested lock the bucket does not give, so \"none\" "+
					"reading as a request would refuse every unlocked bucket", line, got)
			}
		}
	})

	// A nil S3 must answer too: app.go asks the config for the requested mode whether
	// or not a bucket was configured.
	t.Run("no bucket at all requests nothing", func(t *testing.T) {
		var s *config.S3
		if got := s.RequestedLockMode(); got != "" {
			t.Errorf("a nil s3 block requested %q", got)
		}
	})

	for _, tc := range []struct{ name, recorder, want string }{
		{
			name: "a directory and a bucket",
			recorder: `recorder:
  dir: recordings
  signing_key: recording.key
  s3:
    bucket: oarlock-recordings
`,
			want: "mutually exclusive",
		},
		{
			name: "a bucket with no name",
			recorder: `recorder:
  signing_key: recording.key
  s3:
    region: eu-west-1
`,
			want: "recorder.s3.bucket is required",
		},
		{
			name: "a bucket with no signing key",
			recorder: `recorder:
  s3:
    bucket: oarlock-recordings
`,
			want: "recorder.signing_key is required",
		},
		{
			name: "a signing key and nowhere to record",
			recorder: `recorder:
  signing_key: recording.key
`,
			want: "neither recorder.dir nor recorder.s3",
		},
		{
			name: "an unknown key in the block",
			recorder: `recorder:
  signing_key: recording.key
  s3:
    bucket: oarlock-recordings
    lock_moed: compliance
`,
			want: "lock_moed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := config.Parse([]byte(base+tc.recorder), "test.yaml")
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error does not mention %q: %v", tc.want, err)
			}
		})
	}
}
