package config_test

import (
	"strings"
	"testing"

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
