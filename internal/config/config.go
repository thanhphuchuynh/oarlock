// Package config is the gateway's configuration file.
//
// Two rules shape it, and both come from having been bitten by the alternatives.
//
// **Unknown keys are refused.** A typo in a key name must not silently mean "default":
// `allow_unrecoreded: true` that quietly stays false is a security setting somebody
// believes they set. So the decoder is strict, and a misspelling refuses the boot with the
// offending line.
//
// **Defaults are documented in one place and applied in one place.** Every limit in
// ARCHITECTURE § 9.3 has a number, and a config file that omits it gets that number
// rather than Go's zero value — a zero rate limit is not "unlimited", it is a stall.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/oarlock/oarlock/internal/authz"
	"github.com/oarlock/oarlock/internal/pump"
	"github.com/oarlock/oarlock/internal/recordpolicy"
	"github.com/oarlock/oarlock/internal/ring"
	"github.com/oarlock/oarlock/internal/safety"
	"github.com/oarlock/oarlock/internal/sessions"
)

// Config is the whole file.
type Config struct {
	// Env selects the strictness of the boot gate. Anything that is not dev or test
	// gets the production checks, including an empty value: an unset environment must
	// fail safe rather than open.
	Env string `yaml:"env"`

	// URL is this node's externally reachable base, e.g. wss://gw-a.example.org.
	//
	// Not a load balancer. An agent dials the replica the operator is waiting on
	// (ADR-025), so this has to be the address of *this* process.
	URL string `yaml:"url"`

	// BrowserOrigins lists origins allowed to open the browser-facing websockets
	// (/ws/session and /ws/attach). Empty means same-origin only.
	//
	// This exists for an embedding console served from a different origin — the MDM
	// hosting the terminal, say. It loosens a real defence: the browser leg is
	// authenticated by a ticket in the OPEN frame, and the Origin check is what stops
	// any page from starting the handshake before that ticket is ever examined. So
	// name exact origins; a wildcard here hands every site on the internet the first
	// half of an attach.
	//
	// Deliberately not applied to /ws/control — the device leg sends no Origin, and
	// widening it there would protect nothing and weaken something.
	BrowserOrigins []string `yaml:"browser_origins"`

	Listen   Listen              `yaml:"listen"`
	SSH      SSH                 `yaml:"ssh"`
	Store    Store               `yaml:"store"`
	Devices  Devices             `yaml:"devices"`
	Auth     Auth                `yaml:"auth"`
	Authz    Authz               `yaml:"authorizer"`
	Dispatch Dispatch            `yaml:"dispatcher"`
	Recorder Recorder            `yaml:"recorder"`
	Policy   recordpolicy.Config `yaml:"policy"`
	Audit    Audit               `yaml:"audit"`
	API      API                 `yaml:"api"`
	Limits   Limits              `yaml:"limits"`
}

// Listen is where the gateway accepts connections.
type Listen struct {
	// SSH is the operator front door.
	SSH string `yaml:"ssh"`
	// HTTP carries /ws/control, /ws/session, /ws/attach and /api.
	HTTP string `yaml:"http"`
	// TLSCert and TLSKey turn the HTTP listener into HTTPS. Without them the gateway
	// serves plain HTTP, which the boot gate refuses outside dev — `wss://` needs TLS,
	// and a device key handshake over `ws://` is a handshake anybody can watch.
	TLSCert string `yaml:"tls_cert"`
	TLSKey  string `yaml:"tls_key"`
	// WSConnRatePerMinute caps how many WebSocket connections one client may open in a
	// minute, across /ws/control, /ws/session and /ws/attach. Zero means
	// ratelimit.DefaultWSConnRatePerMinute (120); negative disables it.
	//
	// Not an anti-guessing control — nothing on these doors can be guessed, since the
	// control channel is an Ed25519 challenge-response and the session doors redeem a
	// 32-byte random ticket. It bounds *work*: a peer that connects, starts a handshake
	// and hangs up costs a goroutine and a signature verify, and until this existed
	// nothing bounded how fast that could be repeated.
	//
	// Sized for a fleet, not an operator. One client here can legitimately be several
	// hundred NAT'd devices reconnecting after a restart, which is why the number is
	// four times the SSH door's. Being refused is a retry rather than a failure — an
	// agent backs off and comes back, and since its backoff resets on a successful
	// handshake rather than a successful dial, a throttled fleet spreads itself out.
	//
	// **Set this to -1 if a proxy terminates these connections**, or every device and
	// operator behind it is counted as one client. Forwarded headers are deliberately
	// not read: a key the caller chooses is not a limit.
	WSConnRatePerMinute int `yaml:"ws_conn_rate_per_minute"`
	// RequireChannelBinding refuses any control-channel handshake that is not bound to
	// the TLS connection underneath it (protocol v1).
	//
	// Binding is what stops a TLS-terminating middlebox from relaying a device's
	// handshake and keeping the authenticated channel for itself: the relay has two TLS
	// sessions, so it exports two different keying materials, and a signature made over
	// one does not verify over the other. Certificate pinning was the stopgap and only
	// covers the case where the middlebox has to present a certificate the agent would
	// reject.
	//
	// Off by default because a development gateway on `ws://` has no channel to bind to
	// and would refuse every agent. `internal/safety` refuses production without it.
	//
	// Agents must also require it on their side: the gateway picks the version, so an
	// agent that accepts v0 can be steered onto it by anything that can rewrite HELLO.
	RequireChannelBinding bool `yaml:"require_channel_binding"`
}

// SSH is the operator-facing SSH server.
type SSH struct {
	// HostKey is the gateway's SSH identity, shared by every replica.
	//
	// Every replica must present the same one. If they do not, operators get a
	// host-key-mismatch warning every time a load balancer moves them — and an operator
	// trained to ignore that warning is an operator who will ignore a real one.
	HostKey string `yaml:"host_key"`
	// GenerateHostKey writes a new key at HostKey when the file is absent. Convenient
	// in dev and refused in production, where a key generated at boot means a warning
	// on every restart.
	GenerateHostKey bool `yaml:"generate_host_key"`
	// AuthorizedKeys is the operator key file for the authorized_keys authenticator.
	AuthorizedKeys string `yaml:"authorized_keys"`
	// HandshakeBudget bounds the interval between a connection arriving at the front
	// door and an operator authenticating on it. Zero means the sshsrv default (15s);
	// negative disables the bound, which no deployment should want.
	//
	// This is not a latency target. Keyboard-interactive authentication asks a human to
	// approve a login in a browser, so raise it rather than lower it if your identity
	// provider is slow — what it exists to stop is a peer holding a goroutine and a file
	// descriptor open forever without proving anything about who it is.
	HandshakeBudget time.Duration `yaml:"handshake_budget"`
	// MaxConnections caps concurrent connections on the SSH listener, authenticated or
	// not. Zero means DefaultMaxSSHConnections; negative means no cap.
	//
	// A backstop, not the primary control — HandshakeBudget is what makes slots come
	// back. Set generously: this is an operator front door, and a limit low enough to
	// bite under real use is a limit that locks out the person handling the incident.
	MaxConnections int `yaml:"max_connections"`
	// ConnRatePerMinute caps how many connections one client may open in a minute,
	// keyed by IPv4 address or IPv6 /64. Zero means sshsrv.DefaultConnRatePerMinute
	// (30); negative disables it.
	//
	// This is the door's answer to somebody *trying* keys: MaxConnections bounds how
	// many connections exist at once and HandshakeBudget bounds how long one may be
	// held, but an attacker who connects, fails fast and reconnects pays neither. Note
	// that a connection carries up to six key attempts, so the real attempt budget is
	// six times this.
	//
	// **Set this to -1 if a TCP load balancer without PROXY protocol fronts the
	// listener.** SSH has no X-Forwarded-For, so every connection would arrive from the
	// balancer, and one counter would cover every operator you have.
	ConnRatePerMinute int `yaml:"conn_rate_per_minute"`
}

// Store configures the gateway's operational database.
type Store struct {
	// Kind is "sqlite" today. Postgres will use the same logical schema later.
	Kind string `yaml:"kind"`
	// Path is the SQLite database path. Empty defaults to ./oarlock.db.
	Path string `yaml:"path"`
	// URL is reserved for postgres.
	URL string `yaml:"url"`
	// Schema is the postgres schema name. SQLite uses oarlock_ table prefixes.
	Schema string `yaml:"schema"`
	// Migrate applies built-in migrations at boot. Default true.
	Migrate *bool `yaml:"migrate"`
}

// Devices configures the device registry. It accepts the legacy scalar form:
//
//	devices: ./devices.yaml
//
// and the database form:
//
//	devices:
//	  kind: sqlite
type Devices struct {
	Kind string `yaml:"kind"`
	Path string `yaml:"path"`
}

// UnmarshalYAML accepts the historical scalar devices path and the newer structured form.
func (d *Devices) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		d.Kind = "file"
		d.Path = n.Value
		return nil
	case yaml.MappingNode:
		type plain Devices
		var out plain
		if err := n.Decode(&out); err != nil {
			return err
		}
		*d = Devices(out)
		return nil
	default:
		return fmt.Errorf("devices must be a path or a mapping")
	}
}

// Auth configures who an operator is. Authz configures whether they may.
type Auth struct {
	// Kind is "oidc" or "sshca", or empty to use ssh.authorized_keys and api.tokens.
	Kind string `yaml:"kind"`

	// ── sshca ──
	// CAKeys is a file of trusted SSH CA public keys, in authorized_keys format. More
	// than one is how a CA is rotated: publish the new key alongside the old, re-issue,
	// then remove the old.
	CAKeys string `yaml:"ca_keys"`
	// Revocations is an optional file of revoked certificate serial numbers.
	//
	// The primary revocation mechanism is the expiry — a list pushed to every replica is
	// the same problem authorized_keys has. This is for the case expiry cannot cover: a
	// certificate known to be stolen while it is still valid.
	Revocations string `yaml:"revocations"`
	// MaxLifetime caps how long a certificate may have been issued for. Zero means
	// sshca.DefaultMaxLifetime (24h); negative disables the cap, which gives up the
	// property this backend exists for. A certificate that never expires is refused
	// whatever this says.
	MaxLifetime time.Duration `yaml:"max_lifetime"`
	// PrincipalFrom is "principals" (the default: the first valid_principal) or
	// "key_id". Vault and Teleport put the username in the key id.
	PrincipalFrom string `yaml:"principal_from"`

	// Issuer is the OIDC issuer URL. Discovery happens at
	// <issuer>/.well-known/openid-configuration, and every token must name this
	// issuer exactly.
	Issuer string `yaml:"issuer"`
	// ClientID identifies this gateway to the provider, and is the default audience a
	// token must name.
	ClientID string `yaml:"client_id"`
	// ClientSecret is used for the device-code exchange. Public clients omit it.
	ClientSecret string `yaml:"client_secret"`
	// Audience overrides ClientID as the audience a token must name.
	Audience string `yaml:"audience"`
	// Scopes are requested during the SSH device-code login. `openid` is always sent.
	Scopes []string `yaml:"scopes"`

	// SubjectClaim becomes the principal id: what is recorded and what an
	// authorisation rule matches. Defaults to `email`, because rules are globs over
	// principal ids and people write `*@oncall.example.com` — at the cost that an
	// unverified email is refused. Set to `sub` to prefer immutability.
	SubjectClaim string `yaml:"subject_claim"`
	EmailClaim   string `yaml:"email_claim"`
	GroupsClaim  string `yaml:"groups_claim"`

	// Skew tolerates clock drift between this gateway and the provider.
	Skew time.Duration `yaml:"skew"`
	// JWKSRefresh is how long a cached key set may be used. It is the upper bound on
	// how long a key the provider has *withdrawn* keeps verifying tokens.
	JWKSRefresh time.Duration `yaml:"jwks_refresh"`
	// DeviceTimeout is how long an SSH device-code login may sit unapproved.
	DeviceTimeout time.Duration `yaml:"device_timeout"`

	// RedirectURL is this gateway's browser callback, exactly as registered with the
	// provider. Setting it turns on the browser login at /auth/*; leaving it empty means
	// the console has no sign-in button and expects a pasted token.
	//
	// Not derived from the request's Host header: a provider matches this byte for byte,
	// and letting a header choose it would let a proxy — or an attacker who can set one —
	// choose where an authorization code is delivered.
	RedirectURL string `yaml:"redirect_url"`
}

// Authz configures the authorisation backend.
type Authz struct {
	// Kind is "rules", "sqlite", "webhook", or "none" to run without authorisation. The boot gate
	// refuses "none" in production.
	Kind string `yaml:"kind"`
	// Path is the rules file, for kind: rules.
	Path string `yaml:"path"`
	// URL is the decision endpoint, for kind: webhook.
	URL string `yaml:"url"`
	// WatchURL is the optional SSE revocation stream, for kind: webhook.
	WatchURL string `yaml:"watch_url"`
	// Token is sent as Authorization: Bearer <token>, for kind: webhook.
	Token string `yaml:"token"`
	// Timeout bounds one webhook decision call or Watch connection attempt.
	Timeout time.Duration `yaml:"timeout"`
	// CacheTTL caches webhook decisions briefly. It must be shorter than
	// RecheckInterval, or a cached grant would outlive the interval that is meant to
	// bound stale authorisation.
	CacheTTL time.Duration `yaml:"cache_ttl"`
	// Grace is how many consecutive failed re-checks a live session survives.
	//
	// A pointer because zero has a meaning and it is not "unset": `grace: 0` is strict
	// fail-closed, which is the right setting where a session is more dangerous than an
	// outage. Omitting the key gets the default of three.
	Grace *int `yaml:"grace"`
	// RecheckInterval is how often a live session's grant is re-checked.
	RecheckInterval time.Duration `yaml:"recheck_interval"`
	// Admins are principal ids allowed the administrative actions — editing device
	// records, editing the policy, ending somebody else's session — regardless of what
	// the backend answers.
	//
	// This is the break-glass, and it exists because the policy store is edited through
	// an API the policy store authorises: on an empty store nobody could write the
	// first permission, and deleting the last `admin:permissions` grant would lock the
	// room. Whoever owns this file can always get back in.
	//
	// It grants `admin:*` and nothing else. A config administrator may repair the
	// policy; they cannot open a shell, watch a session or query the database until
	// they write themselves a grant — which is a visible row and an audit line, unlike
	// a line in a config file nobody re-reads.
	//
	// Exact principal ids. Patterns are not accepted here on purpose.
	Admins []string `yaml:"admins"`
}

const defaultWebhookCacheTTL = 5 * time.Second

// Dispatch configures the out-of-band doorbell used by dispatch-mode devices.
type Dispatch struct {
	// Kind is "none", "exec", "webhook", or "mqtt". Empty is "none".
	Kind string `yaml:"kind"`
	// Command is the argv for kind: exec.
	Command []string `yaml:"command"`
	// URL is the webhook endpoint for kind: webhook, or broker URL for kind: mqtt.
	URL string `yaml:"url"`
	// Secret signs webhook requests.
	Secret string `yaml:"secret"`
	// Timeout bounds one wake attempt.
	Timeout time.Duration `yaml:"timeout"`
	// Topic is the MQTT topic template. Use {device_id}; the default is per-device.
	Topic string `yaml:"topic"`
	// ClientID, Username and Password are MQTT CONNECT credentials.
	ClientID string `yaml:"client_id"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	// QoS is MQTT publish quality of service. Only 0 and 1 are supported.
	QoS *int `yaml:"qos"`
}

// Recorder configures session recording.
type Recorder struct {
	// Dir is where recordings go. Empty records nothing — and says so in the operator's
	// banner and in the session row, because an unrecorded session must be a fact you
	// can query for rather than an absence somebody has to notice.
	Dir string `yaml:"dir"`
	// SigningKey is the ed25519 key the manifest is signed with.
	SigningKey string `yaml:"signing_key"`
	// GenerateSigningKey writes one when the file is absent. Dev only: a recording
	// signed by a key that changes on restart cannot be verified afterwards.
	GenerateSigningKey bool `yaml:"generate_signing_key"`
	// KeyID names the key in the manifest, so a verifier knows which one to ask for.
	KeyID string `yaml:"key_id"`
}

// Audit configures the audit sink.
type Audit struct {
	// Kind is "stderr" or "none". The built-in stderr sink writes JSON lines.
	Kind string `yaml:"kind"`
	// Buffer is the bounded async queue depth. A full queue drops events and counts
	// them rather than blocking a session.
	Buffer int `yaml:"buffer"`
}

// API configures the control API.
type API struct {
	// Tokens maps a bearer token to a principal. For development and CI: a real
	// deployment uses an authenticator that can validate a token it did not mint.
	Tokens map[string]string `yaml:"tokens"`
	// RatePerMinute is the per-principal request budget.
	RatePerMinute int `yaml:"rate_per_minute"`
	// AllowUnattended permits explicitly marked service principals to open sessions
	// with no human subject. Off by default: a service account should not become the
	// principal on an operator shell by accident.
	AllowUnattended bool `yaml:"allow_unattended"`
	// DelegationSecret enables service-signed On-Behalf-Of assertions. Use at least
	// 32 bytes of secret material.
	DelegationSecret string `yaml:"delegation_secret"`
	// DelegationAudience is the audience service-signed assertions must name.
	DelegationAudience string `yaml:"delegation_audience"`
	// DelegationMaxTTL caps assertion lifetime. Defaults to 60s in the wrapper.
	DelegationMaxTTL time.Duration `yaml:"delegation_max_ttl"`
	// MayActFor maps service principal id to subject or group globs. Group globs are
	// prefixed with "group:".
	MayActFor map[string][]string `yaml:"may_act_for"`
}

// Limits are the server-side ceilings from ARCHITECTURE § 9.3.
//
// Every one is server-side. A client-side limit is a suggestion.
type Limits struct {
	Rate                 int           `yaml:"rate"`
	Burst                int           `yaml:"burst"`
	Batch                int           `yaml:"batch"`
	Window               time.Duration `yaml:"window"`
	HighWater            int           `yaml:"high_water"`
	LowWater             int           `yaml:"low_water"`
	Idle                 time.Duration `yaml:"idle"`
	IdleInput            time.Duration `yaml:"idle_input"`
	MaxDuration          time.Duration `yaml:"max_duration"`
	Scrollback           int           `yaml:"scrollback"`
	SessionsPerDevice    int           `yaml:"sessions_per_device"`
	SessionsPerPrincipal int           `yaml:"sessions_per_principal"`
	// TCPConnsPerDevice caps live forwarded connections (`ssh -L`) on one device.
	// Counted apart from sessions_per_device because a forward is not one of anything:
	// one `ssh -L` is as many connections as the client opens, and a browser loading a
	// page opens six. Default 16.
	TCPConnsPerDevice int `yaml:"tcp_conns_per_device"`
}

// Load reads and validates a configuration file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: reading %s: %w", path, err)
	}
	return Parse(b, path)
}

// Parse decodes and validates configuration.
func Parse(b []byte, name string) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true) // a typo must not silently mean "default"
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: parsing %s: %w", name, err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Defaults returns the configuration a file that sets nothing gets.
func Defaults() Config {
	var c Config
	c.applyDefaults()
	return c
}

func (c *Config) applyDefaults() {
	if c.Listen.SSH == "" {
		c.Listen.SSH = ":2222"
	}
	if c.Listen.HTTP == "" {
		c.Listen.HTTP = ":8443"
	}
	if c.Devices.Kind == "" {
		if c.Devices.Path != "" {
			c.Devices.Kind = "file"
		} else {
			c.Devices.Kind = "sqlite"
		}
	}
	if c.Store.Kind == "" && c.Devices.Kind == "sqlite" {
		c.Store.Kind = "sqlite"
	}
	if c.Store.Kind == "sqlite" && c.Store.Path == "" {
		c.Store.Path = "./oarlock.db"
	}
	if c.Store.Kind != "" && c.Store.Schema == "" {
		c.Store.Schema = "oarlock"
	}
	if c.Store.Kind != "" && c.Store.Migrate == nil {
		yes := true
		c.Store.Migrate = &yes
	}
	if c.Authz.Kind == "" {
		c.Authz.Kind = "rules"
	}
	if c.Authz.RecheckInterval == 0 {
		c.Authz.RecheckInterval = authz.DefaultRecheckInterval
	}
	if c.Authz.Kind == "webhook" && c.Authz.CacheTTL == 0 {
		c.Authz.CacheTTL = defaultWebhookCacheTTL
	}
	if c.Dispatch.Kind == "" {
		c.Dispatch.Kind = "none"
	}
	if c.Dispatch.Kind == "mqtt" {
		if c.Dispatch.Topic == "" {
			c.Dispatch.Topic = "oarlock/devices/{device_id}/wake"
		}
		if c.Dispatch.QoS == nil {
			qos := 1
			c.Dispatch.QoS = &qos
		}
	}
	if c.Recorder.KeyID == "" {
		c.Recorder.KeyID = "oarlock-recorder"
	}
	if c.API.RatePerMinute == 0 {
		c.API.RatePerMinute = 120
	}
	if c.API.DelegationAudience == "" {
		c.API.DelegationAudience = "oarlock-api"
	}
	if c.Audit.Kind == "" {
		c.Audit.Kind = "stderr"
	}
	if c.Audit.Buffer == 0 {
		c.Audit.Buffer = 1024
	}

	// The table in ARCHITECTURE § 9.3, in one place. A zero here is Go's zero value
	// rather than a decision, and for a rate limit the two are very different: unset
	// means "the documented default", not "stall the session".
	d := pump.DefaultDeadlines()
	if c.Limits.Rate == 0 {
		c.Limits.Rate = 256 << 10
	}
	if c.Limits.Burst == 0 {
		c.Limits.Burst = 1 << 20
	}
	if c.Limits.Batch == 0 {
		c.Limits.Batch = 64 << 10
	}
	if c.Limits.Window == 0 {
		c.Limits.Window = 25 * time.Millisecond
	}
	if c.Limits.HighWater == 0 {
		c.Limits.HighWater = 256 << 10
	}
	if c.Limits.LowWater == 0 {
		c.Limits.LowWater = 64 << 10
	}
	if c.Limits.Idle == 0 {
		c.Limits.Idle = d.Idle
	}
	if c.Limits.IdleInput == 0 {
		c.Limits.IdleInput = d.IdleInput
	}
	if c.Limits.MaxDuration == 0 {
		c.Limits.MaxDuration = d.Max
	}
	if c.Limits.Scrollback == 0 {
		c.Limits.Scrollback = ring.DefaultSize
	}
	if c.Limits.SessionsPerDevice == 0 {
		c.Limits.SessionsPerDevice = 1
	}
	if c.Limits.SessionsPerPrincipal == 0 {
		c.Limits.SessionsPerPrincipal = 5
	}
	if c.Limits.TCPConnsPerDevice == 0 {
		c.Limits.TCPConnsPerDevice = sessions.DefaultTCPConnsPerDevice
	}
}

// Validate reports every problem at once.
//
// Every problem, not the first: a config file with three mistakes should take one edit to
// fix rather than three boots to discover.
func (c *Config) Validate() error {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	if c.URL == "" {
		add("url is required: it is the address agents dial back on, and it must be " +
			"this node rather than a load balancer (ADR-025)")
	} else if !strings.HasPrefix(c.URL, "ws://") && !strings.HasPrefix(c.URL, "wss://") {
		add("url %q must start with ws:// or wss://", c.URL)
	}
	switch c.Store.Kind {
	case "":
	case "sqlite":
		if c.Store.Path == "" {
			add("store.path is required for kind: sqlite")
		}
	case "postgres":
		if c.Store.URL == "" {
			add("store.url is required for kind: postgres")
		}
	default:
		add("store.kind %q is not known (sqlite, postgres)", c.Store.Kind)
	}
	switch c.Devices.Kind {
	case "file":
		if c.Devices.Path == "" {
			add("devices.path is required for kind: file")
		}
	case "sqlite":
		if c.Store.Kind != "sqlite" {
			add("devices.kind sqlite requires store.kind sqlite")
		}
	case "postgres":
		if c.Store.Kind != "postgres" {
			add("devices.kind postgres requires store.kind postgres")
		}
	default:
		add("devices.kind %q is not known (file, sqlite, postgres)", c.Devices.Kind)
	}
	switch c.Authz.Kind {
	case "rules":
		if c.Authz.Path == "" {
			add("authorizer.path is required for kind: rules")
		}
	case "sqlite":
		if c.Store.Kind != "sqlite" {
			add("authorizer.kind sqlite requires store.kind sqlite")
		}
	case "webhook":
		if c.Authz.URL == "" {
			add("authorizer.url is required for kind: webhook")
		}
		if c.Authz.CacheTTL < 0 {
			add("authorizer.cache_ttl is negative")
		}
		if c.Authz.Timeout < 0 {
			add("authorizer.timeout is negative")
		}
		if c.Authz.CacheTTL > 0 && c.Authz.RecheckInterval > 0 &&
			c.Authz.CacheTTL >= c.Authz.RecheckInterval {
			add("authorizer.cache_ttl (%s) must be shorter than authorizer.recheck_interval (%s): "+
				"otherwise a revoked grant can stay cached past the interval",
				c.Authz.CacheTTL, c.Authz.RecheckInterval)
		}
	case "none":
		// Allowed here and refused by the boot gate in production, which is the right
		// division: the config file describes what was asked for, and the gate decides
		// whether this environment may have it.
	default:
		add("authorizer.kind %q is not known (rules, sqlite, webhook, none)", c.Authz.Kind)
	}
	if c.Authz.Grace != nil && *c.Authz.Grace < 0 {
		add("authorizer.grace is negative, which has no meaning. Zero is strict " +
			"fail-closed; a positive value is how many failed re-checks a live session " +
			"survives")
	}
	if c.Authz.RecheckInterval < 0 {
		add("authorizer.recheck_interval is negative")
	}
	switch c.Auth.Kind {
	case "", "none":
		// The existing surfaces: ssh.authorized_keys and api.tokens. Checked elsewhere.
	case "oidc":
		if c.Auth.Issuer == "" {
			add("auth.issuer is required for kind: oidc")
		}
		if c.Auth.ClientID == "" {
			add("auth.client_id is required for kind: oidc")
		}
		if c.Auth.Skew < 0 {
			add("auth.skew is negative")
		}
		if c.Auth.JWKSRefresh < 0 {
			add("auth.jwks_refresh is negative")
		}
		if c.Auth.DeviceTimeout < 0 {
			add("auth.device_timeout is negative")
		}
		if c.Auth.RedirectURL != "" {
			u, err := url.Parse(c.Auth.RedirectURL)
			switch {
			case err != nil:
				add("auth.redirect_url is not a URL: %v", err)
			case u.Scheme != "https" && u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost":
				add("auth.redirect_url must be https outside loopback: an authorization " +
					"code delivered over http is a code anybody on the path can read")
			}
		}
	case "sshca":
		if c.Auth.CAKeys == "" {
			add("auth.ca_keys is required for kind: sshca — there is nothing to trust")
		}
		// A negative max_lifetime is legal and not checked here: it gives up the
		// property the backend exists for, and sshca.Open says so loudly at boot, which
		// is the right place for a warning that is not a refusal.
		switch c.Auth.PrincipalFrom {
		case "", "principals", "key_id":
		default:
			add("auth.principal_from %q is not \"principals\" or \"key_id\"",
				c.Auth.PrincipalFrom)
		}
	default:
		add("auth.kind %q is not known (oidc, sshca, or empty for authorized_keys and "+
			"api.tokens)", c.Auth.Kind)
	}
	for i, admin := range c.Authz.Admins {
		switch {
		case strings.TrimSpace(admin) == "":
			add("authorizer.admins[%d] is empty", i)
		case strings.ContainsAny(admin, "*?["):
			// A pattern here would be a break-glass for a whole domain rather than a
			// person, and the field is the one place in the config that outranks the
			// policy store. Grants take patterns; this does not.
			add("authorizer.admins[%d] (%q) looks like a pattern. This field takes exact "+
				"principal ids: write a permission with actions: [\"admin:permissions\"] "+
				"if you want a rule", i, admin)
		}
	}
	switch c.Dispatch.Kind {
	case "none":
	case "exec":
		if len(c.Dispatch.Command) == 0 {
			add("dispatcher.command is required for kind: exec")
		}
	case "webhook":
		if c.Dispatch.URL == "" {
			add("dispatcher.url is required for kind: webhook")
		}
	case "mqtt":
		if c.Dispatch.URL == "" {
			add("dispatcher.url is required for kind: mqtt")
		}
		if c.Dispatch.Topic == "" {
			add("dispatcher.topic is required for kind: mqtt")
		}
		if !strings.Contains(c.Dispatch.Topic, "{device_id}") {
			add("dispatcher.topic must contain {device_id}, so each device has its own doorbell")
		}
		if c.Dispatch.QoS != nil && *c.Dispatch.QoS != 0 && *c.Dispatch.QoS != 1 {
			add("dispatcher.qos must be 0 or 1")
		}
		if c.Dispatch.Password != "" && c.Dispatch.Username == "" {
			add("dispatcher.username is required when dispatcher.password is set")
		}
	default:
		add("dispatcher.kind %q is not known (none, exec, webhook, mqtt)", c.Dispatch.Kind)
	}
	if c.Dispatch.Timeout < 0 {
		add("dispatcher.timeout is negative")
	}
	if c.SSH.HostKey == "" {
		add("ssh.host_key is required: every replica must present the same key, or " +
			"operators get a host-key-mismatch warning whenever a load balancer moves " +
			"them — and an operator trained to ignore that warning will ignore a real one")
	}
	if (c.Listen.TLSCert == "") != (c.Listen.TLSKey == "") {
		add("listen.tls_cert and listen.tls_key must be set together")
	}
	if c.Recorder.Dir == "" && c.Recorder.SigningKey != "" {
		add("recorder.signing_key is set but recorder.dir is not, so nothing is recorded")
	}
	if c.Recorder.Dir != "" && c.Recorder.SigningKey == "" {
		add("recorder.signing_key is required when recording: an unsigned manifest " +
			"cannot be verified, which is most of the point")
	}
	if c.Limits.LowWater >= c.Limits.HighWater {
		add("limits.low_water (%d) must be below limits.high_water (%d): releasing "+
			"backpressure at the mark that engaged it makes the reader oscillate",
			c.Limits.LowWater, c.Limits.HighWater)
	}
	if c.Limits.Rate < 0 || c.Limits.Batch <= 0 || c.Limits.Scrollback < 0 {
		add("limits.rate, limits.batch and limits.scrollback must be positive")
	}
	if c.Limits.TCPConnsPerDevice <= 0 {
		add("limits.tcp_conns_per_device must be positive")
	}
	if c.Limits.SessionsPerDevice <= 0 || c.Limits.SessionsPerPrincipal <= 0 {
		add("limits.sessions_per_device and limits.sessions_per_principal must be positive")
	}
	if c.API.DelegationSecret != "" && len(c.API.DelegationSecret) < 32 {
		add("api.delegation_secret must be at least 32 bytes")
	}
	if c.API.DelegationMaxTTL < 0 {
		add("api.delegation_max_ttl is negative")
	}
	if err := c.Policy.RecordInput.Validate(); err != nil {
		add("%s", err.Error())
	}
	switch c.Audit.Kind {
	case "stderr", "none":
	default:
		add("audit.kind %q is not known (stderr, none)", c.Audit.Kind)
	}
	if c.Audit.Buffer < 0 {
		add("audit.buffer is negative")
	}

	if len(problems) > 0 {
		return fmt.Errorf("config: %d problem(s):\n  - %s",
			len(problems), strings.Join(problems, "\n  - "))
	}
	return nil
}

// SafetyEnv is the environment as the boot gate understands it.
func (c *Config) SafetyEnv() safety.Env { return safety.Env(c.Env) }

// PumpLimits is the configuration the pump wants.
func (c *Config) PumpLimits() pump.Limits {
	return pump.Limits{
		Batch:     c.Limits.Batch,
		Window:    c.Limits.Window,
		Rate:      c.Limits.Rate,
		Burst:     c.Limits.Burst,
		HighWater: c.Limits.HighWater,
		LowWater:  c.Limits.LowWater,
	}
}

// Deadlines is the configuration the pump's supervisor wants.
func (c *Config) Deadlines() pump.Deadlines {
	return pump.Deadlines{
		Idle:      c.Limits.Idle,
		IdleInput: c.Limits.IdleInput,
		Max:       c.Limits.MaxDuration,
	}
}

// ErrNoConfig is returned when no path was given.
var ErrNoConfig = errors.New("config: a path is required")
