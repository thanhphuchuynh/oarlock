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
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/oarlock/oarlock/internal/authz"
	"github.com/oarlock/oarlock/internal/pump"
	"github.com/oarlock/oarlock/internal/ring"
	"github.com/oarlock/oarlock/internal/safety"
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

	Listen   Listen   `yaml:"listen"`
	SSH      SSH      `yaml:"ssh"`
	Devices  string   `yaml:"devices"`
	Authz    Authz    `yaml:"authorizer"`
	Recorder Recorder `yaml:"recorder"`
	API      API      `yaml:"api"`
	Limits   Limits   `yaml:"limits"`
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
}

// Authz configures the authorisation backend.
type Authz struct {
	// Kind is "rules", or "none" to run without authorisation. The boot gate refuses
	// "none" in production.
	Kind string `yaml:"kind"`
	// Path is the rules file, for kind: rules.
	Path string `yaml:"path"`
	// Grace is how many consecutive failed re-checks a live session survives.
	//
	// A pointer because zero has a meaning and it is not "unset": `grace: 0` is strict
	// fail-closed, which is the right setting where a session is more dangerous than an
	// outage. Omitting the key gets the default of three.
	Grace *int `yaml:"grace"`
	// RecheckInterval is how often a live session's grant is re-checked.
	RecheckInterval time.Duration `yaml:"recheck_interval"`
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

// API configures the control API.
type API struct {
	// Tokens maps a bearer token to a principal. For development and CI: a real
	// deployment uses an authenticator that can validate a token it did not mint.
	Tokens map[string]string `yaml:"tokens"`
	// RatePerMinute is the per-principal request budget.
	RatePerMinute int `yaml:"rate_per_minute"`
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
	if c.Authz.Kind == "" {
		c.Authz.Kind = "rules"
	}
	if c.Authz.RecheckInterval == 0 {
		c.Authz.RecheckInterval = authz.DefaultRecheckInterval
	}
	if c.Recorder.KeyID == "" {
		c.Recorder.KeyID = "oarlock-recorder"
	}
	if c.API.RatePerMinute == 0 {
		c.API.RatePerMinute = 120
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
	if c.Devices == "" {
		add("devices is required: a path to the device registry")
	}
	switch c.Authz.Kind {
	case "rules":
		if c.Authz.Path == "" {
			add("authorizer.path is required for kind: rules")
		}
	case "none":
		// Allowed here and refused by the boot gate in production, which is the right
		// division: the config file describes what was asked for, and the gate decides
		// whether this environment may have it.
	default:
		add("authorizer.kind %q is not known (rules, none)", c.Authz.Kind)
	}
	if c.Authz.Grace != nil && *c.Authz.Grace < 0 {
		add("authorizer.grace is negative, which has no meaning. Zero is strict " +
			"fail-closed; a positive value is how many failed re-checks a live session " +
			"survives")
	}
	if c.Authz.RecheckInterval < 0 {
		add("authorizer.recheck_interval is negative")
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
	if c.Limits.SessionsPerDevice <= 0 || c.Limits.SessionsPerPrincipal <= 0 {
		add("limits.sessions_per_device and limits.sessions_per_principal must be positive")
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
