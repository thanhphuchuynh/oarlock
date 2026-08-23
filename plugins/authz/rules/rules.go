// Package rules is the default Authorizer: principal → device selector → actions, in
// YAML.
//
// It is the built-in that makes a small deployment work without standing up a permissions
// service, and the reference for what a correct backend looks like — it runs through
// `plugintest` like any third-party one.
//
// # Why it never returns an error
//
// The three-outcome contract exists because a backend that cannot reach its source of
// truth must say so rather than answer "no". This backend's source of truth is a file it
// has already read into memory, so it always has an answer, and `Authorize` cannot fail.
//
// That is worth stating rather than leaving implicit, because it is *why* this is a safe
// default: there is no outage in which it starts denying people. A reload that fails
// leaves the previous rules in place and logs — the alternative, dropping to no rules,
// would deny everybody the moment somebody saved a file with a typo in it.
package rules

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/oarlock/oarlock/pkg/plugin"
)

// DefaultReloadInterval is how often the file is checked for changes.
//
// Polling rather than fsnotify: a watch adds a dependency and a set of platform edge
// cases (editors that replace rather than write, containers where inotify is scarce) to
// save a few seconds of latency on a change nobody is waiting on synchronously.
const DefaultReloadInterval = 5 * time.Second

// Authorizer answers from a rules file.
type Authorizer struct {
	path string
	log  *slog.Logger

	// rules is swapped atomically, so Authorize never blocks on a reload and a reload
	// never publishes a half-parsed file.
	rules atomic.Pointer[ruleset]

	// mod is the file state the last successful load came from.
	mu      sync.Mutex
	modTime time.Time
	size    int64

	stop chan struct{}
	once sync.Once
}

type doc struct {
	Rules []entry `yaml:"rules"`
}

type entry struct {
	// Principals are matched by exact id or by glob.
	Principals []string `yaml:"principals"`
	// Devices selects by id or glob. Empty means every device.
	Devices []string `yaml:"devices"`
	// Tags selects by device tag. Every listed tag must match.
	Tags map[string]string `yaml:"tags"`
	// Actions are the actions this rule grants. `"*"` grants every action, which is
	// spelled out rather than implied by an empty list — an empty `actions:` is much
	// more likely to be an unfinished rule than an intent to grant everything.
	Actions []string `yaml:"actions"`
	// Deny inverts the rule. A matching deny beats every allow, so a broad grant can be
	// carved out without rewriting it.
	Deny bool `yaml:"deny"`
	// Reason is shown to the operator when this rule is the one that refused them.
	Reason string `yaml:"reason"`

	// MaxDuration and Idle tighten the session's limits for grants made by this rule.
	MaxDuration time.Duration `yaml:"max_duration"`
	Idle        time.Duration `yaml:"idle"`
	// TTL asks for a sooner re-check than the gateway's default.
	TTL time.Duration `yaml:"ttl"`
}

type ruleset struct {
	entries []entry
}

// Open reads a rules file and starts watching it.
func Open(path string, log *slog.Logger) (*Authorizer, error) {
	if path == "" {
		return nil, errors.New("rules: a path is required")
	}
	a := &Authorizer{path: path, log: log, stop: make(chan struct{})}
	if a.log == nil {
		a.log = slog.Default()
	}
	if err := a.Reload(); err != nil {
		return nil, err
	}
	go a.watch(DefaultReloadInterval)
	return a, nil
}

// Close stops watching the file.
func (a *Authorizer) Close() error {
	a.once.Do(func() { close(a.stop) })
	return nil
}

// Reload re-reads the file, replacing the rules only if the whole file is valid.
//
// A half-applied ruleset would be worse than a stale one: the rules that failed to parse
// would silently stop granting, which looks exactly like a revocation to everybody they
// covered.
func (a *Authorizer) Reload() error {
	b, err := os.ReadFile(a.path)
	if err != nil {
		return fmt.Errorf("rules: reading %s: %w", a.path, err)
	}
	var d doc
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true) // a typo in a key name must not silently mean "default"
	if err := dec.Decode(&d); err != nil {
		return fmt.Errorf("rules: parsing %s: %w", a.path, err)
	}

	var problems []string
	for i, e := range d.Rules {
		where := fmt.Sprintf("rules[%d]", i)
		switch {
		case len(e.Principals) == 0:
			problems = append(problems, where+": no principals")
		case len(e.Actions) == 0:
			// Not defaulted to "everything": an empty actions list is far more likely
			// to be an unfinished rule than an intent to grant the fleet.
			problems = append(problems, where+": no actions — write actions: [\"*\"] if "+
				"you mean every action")
		}
		for _, act := range e.Actions {
			if act != "*" && !knownAction(act) {
				problems = append(problems, fmt.Sprintf(
					"%s: %q is not an action — the set is %s", where, act, actionList()))
			}
		}
		for _, p := range append(append([]string{}, e.Principals...), e.Devices...) {
			if _, err := filepath.Match(p, ""); err != nil {
				problems = append(problems, fmt.Sprintf("%s: %q is not a valid pattern: %v",
					where, p, err))
			}
		}
		if e.MaxDuration < 0 || e.Idle < 0 || e.TTL < 0 {
			problems = append(problems, where+": a negative duration")
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("rules: %s is invalid:\n  %s", a.path, strings.Join(problems, "\n  "))
	}

	a.rules.Store(&ruleset{entries: d.Rules})
	if info, err := os.Stat(a.path); err == nil {
		a.mu.Lock()
		a.modTime, a.size = info.ModTime(), info.Size()
		a.mu.Unlock()
	}
	return nil
}

func (a *Authorizer) watch(every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-a.stop:
			return
		case <-t.C:
			info, err := os.Stat(a.path)
			if err != nil {
				// The file went away. The rules in memory stay: a deleted file is far
				// more likely to be a deployment mid-flight than an intent to revoke
				// everybody's access.
				a.log.Warn("rules file is unreadable; keeping the rules already loaded",
					"path", a.path, "error", err)
				continue
			}
			a.mu.Lock()
			changed := !info.ModTime().Equal(a.modTime) || info.Size() != a.size
			a.mu.Unlock()
			if !changed {
				continue
			}
			if err := a.Reload(); err != nil {
				// Same reasoning as above, and this is the case that matters most:
				// somebody has just saved a file with a typo in it. Dropping to no
				// rules would deny everybody, instantly, because of a syntax error.
				a.log.Error("rules file changed but did not load; keeping the previous rules",
					"path", a.path, "error", err)
				continue
			}
			a.log.Info("rules reloaded", "path", a.path, "rules", len(a.rules.Load().entries))
		}
	}
}

// Authorize answers from the rules in memory.
//
// It never returns an error, and the signature keeps one because the interface does. See
// the package comment: having no dependency that can fail is what makes this a safe
// default rather than an accident.
func (a *Authorizer) Authorize(ctx context.Context, p *plugin.Principal, dev *plugin.Device,
	act plugin.Action) (plugin.Decision, error) {
	if err := ctx.Err(); err != nil {
		return plugin.Decision{}, err
	}
	if p == nil || dev == nil {
		return plugin.Decision{Allow: false, Reason: "no principal or device"}, nil
	}
	rs := a.rules.Load()
	if rs == nil {
		return plugin.Decision{Allow: false, Reason: "no rules are loaded"}, nil
	}

	var granted *entry
	for i := range rs.entries {
		e := &rs.entries[i]
		if !e.matches(p, dev, act) {
			continue
		}
		if e.Deny {
			// A matching deny beats every allow, wherever it appears, so a broad grant
			// can be carved out without rewriting it — and so that adding a deny cannot
			// be defeated by rule ordering somebody else controls.
			reason := e.Reason
			if reason == "" {
				reason = fmt.Sprintf("denied %s on %s by rule", act, dev.ID)
			}
			return plugin.Decision{Allow: false, Reason: reason}, nil
		}
		if granted == nil {
			granted = e
		}
	}
	if granted == nil {
		// Nothing matched. The reason names the action and the device, because "denied"
		// tells an operator nothing they can take to whoever manages access.
		return plugin.Decision{
			Allow:  false,
			Reason: fmt.Sprintf("no rule grants %s on %s to %s", act, dev.ID, p.ID),
		}, nil
	}

	d := plugin.Decision{Allow: true, TTL: granted.TTL}
	if granted.MaxDuration > 0 || granted.Idle > 0 {
		d.Limits = &plugin.GrantLimits{}
		if granted.MaxDuration > 0 {
			md := granted.MaxDuration
			d.Limits.MaxDuration = &md
		}
		if granted.Idle > 0 {
			idle := granted.Idle
			d.Limits.Idle = &idle
		}
	}
	return d, nil
}

// Watch is not implemented: a file has nothing to stream.
//
// Returning ErrUnsupported rather than a channel that never sends is the difference
// between the gateway polling on its interval and the gateway waiting forever for
// revocations that were never coming.
func (a *Authorizer) Watch(context.Context) (<-chan plugin.RevocationEvent, error) {
	return nil, plugin.ErrUnsupported
}

func (e *entry) matches(p *plugin.Principal, dev *plugin.Device, act plugin.Action) bool {
	if !matchAny(e.Principals, p.ID) {
		return false
	}
	if len(e.Devices) > 0 && !matchAny(e.Devices, dev.ID) {
		return false
	}
	for k, want := range e.Tags {
		if dev.Tags[k] != want {
			return false
		}
	}
	return matchAction(e.Actions, act)
}

func matchAny(patterns []string, s string) bool {
	for _, p := range patterns {
		if p == "*" || p == s {
			return true
		}
		if ok, err := filepath.Match(p, s); err == nil && ok {
			return true
		}
	}
	return false
}

func matchAction(actions []string, act plugin.Action) bool {
	for _, a := range actions {
		if a == "*" || a == string(act) {
			return true
		}
	}
	return false
}

var allActions = []plugin.Action{
	plugin.ActionShell, plugin.ActionExec, plugin.ActionFileRead, plugin.ActionFileWrite,
	plugin.ActionTCP, plugin.ActionPassthrough, plugin.ActionReplay, plugin.ActionObserve,
	plugin.ActionSQLRead,
	plugin.ActionAdminDevices, plugin.ActionAdminPermissions, plugin.ActionAdminKill,
}

func knownAction(s string) bool {
	for _, a := range allActions {
		if string(a) == s {
			return true
		}
	}
	return false
}

func actionList() string {
	names := make([]string, 0, len(allActions))
	for _, a := range allActions {
		names = append(names, string(a))
	}
	return strings.Join(names, ", ")
}
