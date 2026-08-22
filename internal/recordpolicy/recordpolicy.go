// Package recordpolicy resolves per-session recording policy.
package recordpolicy

import (
	"fmt"
	"path/filepath"

	"github.com/oarlock/oarlock/pkg/plugin"
)

// Config is the policy section of oarlock.yaml.
type Config struct {
	RecordInput RecordInput `yaml:"record_input"`
}

// RecordInput resolves whether operator keystrokes are recorded.
type RecordInput struct {
	Default bool   `yaml:"default"`
	Rules   []Rule `yaml:"rules"`
}

// Rule is one selector and the value it asserts when it matches.
type Rule struct {
	Name      string   `yaml:"name"`
	When      Selector `yaml:"when"`
	Value     bool     `yaml:"value"`
	Authority string   `yaml:"authority"`
}

// Selector matches both sides of a session.
type Selector struct {
	Principals      []string          `yaml:"principals"`
	PrincipalGroups []string          `yaml:"principal_groups"`
	PrincipalAttrs  map[string]string `yaml:"principal_attrs"`
	DeviceIDs       []string          `yaml:"devices"`
	DeviceTags      map[string]string `yaml:"device_tags"`
}

// ConflictError means two matching rules disagreed.
type ConflictError struct {
	First  string
	Second string
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("recordpolicy: record_input conflict between %s and %s",
		e.First, e.Second)
}

// Validate catches malformed patterns before the gateway starts.
func (p RecordInput) Validate() error {
	for i, r := range p.Rules {
		where := p.label(i, r)
		for _, pat := range append(append([]string{}, r.When.Principals...), r.When.DeviceIDs...) {
			if _, err := filepath.Match(pat, ""); err != nil {
				return fmt.Errorf("recordpolicy: %s has invalid pattern %q: %w",
					where, pat, err)
			}
		}
		for _, pat := range r.When.PrincipalGroups {
			if _, err := filepath.Match(pat, ""); err != nil {
				return fmt.Errorf("recordpolicy: %s has invalid group pattern %q: %w",
					where, pat, err)
			}
		}
	}
	return nil
}

// Resolve returns the per-session record_input value.
func (p RecordInput) Resolve(principal *plugin.Principal, dev *plugin.Device) (bool, error) {
	resolved := p.Default
	var source string
	for i, r := range p.Rules {
		if !r.When.match(principal, dev) {
			continue
		}
		label := p.label(i, r)
		if source != "" && r.Value != resolved {
			return false, &ConflictError{First: source, Second: label}
		}
		resolved, source = r.Value, label
	}
	return resolved, nil
}

func (p RecordInput) label(i int, r Rule) string {
	if r.Name != "" {
		return r.Name
	}
	if r.Authority != "" {
		return r.Authority
	}
	return fmt.Sprintf("record_input.rules[%d]", i)
}

func (s Selector) match(principal *plugin.Principal, dev *plugin.Device) bool {
	if len(s.Principals) > 0 && !matchAny(s.Principals, principalID(principal)) {
		return false
	}
	if len(s.PrincipalGroups) > 0 && !matchAnyGroup(s.PrincipalGroups, principalGroups(principal)) {
		return false
	}
	if !matchMap(s.PrincipalAttrs, principalAttrs(principal)) {
		return false
	}
	if len(s.DeviceIDs) > 0 && !matchAny(s.DeviceIDs, deviceID(dev)) {
		return false
	}
	if !matchMap(s.DeviceTags, deviceTags(dev)) {
		return false
	}
	return true
}

func matchAny(patterns []string, value string) bool {
	for _, pat := range patterns {
		if ok, _ := filepath.Match(pat, value); ok {
			return true
		}
	}
	return false
}

func matchAnyGroup(patterns, groups []string) bool {
	for _, group := range groups {
		if matchAny(patterns, group) {
			return true
		}
	}
	return false
}

func matchMap(want, have map[string]string) bool {
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

func principalID(p *plugin.Principal) string {
	if p == nil {
		return ""
	}
	return p.ID
}

func principalGroups(p *plugin.Principal) []string {
	if p == nil {
		return nil
	}
	return p.Groups
}

func principalAttrs(p *plugin.Principal) map[string]string {
	if p == nil {
		return nil
	}
	return p.Attrs
}

func deviceID(d *plugin.Device) string {
	if d == nil {
		return ""
	}
	return d.ID
}

func deviceTags(d *plugin.Device) map[string]string {
	if d == nil {
		return nil
	}
	return d.Tags
}
