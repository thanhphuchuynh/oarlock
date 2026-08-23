package plugin_test

import (
	"testing"

	"github.com/oarlock/oarlock/pkg/plugin"
)

// TestAppliesToIsDeviceAndTagsOnly. The predicate the admin API and the authorisation
// backend share, so its edges are worth pinning: an empty device list is every device,
// every listed tag must match, and a glob does not cross into principals or actions.
func TestAppliesToIsDeviceAndTagsOnly(t *testing.T) {
	pci := &plugin.Device{ID: "treadmill-4821", Tags: map[string]string{
		"pci_scope": "true", "region": "eu",
	}}
	plain := &plugin.Device{ID: "rower-9001"}

	for _, tc := range []struct {
		name string
		p    plugin.Permission
		dev  *plugin.Device
		want bool
	}{
		{"an empty device list is every device",
			plugin.Permission{Principals: []string{"a"}}, pci, true},
		{"an exact id",
			plugin.Permission{Devices: []string{"treadmill-4821"}}, pci, true},
		{"a glob",
			plugin.Permission{Devices: []string{"treadmill-*"}}, pci, true},
		{"a glob that does not match",
			plugin.Permission{Devices: []string{"treadmill-*"}}, plain, false},
		{"a star",
			plugin.Permission{Devices: []string{"*"}}, plain, true},
		{"one of several patterns",
			plugin.Permission{Devices: []string{"rower-*", "treadmill-*"}}, pci, true},
		{"a matching tag",
			plugin.Permission{Tags: map[string]string{"pci_scope": "true"}}, pci, true},
		{"a tag the device does not carry",
			plugin.Permission{Tags: map[string]string{"pci_scope": "true"}}, plain, false},
		{"every tag must match, not any",
			plugin.Permission{Tags: map[string]string{"pci_scope": "true", "region": "us"}}, pci, false},
		{"a tag value that differs",
			plugin.Permission{Tags: map[string]string{"region": "us"}}, pci, false},
		{"device and tags together",
			plugin.Permission{Devices: []string{"treadmill-*"},
				Tags: map[string]string{"region": "eu"}}, pci, true},
		{"the device matches and the tag does not",
			plugin.Permission{Devices: []string{"treadmill-*"},
				Tags: map[string]string{"region": "us"}}, pci, false},
		{"a nil device",
			plugin.Permission{Devices: []string{"*"}}, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.p.AppliesTo(tc.dev); got != tc.want {
				t.Fatalf("AppliesTo = %v, want %v", got, tc.want)
			}
		})
	}

	// Principals and actions are not consulted. A rule about somebody else still applies
	// to the device, which is exactly what "who can reach it" needs to list.
	about := plugin.Permission{Principals: []string{"someone@else"}, Devices: []string{"*"},
		Actions: []string{"replay"}}
	if !about.AppliesTo(plain) {
		t.Fatal("a rule about another principal does not apply to the device")
	}
	if about.MatchesPrincipal("me@example.com") {
		t.Fatal("MatchesPrincipal matched the wrong principal")
	}
	if !about.MatchesPrincipal("someone@else") {
		t.Fatal("MatchesPrincipal missed its own principal")
	}
	if about.Grants(plugin.ActionShell) || !about.Grants(plugin.ActionReplay) {
		t.Fatal("Grants does not match the action list")
	}
	star := plugin.Permission{Actions: []string{"*"}}
	if !star.Grants(plugin.ActionShell) {
		t.Fatal(`actions: ["*"] does not grant shell`)
	}
}
