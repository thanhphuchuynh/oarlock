// Package file is a DeviceRegistry backed by one YAML file.
//
// It is the default so that `go run` needs no database. It is obviously not enough
// for a fleet, and the point at which it stops being enough is when you would
// rather edit a device through an API than through a file — which is the moment to
// implement plugin.DeviceRegistry against whatever already owns enrollment.
package file

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/oarlock/oarlock/pkg/plugin"
)

type doc struct {
	Devices []entry `yaml:"devices"`
}

type entry struct {
	ID               string            `yaml:"id"`
	Platform         string            `yaml:"platform"`
	Mode             string            `yaml:"mode"`
	Keys             []string          `yaml:"keys"`
	AllowPassthrough bool              `yaml:"allow_passthrough"`
	Tags             map[string]string `yaml:"tags"`
	Profiles         []string          `yaml:"profiles"`
}

// Registry is a read-only device registry over a file.
type Registry struct {
	path string

	mu      sync.RWMutex
	byID    map[string]*plugin.Device
	ordered []*plugin.Device // sorted by id, so pagination is stable
}

var _ plugin.DeviceRegistry = (*Registry)(nil)

// Open loads the file. Every problem in it is reported at once rather than one per
// run: a registry with three malformed keys should take one edit to fix, not three
// boots.
func Open(path string) (*Registry, error) {
	r := &Registry{path: path}
	if err := r.Reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// Reload re-reads the file, replacing the contents only if the whole file is valid.
// A half-applied registry would be worse than a stale one: the devices that failed
// to parse would silently stop being reachable.
func (r *Registry) Reload() error {
	b, err := os.ReadFile(r.path)
	if err != nil {
		return fmt.Errorf("registry: reading %s: %w", r.path, err)
	}
	var d doc
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true) // a typo in a key name must not silently mean "default"
	if err := dec.Decode(&d); err != nil {
		return fmt.Errorf("registry: parsing %s: %w", r.path, err)
	}

	byID := make(map[string]*plugin.Device, len(d.Devices))
	var problems []string
	for i, e := range d.Devices {
		where := fmt.Sprintf("devices[%d]", i)
		if e.ID != "" {
			where = fmt.Sprintf("devices[%d] (%s)", i, e.ID)
		}
		dev, errs := e.toDevice()
		for _, msg := range errs {
			problems = append(problems, where+": "+msg)
		}
		if dev == nil {
			continue
		}
		if _, dup := byID[dev.ID]; dup {
			problems = append(problems, where+": duplicate id")
			continue
		}
		byID[dev.ID] = dev
	}
	if len(problems) > 0 {
		return fmt.Errorf("registry: %s has %d problem(s):\n  %s",
			r.path, len(problems), strings.Join(problems, "\n  "))
	}

	ordered := make([]*plugin.Device, 0, len(byID))
	for _, d := range byID {
		ordered = append(ordered, d)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })

	r.mu.Lock()
	r.byID, r.ordered = byID, ordered
	r.mu.Unlock()
	return nil
}

func (e entry) toDevice() (*plugin.Device, []string) {
	var problems []string
	if !plugin.ValidDeviceID(e.ID) {
		problems = append(problems, fmt.Sprintf("id %q is not a valid device id", e.ID))
	}

	platform := plugin.Platform(e.Platform)
	switch platform {
	case plugin.PlatformAndroid, plugin.PlatformLinux, plugin.PlatformContainer, plugin.PlatformOther:
	case "":
		problems = append(problems, "platform is required (android, linux, container, other)")
	default:
		problems = append(problems, fmt.Sprintf("unknown platform %q", e.Platform))
	}

	mode := plugin.Mode(e.Mode)
	switch mode {
	case plugin.ModePersistent, plugin.ModeDispatch, "":
	default:
		problems = append(problems, fmt.Sprintf(
			"unknown mode %q (omit it to resolve from the platform)", e.Mode))
	}

	dev := &plugin.Device{
		ID: e.ID, Platform: platform, Mode: mode,
		AllowPassthrough: e.AllowPassthrough,
		Tags:             e.Tags, Profiles: e.Profiles,
	}
	for j, k := range e.Keys {
		pub, err := plugin.ParseDeviceKey(k)
		if err != nil {
			problems = append(problems, fmt.Sprintf("keys[%d]: %v", j, err))
			continue
		}
		dev.Keys = append(dev.Keys, pub)
	}

	// A persistent-mode device authenticates its control channel with a key. A
	// dispatch-mode device may legitimately have none: every one of its connections
	// is a session connection authenticated by a single-use ticket.
	if len(dev.Keys) == 0 && dev.ResolvedMode() == plugin.ModePersistent {
		problems = append(problems, "a persistent-mode device needs at least one key "+
			"(set mode: dispatch if it is never expected to hold a control channel)")
	}
	if len(problems) > 0 {
		return nil, problems
	}
	return dev, nil
}

// Get returns the device or an error wrapping plugin.ErrNoDevice.
func (r *Registry) Get(_ context.Context, id string) (*plugin.Device, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.byID[id]
	if !ok {
		return nil, fmt.Errorf("%w: %q", plugin.ErrNoDevice, id)
	}
	return d, nil
}

// List returns a page of devices ordered by id, and the cursor for the next page.
func (r *Registry) List(_ context.Context, q plugin.DeviceQuery) ([]*plugin.Device, string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	limit := q.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	out := make([]*plugin.Device, 0, limit)
	for _, d := range r.ordered {
		if q.After != "" && d.ID <= q.After {
			continue
		}
		if q.Platform != "" && d.Platform != q.Platform {
			continue
		}
		if q.Mode != "" && d.ResolvedMode() != q.Mode {
			continue
		}
		if !matchTags(d.Tags, q.Tags) {
			continue
		}
		if len(out) == limit {
			return out, out[len(out)-1].ID, nil
		}
		out = append(out, d)
	}
	return out, "", nil
}

func matchTags(have, want map[string]string) bool {
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

// Len is the number of devices loaded, for logs and health output.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byID)
}

// ErrNotFile is returned when the path is a directory.
var ErrNotFile = errors.New("registry: path is not a file")
