package file_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oarlock/oarlock/internal/registry/file"
	"github.com/oarlock/oarlock/pkg/plugin"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "devices.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func key(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return plugin.EncodeDeviceKey(pub)
}

func keypair(t *testing.T) (string, ed25519.PublicKey) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return plugin.EncodeDeviceKey(pub), pub
}

func TestOpenValid(t *testing.T) {
	k := key(t)
	p := write(t, `
devices:
  - id: treadmill-4821
    platform: android
    keys: ["`+k+`"]
    tags:
      region: eu
      pci_scope: "false"
    profiles: [shell, log]
  - id: rower-1
    platform: linux
    mode: dispatch
    keys: ["`+k+`"]
    allow_passthrough: true
`)
	r, err := file.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if r.Len() != 2 {
		t.Fatalf("loaded %d devices, want 2", r.Len())
	}

	ctx := context.Background()
	d, err := r.Get(ctx, "treadmill-4821")
	if err != nil {
		t.Fatal(err)
	}
	// Android with no explicit mode resolves to dispatch, because the platform
	// resists a held connection.
	if d.ResolvedMode() != plugin.ModeDispatch || !d.ModeWasDefaulted() {
		t.Errorf("android default: %q defaulted=%v", d.ResolvedMode(), d.ModeWasDefaulted())
	}
	if d.Tags["region"] != "eu" || !d.Supports("shell") || d.Supports("tcp") {
		t.Errorf("device loaded wrong: %+v", d)
	}
	if d.AllowPassthrough {
		t.Error("allow_passthrough defaulted to true; an unrecorded session must never be an accident")
	}

	d2, err := r.Get(ctx, "rower-1")
	if err != nil {
		t.Fatal(err)
	}
	if d2.ResolvedMode() != plugin.ModeDispatch || d2.ModeWasDefaulted() {
		t.Errorf("explicit mode ignored: %q defaulted=%v", d2.ResolvedMode(), d2.ModeWasDefaulted())
	}
}

func TestGetUnknown(t *testing.T) {
	r, err := file.Open(write(t, "devices: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Get(context.Background(), "ghost"); !errors.Is(err, plugin.ErrNoDevice) {
		t.Fatalf("got %v, want ErrNoDevice", err)
	}
}

func TestOpenSSHKeyForm(t *testing.T) {
	// What ssh-keygen produces, so a registry file is something a person can write.
	p := write(t, `
devices:
  - id: rower-2
    platform: linux
    keys:
      - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB6+Nvxc0k7yHqCJqmVvHTf3O7Fh0kwWQZM6xLXKZG7Y comment here"
`)
	r, err := file.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	d, err := r.Get(context.Background(), "rower-2")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Keys) != 1 || len(d.Keys[0]) != ed25519.PublicKeySize {
		t.Fatalf("key not parsed: %v", d.Keys)
	}
}

func TestRetiredKeysLoadSeparately(t *testing.T) {
	active, activePub := keypair(t)
	retired, retiredPub := keypair(t)
	r, err := file.Open(write(t, `
devices:
  - id: rower-rotation
    platform: linux
    keys: ["`+active+`"]
    retired_keys: ["`+retired+`"]
`))
	if err != nil {
		t.Fatal(err)
	}
	d, err := r.Get(context.Background(), "rower-rotation")
	if err != nil {
		t.Fatal(err)
	}
	if !d.HasKey(activePub) || d.HasKey(retiredPub) {
		t.Fatalf("active key state wrong: active=%v retired-as-active=%v",
			d.HasKey(activePub), d.HasKey(retiredPub))
	}
	if !d.HasRetiredKey(retiredPub) || d.HasRetiredKey(activePub) {
		t.Fatalf("retired key state wrong: retired=%v active-as-retired=%v",
			d.HasRetiredKey(retiredPub), d.HasRetiredKey(activePub))
	}
}

func TestAKeyCannotBeActiveAndRetired(t *testing.T) {
	k := key(t)
	_, err := file.Open(write(t, `
devices:
  - id: confused
    platform: linux
    keys: ["`+k+`"]
    retired_keys: ["`+k+`"]
`))
	if err == nil || !strings.Contains(err.Error(), "also retired") {
		t.Fatalf("got %v, want active/retired conflict", err)
	}
}

// TestAllProblemsReportedAtOnce covers the rule that a registry with three
// mistakes should take one edit to fix, not three boots.
func TestAllProblemsReportedAtOnce(t *testing.T) {
	p := write(t, `
devices:
  - id: "bad id with spaces"
    platform: android
    keys: ["not-base64!!"]
  - id: ok-1
    platform: martian
  - id: ok-2
    platform: linux
    mode: telepathy
    keys: ["`+key(t)+`"]
`)
	_, err := file.Open(p)
	if err == nil {
		t.Fatal("an invalid file loaded successfully")
	}
	msg := err.Error()
	for _, want := range []string{
		"not a valid device id", "not base64", "unknown platform", "unknown mode",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error does not mention %q:\n%s", want, msg)
		}
	}
}

func TestDuplicateID(t *testing.T) {
	k := key(t)
	_, err := file.Open(write(t, `
devices:
  - id: dup
    platform: linux
    keys: ["`+k+`"]
  - id: dup
    platform: linux
    keys: ["`+k+`"]
`))
	if err == nil || !strings.Contains(err.Error(), "duplicate id") {
		t.Fatalf("got %v, want a duplicate-id error", err)
	}
}

// TestPersistentDeviceNeedsAKey covers the one asymmetry between the modes: a
// persistent device authenticates its control channel with a key, and a dispatch
// device legitimately has none because every connection it makes is a session
// connection carrying a single-use ticket.
func TestPersistentDeviceNeedsAKey(t *testing.T) {
	_, err := file.Open(write(t, `
devices:
  - id: keyless
    platform: linux
`))
	if err == nil || !strings.Contains(err.Error(), "needs at least one key") {
		t.Fatalf("got %v, want a missing-key error", err)
	}

	// The same device in dispatch mode is fine.
	if _, err := file.Open(write(t, `
devices:
  - id: keyless
    platform: linux
    mode: dispatch
`)); err != nil {
		t.Fatalf("a keyless dispatch device was rejected: %v", err)
	}
}

// TestTypoInAKeyNameIsRejected: a misspelled field must not silently mean
// "default". A device meant to allow passthrough that quietly does not is a
// surprise; one meant to forbid it that quietly allows it is an incident.
func TestTypoInAKeyNameIsRejected(t *testing.T) {
	_, err := file.Open(write(t, `
devices:
  - id: rower-3
    platform: linux
    keys: ["`+key(t)+`"]
    allow_pasthrough: true
`))
	if err == nil {
		t.Fatal("a misspelled field was accepted")
	}
}

func TestMissingFile(t *testing.T) {
	if _, err := file.Open(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("a missing file loaded successfully")
	}
}

// TestReloadIsAtomic: a half-applied registry is worse than a stale one, because
// the devices that failed to parse would silently stop being reachable.
func TestReloadIsAtomic(t *testing.T) {
	k := key(t)
	p := write(t, `
devices:
  - id: rower-4
    platform: linux
    keys: ["`+k+`"]
`)
	r, err := file.Open(p)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(p, []byte("devices:\n  - id: \"!!bad\"\n    platform: linux\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.Reload(); err == nil {
		t.Fatal("an invalid reload succeeded")
	}
	if _, err := r.Get(context.Background(), "rower-4"); err != nil {
		t.Errorf("the previous contents were discarded by a failed reload: %v", err)
	}

	// A valid reload does replace them.
	if err := os.WriteFile(p, []byte("devices:\n  - id: rower-5\n    platform: linux\n    mode: dispatch\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Get(context.Background(), "rower-5"); err != nil {
		t.Errorf("reload did not apply: %v", err)
	}
	if _, err := r.Get(context.Background(), "rower-4"); !errors.Is(err, plugin.ErrNoDevice) {
		t.Error("the old device survived a successful reload")
	}
}

func TestListFiltersAndPaginates(t *testing.T) {
	k := key(t)
	var b strings.Builder
	b.WriteString("devices:\n")
	for _, id := range []string{"a1", "a2", "a3", "b1", "b2"} {
		platform := "linux"
		if strings.HasPrefix(id, "b") {
			platform = "android"
		}
		b.WriteString("  - id: " + id + "\n    platform: " + platform +
			"\n    keys: [\"" + k + "\"]\n    tags:\n      site: " + id[:1] + "\n")
	}
	r, err := file.Open(write(t, b.String()))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	all, next, err := r.List(ctx, plugin.DeviceQuery{})
	if err != nil || len(all) != 5 || next != "" {
		t.Fatalf("List: %d devices, next=%q, err=%v", len(all), next, err)
	}
	// Ordered by id, so pagination is stable rather than map-random.
	for i := 1; i < len(all); i++ {
		if all[i-1].ID >= all[i].ID {
			t.Fatalf("not ordered: %s before %s", all[i-1].ID, all[i].ID)
		}
	}

	page1, next, err := r.List(ctx, plugin.DeviceQuery{Limit: 2})
	if err != nil || len(page1) != 2 || next != "a2" {
		t.Fatalf("page 1: %v next=%q err=%v", ids(page1), next, err)
	}
	page2, _, err := r.List(ctx, plugin.DeviceQuery{Limit: 2, After: next})
	if err != nil || len(page2) != 2 || page2[0].ID != "a3" {
		t.Fatalf("page 2: %v err=%v", ids(page2), err)
	}

	byPlatform, _, _ := r.List(ctx, plugin.DeviceQuery{Platform: plugin.PlatformAndroid})
	if len(byPlatform) != 2 {
		t.Errorf("platform filter: %v", ids(byPlatform))
	}
	// Android resolves to dispatch, so a mode filter finds the same two.
	byMode, _, _ := r.List(ctx, plugin.DeviceQuery{Mode: plugin.ModeDispatch})
	if len(byMode) != 2 {
		t.Errorf("mode filter matched %v; it must use the resolved mode", ids(byMode))
	}
	byTag, _, _ := r.List(ctx, plugin.DeviceQuery{Tags: map[string]string{"site": "a"}})
	if len(byTag) != 3 {
		t.Errorf("tag filter: %v", ids(byTag))
	}
}

func ids(ds []*plugin.Device) []string {
	out := make([]string, len(ds))
	for i, d := range ds {
		out[i] = d.ID
	}
	return out
}
