package sqlite_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"

	"github.com/oarlock/oarlock/internal/registry/sqlite"
	"github.com/oarlock/oarlock/pkg/plugin"
)

func TestCreateListUpdateDeleteDevice(t *testing.T) {
	r, err := sqlite.Open(filepath.Join(t.TempDir(), "oarlock.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	dev := &plugin.Device{
		ID: "treadmill-4821", Platform: plugin.PlatformLinux,
		Keys:     []ed25519.PublicKey{pub},
		Tags:     map[string]string{"region": "eu"},
		Profiles: []string{"shell"},
	}
	if err := r.Create(context.Background(), dev); err != nil {
		t.Fatal(err)
	}
	got, err := r.Get(context.Background(), "treadmill-4821")
	if err != nil {
		t.Fatal(err)
	}
	if got.Platform != plugin.PlatformLinux || got.Tags["region"] != "eu" ||
		len(got.Keys) != 1 || len(got.Profiles) != 1 {
		t.Fatalf("stored device changed: %+v", got)
	}

	got.Platform = plugin.PlatformAndroid
	got.Mode = plugin.ModeDispatch
	got.Keys = nil
	got.Tags = map[string]string{"region": "us"}
	got.Profiles = []string{"shell", "log"}
	if err := r.Update(context.Background(), got); err != nil {
		t.Fatal(err)
	}
	page, next, err := r.List(context.Background(), plugin.DeviceQuery{
		Platform: plugin.PlatformAndroid,
		Tags:     map[string]string{"region": "us"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if next != "" || len(page) != 1 || page[0].ResolvedMode() != plugin.ModeDispatch {
		t.Fatalf("page=%+v next=%q", page, next)
	}

	if err := r.Delete(context.Background(), "treadmill-4821"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Get(context.Background(), "treadmill-4821"); !errors.Is(err, plugin.ErrNoDevice) {
		t.Fatalf("Get after delete = %v", err)
	}
}

func TestValidationRejectsInvalidDevices(t *testing.T) {
	r, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })

	tests := map[string]*plugin.Device{
		"bad id":           {ID: "!!bad", Platform: plugin.PlatformAndroid, Mode: plugin.ModeDispatch},
		"missing key":      {ID: "linux-1", Platform: plugin.PlatformLinux},
		"unknown platform": {ID: "x", Platform: plugin.Platform("beos"), Mode: plugin.ModeDispatch},
	}
	for name, dev := range tests {
		t.Run(name, func(t *testing.T) {
			if err := r.Create(context.Background(), dev); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}
