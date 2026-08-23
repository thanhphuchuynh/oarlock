package sqlite_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
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
	got.Disabled = true
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
	if next != "" || len(page) != 1 || page[0].ResolvedMode() != plugin.ModeDispatch || !page[0].Disabled {
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
		"invalid profile":  {ID: "x", Platform: plugin.PlatformAndroid, Profiles: []string{"Shell Access"}},
	}
	for name, dev := range tests {
		t.Run(name, func(t *testing.T) {
			if err := r.Create(context.Background(), dev); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestDuplicateDeviceHasAStableError(t *testing.T) {
	r, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	dev := &plugin.Device{ID: "rower-1", Platform: plugin.PlatformAndroid}
	if err := r.Create(context.Background(), dev); err != nil {
		t.Fatal(err)
	}
	if err := r.Create(context.Background(), dev); !errors.Is(err, plugin.ErrDeviceExists) {
		t.Fatalf("duplicate create = %v, want ErrDeviceExists", err)
	}
}

func TestOpenMigratesDisabledState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE oarlock_devices (
		id TEXT PRIMARY KEY,
		platform TEXT NOT NULL,
		mode TEXT NOT NULL DEFAULT '',
		allow_passthrough INTEGER NOT NULL DEFAULT 0,
		created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	r, err := sqlite.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	dev := &plugin.Device{ID: "rower-1", Platform: plugin.PlatformAndroid, Disabled: true}
	if err := r.Create(context.Background(), dev); err != nil {
		t.Fatal(err)
	}
	got, err := r.Get(context.Background(), dev.ID)
	if err != nil || !got.Disabled {
		t.Fatalf("migrated disabled device = %+v, %v", got, err)
	}
}
