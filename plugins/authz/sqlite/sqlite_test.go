package sqlite_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/oarlock/oarlock/pkg/plugin"
	authsqlite "github.com/oarlock/oarlock/plugins/authz/sqlite"
)

func open(t *testing.T) *authsqlite.Store {
	t.Helper()
	store, err := authsqlite.Open(filepath.Join(t.TempDir(), "oarlock.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestPermissionLifecycleAndDecision(t *testing.T) {
	ctx := context.Background()
	store := open(t)
	permission := &plugin.Permission{
		ID: "support-shell", Name: "Support shell", Principals: []string{"phuc@example.com"},
		Devices: []string{"samsung-*"}, Tags: map[string]string{"fleet": "qa"},
		Actions: []string{"shell", "exec"}, Enabled: true, MaxDuration: 15 * time.Minute,
	}
	if err := store.CreatePermission(ctx, permission); err != nil {
		t.Fatal(err)
	}
	decision, err := store.Authorize(ctx, &plugin.Principal{ID: "phuc@example.com"},
		&plugin.Device{ID: "samsung-s23", Tags: map[string]string{"fleet": "qa"}}, plugin.ActionShell, plugin.Target{})
	if err != nil || !decision.Allow {
		t.Fatalf("decision = %+v, error = %v", decision, err)
	}
	if decision.Limits == nil || decision.Limits.MaxDuration == nil || *decision.Limits.MaxDuration != 15*time.Minute {
		t.Fatalf("grant limit was lost: %+v", decision.Limits)
	}

	permission.Enabled = false
	if err := store.UpdatePermission(ctx, permission); err != nil {
		t.Fatal(err)
	}
	decision, err = store.Authorize(ctx, &plugin.Principal{ID: "phuc@example.com"},
		&plugin.Device{ID: "samsung-s23", Tags: map[string]string{"fleet": "qa"}}, plugin.ActionShell, plugin.Target{})
	if err != nil || decision.Allow {
		t.Fatalf("disabled permission decision = %+v, error = %v", decision, err)
	}

	if err := store.DeletePermission(ctx, permission.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetPermission(ctx, permission.ID); !errors.Is(err, plugin.ErrNoPermission) {
		t.Fatalf("deleted permission lookup = %v", err)
	}
}

func TestDenyBeatsHigherPriorityAllow(t *testing.T) {
	ctx := context.Background()
	store := open(t)
	for _, permission := range []*plugin.Permission{
		{ID: "allow-all", Principals: []string{"*"}, Actions: []string{"shell"}, Priority: 100, Enabled: true},
		{ID: "deny-pci", Principals: []string{"*"}, Tags: map[string]string{"scope": "pci"}, Actions: []string{"*"}, Deny: true, Reason: "change ticket required", Enabled: true},
	} {
		if err := store.CreatePermission(ctx, permission); err != nil {
			t.Fatal(err)
		}
	}
	decision, err := store.Authorize(ctx, &plugin.Principal{ID: "phuc@example.com"},
		&plugin.Device{ID: "pos-1", Tags: map[string]string{"scope": "pci"}}, plugin.ActionShell, plugin.Target{})
	if err != nil || decision.Allow || decision.Reason != "change ticket required" {
		t.Fatalf("deny decision = %+v, error = %v", decision, err)
	}
}

func TestValidationAndDatabaseFailureAreDistinct(t *testing.T) {
	ctx := context.Background()
	store := open(t)
	if err := store.CreatePermission(ctx, &plugin.Permission{ID: "bad", Principals: []string{"*"}, Actions: []string{"root"}, Enabled: true}); err == nil {
		t.Fatal("unknown action was accepted")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	decision, err := store.Authorize(ctx, &plugin.Principal{ID: "phuc@example.com"},
		&plugin.Device{ID: "samsung-s23"}, plugin.ActionShell, plugin.Target{})
	if err == nil || decision.Allow {
		t.Fatalf("database outage was reported as a decision: %+v, %v", decision, err)
	}
}
