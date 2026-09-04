package sqlite_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/oarlock/oarlock/pkg/plugin"
	authsqlite "github.com/oarlock/oarlock/plugins/authz/sqlite"
)

// TestTargetsRoundTripThroughTheDatabase pins that the narrowing survives storage.
//
// A target constraint that is accepted by the admin API, written, and then read back empty
// is worse than one that was refused: the console shows a narrow grant and the gateway
// enforces a wide one, and nothing anywhere disagrees out loud.
func TestTargetsRoundTripThroughTheDatabase(t *testing.T) {
	ctx := context.Background()
	store := open(t)

	want := &plugin.Permission{
		ID: "support-forward", Principals: []string{"support@example.com"},
		Actions: []string{"tcp", "file:read", "exec"}, Enabled: true,
		Ports: []int{3000, 8080}, Paths: []string{"logs/*"}, Commands: []string{"/bin/echo"},
	}
	if err := store.CreatePermission(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetPermission(ctx, want.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Ports) != 2 || got.Ports[0] != 3000 || got.Ports[1] != 8080 {
		t.Errorf("ports = %v, want [3000 8080]", got.Ports)
	}
	if len(got.Paths) != 1 || got.Paths[0] != "logs/*" {
		t.Errorf("paths = %v, want [logs/*]", got.Paths)
	}
	if len(got.Commands) != 1 || got.Commands[0] != "/bin/echo" {
		t.Errorf("commands = %v, want [/bin/echo]", got.Commands)
	}
}

// TestStoredTargetsNarrowTheDecision is the same property the rules backend has, asserted
// against the durable one so the two cannot drift into disagreeing about the same policy.
func TestStoredTargetsNarrowTheDecision(t *testing.T) {
	ctx := context.Background()
	store := open(t)

	if err := store.CreatePermission(ctx, &plugin.Permission{
		ID: "support-forward", Principals: []string{"support@example.com"},
		Actions: []string{"tcp"}, Enabled: true, Ports: []int{3000},
	}); err != nil {
		t.Fatal(err)
	}
	p := &plugin.Principal{ID: "support@example.com"}
	dev := &plugin.Device{ID: "treadmill-4821"}

	for _, tc := range []struct {
		port int
		want bool
	}{
		{3000, true},
		{22, false},
	} {
		d, err := store.Authorize(ctx, p, dev, plugin.ActionTCP, plugin.Target{Port: tc.port})
		if err != nil {
			t.Fatal(err)
		}
		if d.Allow != tc.want {
			t.Errorf("port %d: allow = %v, want %v (%s)", tc.port, d.Allow, tc.want, d.Reason)
		}
	}
}

// TestAnUnconstrainedPermissionStillCoversEveryTarget is the compatibility guarantee, and
// the one that matters most here: every row already in somebody's database has no targets,
// and adding the column must not have narrowed a single one of them.
func TestAnUnconstrainedPermissionStillCoversEveryTarget(t *testing.T) {
	ctx := context.Background()
	store := open(t)

	if err := store.CreatePermission(ctx, &plugin.Permission{
		ID: "oncall-everything", Principals: []string{"oncall@example.com"},
		Actions: []string{"tcp"}, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	d, err := store.Authorize(ctx, &plugin.Principal{ID: "oncall@example.com"},
		&plugin.Device{ID: "treadmill-4821"}, plugin.ActionTCP, plugin.Target{Port: 22})
	if err != nil {
		t.Fatal(err)
	}
	if !d.Allow {
		t.Fatalf("an unconstrained permission stopped granting a port: %s", d.Reason)
	}
}

// TestOpeningADatabaseTwiceIsFine covers the ALTER TABLE that adds targets_json to a
// database written before the column existed. SQLite has no ADD COLUMN IF NOT EXISTS, so
// every start after the first hits a duplicate-column error that Open must swallow — and
// swallowing it wrongly means the gateway refuses to start on the second boot.
func TestOpeningADatabaseTwiceIsFine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oarlock.db")

	first, err := authsqlite.Open(path, nil)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	if err := first.CreatePermission(context.Background(), &plugin.Permission{
		ID: "p", Principals: []string{"admin@mail.com"},
		Actions: []string{"tcp"}, Enabled: true, Ports: []int{3000},
	}); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second, err := authsqlite.Open(path, nil)
	if err != nil {
		t.Fatalf("second open of an existing database: %v", err)
	}
	defer second.Close()

	got, err := second.GetPermission(context.Background(), "p")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Ports) != 1 || got.Ports[0] != 3000 {
		t.Errorf("ports after reopening = %v, want [3000]", got.Ports)
	}
}
