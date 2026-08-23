package sqlexplore

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func testExplorer(t *testing.T) *SQLite {
	t.Helper()
	path := filepath.Join(t.TempDir(), "oarlock.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
CREATE TABLE sessions (id TEXT, device_id TEXT, profile TEXT, mode TEXT, principal TEXT, opened_by TEXT, why TEXT, state TEXT, created_at TEXT, connected_at TEXT, closed_at TEXT, close_reason TEXT, recording_ref TEXT);
CREATE TABLE oarlock_devices (id TEXT, platform TEXT, mode TEXT, disabled INTEGER, allow_passthrough INTEGER, created_at TEXT, updated_at TEXT);
CREATE TABLE oarlock_api_tokens (id TEXT, token_hash TEXT, principal TEXT);
INSERT INTO sessions VALUES ('ses_1','dev_1','shell','dispatch','ana','ana','ticket-1','closed','2026-01-01',NULL,'2026-01-01','done','rec_1');
INSERT INTO oarlock_devices VALUES ('dev_1','android','dispatch',0,0,'2026-01-01','2026-01-01');
INSERT INTO oarlock_api_tokens VALUES ('tok_1','secret-hash','admin');`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	explorer, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = explorer.Close() })
	return explorer
}

func TestQuerySelectAndCTE(t *testing.T) {
	explorer := testExplorer(t)
	result, err := explorer.Query(context.Background(), `WITH online AS (SELECT id FROM oarlock_devices WHERE disabled = 0) SELECT id FROM online`, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 1 || result.Rows[0][0] != "dev_1" {
		t.Fatalf("result = %#v", result)
	}
}

func TestQueryDoesNotExposeUncataloguedTables(t *testing.T) {
	explorer := testExplorer(t)
	_, err := explorer.Query(context.Background(), `SELECT token_hash FROM oarlock_api_tokens`, 20)
	if !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("error = %v", err)
	}
}

func TestQueryRejectsWritesPragmasAndMultipleStatements(t *testing.T) {
	explorer := testExplorer(t)
	for _, query := range []string{
		`DELETE FROM sessions`,
		`PRAGMA database_list`,
		`SELECT id FROM sessions; SELECT id FROM sessions`,
		`WITH gone AS (SELECT id FROM sessions) DELETE FROM sessions`,
	} {
		if _, err := explorer.Query(context.Background(), query, 20); !errors.Is(err, ErrInvalidQuery) {
			t.Errorf("query %q: error = %v", query, err)
		}
	}
}

func TestQueryBoundsRows(t *testing.T) {
	explorer := testExplorer(t)
	result, err := explorer.Query(context.Background(), `SELECT id FROM sessions UNION ALL SELECT id FROM sessions`, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 1 || !result.Truncated {
		t.Fatalf("result = %#v", result)
	}
}

func TestSchemaReturnsOnlyCatalog(t *testing.T) {
	explorer := testExplorer(t)
	tables, err := explorer.Schema(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range tables {
		if table.Name == "oarlock_api_tokens" || table.Name == "oarlock_device_keys" {
			t.Fatalf("sensitive table exposed: %s", table.Name)
		}
	}
}
