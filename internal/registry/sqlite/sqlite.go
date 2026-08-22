// Package sqlite is a read/write DeviceRegistry backed by Oarlock's operational DB.
package sqlite

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"

	"github.com/oarlock/oarlock/pkg/plugin"
)

const schema = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS oarlock_config (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS oarlock_devices (
  id                TEXT PRIMARY KEY,
  platform          TEXT NOT NULL,
  mode              TEXT NOT NULL DEFAULT '',
  allow_passthrough INTEGER NOT NULL DEFAULT 0,
  created_at        TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at        TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS oarlock_device_keys (
  device_id TEXT NOT NULL REFERENCES oarlock_devices(id) ON DELETE CASCADE,
  key       TEXT NOT NULL,
  PRIMARY KEY (device_id, key)
);

CREATE TABLE IF NOT EXISTS oarlock_device_retired_keys (
  device_id TEXT NOT NULL REFERENCES oarlock_devices(id) ON DELETE CASCADE,
  key       TEXT NOT NULL,
  PRIMARY KEY (device_id, key)
);

CREATE TABLE IF NOT EXISTS oarlock_device_tags (
  device_id TEXT NOT NULL REFERENCES oarlock_devices(id) ON DELETE CASCADE,
  key       TEXT NOT NULL,
  value     TEXT NOT NULL,
  PRIMARY KEY (device_id, key)
);

CREATE TABLE IF NOT EXISTS oarlock_device_profiles (
  device_id TEXT NOT NULL REFERENCES oarlock_devices(id) ON DELETE CASCADE,
  profile   TEXT NOT NULL,
  PRIMARY KEY (device_id, profile)
);

CREATE TABLE IF NOT EXISTS oarlock_audit_events (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  at         TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  kind       TEXT NOT NULL,
  payload    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS oarlock_api_tokens (
  id          TEXT PRIMARY KEY,
  token_hash  TEXT NOT NULL UNIQUE,
  principal   TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at TEXT
);

CREATE INDEX IF NOT EXISTS oarlock_devices_by_platform ON oarlock_devices(platform, id);
CREATE INDEX IF NOT EXISTS oarlock_devices_by_mode ON oarlock_devices(mode, id);
`

// Registry is a SQLite-backed read/write device registry.
type Registry struct {
	db *sql.DB
}

var _ plugin.DeviceRegistry = (*Registry)(nil)
var _ plugin.DeviceRegistryAdmin = (*Registry)(nil)

// Open opens or creates the registry database.
func Open(path string) (*Registry, error) {
	if path == "" {
		return nil, errors.New("sqlite registry: path is required")
	}
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("sqlite registry: creating %s: %w", filepath.Dir(path), err)
		}
	}
	dsn := path
	if path == ":memory:" {
		dsn = "file::memory:?cache=shared"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite registry: opening %s: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite registry: applying schema: %w", err)
	}
	return &Registry{db: db}, nil
}

// Close closes the underlying database.
func (r *Registry) Close() error { return r.db.Close() }

func (r *Registry) Get(ctx context.Context, id string) (*plugin.Device, error) {
	devs, _, err := r.list(ctx, plugin.DeviceQuery{After: "", Limit: 1}, id)
	if err != nil {
		return nil, err
	}
	if len(devs) == 0 {
		return nil, fmt.Errorf("%w: %q", plugin.ErrNoDevice, id)
	}
	return devs[0], nil
}

func (r *Registry) List(ctx context.Context, q plugin.DeviceQuery) ([]*plugin.Device, string, error) {
	return r.list(ctx, q, "")
}

func (r *Registry) list(ctx context.Context, q plugin.DeviceQuery, exact string) ([]*plugin.Device, string, error) {
	limit := q.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var args []any
	where := []string{"1=1"}
	if exact != "" {
		where = append(where, "id = ?")
		args = append(args, exact)
	}
	if q.After != "" {
		where = append(where, "id > ?")
		args = append(args, q.After)
	}
	if q.Platform != "" {
		where = append(where, "platform = ?")
		args = append(args, string(q.Platform))
	}
	args = append(args, limit+1)
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, platform, mode, allow_passthrough
		FROM oarlock_devices
		WHERE `+strings.Join(where, " AND ")+`
		ORDER BY id
		LIMIT ?`, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()

	var base []*plugin.Device
	for rows.Next() {
		d := &plugin.Device{}
		var platform, mode string
		var allow int
		if err := rows.Scan(&d.ID, &platform, &mode, &allow); err != nil {
			return nil, "", err
		}
		d.Platform = plugin.Platform(platform)
		d.Mode = plugin.Mode(mode)
		d.AllowPassthrough = allow != 0
		base = append(base, d)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	if err := rows.Close(); err != nil {
		return nil, "", err
	}

	var out []*plugin.Device
	for _, d := range base {
		if err := r.fill(ctx, d); err != nil {
			return nil, "", err
		}
		if q.Mode != "" && d.ResolvedMode() != q.Mode {
			continue
		}
		if !matchTags(d.Tags, q.Tags) {
			continue
		}
		out = append(out, d)
	}
	next := ""
	if len(out) > limit {
		next = out[limit-1].ID
		out = out[:limit]
	}
	return out, next, nil
}

func (r *Registry) fill(ctx context.Context, d *plugin.Device) error {
	keys, err := r.strings(ctx, `SELECT key FROM oarlock_device_keys WHERE device_id = ? ORDER BY key`, d.ID)
	if err != nil {
		return err
	}
	for _, k := range keys {
		pub, err := plugin.ParseDeviceKey(k)
		if err != nil {
			return fmt.Errorf("sqlite registry: stored key for %s is invalid: %w", d.ID, err)
		}
		d.Keys = append(d.Keys, pub)
	}
	retired, err := r.strings(ctx, `SELECT key FROM oarlock_device_retired_keys WHERE device_id = ? ORDER BY key`, d.ID)
	if err != nil {
		return err
	}
	for _, k := range retired {
		pub, err := plugin.ParseDeviceKey(k)
		if err != nil {
			return fmt.Errorf("sqlite registry: stored retired key for %s is invalid: %w", d.ID, err)
		}
		d.RetiredKeys = append(d.RetiredKeys, pub)
	}
	tags, err := r.tags(ctx, d.ID)
	if err != nil {
		return err
	}
	d.Tags = tags
	d.Profiles, err = r.strings(ctx, `SELECT profile FROM oarlock_device_profiles WHERE device_id = ? ORDER BY profile`, d.ID)
	return err
}

func (r *Registry) strings(ctx context.Context, q, id string) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, q, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *Registry) tags(ctx context.Context, id string) (map[string]string, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT key, value FROM oarlock_device_tags WHERE device_id = ?`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

func (r *Registry) Create(ctx context.Context, d *plugin.Device) error {
	if err := validate(d); err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO oarlock_devices (id, platform, mode, allow_passthrough)
		VALUES (?, ?, ?, ?)`,
		d.ID, string(d.Platform), string(d.Mode), boolToInt(d.AllowPassthrough)); err != nil {
		return fmt.Errorf("sqlite registry: create device: %w", err)
	}
	if err := writeChildren(ctx, tx, d); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *Registry) Update(ctx context.Context, d *plugin.Device) error {
	if err := validate(d); err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `
		UPDATE oarlock_devices
		SET platform = ?, mode = ?, allow_passthrough = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`,
		string(d.Platform), string(d.Mode), boolToInt(d.AllowPassthrough), d.ID)
	if err != nil {
		return fmt.Errorf("sqlite registry: update device: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: %q", plugin.ErrNoDevice, d.ID)
	}
	for _, table := range []string{"oarlock_device_keys", "oarlock_device_retired_keys", "oarlock_device_tags", "oarlock_device_profiles"} {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE device_id = ?`, d.ID); err != nil {
			return err
		}
	}
	if err := writeChildren(ctx, tx, d); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *Registry) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM oarlock_devices WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: %q", plugin.ErrNoDevice, id)
	}
	return nil
}

func writeChildren(ctx context.Context, tx *sql.Tx, d *plugin.Device) error {
	for _, k := range d.Keys {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO oarlock_device_keys (device_id, key) VALUES (?, ?)`,
			d.ID, plugin.EncodeDeviceKey(k)); err != nil {
			return err
		}
	}
	for _, k := range d.RetiredKeys {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO oarlock_device_retired_keys (device_id, key) VALUES (?, ?)`,
			d.ID, plugin.EncodeDeviceKey(k)); err != nil {
			return err
		}
	}
	for k, v := range d.Tags {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO oarlock_device_tags (device_id, key, value) VALUES (?, ?, ?)`,
			d.ID, k, v); err != nil {
			return err
		}
	}
	for _, p := range d.Profiles {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO oarlock_device_profiles (device_id, profile) VALUES (?, ?)`,
			d.ID, p); err != nil {
			return err
		}
	}
	return nil
}

func validate(d *plugin.Device) error {
	var problems []string
	if d == nil {
		return errors.New("sqlite registry: device is required")
	}
	if !plugin.ValidDeviceID(d.ID) {
		problems = append(problems, fmt.Sprintf("id %q is not a valid device id", d.ID))
	}
	switch d.Platform {
	case plugin.PlatformAndroid, plugin.PlatformLinux, plugin.PlatformContainer, plugin.PlatformOther:
	default:
		problems = append(problems, "platform is required (android, linux, container, other)")
	}
	switch d.Mode {
	case "", plugin.ModePersistent, plugin.ModeDispatch:
	default:
		problems = append(problems, fmt.Sprintf("unknown mode %q", d.Mode))
	}
	active := map[string]struct{}{}
	for i, k := range d.Keys {
		if len(k) != ed25519.PublicKeySize {
			problems = append(problems, fmt.Sprintf("keys[%d] is %d bytes", i, len(k)))
			continue
		}
		active[plugin.EncodeDeviceKey(k)] = struct{}{}
	}
	for i, k := range d.RetiredKeys {
		if len(k) != ed25519.PublicKeySize {
			problems = append(problems, fmt.Sprintf("retired_keys[%d] is %d bytes", i, len(k)))
			continue
		}
		if _, ok := active[plugin.EncodeDeviceKey(k)]; ok {
			problems = append(problems, fmt.Sprintf("retired_keys[%d] is also active", i))
		}
	}
	if len(d.Keys) == 0 && d.ResolvedMode() == plugin.ModePersistent {
		problems = append(problems, "a persistent-mode device needs at least one key")
	}
	for k := range d.Tags {
		if strings.TrimSpace(k) == "" {
			problems = append(problems, "tag keys cannot be blank")
		}
	}
	for i, p := range d.Profiles {
		if strings.TrimSpace(p) == "" {
			problems = append(problems, fmt.Sprintf("profiles[%d] cannot be blank", i))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("sqlite registry: %d problem(s):\n  - %s",
			len(problems), strings.Join(problems, "\n  - "))
	}
	return nil
}

func matchTags(have, want map[string]string) bool {
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
