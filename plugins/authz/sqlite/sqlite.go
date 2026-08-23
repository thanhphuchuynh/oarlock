// Package sqlite provides durable, admin-managed authorization rules.
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/oarlock/oarlock/pkg/plugin"
)

const schema = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS oarlock_permissions (
  id                  TEXT PRIMARY KEY,
  name                TEXT NOT NULL DEFAULT '',
  principals_json     TEXT NOT NULL,
  devices_json        TEXT NOT NULL DEFAULT '[]',
  tags_json           TEXT NOT NULL DEFAULT '{}',
  actions_json        TEXT NOT NULL,
  effect              TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
  reason              TEXT NOT NULL DEFAULT '',
  priority            INTEGER NOT NULL DEFAULT 0,
  enabled             INTEGER NOT NULL DEFAULT 1,
  max_duration_ns     INTEGER NOT NULL DEFAULT 0,
  idle_ns             INTEGER NOT NULL DEFAULT 0,
  ttl_ns              INTEGER NOT NULL DEFAULT 0,
  created_at          TEXT NOT NULL,
  updated_at          TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS oarlock_permissions_enabled_priority
  ON oarlock_permissions(enabled, priority DESC, created_at, id);
`

var validID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type Store struct {
	db  *sql.DB
	now func() time.Time
}

var _ plugin.Authorizer = (*Store)(nil)
var _ plugin.PermissionAdmin = (*Store)(nil)

func Open(path string, now func() time.Time) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("sqlite authorizer: a database path is required")
	}
	if now == nil {
		now = time.Now
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("sqlite authorizer: opening %s: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite authorizer: applying schema: %w", err)
	}
	return &Store{db: db, now: now}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Authorize(ctx context.Context, principal *plugin.Principal, device *plugin.Device, action plugin.Action) (plugin.Decision, error) {
	if principal == nil || device == nil {
		return plugin.Decision{Reason: "no principal or device"}, nil
	}
	permissions, err := s.list(ctx, true)
	if err != nil {
		return plugin.Decision{}, err
	}
	var granted *plugin.Permission
	for _, permission := range permissions {
		if !matches(permission, principal, device, action) {
			continue
		}
		if permission.Deny {
			reason := permission.Reason
			if reason == "" {
				reason = fmt.Sprintf("denied %s on %s by permission %s", action, device.ID, permission.ID)
			}
			return plugin.Decision{Reason: reason}, nil
		}
		if granted == nil {
			granted = permission
		}
	}
	if granted == nil {
		return plugin.Decision{Reason: fmt.Sprintf("no permission grants %s on %s to %s", action, device.ID, principal.ID)}, nil
	}
	decision := plugin.Decision{Allow: true, TTL: granted.TTL}
	if granted.MaxDuration > 0 || granted.Idle > 0 {
		decision.Limits = &plugin.GrantLimits{}
		if granted.MaxDuration > 0 {
			value := granted.MaxDuration
			decision.Limits.MaxDuration = &value
		}
		if granted.Idle > 0 {
			value := granted.Idle
			decision.Limits.Idle = &value
		}
	}
	return decision, nil
}

func (s *Store) Watch(context.Context) (<-chan plugin.RevocationEvent, error) {
	return nil, plugin.ErrUnsupported
}

func (s *Store) ListPermissions(ctx context.Context) ([]*plugin.Permission, error) {
	return s.list(ctx, false)
}

func (s *Store) list(ctx context.Context, enabledOnly bool) ([]*plugin.Permission, error) {
	query := `SELECT id, name, principals_json, devices_json, tags_json, actions_json,
	  effect, reason, priority, enabled, max_duration_ns, idle_ns, ttl_ns, created_at, updated_at
	  FROM oarlock_permissions`
	if enabledOnly {
		query += ` WHERE enabled = 1`
	}
	query += ` ORDER BY priority DESC, created_at, id`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("sqlite authorizer: listing permissions: %w", err)
	}
	defer rows.Close()
	var out []*plugin.Permission
	for rows.Next() {
		permission, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, permission)
	}
	return out, rows.Err()
}

func (s *Store) GetPermission(ctx context.Context, id string) (*plugin.Permission, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, name, principals_json, devices_json, tags_json,
	  actions_json, effect, reason, priority, enabled, max_duration_ns, idle_ns, ttl_ns,
	  created_at, updated_at FROM oarlock_permissions WHERE id = ?`, id)
	permission, err := scan(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", plugin.ErrNoPermission, id)
	}
	return permission, err
}

func (s *Store) CreatePermission(ctx context.Context, permission *plugin.Permission) error {
	if err := validate(permission); err != nil {
		return err
	}
	principals, devices, tags, actions, err := encode(permission)
	if err != nil {
		return err
	}
	now := s.now().UTC()
	_, err = s.db.ExecContext(ctx, `INSERT INTO oarlock_permissions
	  (id, name, principals_json, devices_json, tags_json, actions_json, effect, reason,
	   priority, enabled, max_duration_ns, idle_ns, ttl_ns, created_at, updated_at)
	  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		permission.ID, permission.Name, principals, devices, tags, actions, effect(permission),
		permission.Reason, permission.Priority, boolInt(permission.Enabled), int64(permission.MaxDuration),
		int64(permission.Idle), int64(permission.TTL), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("%w: %s", plugin.ErrPermissionExists, permission.ID)
		}
		return fmt.Errorf("sqlite authorizer: creating permission: %w", err)
	}
	permission.CreatedAt, permission.UpdatedAt = now, now
	return nil
}

func (s *Store) UpdatePermission(ctx context.Context, permission *plugin.Permission) error {
	if err := validate(permission); err != nil {
		return err
	}
	principals, devices, tags, actions, err := encode(permission)
	if err != nil {
		return err
	}
	now := s.now().UTC()
	res, err := s.db.ExecContext(ctx, `UPDATE oarlock_permissions SET name=?, principals_json=?,
	  devices_json=?, tags_json=?, actions_json=?, effect=?, reason=?, priority=?, enabled=?,
	  max_duration_ns=?, idle_ns=?, ttl_ns=?, updated_at=? WHERE id=?`, permission.Name,
		principals, devices, tags, actions, effect(permission), permission.Reason, permission.Priority,
		boolInt(permission.Enabled), int64(permission.MaxDuration), int64(permission.Idle),
		int64(permission.TTL), now.Format(time.RFC3339Nano), permission.ID)
	if err != nil {
		return fmt.Errorf("sqlite authorizer: updating permission: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%w: %s", plugin.ErrNoPermission, permission.ID)
	}
	permission.UpdatedAt = now
	return nil
}

func (s *Store) DeletePermission(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM oarlock_permissions WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("sqlite authorizer: deleting permission: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%w: %s", plugin.ErrNoPermission, id)
	}
	return nil
}

type scanner interface{ Scan(...any) error }

func scan(row scanner) (*plugin.Permission, error) {
	var permission plugin.Permission
	var principals, devices, tags, actions, effectValue, created, updated string
	var enabled int
	var maxDuration, idle, ttl int64
	if err := row.Scan(&permission.ID, &permission.Name, &principals, &devices, &tags, &actions,
		&effectValue, &permission.Reason, &permission.Priority, &enabled, &maxDuration, &idle,
		&ttl, &created, &updated); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(principals), &permission.Principals); err != nil {
		return nil, fmt.Errorf("sqlite authorizer: decoding principals for %s: %w", permission.ID, err)
	}
	if err := json.Unmarshal([]byte(devices), &permission.Devices); err != nil {
		return nil, fmt.Errorf("sqlite authorizer: decoding devices for %s: %w", permission.ID, err)
	}
	if err := json.Unmarshal([]byte(tags), &permission.Tags); err != nil {
		return nil, fmt.Errorf("sqlite authorizer: decoding tags for %s: %w", permission.ID, err)
	}
	if err := json.Unmarshal([]byte(actions), &permission.Actions); err != nil {
		return nil, fmt.Errorf("sqlite authorizer: decoding actions for %s: %w", permission.ID, err)
	}
	permission.Deny = effectValue == "deny"
	permission.Enabled = enabled != 0
	permission.MaxDuration = time.Duration(maxDuration)
	permission.Idle = time.Duration(idle)
	permission.TTL = time.Duration(ttl)
	permission.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	permission.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return &permission, nil
}

func encode(permission *plugin.Permission) (string, string, string, string, error) {
	devices := permission.Devices
	if devices == nil {
		devices = []string{}
	}
	tags := permission.Tags
	if tags == nil {
		tags = map[string]string{}
	}
	values := []any{permission.Principals, devices, tags, permission.Actions}
	out := make([]string, 4)
	for i, value := range values {
		encoded, err := json.Marshal(value)
		if err != nil {
			return "", "", "", "", fmt.Errorf("sqlite authorizer: encoding permission: %w", err)
		}
		out[i] = string(encoded)
	}
	return out[0], out[1], out[2], out[3], nil
}

func validate(permission *plugin.Permission) error {
	if permission == nil {
		return errors.New("permission is required")
	}
	if !validID.MatchString(permission.ID) {
		return errors.New("permission id must be 1-128 letters, digits, dots, underscores, or hyphens")
	}
	if len(permission.Principals) == 0 {
		return errors.New("permission requires at least one principal")
	}
	if len(permission.Actions) == 0 {
		return errors.New(`permission requires at least one action; use "*" explicitly for every action`)
	}
	for _, pattern := range append(append([]string{}, permission.Principals...), permission.Devices...) {
		if pattern == "" {
			return errors.New("permission patterns cannot be empty")
		}
		if _, err := filepath.Match(pattern, ""); err != nil {
			return fmt.Errorf("invalid permission pattern %q: %w", pattern, err)
		}
	}
	for _, action := range permission.Actions {
		if action != "*" && !knownAction(action) {
			return fmt.Errorf("unknown permission action %q", action)
		}
	}
	for key := range permission.Tags {
		if strings.TrimSpace(key) == "" {
			return errors.New("permission tag keys cannot be empty")
		}
	}
	if permission.MaxDuration < 0 || permission.Idle < 0 || permission.TTL < 0 {
		return errors.New("permission durations cannot be negative")
	}
	return nil
}

// matches is the whole decision: principal, device and tags, then action.
//
// Each clause is a method on plugin.Permission so that the admin API's "who can reach
// this device" view and this decision cannot disagree about what a rule means. The one
// that would bite is the device half — a console with its own copy of glob-and-tag
// matching drifts, and it drifts towards telling somebody they cannot reach a device
// they can.
func matches(permission *plugin.Permission, principal *plugin.Principal, device *plugin.Device, action plugin.Action) bool {
	return permission.MatchesPrincipal(principal.ID) &&
		permission.AppliesTo(device) &&
		permission.Grants(action)
}

var actions = []plugin.Action{
	plugin.ActionShell, plugin.ActionExec, plugin.ActionFileRead, plugin.ActionFileWrite,
	plugin.ActionTCP, plugin.ActionPassthrough, plugin.ActionReplay, plugin.ActionObserve,
	plugin.ActionSQLRead,
	plugin.ActionAdminDevices, plugin.ActionAdminPermissions, plugin.ActionAdminKill,
}

func knownAction(value string) bool {
	for _, action := range actions {
		if string(action) == value {
			return true
		}
	}
	return false
}

func effect(permission *plugin.Permission) string {
	if permission.Deny {
		return "deny"
	}
	return "allow"
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
