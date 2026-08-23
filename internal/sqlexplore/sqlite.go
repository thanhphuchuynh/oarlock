// Package sqlexplore provides a bounded, read-only view of operational SQLite data.
package sqlexplore

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	_ "modernc.org/sqlite"
)

const (
	DefaultLimit = 200
	MaxLimit     = 500
	MaxColumns   = 64
	MaxQuerySize = 16 << 10
)

var (
	ErrInvalidQuery = errors.New("sql explorer: invalid query")
	ErrUnavailable  = errors.New("sql explorer: unavailable")
)

// Column describes a column exposed to SQL Explorer.
type Column struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// Table describes an exposed table.
type Table struct {
	Name    string   `json:"name"`
	Columns []Column `json:"columns"`
}

// Result is a bounded query result.
type Result struct {
	Columns    []string `json:"columns"`
	Rows       [][]any  `json:"rows"`
	Truncated  bool     `json:"truncated"`
	DurationMS int64    `json:"duration_ms"`
}

var catalog = []Table{
	{Name: "sessions", Columns: []Column{
		{Name: "id", Type: "TEXT"}, {Name: "device_id", Type: "TEXT"},
		{Name: "profile", Type: "TEXT"}, {Name: "mode", Type: "TEXT"},
		{Name: "principal", Type: "TEXT"}, {Name: "opened_by", Type: "TEXT"},
		{Name: "unattended", Type: "INTEGER"}, {Name: "record_input", Type: "INTEGER"},
		{Name: "reason", Type: "TEXT"}, {Name: "state", Type: "TEXT"},
		{Name: "recording_state", Type: "TEXT"}, {Name: "close_reason", Type: "TEXT"},
		{Name: "exit_code", Type: "INTEGER"}, {Name: "bytes_in", Type: "INTEGER"},
		{Name: "bytes_out", Type: "INTEGER"}, {Name: "bytes_dropped", Type: "INTEGER"},
		{Name: "created_at", Type: "TEXT"}, {Name: "attached_at", Type: "TEXT"},
		{Name: "closed_at", Type: "TEXT"},
	}},
	{Name: "oarlock_devices", Columns: []Column{
		{Name: "id", Type: "TEXT"}, {Name: "platform", Type: "TEXT"},
		{Name: "mode", Type: "TEXT"}, {Name: "disabled", Type: "INTEGER"},
		{Name: "allow_passthrough", Type: "INTEGER"},
		{Name: "created_at", Type: "TEXT"}, {Name: "updated_at", Type: "TEXT"},
	}},
	{Name: "oarlock_device_tags", Columns: []Column{
		{Name: "device_id", Type: "TEXT"}, {Name: "key", Type: "TEXT"},
		{Name: "value", Type: "TEXT"},
	}},
	{Name: "oarlock_device_profiles", Columns: []Column{
		{Name: "device_id", Type: "TEXT"}, {Name: "profile", Type: "TEXT"},
	}},
	{Name: "oarlock_permissions", Columns: []Column{
		{Name: "id", Type: "TEXT"}, {Name: "name", Type: "TEXT"},
		{Name: "principals_json", Type: "TEXT"}, {Name: "devices_json", Type: "TEXT"},
		{Name: "tags_json", Type: "TEXT"}, {Name: "actions_json", Type: "TEXT"},
		{Name: "effect", Type: "TEXT"}, {Name: "reason", Type: "TEXT"},
		{Name: "priority", Type: "INTEGER"}, {Name: "enabled", Type: "INTEGER"},
		{Name: "max_duration_ns", Type: "INTEGER"}, {Name: "idle_ns", Type: "INTEGER"},
		{Name: "ttl_ns", Type: "INTEGER"}, {Name: "created_at", Type: "TEXT"},
		{Name: "updated_at", Type: "TEXT"},
	}},
	{Name: "oarlock_audit_events", Columns: []Column{
		{Name: "id", Type: "INTEGER"}, {Name: "at", Type: "TEXT"},
		{Name: "kind", Type: "TEXT"}, {Name: "payload", Type: "TEXT"},
	}},
}

// SQLite reads the live file through a read-only connection and executes each user
// query against an isolated in-memory snapshot containing only catalogued columns.
type SQLite struct {
	source *sql.DB
}

// Open opens an existing SQLite database without write access.
func Open(path string) (*SQLite, error) {
	if path == "" || path == ":memory:" {
		return nil, fmt.Errorf("%w: a file-backed SQLite store is required", ErrUnavailable)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("sql explorer: resolve database path: %w", err)
	}
	dsn := (&url.URL{Scheme: "file", Path: abs}).String() + "?mode=ro"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sql explorer: open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sql explorer: open database: %w", err)
	}
	return &SQLite{source: db}, nil
}

func (s *SQLite) Close() error { return s.source.Close() }

// Schema returns a copy so callers cannot mutate the package catalog.
func (s *SQLite) Schema(context.Context) ([]Table, error) {
	out := make([]Table, len(catalog))
	for i, table := range catalog {
		out[i] = Table{Name: table.Name, Columns: append([]Column(nil), table.Columns...)}
	}
	return out, nil
}

// Query executes one SELECT (or WITH query) and returns at most limit rows.
func (s *SQLite) Query(ctx context.Context, query string, limit int) (Result, error) {
	started := time.Now()
	if err := validate(query); err != nil {
		return Result{}, err
	}
	if limit <= 0 {
		limit = DefaultLimit
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}

	mem, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return Result{}, fmt.Errorf("sql explorer: open snapshot: %w", err)
	}
	defer mem.Close()
	mem.SetMaxOpenConns(1)
	if err := s.snapshot(ctx, mem); err != nil {
		return Result{}, err
	}
	if _, err := mem.ExecContext(ctx, "PRAGMA query_only = ON"); err != nil {
		return Result{}, fmt.Errorf("sql explorer: lock snapshot: %w", err)
	}

	rows, err := mem.QueryContext(ctx, query)
	if err != nil {
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		return Result{}, fmt.Errorf("%w: %v", ErrInvalidQuery, err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return Result{}, fmt.Errorf("sql explorer: result columns: %w", err)
	}
	if len(columns) > MaxColumns {
		return Result{}, fmt.Errorf("%w: result has more than %d columns", ErrInvalidQuery, MaxColumns)
	}

	result := Result{Columns: columns, Rows: make([][]any, 0, limit)}
	for rows.Next() {
		values := make([]any, len(columns))
		dest := make([]any, len(columns))
		for i := range values {
			dest[i] = &values[i]
		}
		if err := rows.Scan(dest...); err != nil {
			return Result{}, fmt.Errorf("sql explorer: scan result: %w", err)
		}
		if len(result.Rows) == limit {
			result.Truncated = true
			break
		}
		for i, value := range values {
			if b, ok := value.([]byte); ok {
				values[i] = "base64:" + base64.StdEncoding.EncodeToString(b)
			}
		}
		result.Rows = append(result.Rows, values)
	}
	if err := rows.Err(); err != nil {
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		return Result{}, fmt.Errorf("sql explorer: read result: %w", err)
	}
	result.DurationMS = time.Since(started).Milliseconds()
	return result, nil
}

func (s *SQLite) snapshot(ctx context.Context, mem *sql.DB) error {
	for _, table := range catalog {
		selects := make([]string, len(table.Columns))
		definitions := make([]string, len(table.Columns))
		placeholders := make([]string, len(table.Columns))
		for i, column := range table.Columns {
			selects[i] = quote(column.Name)
			definitions[i] = quote(column.Name) + " " + column.Type
			placeholders[i] = "?"
		}
		rows, err := s.source.QueryContext(ctx, "SELECT "+strings.Join(selects, ",")+" FROM "+quote(table.Name))
		if err != nil {
			// Older databases may not have every optional operational table yet.
			if strings.Contains(strings.ToLower(err.Error()), "no such table") {
				continue
			}
			return fmt.Errorf("sql explorer: snapshot %s: %w", table.Name, err)
		}
		if _, err := mem.ExecContext(ctx, "CREATE TABLE "+quote(table.Name)+" ("+strings.Join(definitions, ",")+")"); err != nil {
			rows.Close()
			return fmt.Errorf("sql explorer: create snapshot table: %w", err)
		}
		stmt, err := mem.PrepareContext(ctx, "INSERT INTO "+quote(table.Name)+" VALUES ("+strings.Join(placeholders, ",")+")")
		if err != nil {
			rows.Close()
			return fmt.Errorf("sql explorer: prepare snapshot: %w", err)
		}
		for rows.Next() {
			values := make([]any, len(table.Columns))
			dest := make([]any, len(values))
			for i := range values {
				dest[i] = &values[i]
			}
			if err := rows.Scan(dest...); err != nil {
				stmt.Close()
				rows.Close()
				return fmt.Errorf("sql explorer: scan snapshot: %w", err)
			}
			if _, err := stmt.ExecContext(ctx, values...); err != nil {
				stmt.Close()
				rows.Close()
				return fmt.Errorf("sql explorer: fill snapshot: %w", err)
			}
		}
		err = rows.Err()
		_ = stmt.Close()
		_ = rows.Close()
		if err != nil {
			return fmt.Errorf("sql explorer: read snapshot: %w", err)
		}
	}
	return nil
}

func validate(query string) error {
	if len(query) == 0 || len(query) > MaxQuerySize {
		return fmt.Errorf("%w: query must be between 1 and %d bytes", ErrInvalidQuery, MaxQuerySize)
	}
	word, semicolon, err := firstWord(query)
	if err != nil {
		return err
	}
	if word != "select" && word != "with" {
		return fmt.Errorf("%w: only SELECT and WITH queries are allowed", ErrInvalidQuery)
	}
	if semicolon {
		return fmt.Errorf("%w: semicolons and multiple statements are not allowed", ErrInvalidQuery)
	}
	return nil
}

func firstWord(query string) (string, bool, error) {
	var word strings.Builder
	for i := 0; i < len(query); {
		switch {
		case unicode.IsSpace(rune(query[i])):
			i++
		case query[i] == '-' && i+1 < len(query) && query[i+1] == '-':
			i += 2
			for i < len(query) && query[i] != '\n' {
				i++
			}
		case query[i] == '/' && i+1 < len(query) && query[i+1] == '*':
			end := strings.Index(query[i+2:], "*/")
			if end < 0 {
				return "", false, fmt.Errorf("%w: unterminated comment", ErrInvalidQuery)
			}
			i += end + 4
		default:
			for i < len(query) && (unicode.IsLetter(rune(query[i])) || query[i] == '_') {
				word.WriteByte(query[i])
				i++
			}
			if word.Len() == 0 {
				return "", false, fmt.Errorf("%w: expected SELECT or WITH", ErrInvalidQuery)
			}
			return strings.ToLower(word.String()), hasSemicolon(query), nil
		}
	}
	return "", false, fmt.Errorf("%w: query is empty", ErrInvalidQuery)
}

func hasSemicolon(query string) bool {
	var quoteByte byte
	lineComment, blockComment := false, false
	for i := 0; i < len(query); i++ {
		c := query[i]
		if lineComment {
			if c == '\n' {
				lineComment = false
			}
			continue
		}
		if blockComment {
			if c == '*' && i+1 < len(query) && query[i+1] == '/' {
				blockComment = false
				i++
			}
			continue
		}
		if quoteByte != 0 {
			if c == quoteByte {
				if i+1 < len(query) && query[i+1] == quoteByte {
					i++
					continue
				}
				quoteByte = 0
			}
			continue
		}
		if c == '-' && i+1 < len(query) && query[i+1] == '-' {
			lineComment = true
			i++
			continue
		}
		if c == '/' && i+1 < len(query) && query[i+1] == '*' {
			blockComment = true
			i++
			continue
		}
		if c == '\'' || c == '"' || c == '`' {
			quoteByte = c
			continue
		}
		if c == ';' {
			return true
		}
	}
	return false
}

func quote(identifier string) string { return `"` + strings.ReplaceAll(identifier, `"`, `""`) + `"` }
