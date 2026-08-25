// Package sqlitestore is a session ledger in one SQLite file.
//
// Pure Go, no cgo: the gateway has to cross-compile without a C toolchain, and a
// ledger that breaks `GOOS=linux GOARCH=arm64 go build` is a ledger that makes the
// whole binary harder to ship.
//
// # Why the caps are enforced in the database
//
// Two operators opening a shell on the same device in the same second is exactly
// the race the per-device cap exists to lose gracefully, and "we counted and it was
// fine" is not an enforcement mechanism. So there are two layers:
//
//   - Every insert runs in a `BEGIN IMMEDIATE` transaction. SQLite has a single
//     writer, so the count and the insert cannot be separated by another writer.
//   - A **partial unique index** on the live-device column makes a second live
//     session for one device impossible even if the counting logic is wrong. That
//     is the layer that catches *our* bugs rather than the caller's.
package sqlitestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/oarlock/oarlock/internal/sessions"
)

const schema = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS sessions (
  id              TEXT PRIMARY KEY,
  device_id       TEXT    NOT NULL,
  profile         TEXT    NOT NULL,
  mode            TEXT    NOT NULL DEFAULT '',
  principal       TEXT    NOT NULL DEFAULT '',
  opened_by       TEXT    NOT NULL DEFAULT '',
  unattended      INTEGER NOT NULL DEFAULT 0,
  record_input    INTEGER NOT NULL DEFAULT 0,
  reason          TEXT    NOT NULL DEFAULT '',
  state           TEXT    NOT NULL,
  recording_state TEXT    NOT NULL,
  close_reason    TEXT    NOT NULL DEFAULT '',
  exit_code       INTEGER,
  bytes_in        INTEGER NOT NULL DEFAULT 0,
  bytes_out       INTEGER NOT NULL DEFAULT 0,
  bytes_dropped   INTEGER NOT NULL DEFAULT 0,
  created_at      TEXT    NOT NULL,
  attached_at     TEXT,
  closed_at       TEXT,

  -- live_device holds device_id while this session is holding the device, and NULL
  -- once it is not. Its *only* job is the partial unique index below, which makes
  -- "one live session per device" a property of the database rather than of the code
  -- above it. Counting and querying use the state column instead — an earlier
  -- version used live_device for both, and because it is only populated when the cap
  -- is one, the per-device cap silently stopped being enforced for any other value.
  --
  -- tcp rows never set it. A forwarded connection does not hold the device in the
  -- sense this index enforces (sessions.HoldsDevice), and one ssh -L would otherwise
  -- take the slot the shell needs.
  live_device     TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS sessions_one_live_per_device
  ON sessions(live_device) WHERE live_device IS NOT NULL;

CREATE INDEX IF NOT EXISTS sessions_by_device    ON sessions(device_id, created_at);
CREATE INDEX IF NOT EXISTS sessions_by_principal ON sessions(principal, created_at);
CREATE INDEX IF NOT EXISTS sessions_by_state     ON sessions(state, created_at);
`

// liveState is what "still holding the device" means, in one place. It has to agree
// with Session.Live(); a drift between the two would show up as a cap that counts
// rows the ledger considers finished.
const liveState = `state NOT IN ('closed','rejected')`

// holdsDevice and isForward are sessions.HoldsDevice expressed in SQL, split so a
// query can ask for either side. The two definitions have to agree; a test asserts it
// rather than trusting that whoever adds the next profile reads both files.
var (
	holdsDevice = `profile <> '` + sessions.ProfileTCP + `'`
	isForward   = `profile = '` + sessions.ProfileTCP + `'`
)

// Store is a SQLite-backed ledger.
type Store struct {
	db     *sql.DB
	limits sessions.Limits
	now    func() time.Time
}

var _ sessions.Store = (*Store)(nil)

// Open opens or creates the database at path. ":memory:" works, and is what tests
// use.
func Open(path string, l sessions.Limits, now func() time.Time) (*Store, error) {
	if l.PerDevice <= 0 {
		l.PerDevice = 1
	}
	if l.PerPrincipal <= 0 {
		l.PerPrincipal = 5
	}
	if l.TCPConnsPerDevice <= 0 {
		l.TCPConnsPerDevice = sessions.DefaultTCPConnsPerDevice
	}
	if now == nil {
		now = time.Now
	}
	dsn := path
	if path == ":memory:" {
		// A shared cache, or every pooled connection gets its own empty database —
		// which looks like data vanishing between calls.
		dsn = "file::memory:?cache=shared"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlitestore: opening %s: %w", path, err)
	}
	// One writer. SQLite serialises writes anyway; letting the pool open several
	// connections only converts that into SQLITE_BUSY errors to retry.
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlitestore: applying the schema: %w", err)
	}
	if err := ensureColumn(db, `ALTER TABLE sessions ADD COLUMN record_input INTEGER NOT NULL DEFAULT 0`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlitestore: migrating sessions.record_input: %w", err)
	}
	return &Store{db: db, limits: l, now: now}, nil
}

// Shutdown closes the database. Not named Close: the ledger interface already has
// a Close-shaped method for finalising a session, and one type with both meanings is
// one somebody will call the wrong one of.
func (s *Store) Shutdown() error { return s.db.Close() }

// Create inserts a row and enforces the caps, atomically.
func (s *Store) Create(ctx context.Context, sess *sessions.Session) error {
	if sess == nil || sess.ID == "" || sess.DeviceID == "" {
		return errors.New("sqlitestore: ID and DeviceID are required")
	}
	row := *sess
	if row.CreatedAt.IsZero() {
		row.CreatedAt = s.now()
	}
	if row.State == "" {
		row.State = sessions.StateWaking
	}
	if row.RecordingState == "" {
		// Never blank. An unrecorded session must be a fact you can query for, not
		// an absence somebody has to interpret.
		row.RecordingState = sessions.NotRecorded
	}

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return fmt.Errorf("sqlitestore: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var existing int
	if err := tx.QueryRowContext(ctx,
		`SELECT count(*) FROM sessions WHERE id = ?`, row.ID).Scan(&existing); err != nil {
		return err
	}
	if existing > 0 {
		return fmt.Errorf("%w: %s", sessions.ErrExists, row.ID)
	}

	// Forwarded connections are counted apart from everything else, and against their
	// own cap — see sessions.HoldsDevice. A `tcp` row must not consume the device's
	// interactive slot, or one `ssh -L` locks out the shell for as long as it runs.
	if !sessions.HoldsDevice(row.Profile) {
		var liveForwards int
		if err := tx.QueryRowContext(ctx,
			`SELECT count(*) FROM sessions WHERE device_id = ? AND `+liveState+
				` AND `+isForward, row.DeviceID).Scan(&liveForwards); err != nil {
			return err
		}
		if liveForwards >= s.limits.TCPConnsPerDevice {
			return fmt.Errorf("%w: %s already has %d of %d forwarded connections",
				sessions.ErrLimit, row.DeviceID, liveForwards, s.limits.TCPConnsPerDevice)
		}
	} else {
		var liveDevice, livePrincipal int
		if err := tx.QueryRowContext(ctx,
			`SELECT count(*) FROM sessions WHERE device_id = ? AND `+liveState+
				` AND `+holdsDevice, row.DeviceID).Scan(&liveDevice); err != nil {
			return err
		}
		if liveDevice >= s.limits.PerDevice {
			return fmt.Errorf("%w: %s already has %d of %d sessions",
				sessions.ErrLimit, row.DeviceID, liveDevice, s.limits.PerDevice)
		}
		if row.Principal != "" {
			if err := tx.QueryRowContext(ctx,
				`SELECT count(*) FROM sessions WHERE principal = ? AND `+liveState+
					` AND `+holdsDevice, row.Principal).Scan(&livePrincipal); err != nil {
				return err
			}
			if livePrincipal >= s.limits.PerPrincipal {
				return fmt.Errorf("%w: %s already has %d of %d sessions",
					sessions.ErrLimit, row.Principal, livePrincipal, s.limits.PerPrincipal)
			}
		}
	}

	// live_device is only set when the cap is one, because that is the case the
	// unique index can express. Above one, the transaction is the only enforcement —
	// which is documented rather than silently different.
	var live any
	if s.limits.PerDevice == 1 && sessions.HoldsDevice(row.Profile) {
		live = row.DeviceID
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO sessions (id, device_id, profile, mode, principal, opened_by,
		  unattended, record_input, reason, state, recording_state, created_at, live_device)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		row.ID, row.DeviceID, row.Profile, row.Mode, row.Principal, row.OpenedBy,
		boolToInt(row.Unattended), boolToInt(row.RecordInput), row.Reason, string(row.State),
		string(row.RecordingState), ts(row.CreatedAt), live)
	if err != nil {
		if isUniqueViolation(err) {
			// The index caught what the count did not. That is the layer working.
			return fmt.Errorf("%w: %s already has a live session (unique index)",
				sessions.ErrLimit, row.DeviceID)
		}
		return fmt.Errorf("sqlitestore: insert: %w", err)
	}
	if err := tx.Commit(); err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: %s already has a live session (unique index)",
				sessions.ErrLimit, row.DeviceID)
		}
		return fmt.Errorf("sqlitestore: commit: %w", err)
	}
	*sess = row
	return nil
}

// Update reads a row, applies f, and writes it back inside one transaction.
func (s *Store) Update(ctx context.Context, id string, f func(*sessions.Session) error) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	row, err := scanOne(tx.QueryRowContext(ctx, selectCols+` WHERE id = ?`, id))
	if err != nil {
		return err
	}
	if err := f(row); err != nil {
		return err
	}
	// A row that is no longer live releases the device's slot. Doing it here means
	// any path that sets a terminal state frees the slot, rather than each caller
	// remembering to.
	var live any
	if row.Live() && s.limits.PerDevice == 1 && sessions.HoldsDevice(row.Profile) {
		live = row.DeviceID
	}
	_, err = tx.ExecContext(ctx, `
		UPDATE sessions SET state=?, recording_state=?, close_reason=?, exit_code=?,
		  bytes_in=?, bytes_out=?, bytes_dropped=?, attached_at=?, closed_at=?,
		  reason=?, mode=?, opened_by=?, unattended=?, record_input=?, live_device=?
		WHERE id=?`,
		string(row.State), string(row.RecordingState), row.CloseReason, row.ExitCode,
		row.BytesIn, row.BytesOut, row.BytesDropped, tsp(row.AttachedAt), tsp(row.ClosedAt),
		row.Reason, row.Mode, row.OpenedBy, boolToInt(row.Unattended),
		boolToInt(row.RecordInput), live, id)
	if err != nil {
		return fmt.Errorf("sqlitestore: update: %w", err)
	}
	return tx.Commit()
}

// Finish finalises a row. The close reason is written once: the first reason is the
// true one, and whatever noticed second is a consequence of it.
func (s *Store) Finish(ctx context.Context, id string, r sessions.Result) error {
	return s.Update(ctx, id, func(row *sessions.Session) error {
		if row.State == sessions.StateClosed {
			return nil
		}
		row.State = sessions.StateClosed
		if row.CloseReason == "" {
			row.CloseReason = r.CloseReason
		}
		if r.ExitCode != nil {
			row.ExitCode = r.ExitCode
		}
		row.BytesIn, row.BytesOut, row.BytesDropped = r.BytesIn, r.BytesOut, r.BytesDropped
		row.ClosedAt = s.now()
		return nil
	})
}

// FinishLive finalises sessions left live by a previous owner of this SQLite ledger.
// Callers must establish exclusive gateway ownership before invoking it; otherwise a
// second process that merely opened the database could close sessions still running.
func (s *Store) FinishLive(ctx context.Context, reason string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE sessions
		SET state = 'closed', close_reason = CASE WHEN close_reason = '' THEN ? ELSE close_reason END,
		    closed_at = ?, live_device = NULL
		WHERE `+liveState, reason, tsp(s.now()))
	if err != nil {
		return 0, fmt.Errorf("sqlitestore: finishing stale live sessions: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("sqlitestore: counting stale live sessions: %w", err)
	}
	return n, nil
}

// Get returns one row.
func (s *Store) Get(ctx context.Context, id string) (*sessions.Session, error) {
	return scanOne(s.db.QueryRowContext(ctx, selectCols+` WHERE id = ?`, id))
}

// List returns a page ordered by creation time then id, so pagination is stable.
func (s *Store) List(ctx context.Context, q sessions.Query) ([]*sessions.Session, string, error) {
	var where []string
	var args []any
	if q.DeviceID != "" {
		where = append(where, "device_id = ?")
		args = append(args, q.DeviceID)
	}
	if q.Principal != "" {
		where = append(where, "principal = ?")
		args = append(args, q.Principal)
	}
	if q.State != "" {
		where = append(where, "state = ?")
		args = append(args, string(q.State))
	}
	if q.Live {
		where = append(where, liveState)
	}
	if q.Unattended != nil {
		where = append(where, "unattended = ?")
		args = append(args, boolToInt(*q.Unattended))
	}
	if q.After != "" {
		where = append(where, "id > ?")
		args = append(args, q.After)
	}
	limit := q.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	sqlText := selectCols
	if len(where) > 0 {
		sqlText += " WHERE " + strings.Join(where, " AND ")
	}
	sqlText += " ORDER BY created_at, id LIMIT ?"
	args = append(args, limit+1) // one extra, to know whether there is a next page

	rows, err := s.db.QueryContext(ctx, sqlText, args...)
	if err != nil {
		return nil, "", fmt.Errorf("sqlitestore: list: %w", err)
	}
	defer rows.Close()

	var out []*sessions.Session
	for rows.Next() {
		row, err := scanRows(rows)
		if err != nil {
			return nil, "", err
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	if len(out) > limit {
		return out[:limit], out[limit-1].ID, nil
	}
	return out, "", nil
}

// Len is the row count, for metrics and health.
func (s *Store) Len(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM sessions`).Scan(&n)
	return n, err
}

// ── scanning ────────────────────────────────────────────────────────────────────

const selectCols = `SELECT id, device_id, profile, mode, principal, opened_by,
  unattended, record_input, reason, state, recording_state, close_reason, exit_code,
  bytes_in, bytes_out, bytes_dropped, created_at, attached_at, closed_at
  FROM sessions`

type scanner interface {
	Scan(dest ...any) error
}

func scanOne(r scanner) (*sessions.Session, error) {
	row, err := scanInto(r)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w", sessions.ErrNotFound)
	}
	return row, err
}

func scanRows(r scanner) (*sessions.Session, error) { return scanInto(r) }

func scanInto(r scanner) (*sessions.Session, error) {
	var (
		row                  sessions.Session
		state, recState      string
		unattended, recInput int
		exitCode             sql.NullInt64
		createdAt            string
		attachedAt, closedAt sql.NullString
	)
	if err := r.Scan(&row.ID, &row.DeviceID, &row.Profile, &row.Mode, &row.Principal,
		&row.OpenedBy, &unattended, &recInput, &row.Reason, &state, &recState,
		&row.CloseReason, &exitCode, &row.BytesIn, &row.BytesOut, &row.BytesDropped,
		&createdAt, &attachedAt, &closedAt); err != nil {
		return nil, err
	}
	row.State = sessions.State(state)
	row.RecordingState = sessions.RecordingState(recState)
	row.Unattended = unattended != 0
	row.RecordInput = recInput != 0
	if exitCode.Valid {
		c := int(exitCode.Int64)
		row.ExitCode = &c
	}
	row.CreatedAt = parseTS(createdAt)
	if attachedAt.Valid {
		row.AttachedAt = parseTS(attachedAt.String)
	}
	if closedAt.Valid {
		row.ClosedAt = parseTS(closedAt.String)
	}
	return &row, nil
}

func ensureColumn(db *sql.DB, stmt string) error {
	if _, err := db.Exec(stmt); err != nil &&
		!strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
		return err
	}
	return nil
}

// Timestamps are RFC 3339 with nanoseconds, in UTC. SQLite has no time type, and a
// sortable text format means ORDER BY created_at is chronological rather than
// alphabetical-by-accident.
func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func tsp(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return ts(t)
}

func parseTS(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func isUniqueViolation(err error) bool {
	// modernc's driver reports constraint failures in the message. Matching on it is
	// unlovely; the alternative is depending on the driver's error type, which is
	// worse to carry across driver versions.
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "unique constraint") || strings.Contains(s, "constraint failed")
}
