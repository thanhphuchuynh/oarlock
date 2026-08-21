package plugin

import (
	"context"
	"io"
	"time"
)

// SessionMeta is what a recording is about. It is handed to Recorder.Open before
// the operator sees a prompt.
type SessionMeta struct {
	SessionID string
	DeviceID  string
	Profile   string
	Mode      string // gateway | passthrough

	// Principal is the human. OpenedBy is the service that acted for them, if any.
	// Both are kept: a recording attributed only to a service account shows someone
	// typing `rm -rf` with a robot's name on it.
	Principal  string
	OpenedBy   string
	Unattended bool

	Term string
	Cols int
	Rows int

	StartedAt time.Time

	// RecordInput says whether keystrokes are captured. Resolved per session from
	// policy, not from a global default, because two compliance regimes disagree
	// about it (ARCHITECTURE § 8.2).
	RecordInput bool
}

// RecordingResult finalises a recording.
type RecordingResult struct {
	CloseReason  string
	ExitCode     *int
	BytesDropped int64
	ClosedAt     time.Time
}

// RecordingWriter accepts one session's events.
//
// Output is on the per-byte path: buffer, and do not perform I/O per call. The
// gateway puts a bounded spool in front of these calls, so a backend that is
// failing for thirty seconds is invisible to the operator — return errors honestly
// and let the spool absorb them rather than retrying internally forever, which
// hides the failure from the mechanism built to handle it.
type RecordingWriter interface {
	// Output records device→operator bytes. at is elapsed time since StartedAt.
	Output(at time.Duration, b []byte) error
	// Input records operator→device bytes. Called only when RecordInput is true.
	Input(at time.Duration, b []byte) error
	// Resize records a terminal size change, so replay reflows correctly.
	Resize(at time.Duration, cols, rows int) error
	// Exit records the process's exit status.
	Exit(at time.Duration, code int) error
	// Close finalises. It runs even when the session died badly, because a
	// recording of a session that ended abruptly is exactly the one somebody will
	// want to read.
	Close(ctx context.Context, r RecordingResult) error
}

// Recorder is where recordings live.
type Recorder interface {
	// Open is called before the operator sees a prompt. An error here fails the
	// session: an unrecorded session that looks recorded is worse than no session,
	// because an audit trail with silent holes is one nobody can rely on.
	Open(ctx context.Context, m *SessionMeta) (RecordingWriter, error)

	// Get streams a recording back.
	Get(ctx context.Context, sessionID string) (io.ReadCloser, error)

	// URL returns a time-limited direct link if the backend can issue one, so
	// replay does not stream through the gateway. ErrUnsupported otherwise.
	URL(ctx context.Context, sessionID string, ttl time.Duration) (string, error)
}
