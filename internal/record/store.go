package record

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/oarlock/oarlock/pkg/plugin"
)

// Store is where recording bytes land. It is the pluggable seam for storage.
//
// # Why storage is a blob store and not an event writer
//
// The first cut of this made the *whole recorder* pluggable — a backend received
// Output/Input/Resize calls and encoded asciicast itself. Building the spool
// (E2.S2) showed that to be the wrong seam, for three reasons:
//
//  1. The spool must buffer exactly the bytes destined for storage, so it has to
//     sit *below* the encoder. Above it, a retry would mean re-encoding, and the
//     hash chain would have to be recomputed — which means a retry could change
//     the recording's identity.
//  2. A spooled fragment dumped to disk is then a valid slice of a .cast file,
//     recoverable by appending it at a known offset. Buffered events are not.
//  3. It is far less for a third-party backend to implement, and it removes the
//     possibility of a backend encoding asciicast subtly wrongly — which would
//     produce recordings that verify but do not play.
//
// So the encoder, the chain and the manifest are Oarlock's, and a backend answers
// one question: where do these bytes go.
type Store interface {
	// Create opens the recording stream. Meta is passed for backends that key on
	// more than the id — a bucket prefix per device, say.
	Create(ctx context.Context, m *plugin.SessionMeta) (io.WriteCloser, error)
	// PutManifest stores the sidecar. Called once, at close.
	PutManifest(ctx context.Context, sessionID string, b []byte) error

	Get(ctx context.Context, sessionID string) (io.ReadCloser, error)
	GetManifest(ctx context.Context, sessionID string) ([]byte, error)

	// URL returns a time-limited direct link if the backend can issue one, so
	// replay does not stream through the gateway. plugin.ErrUnsupported otherwise.
	URL(ctx context.Context, sessionID string, ttl time.Duration) (string, error)
}

// ErrNotFound is returned when a recording is not in the store.
var ErrNotFound = errors.New("record: no such recording")

// ── immutability ────────────────────────────────────────────────────────────────

// Mode is what a store can enforce about altering a recording after it is written.
//
// The hash chain and the signed manifest make tampering *detectable*. Only storage
// can make it *impossible*, and the two are not substitutes: detection tells you
// afterwards, and afterwards is when somebody is already asking why the recording
// disagrees with the incident report.
type Mode string

const (
	// ModeUnknown: the store cannot say. Treated as mutable, because a guarantee
	// nobody can describe is not one.
	ModeUnknown Mode = "unknown"
	// ModeMutable: anything with write access can alter or delete a recording.
	ModeMutable Mode = "mutable"
	// ModeDeclared: the operator says the storage is protected — an append-only
	// mount, a snapshotting filesystem — and the store cannot verify it. Better than
	// nothing, because it is a claim somebody made on the record, and worse than a
	// lock, because nothing checks it.
	ModeDeclared Mode = "declared"
	// ModeGovernance: an object lock that sufficiently privileged users can lift.
	// Stops an accident and a compromised writer; does not stop an administrator.
	ModeGovernance Mode = "governance"
	// ModeCompliance: a lock nobody can lift until retention expires, including the
	// account owner. The only mode that survives a compromised administrator.
	ModeCompliance Mode = "compliance"
)

// Protected reports whether the mode offers more than detection.
func (m Mode) Protected() bool {
	switch m {
	case ModeGovernance, ModeCompliance, ModeDeclared:
		return true
	}
	return false
}

// Immutability is what a store reports about its own guarantee.
type Immutability struct {
	Mode Mode `json:"mode"`
	// RetainFor is how long the lock holds. Zero means indefinite or unknown.
	RetainFor time.Duration `json:"retain_for,omitempty"`
	// Detail is for a human reading a manifest years later.
	Detail string `json:"detail,omitempty"`
	// Kind names the store, e.g. "file", "s3".
	Kind string `json:"kind,omitempty"`
}

// ImmutabilityReporter is an optional interface a Store may implement.
//
// Optional rather than part of Store, so a backend written before this existed keeps
// compiling — and so the answer for such a backend is ModeUnknown, which is treated
// as mutable. Silence is not a guarantee.
type ImmutabilityReporter interface {
	Immutability(ctx context.Context) (Immutability, error)
}

// immutabilityOf asks a store, defaulting to unknown.
func immutabilityOf(ctx context.Context, s Store) Immutability {
	r, ok := s.(ImmutabilityReporter)
	if !ok {
		return Immutability{Mode: ModeUnknown,
			Detail: "the store does not report an immutability guarantee"}
	}
	im, err := r.Immutability(ctx)
	if err != nil {
		return Immutability{Mode: ModeUnknown, Detail: "could not read: " + err.Error()}
	}
	if im.Mode == "" {
		im.Mode = ModeUnknown
	}
	return im
}

// ── the file store ──────────────────────────────────────────────────────────────

// FileStore writes recordings to a directory:
//
//	<Dir>/2026-08-21/sess_01J8Z….cast    the asciicast v3 stream
//	<Dir>/2026-08-21/sess_01J8Z….json    the signed manifest
//
// # On WORM
//
// A local directory is not tamper-proof and this store does not pretend to be:
// anyone who can write the .cast can write the sidecar too. What the signature buys
// is that they cannot produce a *valid* sidecar without the signing key — so keep
// that key somewhere the recording store cannot reach. Storage that can enforce
// immutability is where WORM actually lives; see the object-store backends and
// E9.S4.
type FileStore struct {
	Dir string
	Now func() time.Time

	// Declared lets an operator record that the directory is protected by something
	// this process cannot see: an append-only attribute, a snapshotting filesystem,
	// a WORM appliance behind NFS.
	//
	// Setting it does not make it true, and the manifest says so — it is recorded as
	// `declared`, never as a lock. The value of writing it down is that an auditor
	// reading the recording years later sees what was claimed at the time, rather
	// than having to guess.
	Declared     bool
	DeclaredWhat string
	DeclaredFor  time.Duration
}

var _ Store = (*FileStore)(nil)

// NewFileStore creates Dir.
func NewFileStore(dir string) (*FileStore, error) {
	if dir == "" {
		return nil, errors.New("record: Dir is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("record: creating %s: %w", dir, err)
	}
	return &FileStore{Dir: dir}, nil
}

func (s *FileStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *FileStore) dayDir(m *plugin.SessionMeta) string {
	at := m.StartedAt
	if at.IsZero() {
		at = s.now()
	}
	return filepath.Join(s.Dir, at.UTC().Format("2006-01-02"))
}

// Create opens the .cast file.
func (s *FileStore) Create(_ context.Context, m *plugin.SessionMeta) (io.WriteCloser, error) {
	if err := safeID(m.SessionID); err != nil {
		return nil, err
	}
	dir := s.dayDir(m)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("record: creating %s: %w", dir, err)
	}
	path := filepath.Join(dir, m.SessionID+".cast")
	// O_EXCL: two writers for one session id would interleave into a file that
	// verifies as neither.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("record: opening %s: %w", path, err)
	}
	return &syncCloser{f: f}, nil
}

// PutManifest writes the sidecar whole and then renames it, so a reader never sees
// half a manifest and a crash mid-write leaves nothing rather than something
// unparseable.
func (s *FileStore) PutManifest(_ context.Context, sessionID string, b []byte) error {
	if err := safeID(sessionID); err != nil {
		return err
	}
	path, err := s.find(sessionID, ".cast")
	if err != nil {
		return err
	}
	target := path[:len(path)-len(".cast")] + ".json"
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("record: writing the manifest: %w", err)
	}
	return os.Rename(tmp, target)
}

func (s *FileStore) Get(_ context.Context, sessionID string) (io.ReadCloser, error) {
	p, err := s.find(sessionID, ".cast")
	if err != nil {
		return nil, err
	}
	return os.Open(p)
}

func (s *FileStore) GetManifest(_ context.Context, sessionID string) ([]byte, error) {
	p, err := s.find(sessionID, ".json")
	if err != nil {
		return nil, err
	}
	return os.ReadFile(p)
}

// URL is not supported: a local directory has no shareable link, and inventing one
// would mean streaming through the gateway while pretending not to.
func (s *FileStore) URL(context.Context, string, time.Duration) (string, error) {
	return "", plugin.ErrUnsupported
}

// Immutability reports what a directory can promise, which is nothing by itself.
func (s *FileStore) Immutability(context.Context) (Immutability, error) {
	if s.Declared {
		what := s.DeclaredWhat
		if what == "" {
			what = "operator-declared protection, unverified by the gateway"
		}
		return Immutability{Mode: ModeDeclared, Kind: "file",
			RetainFor: s.DeclaredFor, Detail: what}, nil
	}
	return Immutability{Mode: ModeMutable, Kind: "file",
		Detail: "a local directory: anything with write access can alter or delete " +
			"a recording, and the signature is the only thing that makes it detectable"}, nil
}

func (s *FileStore) find(sessionID, ext string) (string, error) {
	if err := safeID(sessionID); err != nil {
		return "", err
	}
	matches, err := filepath.Glob(filepath.Join(s.Dir, "*", sessionID+ext))
	if err != nil {
		return "", err
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("%w: %s%s", ErrNotFound, sessionID, ext)
	}
	return matches[0], nil
}

// safeID checks an id before it reaches the filesystem. The id format is already
// constrained upstream; this is the second line, at the boundary where it matters.
func safeID(id string) error {
	if id == "" || filepath.Base(id) != id || id == "." || id == ".." {
		return fmt.Errorf("record: unsafe session id %q", id)
	}
	return nil
}

// syncCloser fsyncs before closing. A recording is evidence, and "it was in the
// page cache when the box lost power" is not a story anybody wants to tell about
// evidence.
type syncCloser struct{ f *os.File }

func (s *syncCloser) Write(b []byte) (int, error) { return s.f.Write(b) }
func (s *syncCloser) Close() error {
	return errors.Join(s.f.Sync(), s.f.Close())
}
