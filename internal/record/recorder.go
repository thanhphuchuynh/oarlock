package record

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/oarlock/oarlock/pkg/plugin"
)

// Options configure a Recorder.
type Options struct {
	// Store is where bytes land. Required.
	Store Store
	// Signer signs manifests. Required: an unsigned manifest is a hash chain anyone
	// with write access can recompute, which is not integrity.
	Signer Signer
	// Spool configures the tolerance band between the encoder and the store. The
	// zero value uses the defaults, which is what almost everyone wants.
	Spool SpoolConfig
	Log   *slog.Logger
}

// Recorder composes the asciicast encoder, the hash chain, the spool and a store.
//
// The layering matters and is worth stating: the encoder and the chain are ours, the
// spool sits below them so a retry never re-encodes anything, and only the last hop
// is pluggable. A backend answers one question — where do these bytes go — and
// cannot get asciicast subtly wrong.
type Recorder struct {
	o       Options
	log     *slog.Logger
	storage Immutability
}

var _ plugin.Recorder = (*Recorder)(nil)

// New validates the configuration.
func New(o Options) (*Recorder, error) {
	switch {
	case o.Store == nil:
		return nil, errors.New("record: Store is required")
	case o.Signer == nil:
		return nil, errors.New("record: Signer is required — an unsigned manifest " +
			"is a chain anyone with write access can recompute")
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Spool.Log == nil {
		o.Spool.Log = o.Log
	}
	r := &Recorder{o: o, log: o.Log}

	// Asked once, at construction, and reported once. Asking per session would be a
	// log line per shell saying the same thing, which is how a real warning becomes
	// something operators filter out.
	r.storage = immutabilityOf(context.Background(), o.Store)
	switch {
	case r.storage.Mode.Protected():
		o.Log.Info("recording store immutability",
			"mode", r.storage.Mode, "kind", r.storage.Kind,
			"retain_for", r.storage.RetainFor, "detail", r.storage.Detail)
	default:
		// Not fatal. A lab has no WORM storage and should still be able to record.
		// But the difference between "tampering is detectable" and "tampering is
		// impossible" is worth stating out loud, once, where somebody will see it.
		o.Log.Warn("recording store cannot enforce immutability — the hash chain "+
			"makes tampering detectable, not impossible. For storage that can, "+
			"configure object lock or retention; see docs/plugins.md § 4.2",
			"mode", r.storage.Mode, "kind", r.storage.Kind, "detail", r.storage.Detail)
	}
	return r, nil
}

// Immutability is what the store promised, for health output and the boot gate.
func (r *Recorder) Immutability() Immutability { return r.storage }

// NewFileRecorder is the zero-configuration recorder: a directory and a key.
//
// Spooling is on with the defaults, so a filesystem that briefly refuses writes —
// a full disk being cleaned up, an NFS hiccup — does not close sessions.
func NewFileRecorder(dir string, signer Signer) (*Recorder, error) {
	store, err := NewFileStore(dir)
	if err != nil {
		return nil, err
	}
	return New(Options{Store: store, Signer: signer})
}

// Open starts a recording. An error here fails the session, deliberately: a session
// that looks recorded and is not is worse than one that never opened.
func (r *Recorder) Open(ctx context.Context, m *plugin.SessionMeta) (plugin.RecordingWriter, error) {
	if m == nil || m.SessionID == "" {
		return nil, errors.New("record: SessionID is required")
	}
	sink, err := r.o.Store.Create(ctx, m)
	if err != nil {
		return nil, fmt.Errorf("record: opening the store: %w", err)
	}

	sp := newSpool(sink, m.SessionID, r.o.Spool)
	w, err := NewWriter(WriterOptions{
		Out:     sp,
		Meta:    m,
		Signer:  r.o.Signer,
		Storage: r.storage,
		OnClose: func(ctx context.Context, man Manifest) error {
			b, err := EncodeManifest(man)
			if err != nil {
				return err
			}
			return r.o.Store.PutManifest(ctx, man.SessionID, b)
		},
	})
	if err != nil {
		_ = sp.Close()
		return nil, err
	}
	return w, nil
}

// Get streams a recording back.
func (r *Recorder) Get(ctx context.Context, sessionID string) (io.ReadCloser, error) {
	return r.o.Store.Get(ctx, sessionID)
}

// URL delegates to the store.
func (r *Recorder) URL(ctx context.Context, sessionID string, ttl time.Duration) (string, error) {
	return r.o.Store.URL(ctx, sessionID, ttl)
}

// Manifest reads a recording's sidecar.
func (r *Recorder) Manifest(ctx context.Context, sessionID string) (Manifest, error) {
	b, err := r.o.Store.GetManifest(ctx, sessionID)
	if err != nil {
		return Manifest{}, err
	}
	return DecodeManifest(b)
}

// RawManifest returns the manifest bytes as stored, undecoded.
//
// For serving a manifest to somebody who will verify it themselves. The signature is over
// a canonical re-encoding of the *struct* — signingBytes marshals it with the signature
// field cleared — so a decode/encode round trip through this build is safe. What is not
// safe is a round trip through a build whose decoder does not know a field a newer writer
// added: that field is dropped, the canonical form changes, and a perfectly good recording
// stops verifying. Handing over the stored bytes removes this gateway from that risk
// entirely, and leaves it where it belongs — with the verifier, who has to understand the
// manifest they are verifying.
func (r *Recorder) RawManifest(ctx context.Context, sessionID string) ([]byte, error) {
	return r.o.Store.GetManifest(ctx, sessionID)
}

// Verify reads both halves and checks them.
//
// This is what `oarlockctl verify` runs (E6.S4) and what replay calls before handing
// a recording to anyone (E3.S6). An integrity guarantee nobody verifies is
// decoration.
func (r *Recorder) Verify(ctx context.Context, sessionID string, pub ed25519.PublicKey) (Verdict, error) {
	m, err := r.Manifest(ctx, sessionID)
	if err != nil {
		return Verdict{}, err
	}
	cast, err := r.Get(ctx, sessionID)
	if err != nil {
		return Verdict{}, err
	}
	defer cast.Close()
	return Verify(cast, m, pub)
}
