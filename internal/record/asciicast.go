package record

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/oarlock/oarlock/pkg/plugin"
)

// Version is the asciicast version written.
//
// v3 rather than v2, and the reason is not novelty: v3 encodes each event as an
// *interval* since the previous one instead of an absolute offset from the start.
// That is what lets a spooling recorder reconnect mid-session and carry on writing
// without rewriting anything it already flushed — which v2's absolute timestamps
// would require. It is not backward compatible with v2, so a reader has to be told.
const Version = 3

// Event codes from the v3 specification.
const (
	codeOutput = "o"
	codeInput  = "i"
	codeResize = "r"
	codeExit   = "x"
	codeMarker = "m"
)

// header is the first line of a .cast file.
type header struct {
	Version   int               `json:"version"`
	Term      headerTerm        `json:"term"`
	Timestamp int64             `json:"timestamp,omitempty"`
	Command   string            `json:"command,omitempty"`
	Title     string            `json:"title,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	Tags      []string          `json:"tags,omitempty"`
}

type headerTerm struct {
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
	Type string `json:"type,omitempty"`
}

// Writer streams one recording.
//
// Streamed and flushed as it goes, never buffered to the end: a gateway killed
// mid-session must still leave a playable file, and an asciicast truncated at any
// line boundary plays perfectly up to that point. That property is worth more than
// a tidy footer.
type Writer struct {
	meta    *plugin.SessionMeta
	storage Immutability

	mu sync.Mutex
	// w is written to directly, with no buffering of our own.
	//
	// There used to be a bufio.Writer here and it was a bug: the spool below is
	// already a buffer, so a second one created a limbo where an event's bytes had
	// been accepted by the encoder — and counted into the hash chain — but had not
	// reached the spool. When the spool went fatal those bytes were lost, and the
	// manifest then claimed one more event than the file contained. Off by exactly
	// one, only under failure, which is the worst kind of wrong.
	w       io.Writer
	closer  io.Closer
	chain   *chain
	last    time.Duration
	closed  bool
	counts  Counts
	onClose func(ctx context.Context, m Manifest) error
	signer  Signer
	err     error
}

// Counts is what a manifest reports about the stream.
type Counts struct {
	Events      int   `json:"events"`
	OutputBytes int64 `json:"output_bytes"`
	InputBytes  int64 `json:"input_bytes"`
	Resizes     int   `json:"resizes"`
}

// WriterOptions configure a Writer.
type WriterOptions struct {
	// Out receives the .cast stream. Closed by Close if it is an io.Closer.
	Out io.Writer
	// Meta describes the session.
	Meta *plugin.SessionMeta
	// Signer signs the manifest. Required: an unsigned manifest is a hash chain
	// anyone with write access can recompute, which is not integrity.
	Signer Signer
	// Storage is what the store promised, recorded into the manifest.
	Storage Immutability
	// OnClose persists the manifest.
	OnClose func(ctx context.Context, m Manifest) error
}

var _ plugin.RecordingWriter = (*Writer)(nil)

// NewWriter writes the header and starts the chain.
func NewWriter(o WriterOptions) (*Writer, error) {
	switch {
	case o.Out == nil:
		return nil, errors.New("record: Out is required")
	case o.Meta == nil:
		return nil, errors.New("record: Meta is required")
	case o.Signer == nil:
		return nil, errors.New("record: Signer is required — an unsigned manifest " +
			"is a chain anyone with write access can recompute")
	}

	cols, rows := o.Meta.Cols, o.Meta.Rows
	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}
	h := header{
		Version: Version,
		Term:    headerTerm{Cols: cols, Rows: rows, Type: o.Meta.Term},
		Env:     map[string]string{},
	}
	if !o.Meta.StartedAt.IsZero() {
		h.Timestamp = o.Meta.StartedAt.Unix()
	}
	// Enough to identify the recording from the file alone, without the sidecar.
	// Not the principal: a .cast may travel further than the manifest, and the
	// name of the person recorded is not something to scatter.
	h.Title = fmt.Sprintf("oarlock %s on %s", o.Meta.Profile, o.Meta.DeviceID)

	line, err := json.Marshal(h)
	if err != nil {
		return nil, fmt.Errorf("record: encoding the header: %w", err)
	}

	w := &Writer{
		meta:    o.Meta,
		storage: o.Storage,
		w:       o.Out,
		chain:   newChain(line),
		signer:  o.Signer,
		onClose: o.OnClose,
	}
	if c, ok := o.Out.(io.Closer); ok {
		w.closer = c
	}
	if err := w.writeRaw(line); err != nil {
		return nil, err
	}
	// The chain's own parameters, so a verifier does not have to guess them.
	if err := w.writeRaw([]byte(chainHeaderComment)); err != nil {
		return nil, err
	}
	return w, nil
}

// Output records device→operator bytes.
func (w *Writer) Output(at time.Duration, b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return w.event(at, codeOutput, string(b), func() {
		w.counts.OutputBytes += int64(len(b))
	})
}

// Input records operator→device bytes.
//
// Only called when the policy resolved RecordInput true. Terminal echo is
// suppressed on the *device*, so these bytes include whatever was typed into a
// sudo prompt — a recording with input in it is a credential store and has to be
// handled as one.
func (w *Writer) Input(at time.Duration, b []byte) error {
	if len(b) == 0 {
		return nil
	}
	if !w.meta.RecordInput {
		return nil
	}
	return w.event(at, codeInput, string(b), func() {
		w.counts.InputBytes += int64(len(b))
	})
}

// Resize records a terminal size change, so replay reflows instead of rendering
// every line at the wrong width.
func (w *Writer) Resize(at time.Duration, cols, rows int) error {
	if cols <= 0 || rows <= 0 {
		return fmt.Errorf("record: bad size %dx%d", cols, rows)
	}
	return w.event(at, codeResize, fmt.Sprintf("%dx%d", cols, rows), func() {
		w.counts.Resizes++
	})
}

// Exit records the process's exit status.
func (w *Writer) Exit(at time.Duration, code int) error {
	return w.event(at, codeExit, fmt.Sprintf("%d", code), nil)
}

// Marker records a labelled point, for anything that wants to annotate a replay.
func (w *Writer) Marker(at time.Duration, label string) error {
	return w.event(at, codeMarker, label, nil)
}

func (w *Writer) event(at time.Duration, code, data string, count func()) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return errors.New("record: writer is closed")
	}
	if w.err != nil {
		return w.err
	}

	// Intervals, never absolute offsets. A clock that goes backwards — or an event
	// timestamped before the previous one — must not produce a negative interval,
	// which no player handles sensibly.
	interval := at - w.last
	if interval < 0 {
		interval = 0
	}
	w.last = at

	line, err := json.Marshal([]any{interval.Seconds(), code, data})
	if err != nil {
		return w.fail(fmt.Errorf("record: encoding an event: %w", err))
	}
	// Written before the chain is advanced. If the write fails the event is not in
	// the chain, so the manifest never claims an event the file does not contain.
	if err := w.writeRaw(line); err != nil {
		return err
	}
	w.chain.add(line)
	if count != nil {
		count()
	}
	w.counts.Events++

	if w.chain.events%CheckpointEvery == 0 {
		if err := w.writeRaw([]byte(w.chain.checkpoint())); err != nil {
			return err
		}
	}
	// No flush step: every event's bytes have already been handed to Out. A gateway
	// killed between two events leaves a file that plays up to the last one,
	// because there is nothing of ours still holding them.
	return nil
}

// writeRaw appends one line and its newline in a single write, so a line and its
// terminator cannot be split by a failure between them. Callers hold the lock.
func (w *Writer) writeRaw(line []byte) error {
	buf := make([]byte, 0, len(line)+1)
	buf = append(buf, line...)
	buf = append(buf, '\n')
	if _, err := w.w.Write(buf); err != nil {
		return w.fail(err)
	}
	return nil
}

func (w *Writer) fail(err error) error {
	if w.err == nil {
		w.err = err
	}
	return w.err
}

// Close writes a final checkpoint, signs the manifest, and finalises.
//
// It runs even when the session died badly — a recording of a session that ended
// abruptly is exactly the one somebody will want to read.
func (w *Writer) Close(ctx context.Context, r plugin.RecordingResult) error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true

	// A closing checkpoint, so the last partial block of events is covered by a
	// comment as well as by the signed head.
	writeErr := w.err
	if writeErr == nil {
		writeErr = w.writeRaw([]byte(w.chain.checkpoint()))
	}

	m := Manifest{
		Manifest:     ManifestVersion,
		SessionID:    w.meta.SessionID,
		DeviceID:     w.meta.DeviceID,
		Principal:    w.meta.Principal,
		OpenedBy:     w.meta.OpenedBy,
		Unattended:   w.meta.Unattended,
		Profile:      w.meta.Profile,
		Mode:         w.meta.Mode,
		Format:       fmt.Sprintf("asciicast-v%d", Version),
		RecordInput:  w.meta.RecordInput,
		StartedAt:    w.meta.StartedAt.UTC(),
		ClosedAt:     r.ClosedAt.UTC(),
		Duration:     w.last.Seconds(),
		CloseReason:  r.CloseReason,
		ExitCode:     r.ExitCode,
		BytesDropped: r.BytesDropped,
		Counts:       w.counts,
		Storage:      w.storage,
		Chain: ChainInfo{
			Alg:             ChainAlg,
			Domain:          ChainDomain,
			Head:            w.chain.head(),
			Events:          w.chain.events,
			CheckpointEvery: CheckpointEvery,
		},
	}
	if m.ClosedAt.IsZero() {
		m.ClosedAt = time.Now().UTC()
	}
	closer, onClose, signer := w.closer, w.onClose, w.signer
	w.mu.Unlock()

	if err := m.Sign(signer); err != nil {
		return errors.Join(writeErr, err)
	}
	var persistErr error
	if onClose != nil {
		persistErr = onClose(ctx, m)
	}
	var closeErr error
	if closer != nil {
		closeErr = closer.Close()
	}
	return errors.Join(writeErr, persistErr, closeErr)
}

// Manifest returns the manifest as it stands, unsigned. For tests and metrics.
func (w *Writer) ChainHead() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.chain.head()
}

// Counts returns a snapshot.
func (w *Writer) Counts() Counts {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.counts
}
