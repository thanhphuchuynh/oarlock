package agent

// The `file` profile: read and write under one configured root.
//
// It exists so that pulling a log off a device does not need a shell. On a machine in
// somebody's home that is most of what support actually wants, and `cat` in a shell is a
// much larger grant than "read one path under /data/vendor/app/logs".
//
// # Confinement is delegated, deliberately
//
// Every hand-rolled version of this check has the same bug list: `..` after cleaning,
// an absolute path that bypasses the join, a symlink whose target is outside the root, and
// the time-of-check-to-time-of-use race where the symlink is swapped between the check and
// the open. The last one cannot be fixed by inspecting a string at all.
//
// So the string is not inspected. `os.Root` opens each component with openat and
// O_NOFOLLOW-equivalent semantics, so a path that leaves the root fails in the kernel
// rather than passing a test here — and there is no window between the check and the use,
// because they are the same syscall. What this file adds on top is the parts os.Root has
// no opinion about: refusing anything that is not a regular file, bounding the size, and
// committing a write atomically.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/oarlock/oarlock/pkg/frame"
)

// DefaultMaxFileBytes bounds one transfer in either direction.
//
// The `file` profile is for configuration and logs, not for images: a caller that wants to
// move a gigabyte wants a different tool, and an unbounded transfer is an unbounded amount
// of somebody's disk or memory.
const DefaultMaxFileBytes int64 = 64 << 20

var (
	// ErrOutsideRoot means the path left the configured root, however it tried to.
	ErrOutsideRoot = errors.New("agent: that path is outside this device's file root")
	// ErrNotRegular means the path names something that is not a regular file.
	ErrNotRegular = errors.New("agent: that path is not a regular file")
	// ErrTooLarge means the transfer exceeds the configured ceiling.
	ErrTooLarge = errors.New("agent: that file is larger than this device allows")
)

// FileRequest is one file operation, as the gateway asked for it.
type FileRequest struct {
	SessionID string
	Principal string // for the agent's own log only; never an authorisation input
	// Op is "read" or "write".
	Op string
	// Path is relative to the device's root, as the operator wrote it. Untrusted.
	Path string
	// Size is the exact byte count for a write.
	Size int64
	// Mode is the permission bits for a created file. Zero means 0o600.
	Mode uint32
}

// FileFunc performs one file operation.
//
// A hook like ShellFunc and ExecFunc, because a root is a deployment's choice and some
// platforms have no filesystem worth exposing. Nil means this build does not offer `file`,
// and then "file" should be left out of Caps so the gateway refuses at open time rather
// than after a round trip.
//
// For a read, the implementation writes the file's bytes to w. For a write, it reads
// exactly Size bytes from r. Returning an error means nothing was committed.
type FileFunc func(ctx context.Context, req FileRequest, w io.Writer, r io.Reader) error

// FileOption configures File.
type FileOption func(*fileOptions)

type fileOptions struct {
	maxBytes int64
	writable bool
	timeout  time.Duration
}

// FileMaxBytes bounds one transfer.
func FileMaxBytes(n int64) FileOption {
	return func(o *fileOptions) {
		if n > 0 {
			o.maxBytes = n
		}
	}
}

// FileWritable allows writes. Off by default: a device that only ever needs its logs read
// should not accept writes because nobody said it should not.
func FileWritable() FileOption { return func(o *fileOptions) { o.writable = true } }

// FileTimeout bounds one transfer.
func FileTimeout(d time.Duration) FileOption {
	return func(o *fileOptions) {
		if d > 0 {
			o.timeout = d
		}
	}
}

// File builds a FileFunc confined to root.
//
// There is no per-session identity here, unlike shell and exec. Those fork a process and
// can drop privileges into it; a file read happens in the agent's own process as the
// agent's own user, and there is nothing to drop into. So the root's own permissions are
// the only boundary below os.Root's — which is a reason to point it at a directory that
// holds only what support should see, rather than at `/`.
//
// The root is opened once, here, and held. That matters: a *os.Root is a file descriptor
// on the directory, so the confinement survives the directory being renamed or replaced
// underneath — a path-string check would silently start resolving somewhere else.
func File(root string, opts ...FileOption) (FileFunc, error) {
	o := fileOptions{maxBytes: DefaultMaxFileBytes, timeout: 5 * time.Minute}
	for _, apply := range opts {
		apply(&o)
	}
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("agent: the file profile needs a root directory")
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("agent: opening the file root %s: %w", root, err)
	}
	return func(ctx context.Context, req FileRequest, w io.Writer, rd io.Reader) error {
		ctx, cancel := context.WithTimeout(ctx, o.timeout)
		defer cancel()

		name, err := cleanRelative(req.Path)
		if err != nil {
			return err
		}
		switch req.Op {
		case "read":
			return readFile(ctx, r, name, w, o.maxBytes)
		case "write":
			if !o.writable {
				return fmt.Errorf("agent: this device's file root is read-only")
			}
			return writeFile(ctx, r, name, rd, req.Size, req.Mode, o.maxBytes)
		default:
			return fmt.Errorf("agent: unknown file operation %q", req.Op)
		}
	}, nil
}

// cleanRelative rejects the shapes os.Root would reject anyway, so the *reason* is
// legible.
//
// os.Root refuses an absolute path and a path that escapes, but its error says "invalid
// argument" or "path escapes from parent" — which sends an operator looking at the file
// rather than at what they typed. This is about the message, not the security: the
// confinement below does not depend on anything decided here.
func cleanRelative(p string) (string, error) {
	if p == "" {
		return "", errors.New("agent: no path")
	}
	// A NUL is not a path component on any system this runs on, and a filesystem call
	// given one fails in a way that is hard to read.
	if strings.ContainsRune(p, 0) {
		return "", errors.New("agent: that path contains a NUL byte")
	}
	// Backslashes are separators on Windows and ordinary characters on Unix, so a path
	// containing one means different things on the two platforms. Refused rather than
	// interpreted: an agent should not be the thing that guesses.
	if strings.ContainsRune(p, '\\') {
		return "", fmt.Errorf("%w: %q contains a backslash", ErrOutsideRoot, p)
	}
	if path.IsAbs(p) || strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("%w: %q is absolute", ErrOutsideRoot, p)
	}
	cleaned := path.Clean(p)
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("%w: %q climbs out of it", ErrOutsideRoot, p)
	}
	if cleaned == "." {
		return "", fmt.Errorf("%w: %q names the root itself, not a file", ErrNotRegular, p)
	}
	return cleaned, nil
}

func readFile(ctx context.Context, root *os.Root, name string, w io.Writer, max int64) error {
	// O_NONBLOCK, because the "is this a regular file" check happens *after* the open and
	// opening some things blocks. A FIFO opened for reading waits for a writer that may
	// never come, so a named pipe anywhere under the root was a way to hang a session
	// until its timeout — the refusal was correct and arrived far too late. On a regular
	// file the flag changes nothing.
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return translate(name, err)
	}
	defer f.Close()

	// Checked on the *open descriptor*, not on the path: a Stat by name and an Open by
	// name are two resolutions, and between them the name can point at something else.
	info, err := f.Stat()
	if err != nil {
		return translate(name, err)
	}
	if !info.Mode().IsRegular() {
		// A directory, a device node, a fifo. Reading /dev/zero here would be an
		// unbounded transfer, and reading a fifo would block until something wrote.
		return fmt.Errorf("%w: %s is %s", ErrNotRegular, name, describe(info.Mode()))
	}
	if info.Size() > max {
		return fmt.Errorf("%w: %s is %d bytes, the limit is %d",
			ErrTooLarge, name, info.Size(), max)
	}

	// One byte over the limit is still an error rather than a silent truncation: a file
	// that grew between the Stat and the read is a file whose transfer is incomplete.
	n, err := io.Copy(w, io.LimitReader(&ctxReader{ctx: ctx, r: f}, max+1))
	if err != nil {
		return fmt.Errorf("agent: reading %s: %w", name, err)
	}
	if n > max {
		return fmt.Errorf("%w: %s grew past %d bytes while being read", ErrTooLarge, name, max)
	}
	return nil
}

func writeFile(ctx context.Context, root *os.Root, name string, r io.Reader,
	size int64, mode uint32, max int64) error {

	if size < 0 {
		return errors.New("agent: a negative size")
	}
	if size > max {
		return fmt.Errorf("%w: %d bytes, the limit is %d", ErrTooLarge, size, max)
	}
	perm := fs.FileMode(0o600)
	if mode != 0 {
		// Masked to permission bits: setuid and sticky arriving over the wire is not a
		// thing this profile grants, whatever a caller sends.
		perm = fs.FileMode(mode) & fs.ModePerm
	}

	// A temporary in the same directory, renamed on success.
	//
	// A direct write leaves a truncated file behind when a transfer is interrupted — and
	// for the thing this profile is mostly used on, a configuration file, a half-written
	// version is worse than the old one. The rename is atomic on the same filesystem,
	// and staying inside the root keeps it on one.
	tmp := name + ".oarlock-partial"
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_TRUNC, perm)
	if err != nil {
		return translate(tmp, err)
	}
	committed := false
	defer func() {
		f.Close()
		if !committed {
			// Best effort: a leftover partial is untidy, but failing to remove it must
			// not turn a failed write into a different error.
			_ = root.Remove(tmp)
		}
	}()

	n, err := io.Copy(f, io.LimitReader(&ctxReader{ctx: ctx, r: r}, size))
	if err != nil {
		return fmt.Errorf("agent: writing %s: %w", name, err)
	}
	if n != size {
		// Fewer bytes than promised means the operator's side stopped early. Committing
		// would publish a truncated file that looks complete.
		return fmt.Errorf("agent: %s: got %d of %d bytes, not committing", name, n, size)
	}
	// Durable before visible. Renaming an unsynced file over a good one is how a power
	// cut leaves neither.
	if err := f.Sync(); err != nil {
		return fmt.Errorf("agent: syncing %s: %w", name, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("agent: closing %s: %w", name, err)
	}
	if err := root.Rename(tmp, name); err != nil {
		return translate(name, err)
	}
	committed = true
	return nil
}

// translate turns a filesystem error into one an operator can act on.
func translate(name string, err error) error {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("agent: %s does not exist", name)
	case errors.Is(err, os.ErrPermission):
		return fmt.Errorf("agent: %s: the agent's own user cannot reach it", name)
	case errors.Is(err, os.ErrExist):
		return fmt.Errorf("agent: %s: a transfer is already in progress", name)
	default:
		// os.Root reports an escape as a path error; say what it means rather than
		// passing on "path escapes from parent of root".
		if strings.Contains(err.Error(), "escapes from parent") ||
			strings.Contains(err.Error(), "invalid argument") {
			return fmt.Errorf("%w: %s", ErrOutsideRoot, name)
		}
		return fmt.Errorf("agent: %s: %w", name, err)
	}
}

func describe(m fs.FileMode) string {
	switch {
	case m.IsDir():
		return "a directory"
	case m&fs.ModeSymlink != 0:
		return "a symbolic link"
	case m&fs.ModeDevice != 0:
		return "a device"
	case m&fs.ModeNamedPipe != 0:
		return "a named pipe"
	case m&fs.ModeSocket != 0:
		return "a socket"
	default:
		return "not a regular file"
	}
}

// ctxReader makes a blocking read abandonable, so a transfer honours its timeout.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// runFile streams one file operation over a session connection.
func (s *session) runFile(ctx context.Context, run FileFunc, inv frame.Invitation) error {
	if run == nil {
		err := errors.New("agent: no File configured, but a file session was requested")
		_ = s.send(ctx, frame.TypeError, frame.Error{
			Code: "profile_unsupported", Message: err.Error()})
		return err
	}
	if inv.File == nil {
		err := errors.New("agent: a file session carried no operation")
		_ = s.send(ctx, frame.TypeError, frame.Error{
			Code: "protocol_error", Message: err.Error()})
		return err
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// The gateway-reading goroutine exists only for a write.
	//
	// Starting it for a read was a bug worth naming: a read carries Size 0, so the
	// "forward exactly Size bytes" loop finished immediately, cancelled the context, and
	// the read was abandoned before it opened anything. A read has no operator input at
	// all — the bytes travel the other way — so there is nothing to consume.
	var reader io.Reader = strings.NewReader("")
	if inv.File.Op == "write" {
		pr, pw := io.Pipe()
		reader = pr
		defer pr.Close()
		go func() {
			err := s.fileFromGateway(runCtx, pw, inv.File.Size)
			_ = pw.CloseWithError(err)
			// Only a *failure* ends the session early. A completed transfer must leave
			// the context alive: the device still has to write, sync, rename and answer.
			if !errors.Is(err, io.EOF) {
				cancel()
			}
		}()
	}

	err := run(runCtx,
		FileRequest{
			SessionID: inv.SessionID, Principal: inv.Principal,
			Op: inv.File.Op, Path: inv.File.Path,
			Size: inv.File.Size, Mode: inv.File.Mode,
		},
		&frameWriter{s: s, ctx: runCtx, kind: frame.TypeData},
		reader)

	// Sent before the reader is stopped, for the reason exec learned the hard way:
	// cancelling a context a websocket read is blocked on closes the connection, so an
	// answer written afterwards goes nowhere.
	if err != nil {
		code := "internal"
		if errors.Is(err, ErrOutsideRoot) || errors.Is(err, ErrNotRegular) {
			code = "not_authorized"
		}
		_ = s.send(ctx, frame.TypeError, frame.Error{Code: code, Message: err.Error()})
	} else {
		_ = s.send(ctx, frame.TypeExit, frame.Exit{Code: 0})
	}
	_ = s.send(ctx, frame.TypeClose, frame.Close{Reason: "device_close"})
	cancel()
	return err
}

// fileFromGateway forwards exactly want bytes of DATA into the pipe.
func (s *session) fileFromGateway(ctx context.Context, pw *io.PipeWriter, want int64) error {
	var got int64
	for got < want {
		msg, err := s.conn.Recv(ctx)
		if err != nil {
			return err
		}
		f, err := s.codec.Decode(msg)
		if err != nil {
			return err
		}
		if frame.Expect(frame.ScopeSession, f) != nil {
			return errors.New("agent: an out-of-scope frame on a file session")
		}
		switch f.Type {
		case frame.TypeData:
			if _, err := pw.Write(f.Payload); err != nil {
				return err
			}
			got += int64(len(f.Payload))
		case frame.TypeClose:
			// The operator stopped early. Returning an error rather than EOF is what
			// makes the write refuse to commit: a short transfer must not become a
			// truncated file that looks whole.
			return fmt.Errorf("agent: the session closed after %d of %d bytes", got, want)
		}
	}
	return io.EOF
}
