package agent

// The `log` profile: tailing a source the device published.
//
// # Why a name and not a path
//
// The gateway asks for `messages`. This file decides that means `/var/log/messages`, and
// on Android something else entirely. The gateway never names a file.
//
// That is the same bargain `exec` and `tcp` make, for the same reason: the gateway
// authorises the *action*, and the device decides what is actually reachable. A gateway
// that could name a path would have an arbitrary-file-read on every device in the fleet.
// `file` accepts exactly that risk on purpose — confined to a configured root, authorised
// per path, because a file transfer is not useful otherwise — and a log tail has no reason
// to.
//
// It also means a mixed fleet answers one question. "May this operator read the agent log"
// is a policy somebody can write; "may they read /var/log/oarlock-agent.log on Linux and
// `logcat -b main` on Android and /data/local/tmp/agent.log on the old build" is a policy
// nobody maintains.
//
// # Why dropping is the right backpressure here
//
// A log tail is the one profile where dropping bytes is *better* than blocking. A shell
// that dropped output leaves a corrupt screen; a log reader that falls behind wants to be
// told it fell behind and shown current lines. internal/pump already applies Drop to this
// profile and announces it with a THROTTLE frame naming the byte count.
//
// The consequence for this file is that it must not buffer to keep up. It reads and writes
// and lets the pump decide what to discard.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/oarlock/oarlock/pkg/frame"
)

// DefaultLogLines is how much history a log session sends before following.
//
// Two hundred, which is a screen or three: enough to see what just happened without
// waiting for a megabyte of last Tuesday to scroll past. A caller who wants the file wants
// the `file` profile.
const DefaultLogLines = 200

// DefaultLogPollInterval is how often a followed file is checked for new bytes.
//
// Polling rather than inotify/FSEvents, deliberately. The agent runs on Android, on
// glibc, on musl, and inside containers where the watch descriptor limit is somebody
// else's, and a log tail is not worth a platform-specific code path per target. A second
// of latency on a log line is not the thing anybody is debugging.
const DefaultLogPollInterval = time.Second

// MaxLogLineBytes bounds one line.
//
// A log with no newline in it is a file, and reading it as a "line" would mean buffering
// the whole thing in the agent — on a device chosen for being cheap. Longer lines are
// split, which is visible and harmless, rather than refused or buffered.
const MaxLogLineBytes = 64 << 10

// ErrNoSuchSource is returned for a name the device does not publish.
var ErrNoSuchSource = errors.New("agent: no such log source on this device")

// LogRequest is what the gateway asked for.
type LogRequest struct {
	SessionID string
	Principal string // for the agent's own log only; never an authorisation input
	// Source is the logical name, from the set this device published. Untrusted: it is
	// whatever arrived on the wire, and Logs looks it up rather than resolving it.
	Source string
	// Follow keeps streaming after the history is sent.
	Follow bool
	// Lines is how much history to send. Zero means DefaultLogLines; negative means none.
	Lines int
}

// LogFunc streams one log source to w until ctx ends or the source does.
//
// A hook for the same reason Shell and Exec are hooks: "the log" is platform-specific.
// Logs covers the case where sources are files; an Android build hands in its own to read
// logcat, and neither has to know about the other.
type LogFunc func(ctx context.Context, r LogRequest, w io.Writer) error

// LogOption configures Logs.
type LogOption func(*logOptions)

type logOptions struct {
	lines int
	poll  time.Duration
}

// LogLines sets the default history size.
func LogLines(n int) LogOption {
	return func(o *logOptions) {
		if n != 0 {
			o.lines = n
		}
	}
}

// LogPollInterval sets how often a followed file is re-checked.
func LogPollInterval(d time.Duration) LogOption {
	return func(o *logOptions) {
		if d > 0 {
			o.poll = d
		}
	}
}

// Logs builds a LogFunc over a fixed map of logical name to file path.
//
// The map *is* the allow-list, and it is the device's. A name that is not in it is refused
// with ErrNoSuchSource — the same refusal for a name that does not exist and one that
// exists and is not published, so a gateway cannot use this to discover what is on the
// disk.
//
// Returns nil for an empty map, which is how a build says it has no logs worth exposing:
// leave "log" out of Caps too, and the gateway refuses such a session at open time rather
// than after a round trip.
func Logs(sources map[string]string, opts ...LogOption) LogFunc {
	o := logOptions{lines: DefaultLogLines, poll: DefaultLogPollInterval}
	for _, apply := range opts {
		apply(&o)
	}

	// Copied, so a caller mutating their map afterwards does not change what this device
	// will serve. The allow-list is fixed at construction on purpose.
	list := make(map[string]string, len(sources))
	for name, path := range sources {
		if name == "" || path == "" {
			continue
		}
		list[name] = path
	}
	if len(list) == 0 {
		return nil
	}

	return func(ctx context.Context, r LogRequest, w io.Writer) error {
		path, ok := list[r.Source]
		if !ok {
			// Deliberately the same error whatever the reason. Distinguishing "no such
			// source" from "not published" would let a gateway enumerate the device's
			// filesystem one name at a time.
			return fmt.Errorf("%w: %q", ErrNoSuchSource, r.Source)
		}
		lines := r.Lines
		if lines == 0 {
			lines = o.lines
		}
		return tail(ctx, path, w, lines, r.Follow, o.poll)
	}
}

// LogSources returns the published names, sorted. For a build that wants to log what it
// offers at startup, and for tests.
func LogSources(sources map[string]string) []string {
	out := make([]string, 0, len(sources))
	for name := range sources {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// tail writes the last `lines` lines of path to w, then follows if asked.
func tail(ctx context.Context, path string, w io.Writer, lines int,
	follow bool, poll time.Duration) error {

	f, err := os.Open(path)
	if err != nil {
		// The path came from this device's own configuration, so naming it is not a leak
		// — and an operator who asked for `messages` and got a refusal needs to know
		// whether the source is missing or unreadable.
		return fmt.Errorf("agent: opening the log source: %w", err)
	}
	defer f.Close()

	offset, err := writeHistory(f, w, lines)
	if err != nil {
		return err
	}
	if !follow {
		return nil
	}
	return followFrom(ctx, f, w, offset, poll)
}

// writeHistory sends the last `lines` lines and returns the offset to follow from.
//
// It reads the whole file to find the line boundaries, which is the honest tradeoff for
// not depending on a platform: a device's log is rotated and small, and the alternative —
// seeking backwards in fixed blocks — is a page of index arithmetic to save a read on a
// file that is usually a few hundred kilobytes. If that stops being true, the fix is
// rotation on the device rather than cleverness here.
func writeHistory(f *os.File, w io.Writer, lines int) (int64, error) {
	if lines < 0 {
		// Only what happens next. Seek to the end without reading anything.
		return f.Seek(0, io.SeekEnd)
	}

	// A ring of the last `lines` lines, so memory is bounded by the request rather than
	// by the file.
	ring := make([]string, 0, min(lines, 4096))
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), MaxLogLineBytes)
	for sc.Scan() {
		if len(ring) == cap(ring) && cap(ring) > 0 {
			copy(ring, ring[1:])
			ring = ring[:len(ring)-1]
		}
		ring = append(ring, sc.Text())
	}
	if err := sc.Err(); err != nil {
		// A line longer than MaxLogLineBytes lands here. Say so rather than sending a
		// silently truncated history.
		return 0, fmt.Errorf("agent: reading the log source: %w", err)
	}
	for _, line := range ring {
		if _, err := io.WriteString(w, line+"\n"); err != nil {
			return 0, err
		}
	}
	return f.Seek(0, io.SeekEnd)
}

// followFrom streams bytes appended after offset.
//
// It handles truncation — a rotated log is the normal case, not an edge one — by noticing
// the file got shorter and starting again from the beginning of whatever is there now.
// Continuing to read at the old offset would produce silence until the file grew past it,
// which looks exactly like a device that has stopped logging.
func followFrom(ctx context.Context, f *os.File, w io.Writer,
	offset int64, poll time.Duration) error {

	buf := make([]byte, 32<<10)
	t := time.NewTicker(poll)
	defer t.Stop()

	for {
		info, err := f.Stat()
		if err != nil {
			return fmt.Errorf("agent: watching the log source: %w", err)
		}
		if info.Size() < offset {
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				return err
			}
			offset = 0
			if _, err := io.WriteString(w, "--- log rotated ---\n"); err != nil {
				return err
			}
		}
		for {
			n, rerr := f.Read(buf)
			if n > 0 {
				offset += int64(n)
				if _, werr := w.Write(buf[:n]); werr != nil {
					return werr
				}
			}
			if rerr == io.EOF || n == 0 {
				break
			}
			if rerr != nil {
				return fmt.Errorf("agent: reading the log source: %w", rerr)
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// runLog streams a log source to the gateway.
func (s *session) runLog(ctx context.Context, logf LogFunc, inv frame.Invitation) error {
	if logf == nil {
		err := errors.New("agent: no Tail configured, but a log was requested")
		_ = s.send(ctx, frame.TypeError, frame.Error{
			Code: "profile_unsupported", Message: err.Error()})
		return err
	}
	if inv.Log == nil || strings.TrimSpace(inv.Log.Name) == "" {
		err := errors.New("agent: the invitation names no log source")
		_ = s.send(ctx, frame.TypeError, frame.Error{
			Code: "protocol_error", Message: err.Error()})
		return err
	}

	req := LogRequest{
		SessionID: inv.SessionID, Principal: inv.Principal,
		Source: inv.Log.Name, Follow: inv.Log.Follow, Lines: inv.Log.Lines,
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// The gateway's side is watched for a CLOSE while the log streams. Without it a
	// followed log would keep reading until the socket broke, and an operator pressing
	// Ctrl-C would wait for the next line before anything noticed.
	go func() {
		s.drainUntilClose(ctx)
		cancel()
	}()

	err := logf(ctx, req, logWriter{s: s, ctx: ctx})
	if err != nil && ctx.Err() == nil {
		_ = s.send(ctx, frame.TypeError, frame.Error{
			Code: logErrorCode(err), Message: err.Error()})
		return err
	}
	_ = s.send(ctx, frame.TypeClose, frame.Close{Reason: "device_close"})
	return nil
}

func logErrorCode(err error) string {
	if errors.Is(err, ErrNoSuchSource) {
		// The device published a set and this was not in it. `profile_unsupported` is
		// the closest honest code: this build cannot serve that request.
		return "profile_unsupported"
	}
	return "internal"
}

// logWriter sends what the tailer produces as DATA frames.
//
// No buffering of its own: the pump's policy for this profile is to drop, and a buffer
// here would defeat that by holding bytes the gateway had decided not to carry.
type logWriter struct {
	s   *session
	ctx context.Context
}

func (w logWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	if err := w.s.sendFrame(w.ctx, frame.Data(p)); err != nil {
		return 0, err
	}
	return len(p), nil
}

// drainUntilClose reads the gateway's side and returns when it says the session is over.
//
// A log session has no input: nothing an operator types goes anywhere. This exists to
// notice CLOSE promptly, and to count anything else rather than let it vanish — a client
// sending DATA on a log session is either old or probing.
func (s *session) drainUntilClose(ctx context.Context) {
	for {
		msg, err := s.conn.Recv(ctx)
		if err != nil {
			return
		}
		f, derr := s.codec.Decode(msg)
		if derr != nil {
			continue
		}
		switch f.Type {
		case frame.TypeClose:
			return
		case frame.TypePing:
			if stamp, serr := frame.ReadStamp(f); serr == nil {
				pong, _ := frame.Stamp(frame.TypePong, stamp)
				_ = s.sendFrame(ctx, pong)
			}
		case frame.TypeData, frame.TypeResize, frame.TypeSignal:
			s.log.Warn("discarded input on a log session", "type", f.Type)
		}
	}
}
