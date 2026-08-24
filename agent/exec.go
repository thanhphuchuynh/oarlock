package agent

// The `exec` profile: one allow-listed command, no shell.
//
// It exists so that automation — and most support work — does not need a shell. Nearly
// everything that reaches for `sh -c` wants a single command, and an allow-list of complete
// argvs is a far smaller thing to audit than a shell that can be handed anything.
//
// Three properties, and each one is a deliberate refusal:
//
//   - **No shell interpretation.** The argv goes to execve. There is no `sh -c`, so there
//     is no quoting to get wrong, no globbing, no `$(…)`, no `;` and no redirection.
//   - **The device holds the allow-list.** The gateway authorises the *action*; the device
//     decides what may actually run on it. Those are different questions and the second
//     one should not be answerable from the network.
//   - **Exact argvs.** An entry matches only if every element matches. See allowList for
//     why a "command plus whatever arguments" form was not chosen.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/oarlock/oarlock/pkg/frame"
)

// ExecRequest is what the gateway asked to run.
type ExecRequest struct {
	SessionID string
	Principal string // for the agent's own log only; never an authorisation input
	// Argv is the command, already split. It is never a shell string.
	Argv []string
}

// ExecResult is a finished command.
type ExecResult struct {
	// Code is the process exit status, or -1 if it was killed by a signal.
	Code int
}

// ExecFunc runs one command and streams its output.
//
// A hook, like ShellFunc, because "run a command" is platform-specific: which binaries
// exist, which user they run as, and whether the platform permits exec at all. A build
// that cannot provide one omits "exec" from its capabilities and the gateway refuses such
// a session at open time with a real reason.
//
// stdout and stderr are separate writers on purpose. Merging them is what a terminal does,
// and it is wrong here: a caller that has to grep an error out of the middle of the output
// it was collecting has been handed the shell problem back.
type ExecFunc func(ctx context.Context, r ExecRequest, stdout, stderr io.Writer) (ExecResult, error)

// ErrNotAllowed is returned for an argv that is not on the list.
var ErrNotAllowed = errors.New("agent: that command is not allowed on this device")

// Exec builds an ExecFunc that will run only the argvs given.
//
// # Why exact matching
//
// The tempting design is an allow-list of *programs*, with the caller supplying arguments.
// It is also where the shell problem comes back in a new shape: `tail` with a
// caller-chosen path reads any file, `find` with `-exec` runs anything, `curl` with `-o`
// writes anywhere, and `git` with `-c` runs a configured pager. Deciding which flags of
// which binary are safe is a per-binary research project, and getting it wrong is silent.
//
// So an entry is a complete argv and must match element for element. Parameterised
// commands are spelled out one per variant, which is more lines in a config file and far
// fewer questions when somebody audits it.
func Exec(allowed [][]string, opts ...ExecOption) ExecFunc {
	// A non-nil empty slice, not nil: os/exec treats a nil Env as "inherit the parent's
	// environment", so the default that reads as "no environment" would have handed the
	// command everything the agent was started with. Caught by a test that set a
	// variable and looked for it in the output.
	o := execOptions{timeout: DefaultExecTimeout, env: []string{}}
	for _, apply := range opts {
		apply(&o)
	}
	list := make([][]string, 0, len(allowed))
	for _, argv := range allowed {
		if len(argv) > 0 {
			list = append(list, slices.Clone(argv))
		}
	}

	return func(ctx context.Context, r ExecRequest, stdout, stderr io.Writer) (ExecResult, error) {
		if len(r.Argv) == 0 {
			return ExecResult{Code: -1}, errors.New("agent: exec was asked to run nothing")
		}
		if !allowedArgv(list, r.Argv) {
			// The refusal names the command, because the operator needs to know which
			// one to get added — and the argv came from an authenticated, authorised
			// caller, so there is nothing here they did not already send.
			return ExecResult{Code: -1}, fmt.Errorf("%w: %s",
				ErrNotAllowed, strings.Join(r.Argv, " "))
		}

		ctx, cancel := context.WithTimeout(ctx, o.timeout)
		defer cancel()

		cmd := exec.CommandContext(ctx, r.Argv[0], r.Argv[1:]...)
		cmd.Stdout, cmd.Stderr = stdout, stderr
		// No stdin. `exec` is not an interactive session, and a command left waiting on
		// a terminal nobody is attached to would hang until the timeout.
		cmd.Stdin = nil
		// Its own process group, so the timeout can reach the whole job. Without this a
		// command that spawns children leaves them running after it is killed.
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if o.identity != nil {
			cmd.SysProcAttr.Credential = &syscall.Credential{
				Uid: o.identity.UID, Gid: o.identity.GID, Groups: o.identity.Groups,
			}
		}
		cmd.Env = o.env

		if err := cmd.Start(); err != nil {
			return ExecResult{Code: -1}, fmt.Errorf("agent: starting %q: %w", r.Argv[0], err)
		}
		// CommandContext kills only the process it started, so the group is killed here.
		done := make(chan struct{})
		defer close(done)
		go func() {
			select {
			case <-ctx.Done():
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			case <-done:
			}
		}()

		err := cmd.Wait()
		switch {
		case err == nil:
			return ExecResult{Code: 0}, nil
		case ctx.Err() != nil:
			return ExecResult{Code: -1}, fmt.Errorf("agent: %q exceeded %s",
				r.Argv[0], o.timeout)
		default:
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				// A non-zero exit is the command's answer, not an error in running it.
				// Reporting it as a failure would make "grep found nothing" look like a
				// broken gateway.
				return ExecResult{Code: ee.ExitCode()}, nil
			}
			return ExecResult{Code: -1}, fmt.Errorf("agent: running %q: %w", r.Argv[0], err)
		}
	}
}

// DefaultExecTimeout bounds one command. `exec` is for things that answer quickly; a
// long-running job wants a shell and an operator watching it.
const DefaultExecTimeout = 60 * time.Second

type execOptions struct {
	timeout  time.Duration
	identity *Identity
	env      []string
}

// ExecOption configures Exec.
type ExecOption func(*execOptions)

// ExecTimeout bounds how long one command may run.
func ExecTimeout(d time.Duration) ExecOption {
	return func(o *execOptions) {
		if d > 0 {
			o.timeout = d
		}
	}
}

// ExecAs runs commands as a given OS identity. Same shape as a session's shell, and the
// same reason: the gateway decides who may run a command, and only the device can decide
// what that command can touch.
func ExecAs(id *Identity) ExecOption {
	return func(o *execOptions) { o.identity = id }
}

// ExecEnv sets the environment.
//
// The default is empty — not inherited — because a command whose behaviour depends on how
// the agent happened to be started behaves differently on two identical devices, and the
// difference shows up as output somebody parses. Pass what is genuinely needed.
func ExecEnv(env []string) ExecOption {
	return func(o *execOptions) {
		if env == nil {
			env = []string{}
		}
		o.env = env
	}
}

func allowedArgv(list [][]string, want []string) bool {
	for _, argv := range list {
		if slices.Equal(argv, want) {
			return true
		}
	}
	return false
}

// runExec streams one command's output over a session connection.
//
// stdout becomes DATA and stderr becomes DATA_ERR, which is the whole reason DATA_ERR is
// in the frame vocabulary: an operator running `ssh device some-command` gets stderr on
// the SSH extended-data channel, exactly where a local shell would put it.
func (s *session) runExec(ctx context.Context, run ExecFunc, inv frame.Invitation) error {
	if run == nil {
		err := errors.New("agent: no Exec configured, but a command was requested")
		_ = s.send(ctx, frame.TypeError, frame.Error{
			Code: "profile_unsupported", Message: err.Error()})
		return err
	}
	if len(inv.Exec) == 0 {
		err := errors.New("agent: an exec session carried no argv")
		_ = s.send(ctx, frame.TypeError, frame.Error{
			Code: "protocol_error", Message: err.Error()})
		return err
	}

	// A separate context for the command, deliberately not shadowing the caller's.
	//
	// The exit status and the close reason are sent *after* the command finishes, and
	// cancelling the context they are sent on drops them silently — which is exactly
	// what happened when this shadowed `ctx`: the output arrived, the status did not, and
	// every command looked like a session that failed. Sending the answer is the last
	// thing this function does, so it needs a context that outlives the work.
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// A reader on the connection, so a CLOSE from the gateway ends the command rather
	// than being noticed only when it finishes. An operator who pressed Ctrl-C is not
	// waiting for a sixty-second timeout.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.execWatchClose(runCtx, cancel)
	}()

	result, err := run(runCtx,
		ExecRequest{SessionID: inv.SessionID, Principal: inv.Principal, Argv: inv.Exec},
		&frameWriter{s: s, ctx: runCtx, kind: frame.TypeData},
		&frameWriter{s: s, ctx: runCtx, kind: frame.TypeDataErr})

	// Everything is sent *before* the watcher is stopped, on both paths.
	//
	// Cancelling a context that a websocket read is blocked on closes the connection —
	// the read cannot be abandoned mid-frame and resumed, so the transport gives up on
	// it. Cancelling first meant every exit status, close reason and refusal was written
	// to a socket that had just been torn down, silently: a command's output arrived and
	// its answer did not, so every one looked like a session that failed. This bit twice,
	// once on each branch, which is why the ordering is now in one place.
	if err != nil {
		// A refused command is the operator's problem to fix and names itself; anything
		// else is the device's. Both close the session — there is nothing to retry on
		// this connection either way.
		code := "internal"
		if errors.Is(err, ErrNotAllowed) {
			code = "not_authorized"
		}
		_ = s.send(ctx, frame.TypeError, frame.Error{Code: code, Message: err.Error()})
	} else {
		// EXIT then CLOSE, in that order: the exit status is the answer, and a caller
		// that saw the close first would have to decide what a session that ended
		// without one meant.
		_ = s.send(ctx, frame.TypeExit, frame.Exit{Code: result.Code})
	}
	_ = s.send(ctx, frame.TypeClose, frame.Close{Reason: "device_close"})

	cancel()
	wg.Wait()
	return err
}

// execWatchClose ends the command when the gateway closes the session.
func (s *session) execWatchClose(ctx context.Context, cancel func()) {
	for {
		msg, err := s.conn.Recv(ctx)
		if err != nil {
			cancel()
			return
		}
		f, err := s.codec.Decode(msg)
		if err != nil || frame.Expect(frame.ScopeSession, f) != nil {
			cancel()
			return
		}
		switch f.Type {
		case frame.TypeClose:
			cancel()
			return
		case frame.TypeData:
			// An exec session has no stdin. Ignored rather than treated as a protocol
			// error: a client that sends a keystroke into a non-interactive session is
			// confused, not hostile, and killing the command over it would be worse.
			continue
		}
	}
}

// frameWriter turns writes into frames of one type.
type frameWriter struct {
	s    *session
	ctx  context.Context
	kind frame.Type
}

func (w *frameWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	// Copied, because the caller — os/exec's copier — reuses its buffer, and a frame
	// that is queued rather than written synchronously would otherwise carry whatever
	// the next read put there.
	body := make([]byte, len(p))
	copy(body, p)
	if err := w.s.sendFrame(w.ctx, frame.Frame{Type: w.kind, Payload: body}); err != nil {
		return 0, err
	}
	return len(p), nil
}
