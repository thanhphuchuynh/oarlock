package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"github.com/creack/pty"
)

// PTY is a running shell with a terminal attached.
type PTY interface {
	io.ReadWriteCloser
	// Resize tells the terminal its new size. A terminal that lies about its size
	// wraps every line wrong, and vi draws over itself.
	Resize(cols, rows int) error
	// Signal delivers a signal by name: INT, TERM, QUIT, HUP, KILL, USR1, USR2,
	// WINCH.
	Signal(name string) error
	// Wait returns the exit code once the process has ended.
	Wait() (int, error)
}

// ShellRequest is what the gateway asked for.
type ShellRequest struct {
	SessionID string
	Principal string // for the agent's own log only; never an authorisation input
	// Profile is the profile the gateway authorised. It reaches here because the OS
	// identity a session runs as is a property of what was asked for, and the agent is
	// the only thing that can act on it.
	Profile string
	Term    string
	Cols    int
	Rows    int
}

// Identity is the OS identity a session's shell runs as.
//
// Deliberately not syscall.Credential: that type in an exported signature would make
// this package's API Unix-shaped, and the point of ShellFunc is that each platform
// supplies its own notion of a shell.
type Identity struct {
	UID uint32
	GID uint32
	// Groups are the supplementary groups to hold. An empty list means none — every
	// supplementary group the agent itself holds is dropped, which is the safe reading
	// of a list nobody wrote. On Android you generally want `log` and `inet` here, or
	// the session cannot write a log line or open a socket.
	Groups []uint32
}

// ShellOptions configures Forkpty beyond the argv.
type ShellOptions struct {
	// Env is appended to the process environment.
	Env []string

	// Identity picks the OS identity for one session, by profile. Nil — or a nil
	// return — inherits the agent's own identity.
	//
	// This is the shape sshd has: the supervisor is privileged and no session ever is.
	// Without it, every operator granted `shell` gets exactly whatever the agent
	// process is, which for a service started by init means root, for everybody. The
	// gateway can say who may open a shell; only the agent can say what that shell can
	// touch.
	Identity func(profile string) *Identity
}

// ShellFunc opens a shell.
//
// This is a hook rather than a fixed implementation because "a shell" is
// platform-specific: which binary, which environment, which uid, and whether a PTY
// is available at all. A build that cannot provide one omits "shell" from its
// capabilities, and the gateway then refuses such a session at open time with a real
// reason instead of after a round trip.
type ShellFunc func(ctx context.Context, r ShellRequest) (PTY, error)

// Forkpty runs argv on a new pseudo-terminal, as the agent's own user. It is the
// obvious implementation of ShellFunc for Linux and for Android builds that can reach
// a shell binary.
func Forkpty(argv []string, env ...string) ShellFunc {
	return ForkptyWith(argv, ShellOptions{Env: env})
}

// ForkptyWith is Forkpty with options — notably a per-session OS identity.
func ForkptyWith(argv []string, o ShellOptions) ShellFunc {
	return func(ctx context.Context, r ShellRequest) (PTY, error) {
		if len(argv) == 0 {
			return nil, errors.New("agent: Forkpty needs an argv")
		}
		cols, rows := r.Cols, r.Rows
		if cols <= 0 {
			cols = 80
		}
		if rows <= 0 {
			rows = 24
		}
		term := r.Term
		if term == "" {
			// Not "dumb": a PTY told TERM=dumb will not emit the escape sequences a
			// browser terminal is built to render, and the operator gets a shell
			// that looks broken rather than one that looks plain.
			term = "xterm-256color"
		}

		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Env = append(os.Environ(), "TERM="+term)
		cmd.Env = append(cmd.Env, o.Env...)
		// Its own process group, so a signal can reach the whole job — a Ctrl-C that
		// only hits the shell and not its children is not the Ctrl-C anyone means.
		attr := &syscall.SysProcAttr{Setsid: true, Setctty: true}

		var id *Identity
		if o.Identity != nil {
			id = o.Identity(r.Profile)
		}
		if id != nil {
			attr.Credential = &syscall.Credential{
				Uid: id.UID, Gid: id.GID, Groups: id.Groups,
			}
		}
		cmd.SysProcAttr = attr

		// The terminal is opened here rather than by pty.StartWithSize because a
		// session that changes uid needs the slave chowned before the child starts.
		// File descriptors are checked at open, so the child could read and write the
		// inherited fds either way — but anything that reopens /dev/tty (sudo asking
		// for a password, ssh asking for a passphrase, an editor taking over the
		// screen) opens the *device*, and that check is against the device's owner.
		// A pty still owned by root is a pty a dropped session cannot reopen.
		ptmx, tty, err := pty.Open()
		if err != nil {
			return nil, fmt.Errorf("agent: opening a pty: %w", err)
		}
		defer tty.Close()
		if id != nil {
			// -1 leaves the group alone: on Linux the slave is already group `tty`,
			// which is what a terminal should be.
			//
			// Both of these fail for the same reason the exec below would, so they
			// carry the same sentence. Whichever step trips first, the operator is
			// told the actual cause rather than being sent to look at the pty layer.
			if err := os.Chown(tty.Name(), int(id.UID), -1); err != nil {
				_ = ptmx.Close()
				return nil, fmt.Errorf("agent: handing the terminal to uid %d (is the "+
					"agent privileged enough to drop?): %w", id.UID, err)
			}
			if err := os.Chmod(tty.Name(), 0o620); err != nil {
				_ = ptmx.Close()
				return nil, fmt.Errorf("agent: terminal permissions for uid %d (is the "+
					"agent privileged enough to drop?): %w", id.UID, err)
			}
		}
		if err := pty.Setsize(ptmx, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)}); err != nil {
			_ = ptmx.Close()
			return nil, fmt.Errorf("agent: sizing a pty: %w", err)
		}
		cmd.Stdin, cmd.Stdout, cmd.Stderr = tty, tty, tty
		if err := cmd.Start(); err != nil {
			_ = ptmx.Close()
			// A refused setuid is the interesting failure here and it is worth saying
			// so plainly: it means the agent is not privileged enough to drop.
			if id != nil {
				return nil, fmt.Errorf("agent: starting a shell as uid %d (is the agent "+
					"privileged enough to drop?): %w", id.UID, err)
			}
			return nil, fmt.Errorf("agent: starting a shell: %w", err)
		}
		return &ptyProcess{f: ptmx, cmd: cmd}, nil
	}
}

type ptyProcess struct {
	f   *os.File
	cmd *exec.Cmd

	waitOnce sync.Once
	waitErr  error
	code     int
}

func (p *ptyProcess) Read(b []byte) (int, error)  { return p.f.Read(b) }
func (p *ptyProcess) Write(b []byte) (int, error) { return p.f.Write(b) }

func (p *ptyProcess) Resize(cols, rows int) error {
	if cols <= 0 || rows <= 0 {
		return fmt.Errorf("agent: bad terminal size %dx%d", cols, rows)
	}
	return pty.Setsize(p.f, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
}

func (p *ptyProcess) Signal(name string) error {
	sig, ok := signals[name]
	if !ok {
		return fmt.Errorf("agent: unknown signal %q", name)
	}
	if p.cmd.Process == nil {
		return errors.New("agent: no process")
	}
	// Negative pid signals the process group, which is what Setsid gave us.
	if err := syscall.Kill(-p.cmd.Process.Pid, sig); err != nil {
		// The group may already be gone; fall back to the process itself.
		return p.cmd.Process.Signal(sig)
	}
	return nil
}

func (p *ptyProcess) Wait() (int, error) {
	p.waitOnce.Do(func() {
		err := p.cmd.Wait()
		var ee *exec.ExitError
		switch {
		case err == nil:
			p.code = 0
		case errors.As(err, &ee):
			p.code = ee.ExitCode()
		default:
			p.waitErr = err
		}
	})
	return p.code, p.waitErr
}

func (p *ptyProcess) Close() error {
	err := p.f.Close()
	if p.cmd.Process != nil {
		// Best effort: the shell may already have exited.
		_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGHUP)
	}
	return err
}

var signals = map[string]syscall.Signal{
	"INT": syscall.SIGINT, "TERM": syscall.SIGTERM, "QUIT": syscall.SIGQUIT,
	"HUP": syscall.SIGHUP, "KILL": syscall.SIGKILL,
	"USR1": syscall.SIGUSR1, "USR2": syscall.SIGUSR2, "WINCH": syscall.SIGWINCH,
}
