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
	Term      string
	Cols      int
	Rows      int
}

// ShellFunc opens a shell.
//
// This is a hook rather than a fixed implementation because "a shell" is
// platform-specific: which binary, which environment, which uid, and whether a PTY
// is available at all. A build that cannot provide one omits "shell" from its
// capabilities, and the gateway then refuses such a session at open time with a real
// reason instead of after a round trip.
type ShellFunc func(ctx context.Context, r ShellRequest) (PTY, error)

// Forkpty runs argv on a new pseudo-terminal. It is the obvious implementation of
// ShellFunc for Linux and for Android builds that can reach a shell binary.
func Forkpty(argv []string, env ...string) ShellFunc {
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
		cmd.Env = append(cmd.Env, env...)
		// Its own process group, so a signal can reach the whole job — a Ctrl-C that
		// only hits the shell and not its children is not the Ctrl-C anyone means.
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}

		f, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
		if err != nil {
			return nil, fmt.Errorf("agent: starting a pty: %w", err)
		}
		return &ptyProcess{f: f, cmd: cmd}, nil
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
