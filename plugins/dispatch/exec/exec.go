// Package exec is a Dispatcher that runs a command with the invitation on stdin.
//
// It exists for two reasons: it makes dispatch mode testable on a laptop with no
// broker, and it is genuinely the right integration for the one case where a shell
// script already knows how to reach the fleet.
//
// The invitation goes on **stdin, never argv**. A ticket in a command line is
// visible in `ps` to every process on the host, and ends up in shell history and
// audit logs — which is the same reason it never travels in a URL.
package exec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"time"

	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
)

// UnreachableExitCode is how a command says "the doorbell rang and the device is
// not there", as opposed to "I could not ring it". Any other non-zero exit is a
// delivery failure.
const UnreachableExitCode = 3

// DefaultTimeout bounds a wake. A doorbell that takes longer than this is a
// dependency of session setup that nobody is going to wait for.
const DefaultTimeout = 10 * time.Second

// Dispatcher runs Command for every wake.
type Dispatcher struct {
	// Command is the argv to run. Required; the first element is the executable.
	Command []string
	// Env is added to the child's environment as KEY=VALUE. The device id is
	// exported as OARLOCK_DEVICE_ID for convenience; the ticket never is.
	Env     []string
	Timeout time.Duration
}

var _ plugin.Dispatcher = (*Dispatcher)(nil)

// New validates the configuration.
func New(command []string, timeout time.Duration) (*Dispatcher, error) {
	if len(command) == 0 {
		return nil, errors.New("exec dispatcher: Command is required")
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Dispatcher{Command: command, Timeout: timeout}, nil
}

// Wake runs the command with the invitation as JSON on stdin.
func (d *Dispatcher) Wake(ctx context.Context, dev *plugin.Device, inv frame.Invitation) error {
	if len(d.Command) == 0 {
		return errors.New("exec dispatcher: Command is required")
	}
	body, err := json.Marshal(inv)
	if err != nil {
		return fmt.Errorf("exec dispatcher: encoding the invitation: %w", err)
	}

	timeout := d.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, d.Command[0], d.Command[1:]...)
	cmd.Stdin = bytes.NewReader(body)
	cmd.Env = append(cmd.Environ(), "OARLOCK_DEVICE_ID="+dev.ID)
	cmd.Env = append(cmd.Env, d.Env...)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == UnreachableExitCode {
			return fmt.Errorf("%w: %s", plugin.ErrDeviceUnreachable, trim(stderr.String()))
		}
		return fmt.Errorf("exec dispatcher: %w: %s", err, trim(stderr.String()))
	}
	return nil
}

func trim(s string) string {
	const max = 200
	s = string(bytes.TrimSpace([]byte(s)))
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
