// Package oarlockagent is the small, gomobile-safe API used by the Android app.
package oarlockagent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	xssh "golang.org/x/crypto/ssh"

	core "github.com/oarlock/oarlock/agent"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/transport/websocket"
)

// Listener receives lifecycle and log updates on gomobile's Java callback bridge.
type Listener interface {
	OnStatus(state, detail string)
	OnLog(line string)
}

// Agent owns one in-process control channel.
type Agent struct {
	gateway  string
	device   string
	keyPath  string
	shell    string
	pins     string
	insecure bool
	listener Listener

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// NewAgent validates the Android service configuration.
func NewAgent(gateway, device, keyPath, shell, pins string, insecure bool, listener Listener) (*Agent, error) {
	gateway = strings.TrimSpace(gateway)
	device = strings.TrimSpace(device)
	keyPath = strings.TrimSpace(keyPath)
	shell = strings.TrimSpace(shell)
	switch {
	case gateway == "":
		return nil, errors.New("gateway is required")
	case device == "":
		return nil, errors.New("device id is required")
	case keyPath == "":
		return nil, errors.New("key path is required")
	case strings.TrimSpace(pins) == "" && !insecure:
		return nil, errors.New("a gateway certificate pin is required unless insecure mode is enabled")
	}
	if shell == "" {
		shell = "/system/bin/sh"
	}
	return &Agent{
		gateway: gateway, device: device, keyPath: keyPath, shell: shell,
		pins: pins, insecure: insecure, listener: listener,
	}, nil
}

// Start starts the control channel asynchronously.
func (a *Agent) Start() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cancel != nil {
		return errors.New("agent is already running")
	}
	key, err := loadKey(a.keyPath)
	if err != nil {
		return err
	}
	var pins []string
	for _, pin := range strings.Split(a.pins, ",") {
		if pin = strings.TrimSpace(pin); pin != "" {
			pins = append(pins, pin)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	log := slog.New(slog.NewTextHandler(listenerWriter{listener: a.listener}, &slog.HandlerOptions{Level: slog.LevelInfo}))
	control, err := core.NewControl(core.Config{
		Gateway: a.gateway, DeviceID: a.device, Signer: key,
		Dialer: websocket.Dialer{}, PinSHA256: pins, Caps: []string{"shell"},
		Info:  frame.AgentInfo{Version: "android-apk", Platform: "android/" + runtime.GOARCH},
		Shell: core.Forkpty(strings.Fields(a.shell)), Log: log,
	})
	if err != nil {
		cancel()
		return err
	}
	a.cancel, a.done = cancel, done
	a.status("starting", a.device)
	go func() {
		defer close(done)
		err := control.Run(ctx)
		detail := "stopped"
		if errors.Is(err, core.ErrStoppedByGateway) {
			detail = "stopped by gateway administrator"
		} else if err != nil && !errors.Is(err, context.Canceled) {
			detail = err.Error()
		}
		a.mu.Lock()
		a.cancel = nil
		a.done = nil
		a.mu.Unlock()
		a.status("stopped", detail)
	}()
	return nil
}

// Stop asks the running control channel to stop and waits briefly for cleanup.
func (a *Agent) Stop() {
	a.mu.Lock()
	cancel, done := a.cancel, a.done
	a.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		a.status("stopping", "waiting for the network connection to close")
	}
}

// IsRunning reports whether this instance currently owns a control loop.
func (a *Agent) IsRunning() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cancel != nil
}

// EnsureKey creates an Ed25519 device key when needed and returns its SSH public key.
func EnsureKey(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("key path is required")
	}
	key, err := loadKey(path)
	if errors.Is(err, os.ErrNotExist) {
		_, key, err = ed25519.GenerateKey(rand.Reader)
		if err == nil {
			err = os.WriteFile(path, key.Seed(), 0o600)
		}
	}
	if err != nil {
		return "", fmt.Errorf("device key: %w", err)
	}
	public, err := xssh.NewPublicKey(key.Public())
	if err != nil {
		return "", fmt.Errorf("device public key: %w", err)
	}
	return strings.TrimSpace(string(xssh.MarshalAuthorizedKey(public))), nil
}

func loadKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	switch len(b) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(b), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(b), nil
	default:
		return nil, fmt.Errorf("%s is %d bytes, not an Ed25519 key", path, len(b))
	}
}

func (a *Agent) status(state, detail string) {
	if a.listener == nil {
		return
	}
	defer func() { _ = recover() }()
	a.listener.OnStatus(state, detail)
}

type listenerWriter struct{ listener Listener }

func (w listenerWriter) Write(p []byte) (int, error) {
	if w.listener != nil {
		func() {
			defer func() { _ = recover() }()
			w.listener.OnLog(strings.TrimSpace(string(p)))
		}()
	}
	return len(p), nil
}

var _ io.Writer = listenerWriter{}
