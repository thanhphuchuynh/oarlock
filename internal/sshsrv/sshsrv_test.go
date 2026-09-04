package sshsrv_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xssh "golang.org/x/crypto/ssh"

	"github.com/oarlock/oarlock/agent"
	"github.com/oarlock/oarlock/internal/auth/authorizedkeys"
	"github.com/oarlock/oarlock/internal/authz"
	"github.com/oarlock/oarlock/internal/invite"
	"github.com/oarlock/oarlock/internal/pump"
	"github.com/oarlock/oarlock/internal/record"
	"github.com/oarlock/oarlock/internal/sessions"
	"github.com/oarlock/oarlock/internal/sessionsrv"
	"github.com/oarlock/oarlock/internal/sshsrv"
	"github.com/oarlock/oarlock/internal/ticket"
	"github.com/oarlock/oarlock/pkg/condition"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
	"github.com/oarlock/oarlock/pkg/transport/websocket"
)

const deviceID = "build-runner-2"

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

type reg struct{ devices map[string]*plugin.Device }

func (r reg) Get(_ context.Context, id string) (*plugin.Device, error) {
	if d, ok := r.devices[id]; ok {
		return d, nil
	}
	return nil, plugin.ErrNoDevice
}
func (r reg) List(context.Context, plugin.DeviceQuery) ([]*plugin.Device, string, error) {
	return nil, "", plugin.ErrUnsupported
}

// stack is the whole gateway plus an agent, wired for real: a real SSH front door,
// a real /ws/session endpoint over WebSocket, a real agent dialling back, and a real
// PTY at the far end. Only the doorbell is in-process.
type stack struct {
	sshAddr string
	client  xssh.Signer
	dev     *plugin.Device
	shell   []string
	// failDoorbell makes the next wake return this error, so a test can see what an
	// operator is actually told when one fails.
	failDoorbell func(error)
	// ledger is the session store, so a test can assert what was *written* about a
	// session rather than only what the operator was shown.
	ledger sessions.Store
}

func newStack(t *testing.T, shell []string, limits pump.Limits) *stack {
	return newStackWith(t, shell, limits, 0, false)
}

// newStackSlowDoorbell delays the wake, so a test can observe what the gateway says
// before the device attaches.
func newStackSlowDoorbell(t *testing.T, delay time.Duration) *stack {
	return newStackWith(t, []string{"/bin/sh"}, fastLimits(), delay, false)
}

// newStackWithRecorder wires a real recorder, so the disclosure can say the other
// thing.
func newStackWithRecorder(t *testing.T) *stack {
	return newStackWith(t, []string{"/bin/sh"}, fastLimits(), 0, true)
}

// authzChecker is what the stack passes to sshsrv. Nil for every existing test — a
// deployment with no authorizer allows, and authentication still applies — and set by the
// authorisation tests to a controllable backend.
var authzChecker *authz.Checker

// authzSupervisor re-checks live sessions. Nil for every test that is not about
// revocation: a supervisor with a 30s interval would never fire inside a test anyway, and
// an explicit nil says the test is not exercising it.
var authzSupervisor *authz.Supervisor

// forwardPorts is the device's `tcp` allow-list, in the same style as authzChecker
// above. Empty for every test that is not about port forwarding — and then the agent
// advertises no "tcp" capability either, which is what an unconfigured device does.
var forwardPorts []int

// handshakeBudget overrides the front door's pre-authentication budget, in the same
// style as authzChecker above. Zero for every test that is not about it, which means
// they get the fifteen-second default and never notice it.
var handshakeBudget time.Duration

// connRate overrides the front door's per-client connection rate limit, in the same
// style as handshakeBudget above. Zero for every test that is not about it — and since
// every test connects from 127.0.0.1, they would all share one key if the default of 30
// ever bit. It does not: each stack builds its own server, and therefore its own counter.
var connRate int

// allowUnrecorded and devAllowPassthrough are the two keys mode A needs, in the same
// package-variable style as the rest of this harness. Both false everywhere else, which
// is what every other test asserts by never reaching passthrough at all.
var allowUnrecorded bool
var devAllowPassthrough bool

// passthroughPort is the device-local sshd port the gateway asks for. It tracks
// forwardPorts, because the device's own allow-list is the other half of the bargain and
// a test where the two disagree is testing the disagreement rather than mode A.
var passthroughPort int

// logSources is the device's published log allow-list, in the same package-variable
// style as the rest of this harness. Empty for every test that is not about it — and then
// the agent advertises no "log" capability either, which is what an unconfigured device
// does.
var logSources map[string]string

// deviceProfiles restricts what the *registry* says this device may be asked to do. Empty
// means the gateway's default set, which is what every other test wants.
var deviceProfiles []string

// newStackLogs wires an agent publishing the named log sources.
func newStackLogs(t *testing.T, sources map[string]string) *stack {
	t.Helper()
	prev := logSources
	logSources = sources
	t.Cleanup(func() { logSources = prev })
	return newStackWith(t, []string{"/bin/sh"}, fastLimits(), 0, false)
}

// newStackWithProfiles restricts the device's registry record, which is what the gateway
// checks before waking anything.
func newStackWithProfiles(t *testing.T, profiles []string) *stack {
	t.Helper()
	prev := deviceProfiles
	deviceProfiles = profiles
	t.Cleanup(func() { deviceProfiles = prev })
	return newStackWith(t, []string{"/bin/sh"}, fastLimits(), 0, false)
}

// newStackPassthrough wires a front door and a device with mode A turned on to the degree
// each argument says, so a test can remove exactly one key and watch the refusal.
func newStackPassthrough(t *testing.T, deployment, device bool, sshdPort int) *stack {
	t.Helper()
	pu, pd, pp := allowUnrecorded, devAllowPassthrough, forwardPorts
	allowUnrecorded, devAllowPassthrough = deployment, device
	prevPort := passthroughPort
	if sshdPort > 0 {
		forwardPorts = []int{sshdPort}
		passthroughPort = sshdPort
	}
	t.Cleanup(func() {
		allowUnrecorded, devAllowPassthrough, forwardPorts = pu, pd, pp
		passthroughPort = prevPort
	})
	return newStackWith(t, []string{"/bin/sh"}, fastLimits(), 0, false)
}

// newStackRateLimited wires a front door that admits `perMinute` connections from one
// client before refusing.
func newStackRateLimited(t *testing.T, perMinute int) *stack {
	t.Helper()
	prev := connRate
	connRate = perMinute
	t.Cleanup(func() { connRate = prev })
	return newStackWith(t, []string{"/bin/sh"}, fastLimits(), 0, false)
}

// newStackBudget wires a front door whose pre-authentication budget is short enough
// for a test to wait out.
func newStackBudget(t *testing.T, budget time.Duration) *stack {
	t.Helper()
	prev := handshakeBudget
	handshakeBudget = budget
	t.Cleanup(func() { handshakeBudget = prev })
	return newStackWith(t, []string{"/bin/sh"}, fastLimits(), 0, false)
}

// newStackForwarding wires an agent that will forward the named device-local ports.
func newStackForwarding(t *testing.T, ports []int) *stack {
	t.Helper()
	prev := forwardPorts
	forwardPorts = ports
	t.Cleanup(func() { forwardPorts = prev })
	return newStackWith(t, []string{"/bin/sh"}, fastLimits(), 0, false)
}

// agentCaps and agentDial keep the forwarding wiring out of the middle of newStackWith,
// where it would read as a second thing that builder does.
func agentCaps() []string {
	caps := []string{"shell", "exec"}
	if len(forwardPorts) > 0 {
		caps = append(caps, "tcp")
	}
	if len(logSources) > 0 {
		caps = append(caps, "log")
	}
	return caps
}

func agentDial() agent.DialFunc {
	if len(forwardPorts) == 0 {
		return nil
	}
	return agent.Dial(forwardPorts)
}

func newStackWith(t *testing.T, shell []string, limits pump.Limits,
	doorbellDelay time.Duration, withRecorder bool) *stack {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// ── the operator's key, in an authorized_keys file ──
	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := xssh.NewSignerFromKey(clientPriv)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := xssh.NewPublicKey(clientPub)
	if err != nil {
		t.Fatal(err)
	}
	akPath := filepath.Join(t.TempDir(), "authorized_keys")
	line := string(xssh.MarshalAuthorizedKey(sshPub))
	line = strings.TrimRight(line, "\n") + " admin@mail.com\n"
	if err := os.WriteFile(akPath, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	authn, err := authorizedkeys.Open(akPath, quiet())
	if err != nil {
		t.Fatal(err)
	}

	// ── a dispatch-mode device: the doorbell is a function call, which keeps the
	// test to one moving part while still exercising the whole session path ──
	dev := &plugin.Device{ID: deviceID, Platform: plugin.PlatformAndroid,
		AllowPassthrough: devAllowPassthrough, Profiles: deviceProfiles}
	registry := reg{map[string]*plugin.Device{dev.ID: dev}}

	tickets := ticket.NewMemory(nil)
	inviter := &invite.Inviter{
		Tickets:        tickets,
		NodeURL:        "", // filled in once the session endpoint has an address
		AnswerDeadline: 10 * time.Second,
		Log:            quiet(),
	}

	sessionEndpoint := &sessionsrv.Server{
		Upgrader: websocket.Upgrader{},
		Inviter:  inviter,
		Log:      quiet(),
		Ready: func(c *ticket.Claims) frame.Ready {
			return frame.Ready{SessionID: c.SessionID, Mode: "gateway"}
		},
	}
	httpSrv := httptest.NewServer(http.HandlerFunc(sessionEndpoint.ServeHTTP))
	t.Cleanup(httpSrv.Close)
	inviter.NodeURL = "ws" + strings.TrimPrefix(httpSrv.URL, "http")

	// ── the agent ──
	_, devPriv, _ := ed25519.GenerateKey(rand.Reader)
	control, err := agent.NewControl(agent.Config{
		Gateway:   "ws://unused/ws/control", // dispatch mode: no control channel
		DeviceID:  deviceID,
		Signer:    devPriv,
		Dialer:    websocket.Dialer{},
		PinSHA256: []string{"unused-in-test"},
		Caps:      agentCaps(),
		Shell:     agent.Forkpty(shell),
		Dial:      agentDial(),
		Tail:      agent.Logs(logSources, agent.LogPollInterval(10*time.Millisecond)),
		// The allow-list the exec tests run against. Exact argvs, which is the profile's
		// whole security property — see agent/exec.go.
		Exec: agent.Exec([][]string{
			{"/bin/echo", "hello"},
			{"/bin/sh", "-c", "printf out; printf err >&2; exit 3"},
			{"/bin/echo", "a;b|c$(d)"},
		}),
		Log: quiet(),
	})
	if err != nil {
		t.Fatal(err)
	}
	var doorbellErr atomic.Value
	inviter.Dispatcher = plugin.DispatcherFunc(
		func(_ context.Context, _ *plugin.Device, inv frame.Invitation) error {
			if e, ok := doorbellErr.Load().(error); ok && e != nil {
				return e
			}
			go func() {
				if doorbellDelay > 0 {
					time.Sleep(doorbellDelay)
				}
				control.HandleInvitation(ctx, inv)
			}()
			return nil
		})

	// ── the SSH front door ──
	var recorder plugin.Recorder
	if withRecorder {
		_, recPriv, _ := ed25519.GenerateKey(rand.Reader)
		r, rerr := record.NewFileRecorder(filepath.Join(t.TempDir(), "rec"),
			&record.KeySigner{Key: recPriv, ID: "test-key"})
		if rerr != nil {
			t.Fatal(rerr)
		}
		recorder = r
	}

	ledger := sessions.NewMemory(sessions.Limits{}, nil)
	srv, err := sshsrv.New(sshsrv.Options{
		Authenticator:     authn,
		Authz:             authzChecker,
		AuthzSupervisor:   authzSupervisor,
		Registry:          registry,
		Inviter:           inviter,
		Sessions:          ledger,
		Recorder:          recorder,
		Limits:            limits,
		HandshakeBudget:   handshakeBudget,
		ConnRatePerMinute: connRate,
		AllowUnrecorded:   allowUnrecorded,
		PassthroughPort:   passthroughPort,
		Log:               quiet(),
	})
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Handler().Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })

	return &stack{
		sshAddr: l.Addr().String(), client: signer, dev: dev, shell: shell,
		failDoorbell: func(e error) { doorbellErr.Store(e) },
		ledger:       ledger,
	}
}

// dial connects as the operator: `ssh <device>@gateway`, with the device as the
// username.
func (s *stack) dial(t *testing.T, signer xssh.Signer, user string) *xssh.Client {
	t.Helper()
	if signer == nil {
		signer = s.client
	}
	if user == "" {
		user = deviceID
	}
	c, err := xssh.Dial("tcp", s.sshAddr, &xssh.ClientConfig{
		User:            user,
		Auth:            []xssh.AuthMethod{xssh.PublicKeys(signer)},
		HostKeyCallback: xssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("ssh dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func shellSession(t *testing.T, c *xssh.Client) (*xssh.Session, io.WriteCloser, *syncBuf) {
	t.Helper()
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.RequestPty("xterm-256color", 24, 80, xssh.TerminalModes{
		xssh.ECHO: 0, // keep the transcript readable: no input echo
	}); err != nil {
		t.Fatal(err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out := &syncBuf{}
	sess.Stdout = out
	sess.Stderr = out
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	return sess, stdin, out
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func waitFor(t *testing.T, out *syncBuf, want string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(out.String(), want) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("never saw %q in:\n%s", want, out.String())
}

// ── the acceptance criterion for M0 ─────────────────────────────────────────────

// TestSSHReachesARealPTY is what E1.S6 exists to make true: an unmodified SSH
// client, no wrapper and no ~/.ssh/config entry, reaching a real shell on a device
// that is holding no listener.
func TestSSHReachesARealPTY(t *testing.T) {
	s := newStack(t, []string{"/bin/sh"}, fastLimits())
	c := s.dial(t, nil, "")
	sess, stdin, out := shellSession(t, c)
	defer sess.Close()

	// The operator is told what they are in before they type.
	waitFor(t, out, "gateway-terminated")
	waitFor(t, out, deviceID)

	if _, err := io.WriteString(stdin, "echo hello-from-the-device\n"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, out, "hello-from-the-device")
}

func TestExitCodePropagates(t *testing.T) {
	s := newStack(t, []string{"/bin/sh"}, fastLimits())
	c := s.dial(t, nil, "")
	sess, stdin, _ := shellSession(t, c)

	if _, err := io.WriteString(stdin, "exit 42\n"); err != nil {
		t.Fatal(err)
	}
	err := sess.Wait()
	var ee *xssh.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("Wait returned %v, want an ExitError", err)
	}
	if ee.ExitStatus() != 42 {
		t.Errorf("exit status %d, want 42", ee.ExitStatus())
	}
}

// TestWindowChangeReachesThePTY: a terminal that lies about its size wraps every
// line wrong. `stty size` asks the PTY itself, so this proves the resize landed on
// the far side rather than merely being sent.
func TestWindowChangeReachesThePTY(t *testing.T) {
	s := newStack(t, []string{"/bin/sh"}, fastLimits())
	c := s.dial(t, nil, "")
	sess, stdin, out := shellSession(t, c)
	defer sess.Close()
	waitFor(t, out, "gateway-terminated")

	if _, err := io.WriteString(stdin, "stty size\n"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, out, "24 80")

	if err := sess.WindowChange(38, 132); err != nil {
		t.Fatal(err)
	}
	// The agent coalesces resizes at 100 ms, so give it a beat.
	time.Sleep(300 * time.Millisecond)
	if _, err := io.WriteString(stdin, "stty size\n"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, out, "38 132")
}

// TestFloodOfEscapeSequencesIsLossless is the vi-shaped test, now with a real PTY.
// A dropped chunk lands in the middle of an escape sequence and leaves the terminal
// corrupt until a full redraw; nothing can repair that, so the shell profile must
// never drop a byte however far behind the operator falls.
func TestFloodOfEscapeSequencesIsLossless(t *testing.T) {
	// A deliberately small buffer, so the pump stalls constantly.
	s := newStack(t, []string{"/bin/sh"}, pump.Limits{
		Batch: 2048, Window: time.Millisecond, HighWater: 8192, LowWater: 1024,
	})
	c := s.dial(t, nil, "")
	sess, stdin, out := shellSession(t, c)
	defer sess.Close()
	waitFor(t, out, "gateway-terminated")

	// 2000 lines, each a cursor-home, an erase, a colour change and a marker: the
	// sequences that corrupt a screen if a byte goes missing from the middle of one.
	const lines = 2000
	// The sentinel is assembled by the shell, so the PTY's echo of the command does
	// not contain it. Waiting on a sentinel that appears in its own echo makes the
	// test pass instantly and prove nothing — which is exactly what it did first.
	script := fmt.Sprintf(
		`i=0; while [ $i -lt %d ]; do printf '\033[H\033[2J\033[1;32mLINE-%%04d\033[0m\r\n' $i; `+
			`i=$((i+1)); done; printf 'FLOOD%%s\r\n' '-COMPLETE'`+"\n", lines)
	if _, err := io.WriteString(stdin, script); err != nil {
		t.Fatal(err)
	}
	waitFor(t, out, "FLOOD-COMPLETE")

	got := out.String()
	// Every line must be present, in order, with its escape sequences intact.
	missing := 0
	for i := range lines {
		if !strings.Contains(got, fmt.Sprintf("\x1b[H\x1b[2J\x1b[1;32mLINE-%04d\x1b[0m", i)) {
			missing++
		}
	}
	if missing > 0 {
		t.Fatalf("%d of %d escape-sequence lines were lost or corrupted "+
			"(%d bytes received)", missing, lines, len(got))
	}
}

// ── refusals ────────────────────────────────────────────────────────────────────

func TestUnknownKeyIsRefused(t *testing.T) {
	s := newStack(t, []string{"/bin/sh"}, fastLimits())
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := xssh.NewSignerFromKey(other)
	if err != nil {
		t.Fatal(err)
	}
	_, err = xssh.Dial("tcp", s.sshAddr, &xssh.ClientConfig{
		User:            deviceID,
		Auth:            []xssh.AuthMethod{xssh.PublicKeys(signer)},
		HostKeyCallback: xssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err == nil {
		t.Fatal("an unregistered key was accepted")
	}
}

// TestUnknownDeviceAndNoAccessLookAlike: an operator with a valid key must not be
// able to enumerate the fleet by trying usernames.
func TestUnknownDeviceIsRefusedWithoutLeaking(t *testing.T) {
	s := newStack(t, []string{"/bin/sh"}, fastLimits())
	c := s.dial(t, nil, "no-such-device")
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.RequestPty("xterm", 24, 80, nil); err != nil {
		t.Fatal(err)
	}
	out := &syncBuf{}
	sess.Stdout, sess.Stderr = out, out
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	_ = sess.Wait()

	got := out.String()
	if !strings.Contains(got, "no such device, or you don't have access") {
		t.Errorf("unexpected message: %q", got)
	}
	// The message must not distinguish "does not exist" from "not yours".
	if strings.Contains(strings.ToLower(got), "unknown device") {
		t.Error("the message leaks whether the device exists")
	}
}

// ── the exec profile ────────────────────────────────────────────────────────────

// TestExecRunsOneCommand: `ssh device some command` runs it under the exec profile, with
// no terminal and no attach.
func TestExecRunsOneCommand(t *testing.T) {
	s := newStack(t, []string{"/bin/sh"}, fastLimits())
	c := s.dial(t, nil, "")
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	out, err := sess.Output("/bin/echo hello")
	if err != nil {
		t.Fatalf("exec failed: %v (output %q)", err, out)
	}
	// **Only** the command's output. The disclosure went to stderr, because stdout here
	// is a caller's data and a banner prepended to it corrupts whatever parses it.
	if strings.TrimSpace(string(out)) != "hello" {
		t.Fatalf("stdout = %q; something other than the command wrote to it", out)
	}
}

// TestExecKeepsStderrSeparateAndPropagatesTheExitCode.
//
// DATA_ERR is in the frame vocabulary for exactly this: stderr arrives on the SSH
// extended-data channel, which is where a local shell would put it.
func TestExecKeepsStderrSeparateAndPropagatesTheExitCode(t *testing.T) {
	s := newStack(t, []string{"/bin/sh"}, fastLimits())
	c := s.dial(t, nil, "")
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	var stdout, stderr syncBuf
	sess.Stdout, sess.Stderr = &stdout, &stderr
	err = sess.Run("/bin/sh -c 'printf out; printf err >&2; exit 3'")

	var exit *xssh.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("err = %v, want an exit status", err)
	}
	if exit.ExitStatus() != 3 {
		t.Fatalf("exit = %d, want 3", exit.ExitStatus())
	}
	if stdout.String() != "out" {
		t.Fatalf("stdout = %q, want only the command's stdout", stdout.String())
	}
	// The disclosure shares stderr with the command, which is the trade: one of the two
	// streams has to carry it, and corrupting the one a caller parses is worse.
	if !strings.Contains(stderr.String(), "err") {
		t.Fatalf("stderr = %q, want the command's stderr in it", stderr.String())
	}
}

// TestExecDoesNotInterpretAShell. There is no `sh -c` between the client and execve, so
// the argv arrives as the client split it.
func TestExecDoesNotInterpretAShell(t *testing.T) {
	s := newStack(t, []string{"/bin/sh"}, fastLimits())
	c := s.dial(t, nil, "")
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	// A single argument full of shell metacharacters. Nothing between the client's
	// lexer and execve interprets it, so it comes back verbatim.
	out, err := sess.Output(`/bin/echo 'a;b|c$(d)'`)
	if err != nil {
		t.Fatalf("exec failed: %v (%q)", err, out)
	}
	if strings.TrimSpace(string(out)) != "a;b|c$(d)" {
		t.Fatalf("stdout = %q; the metacharacters were interpreted somewhere", out)
	}
}

// TestExecRefusesACommandOffTheList, and says so where a caller will see it.
func TestExecRefusesACommandOffTheList(t *testing.T) {
	s := newStack(t, []string{"/bin/sh"}, fastLimits())
	c := s.dial(t, nil, "")
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	var stdout, stderr syncBuf
	sess.Stdout, sess.Stderr = &stdout, &stderr
	if err := sess.Run("/bin/cat /etc/passwd"); err == nil {
		t.Fatal("a command that is not on the device's allow-list ran")
	}
	if stdout.String() != "" {
		t.Fatalf("a refused command wrote to stdout: %q", stdout.String())
	}
	// The device refused, and named the command, so an operator knows what to ask for.
	if !strings.Contains(stderr.String(), "not allowed") {
		t.Fatalf("stderr = %q, want the device's refusal", stderr.String())
	}
}

// TestExecNeedsNoTerminal is the point of the profile: automation does not have one.
func TestExecNeedsNoTerminal(t *testing.T) {
	s := newStack(t, []string{"/bin/sh"}, fastLimits())
	c := s.dial(t, nil, "")
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	// No RequestPty at all, which is what `ssh -T device cmd` and every library client
	// does. A shell in the same position is refused with "this needs a terminal".
	if out, err := sess.Output("/bin/echo hello"); err != nil {
		t.Fatalf("exec required a terminal: %v (%q)", err, out)
	}
}

// TestASubsystemIsStillRefused. `sshpass` is the only one this gateway serves; everything
// else has to say so.
//
// Read through StderrPipe rather than sess.Stderr, and that is not a style choice:
// x/crypto's RequestSubsystem sends the request without calling start(), so the copy
// goroutines that would fill sess.Stderr are never created and it stays empty however long
// you wait. This test used to "pass" through its early-return branch, because no subsystem
// handler was registered at all and the request was rejected outright — so the message it
// was checking for had never once been delivered.
func TestASubsystemIsStillRefused(t *testing.T) {
	s := newStack(t, []string{"/bin/sh"}, fastLimits())
	c := s.dial(t, nil, "")
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	stderr, err := sess.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.RequestSubsystem("sftp"); err != nil {
		return // rejected outright, which is also a refusal
	}
	buf := make([]byte, 256)
	n, _ := stderr.Read(buf)
	if !strings.Contains(string(buf[:n]), "sftp") {
		t.Fatalf("stderr = %q, want it to name the unsupported subsystem", buf[:n])
	}
}

func TestNoPtyIsRefused(t *testing.T) {
	s := newStack(t, []string{"/bin/sh"}, fastLimits())
	c := s.dial(t, nil, "")
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	out := &syncBuf{}
	sess.Stdout, sess.Stderr = out, out
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	_ = sess.Wait()
	if !strings.Contains(out.String(), "needs a terminal") {
		t.Errorf("unexpected message: %q", out.String())
	}
}

func TestConfigValidation(t *testing.T) {
	store := sessions.NewMemory(sessions.Limits{}, nil)
	for name, o := range map[string]sshsrv.Options{
		"no authenticator": {Registry: reg{}, Sessions: store},
		"no registry":      {Sessions: store},
		"no sessions":      {Registry: reg{}},
	} {
		if _, err := sshsrv.New(o); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func fastLimits() pump.Limits {
	return pump.Limits{Batch: 16 << 10, Window: 5 * time.Millisecond,
		HighWater: 256 << 10, LowWater: 64 << 10}
}

// ── mode disclosure and prefix truncation (E2.S4) ───────────────────────────────

// TestStrictKexIsAdvertised is the actual Terrapin defence, asserted rather than
// assumed.
//
// CVE-2023-48795 lets an attacker who can modify traffic delete a bounded number of
// packets immediately after the channel is established — which for a gateway whose
// job includes telling an operator "this session is NOT recorded" is a real attack,
// not a theoretical one. Strict key exchange removes the primitive; x/crypto
// implements it from v0.17.0 and negotiates it automatically, so there is no switch
// to flip and the version pin *is* the control.
//
// This reads the server's KEXINIT off the wire and looks for the marker, so the
// property is checked where it is actually visible rather than inferred from go.mod.
func TestStrictKexIsAdvertised(t *testing.T) {
	s := newStack(t, []string{"/bin/sh"}, fastLimits())

	conn, err := net.DialTimeout("tcp", s.sshAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// A client identification string, or the server will not proceed.
	if _, err := conn.Write([]byte("SSH-2.0-oarlock-test\r\n")); err != nil {
		t.Fatal(err)
	}
	// The server's identification line, then its first binary packet (KEXINIT).
	br := bufio.NewReader(conn)
	ident, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ident, "SSH-2.0-") {
		t.Fatalf("unexpected identification string %q", ident)
	}
	buf := make([]byte, 8192)
	n, err := br.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	const marker = "kex-strict-s-v00@openssh.com"
	if !bytes.Contains(buf[:n], []byte(marker)) {
		t.Fatalf("the server did not advertise %s in its KEXINIT — strict key "+
			"exchange is not in effect, so prefix truncation is possible:\n%q",
			marker, buf[:n])
	}
}

// TestDisclosureIsSaidTwice is the structural half of the same problem.
//
// A disclosure carried by a single early message is one deletion away from never
// having been said. Repeating it as the session ends puts a copy at a point no
// prefix-truncation attack can reach, and that copy carries the session id — which
// is what somebody needs to go and find the recording.
func TestDisclosureIsSaidTwice(t *testing.T) {
	s := newStack(t, []string{"/bin/sh"}, fastLimits())
	c := s.dial(t, nil, "")
	sess, stdin, out := shellSession(t, c)

	waitFor(t, out, "gateway-terminated")
	before := out.String()
	if !strings.Contains(before, "not recorded") {
		t.Errorf("the opening disclosure does not name the recording state: %q", before)
	}

	if _, err := io.WriteString(stdin, "exit 0\n"); err != nil {
		t.Fatal(err)
	}
	_ = sess.Wait()

	got := out.String()
	// Two independent statements of the same fact.
	if n := strings.Count(got, "gateway-terminated"); n < 2 {
		t.Fatalf("the disclosure appears %d time(s); it must be repeated at close "+
			"so deleting the first one cannot suppress it:\n%s", n, got)
	}
	if !strings.Contains(got, "ended") || !strings.Contains(got, "was not recorded") {
		t.Errorf("the closing disclosure is missing or incomplete:\n%s", got)
	}
	// And it names the session, so the recording is findable.
	if !strings.Contains(got, "session sess_") && !strings.Contains(got, "session ") {
		t.Errorf("the closing disclosure does not name the session:\n%s", got)
	}
}

// TestEarlyMessageCarriesNoSecurityClaim: the one thing written inside the window a
// truncation attack could reach is progress text. If a security-relevant claim ever
// migrates into it, this fails.
func TestEarlyMessageCarriesNoSecurityClaim(t *testing.T) {
	// A doorbell that takes its time, so there is a measurable gap between the early
	// message and the disclosure.
	s := newStackSlowDoorbell(t, 400*time.Millisecond)
	c := s.dial(t, nil, "")
	sess, _, out := shellSession(t, c)
	defer sess.Close()

	waitFor(t, out, "waking")
	early := out.String()

	for _, claim := range []string{"recorded", "not recorded", "gateway-terminated", "passthrough"} {
		if strings.Contains(early, claim) {
			t.Errorf("the pre-pairing message contains the security claim %q — it is "+
				"inside the prefix-truncation window and must carry none:\n%q",
				claim, early)
		}
	}
	// The disclosure does arrive, just later.
	waitFor(t, out, "gateway-terminated")
}

// TestRecordedSessionSaysSo: the disclosure has to be able to say the other thing,
// or it is decoration.
func TestRecordedSessionSaysSo(t *testing.T) {
	s := newStackWithRecorder(t)
	c := s.dial(t, nil, "")
	sess, stdin, out := shellSession(t, c)

	waitFor(t, out, "this session is recorded")
	if _, err := io.WriteString(stdin, "exit 0\n"); err != nil {
		t.Fatal(err)
	}
	_ = sess.Wait()
	if !strings.Contains(out.String(), "was recorded") {
		t.Errorf("the closing disclosure does not say it was recorded:\n%s", out.String())
	}
}

// TestAnSSHOperatorIsToldWhatToDo, not merely what happened.
//
// The two surfaces render the same conditions from the same table, so an operator who
// switches surfaces mid-incident is not told two different stories about one device. This
// used to print only the headline: a browser operator was told what to do about a broken
// doorbell and an ssh operator was told only that it was broken.
func TestAnSSHOperatorIsToldWhatToDo(t *testing.T) {
	s := newStack(t, []string{"/bin/sh"}, fastLimits())
	s.failDoorbell(errors.New("mqtt: connection refused"))

	c := s.dial(t, nil, s.dev.ID)
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.RequestPty("xterm", 24, 80, nil); err != nil {
		t.Fatal(err)
	}
	out := &syncBuf{}
	sess.Stdout, sess.Stderr = out, out
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	_ = sess.Wait()

	got := out.String()
	want, ok := condition.Lookup("doorbell_failed")
	if !ok {
		t.Fatal("doorbell_failed is missing from the condition table")
	}
	if !strings.Contains(got, want.Headline) {
		t.Errorf("stderr does not name the thing.\ngot:  %q\nwant: %q", got, want.Headline)
	}
	if !strings.Contains(got, want.NextAction) {
		t.Errorf("stderr does not say what to do about it.\ngot:  %q\nwant: %q",
			got, want.NextAction)
	}
	// A broken doorbell is our fault, and saying "offline" sends somebody to look at
	// hardware in a gym when the broker is what is down.
	if strings.Contains(strings.ToLower(got), "offline") {
		t.Errorf("a broken doorbell was reported as an offline device: %q", got)
	}
}

// ── the three-outcome contract, at the SSH front door ───────────────────────────

type sshAuthz struct {
	allow  bool
	reason string
	err    error
}

func (s *sshAuthz) Authorize(context.Context, *plugin.Principal, *plugin.Device,
	plugin.Action, plugin.Target) (plugin.Decision, error) {
	if s.err != nil {
		return plugin.Decision{}, s.err
	}
	return plugin.Decision{Allow: s.allow, Reason: s.reason}, nil
}

func (s *sshAuthz) Watch(context.Context) (<-chan plugin.RevocationEvent, error) {
	return nil, plugin.ErrUnsupported
}

// withAuthz points the stack at a controllable authorizer for one test.
func withAuthz(t *testing.T, b plugin.Authorizer) {
	t.Helper()
	prev := authzChecker
	authzChecker = &authz.Checker{Backend: b, Log: quiet()}
	t.Cleanup(func() { authzChecker = prev })
}

// shellOutput opens a shell and returns everything the operator saw.
//
// It sends `exit` and bounds the wait, because a session no longer ends when the client's
// stdin reaches EOF — that used to close it, which broke `ssh host < script` by ending the
// session before the device's output came back. What ends a session now is the device's
// shell exiting, a timer, or the connection going away, so a test that wants an ending
// has to ask for one.
func shellOutput(t *testing.T, s *stack) string {
	t.Helper()
	c := s.dial(t, nil, s.dev.ID)
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.RequestPty("xterm", 24, 80, nil); err != nil {
		t.Fatal(err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out := &syncBuf{}
	sess.Stdout, sess.Stderr = out, out
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	_, _ = stdin.Write([]byte("exit\n"))

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = sess.Wait()
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		// A refusal returns before a shell exists, so there is nothing to exit — and
		// the output is already complete.
	}
	return out.String()
}

// TestSSHRefusesADenialWithTheBackendsOwnWords.
//
// "not in the on-call group" tells somebody what to do about it. Our generic copy does
// not, and it is what an operator gets if the backend's sentence is dropped on the way.
func TestSSHRefusesADenialWithTheBackendsOwnWords(t *testing.T) {
	withAuthz(t, &sshAuthz{allow: false, reason: "not in the on-call rota this week"})
	s := newStack(t, []string{"/bin/sh"}, fastLimits())

	got := shellOutput(t, s)
	if !strings.Contains(got, "not in the on-call rota this week") {
		t.Errorf("the backend's reason did not reach the operator:\n%s", got)
	}
	// And no shell was opened.
	if strings.Contains(got, "$") && strings.Contains(got, "oarlock: session") {
		t.Errorf("a denied session produced a shell:\n%s", got)
	}
}

// TestSSHRefusesAnOutageWithoutSayingRevoked is the distinction, on the surface where an
// operator reads a sentence rather than switching on a code.
func TestSSHRefusesAnOutageWithoutSayingRevoked(t *testing.T) {
	withAuthz(t, &sshAuthz{err: errors.New("dial tcp 10.0.0.9:443: connection refused")})
	s := newStack(t, []string{"/bin/sh"}, fastLimits())

	got := shellOutput(t, s)
	want, ok := condition.Lookup("authz_unavailable")
	if !ok {
		t.Fatal("authz_unavailable is missing from the condition table")
	}
	if !strings.Contains(got, want.Headline) {
		t.Errorf("the outage did not produce its own sentence:\ngot:  %q\nwant: %q",
			got, want.Headline)
	}
	// An operator told "your access was revoked" for an outage goes and asks a manager
	// about a permission that was never taken away.
	for _, forbidden := range []string{"revoked", "withdrawn", "don’t have"} {
		if strings.Contains(strings.ToLower(got), strings.ToLower(forbidden)) {
			t.Errorf("an outage read as a revocation (%q):\n%s", forbidden, got)
		}
	}
	// The backend's error is for the logs. An operator cannot act on a dial error.
	if strings.Contains(got, "connection refused") {
		t.Errorf("the backend's error reached the operator:\n%s", got)
	}
}

func TestSSHAllowsWhenAuthorized(t *testing.T) {
	withAuthz(t, &sshAuthz{allow: true})
	s := newStack(t, []string{"/bin/sh"}, fastLimits())
	got := shellOutput(t, s)
	for _, refusal := range []string{"don’t have", "couldn’t confirm"} {
		if strings.Contains(got, refusal) {
			t.Errorf("an authorized session was refused:\n%s", got)
		}
	}
}
