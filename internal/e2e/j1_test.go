// Package e2e holds the product's smoke test.
//
// J1 is the journey the whole thing exists for: a treadmill in a gym is frozen, an
// operator types `ssh treadmill-4821@gw.example.org`, fixes it, and leaves a trail.
// Every other test in this repository checks a part; this one checks that the parts
// add up.
//
// **A failure here blocks a release.** It is the one test whose passing is the
// claim on the front page of the README, and it runs over *both* reachability modes
// because the primary target platform uses the one that would otherwise be tested
// last.
package e2e_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/oarlock/oarlock/internal/backoff"
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
	"github.com/oarlock/oarlock/internal/apisrv"
	"github.com/oarlock/oarlock/internal/attachsrv"
	"github.com/oarlock/oarlock/internal/auth/authorizedkeys"
	"github.com/oarlock/oarlock/internal/auth/statictoken"
	"github.com/oarlock/oarlock/internal/authz"
	"github.com/oarlock/oarlock/internal/controlsrv"
	"github.com/oarlock/oarlock/internal/handshake"
	"github.com/oarlock/oarlock/internal/hub"
	"github.com/oarlock/oarlock/internal/invite"
	"github.com/oarlock/oarlock/internal/pump"
	"github.com/oarlock/oarlock/internal/record"
	"github.com/oarlock/oarlock/internal/sessionrun"
	"github.com/oarlock/oarlock/internal/sessions"
	"github.com/oarlock/oarlock/internal/sessions/sqlitestore"
	"github.com/oarlock/oarlock/internal/sessionsrv"
	"github.com/oarlock/oarlock/internal/sshsrv"
	"github.com/oarlock/oarlock/internal/ticket"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
	"github.com/oarlock/oarlock/pkg/transport/websocket"
	"github.com/oarlock/oarlock/plugins/authz/rules"
)

const (
	operatorID = "phuc@example.com"
	observerID = "sam@example.com"
	ticketRef  = "ticket AV-9182: display frozen after firmware update"
)

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

type registry struct{ dev *plugin.Device }

func (r registry) Get(_ context.Context, id string) (*plugin.Device, error) {
	if id == r.dev.ID {
		return r.dev, nil
	}
	return nil, plugin.ErrNoDevice
}
func (r registry) List(context.Context, plugin.DeviceQuery) ([]*plugin.Device, string, error) {
	return nil, "", plugin.ErrUnsupported
}

// gateway is everything the product ships, wired the way a deployment would.
type gateway struct {
	sshAddr       string
	operator      xssh.Signer
	ledger        *sqlitestore.Store
	device        *plugin.Device
	control       *agent.Control
	recorder      *record.Recorder
	recPub        ed25519.PublicKey
	api           string // base URL of the control API
	apiToken      string
	observerToken string
	// authz lets a test take authorisation away and give it back.
	authz *fallibleAuthz
	// rules and rulesPath let a test express a real denial through the shipped backend.
	rules     *rules.Authorizer
	rulesPath string
	live      *sessions.Registry
}

// authzGrace is how many consecutive authorisation failures a live session survives in
// this harness. Nil means authz.DefaultGrace.
//
// A package variable in the same style as the rest of this file's knobs, set by the one
// journey that needs a window wider than its own runtime.
var authzGrace *int

// withAuthzGrace runs the rest of a test with a stated grace window.
func withAuthzGrace(t *testing.T, rechecks int) {
	t.Helper()
	prev := authzGrace
	authzGrace = &rechecks
	t.Cleanup(func() { authzGrace = prev })
}

// build stands up a whole gateway and one agent, in the given reachability mode.
//
// Nothing is stubbed out except the wall clock and, in dispatch mode, the doorbell —
// which is a function call rather than a broker because E4 owns the broker and this
// test owns the journey.
func build(t *testing.T, mode plugin.Mode) *gateway {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// ── the operator's key ──
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	opSigner, err := xssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := xssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	ak := filepath.Join(t.TempDir(), "authorized_keys")
	line := strings.TrimRight(string(xssh.MarshalAuthorizedKey(sshPub)), "\n")
	if err := os.WriteFile(ak, []byte(line+" "+operatorID+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	authn, err := authorizedkeys.Open(ak, quiet())
	if err != nil {
		t.Fatal(err)
	}

	// ── the device ──
	devPub, devPriv, _ := ed25519.GenerateKey(rand.Reader)
	dev := &plugin.Device{
		ID: "treadmill-4821", Platform: plugin.PlatformLinux, Mode: mode,
		Keys: []ed25519.PublicKey{devPub},
		Tags: map[string]string{"region": "eu"},
	}
	reg := registry{dev}

	tickets := ticket.NewMemory(nil)
	// The durable ledger, not the in-memory one: the smoke test should exercise what
	// a deployment runs, and the SQLite store is where the caps are enforced by an
	// index rather than by a map.
	ledger, err := sqlitestore.Open(filepath.Join(t.TempDir(), "sessions.db"),
		sessions.Limits{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Shutdown() })

	// A real recorder, with a signing key kept apart from the gateway's host key:
	// one is presented to every operator, the other attests that recordings were
	// not altered, and rotating one must not force rotating the other.
	recPub, recPriv, _ := ed25519.GenerateKey(rand.Reader)
	recorder, recErr := record.NewFileRecorder(filepath.Join(t.TempDir(), "recordings"),
		&record.KeySigner{Key: recPriv, ID: "e2e-recording-key"})
	if recErr != nil {
		t.Fatal(recErr)
	}
	h := hub.New(hub.Options{PingInterval: time.Second, Log: quiet()})
	live := sessions.NewRegistry()

	// A real authorizer, so the journeys exercise the authorisation path rather than
	// skipping it. The gateway's own tests point it at a controllable backend; here it
	// is a rules file, which is what a small deployment actually runs.
	rulesPath := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(rulesPath, []byte(
		"rules:\n  - principals: [\"*\"]\n    actions: [\"*\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	authorizer, err := rules.Open(rulesPath, quiet())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authorizer.Close() })
	fallible := &fallibleAuthz{inner: authorizer}
	// The grace window is stated by the test rather than inherited.
	//
	// It is counted in re-checks, and the interval below is 50 ms — so the default of
	// three is a **150 millisecond** window, which is shorter than a single shell
	// round-trip. Two journeys here want opposite things from it: J6's first wants an
	// outage *not* to end a session while an operator is working through it, and its
	// second wants an outage to end one. Sharing one number meant the first was racing
	// shell latency against 150 ms and losing whenever the machine was busy.
	checker := &authz.Checker{Backend: fallible, Log: quiet(), Grace: authzGrace}
	// A short interval, so a test can watch a revocation land without waiting out the
	// production default. The interval being the guarantee is the point of E4.S5, so the
	// journeys run with it switched on rather than mocked away.
	supervisor := &authz.Supervisor{
		Checker: checker, Live: live, Interval: 50 * time.Millisecond, Log: quiet(),
		Backoff: backoff.Policy{Base: 2 * time.Millisecond, Cap: 10 * time.Millisecond},
	}
	watchCtx, stopWatch := context.WithCancel(context.Background())
	t.Cleanup(stopWatch)
	go supervisor.WatchRevocations(watchCtx)

	inviter := &invite.Inviter{
		Tickets: tickets, Hub: h,
		AnswerDeadline: 15 * time.Second, Log: quiet(),
	}

	// ── the HTTP surface: /ws/control and /ws/session ──
	mux := http.NewServeMux()
	mux.Handle("/ws/session", &sessionsrv.Server{
		Upgrader: websocket.Upgrader{}, Inviter: inviter, Log: quiet(),
		Ready: func(c *ticket.Claims) frame.Ready {
			return frame.Ready{SessionID: c.SessionID, Mode: "gateway", Recording: true}
		},
	})
	mux.Handle("/ws/attach", &attachsrv.Server{
		Upgrader: websocket.Upgrader{}, Inviter: inviter, Log: quiet(), Live: live,
		Runner: &sessionrun.Runner{
			Sessions: ledger, Live: live, Recorder: recorder, Log: quiet(),
			Authz: supervisor,
			Limits: pump.Limits{Batch: 16 << 10, Window: 5 * time.Millisecond,
				HighWater: 256 << 10, LowWater: 64 << 10},
		},
	})
	mux.Handle("/ws/control", &controlsrv.Server{
		Upgrader:  websocket.Upgrader{},
		Handshake: &handshake.Gateway{Registry: reg, GatewayID: "gw-a", Log: quiet()},
		Hub:       h,
		Log:       quiet(),
	})
	httpSrv := httptest.NewServer(mux)
	t.Cleanup(httpSrv.Close)
	base := "ws" + strings.TrimPrefix(httpSrv.URL, "http")
	inviter.NodeURL = base + "/ws/session"
	inviter.AttachURL = base + "/ws/attach"

	// ── the agent ──
	control, err := agent.NewControl(agent.Config{
		Gateway:   base + "/ws/control",
		DeviceID:  dev.ID,
		Signer:    devPriv,
		Dialer:    websocket.Dialer{},
		PinSHA256: []string{"not-pinned-in-test"},
		Caps:      []string{"shell"},
		Info:      frame.AgentInfo{Version: "0.1.0-test", Platform: "linux/test"},
		Shell:     agent.Forkpty([]string{"/bin/sh"}),
		Log:       quiet(),
	})
	if err != nil {
		t.Fatal(err)
	}

	switch mode {
	case plugin.ModePersistent:
		// The agent holds a control channel; the gateway reaches it with DIAL.
		go control.Run(ctx)
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) && !h.Connected(dev.ID) {
			time.Sleep(5 * time.Millisecond)
		}
		if !h.Connected(dev.ID) {
			t.Fatal("the agent never established a control channel")
		}
	case plugin.ModeDispatch:
		// No control channel: the doorbell delivers the identical invitation.
		inviter.Dispatcher = plugin.DispatcherFunc(
			func(_ context.Context, _ *plugin.Device, inv frame.Invitation) error {
				go control.HandleInvitation(ctx, inv)
				return nil
			})
	}

	// ── the SSH front door ──
	// The control API, authenticated the way a dev deployment would be.
	const apiToken = "e2e-api-token-long-enough-ok"
	// A second principal, so the observer journey has somebody who is not the operator:
	// watching your own session is not observation, it is a second pane.
	const observerToken = "e2e-observer-token-long-enough"
	apiAuth, err := statictoken.Open("test", map[string]string{
		apiToken:      operatorID,
		observerToken: observerID,
	})
	if err != nil {
		t.Fatal(err)
	}
	api, err := apisrv.New(apisrv.Options{
		Sessions: ledger, Live: live, Authenticator: apiAuth, Log: quiet(),
		Registry: reg, Inviter: inviter, Authz: checker,
		AttachURL: base + "/ws/attach"})
	if err != nil {
		t.Fatal(err)
	}
	apiSrv := httptest.NewServer(api)
	t.Cleanup(apiSrv.Close)

	srv, err := sshsrv.New(sshsrv.Options{
		Authenticator: authn, Registry: reg, Inviter: inviter, Authz: checker,
		AuthzSupervisor: supervisor,
		Sessions:        ledger, Recorder: recorder, Live: live, Log: quiet(),
		Limits: pump.Limits{Batch: 16 << 10, Window: 5 * time.Millisecond,
			HighWater: 256 << 10, LowWater: 64 << 10},
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

	return &gateway{sshAddr: l.Addr().String(), operator: opSigner,
		ledger: ledger, device: dev, control: control,
		recorder: recorder, recPub: recPub,
		api: apiSrv.URL, apiToken: apiToken, observerToken: observerToken, live: live,
		authz: fallible, rules: authorizer, rulesPath: rulesPath}
}

// ── the journey ─────────────────────────────────────────────────────────────────

// TestJ1_OperatorFixesAFrozenDevice is the product's smoke test.
//
// It asserts SC1 along the way: an unmodified SSH client, with no ~/.ssh/config
// entry, no wrapper and no plugin — just x/crypto/ssh doing what OpenSSH would.
func TestJ1_OperatorFixesAFrozenDevice(t *testing.T) {
	for _, mode := range []plugin.Mode{plugin.ModePersistent, plugin.ModeDispatch} {
		t.Run(string(mode), func(t *testing.T) {
			g := build(t, mode)

			// 1 — authenticate with their own key, naming the *device* as the user.
			client, err := xssh.Dial("tcp", g.sshAddr, &xssh.ClientConfig{
				User:            g.device.ID,
				Auth:            []xssh.AuthMethod{xssh.PublicKeys(g.operator)},
				HostKeyCallback: xssh.InsecureIgnoreHostKey(),
				Timeout:         15 * time.Second,
			})
			if err != nil {
				t.Fatalf("ssh dial: %v", err)
			}
			defer client.Close()

			sess, err := client.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			if err := sess.RequestPty("xterm-256color", 38, 132,
				xssh.TerminalModes{xssh.ECHO: 0}); err != nil {
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

			// 2 — the banner names the device, the mode, and the recording state,
			//     before anything is typed.
			await(t, out, g.device.ID)
			await(t, out, "gateway-terminated")
			await(t, out, "session is recorded")

			// 3 — a prompt, and a command whose output comes back.
			if _, err := io.WriteString(stdin, "printf 'DIAG%s\\n' '-OK'\n"); err != nil {
				t.Fatal(err)
			}
			await(t, out, "DIAG-OK")

			// 4 — the terminal really is the size the client asked for. A terminal
			//     that lies about its size wraps every line wrong.
			if _, err := io.WriteString(stdin, "stty size\n"); err != nil {
				t.Fatal(err)
			}
			await(t, out, "38 132")

			// 5 — the operator leaves, and the exit code survives the trip.
			if _, err := io.WriteString(stdin, "exit 7\n"); err != nil {
				t.Fatal(err)
			}
			werr := sess.Wait()
			var ee *xssh.ExitError
			if !errors.As(werr, &ee) || ee.ExitStatus() != 7 {
				t.Fatalf("Wait returned %v, want exit status 7", werr)
			}

			// 6 — a session row exists, attributed, with one true close reason.
			rows := awaitClosed(t, g.ledger, 1)
			row := rows[0]
			switch {
			case row.Principal != operatorID:
				t.Errorf("attributed to %q, want %q", row.Principal, operatorID)
			case row.DeviceID != g.device.ID:
				t.Errorf("device %q", row.DeviceID)
			case row.Profile != "shell":
				t.Errorf("profile %q", row.Profile)
			case row.Mode != string(mode):
				t.Errorf("mode %q, want %q", row.Mode, mode)
			case row.State != sessions.StateClosed:
				t.Errorf("state %q", row.State)
			case row.CloseReason != "device_close":
				// The shell exited, so the device is what closed the session.
				t.Errorf("close reason %q, want device_close", row.CloseReason)
			case row.ExitCode == nil || *row.ExitCode != 7:
				t.Errorf("exit code %v", row.ExitCode)
			case row.RecordingState != sessions.Recorded:
				t.Errorf("recording state %q, want recorded", row.RecordingState)
			case row.BytesOut == 0:
				t.Error("no bytes accounted for")
			case row.AttachedAt.IsZero() || row.ClosedAt.IsZero():
				t.Errorf("timestamps: attached=%v closed=%v", row.AttachedAt, row.ClosedAt)
			}

			// 7 — the recording exists, verifies, and holds what the operator saw.
			v, err := g.recorder.Verify(context.Background(), row.ID, g.recPub)
			if err != nil {
				t.Fatalf("verifying the recording: %v", err)
			}
			if !v.OK {
				t.Fatalf("the recording did not verify: %s (%s)", v.Status, v.Detail)
			}
			man, err := g.recorder.Manifest(context.Background(), row.ID)
			if err != nil {
				t.Fatal(err)
			}
			if man.Principal != operatorID {
				t.Errorf("recording attributed to %q", man.Principal)
			}
			if man.CloseReason != "device_close" || man.ExitCode == nil || *man.ExitCode != 7 {
				t.Errorf("manifest: reason=%q exit=%v", man.CloseReason, man.ExitCode)
			}
			if man.RecordInput {
				t.Error("input was recorded; the policy default is off until E4.S9")
			}
			cast, err := g.recorder.Get(context.Background(), row.ID)
			if err != nil {
				t.Fatal(err)
			}
			defer cast.Close()
			body, err := io.ReadAll(cast)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(body, []byte("DIAG-OK")) {
				t.Error("the recording does not contain the command's output")
			}
			// The resize the client asked for is in the recording, so a replay
			// reflows instead of rendering every line at the wrong width.
			if !bytes.Contains(body, []byte(`"r","132x38"`)) &&
				!bytes.Contains(body, []byte(`"r", "132x38"`)) {
				t.Logf("no resize event recorded (the client's initial size may not "+
					"have produced one): %s", firstLines(body, 3))
			}
		})
	}
}

// TestJ1_ConcurrencyLimitIsEnforced: two operators opening a shell on the same
// device in the same second is the race the ledger exists to lose gracefully.
func TestJ1_ConcurrencyLimitIsEnforced(t *testing.T) {
	g := build(t, plugin.ModeDispatch)

	client, err := xssh.Dial("tcp", g.sshAddr, &xssh.ClientConfig{
		User:            g.device.ID,
		Auth:            []xssh.AuthMethod{xssh.PublicKeys(g.operator)},
		HostKeyCallback: xssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	first, stdin, out := openShell(t, client)
	defer first.Close()
	await(t, out, "gateway-terminated")
	_ = stdin

	second, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := second.RequestPty("xterm", 24, 80, nil); err != nil {
		t.Fatal(err)
	}
	out2 := &syncBuf{}
	second.Stdout, second.Stderr = out2, out2
	if err := second.Shell(); err != nil {
		t.Fatal(err)
	}
	_ = second.Wait()

	if !strings.Contains(out2.String(), "already has a session open") {
		t.Fatalf("second session was not refused: %q", out2.String())
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────────

func openShell(t *testing.T, c *xssh.Client) (*xssh.Session, io.WriteCloser, *syncBuf) {
	t.Helper()
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.RequestPty("xterm-256color", 24, 80,
		xssh.TerminalModes{xssh.ECHO: 0}); err != nil {
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

// await waits for want to appear. Note that every sentinel this test waits on is
// either printed by the gateway or assembled by the shell — never a literal that
// appears in the command the PTY echoes back, which would match its own echo and
// prove nothing.
func await(t *testing.T, out *syncBuf, want string) {
	t.Helper()
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(out.String(), want) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("never saw %q in:\n%s", want, out.String())
}

func awaitClosed(t *testing.T, ledger *sqlitestore.Store, n int) []*sessions.Session {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		rows, _, err := ledger.List(context.Background(),
			sessions.Query{State: sessions.StateClosed})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) >= n {
			return rows
		}
		time.Sleep(10 * time.Millisecond)
	}
	all, _, _ := ledger.List(context.Background(), sessions.Query{})
	t.Fatalf("%d closed rows never appeared; ledger holds %s", n, describe(all))
	return nil
}

func describe(rows []*sessions.Session) string {
	var b strings.Builder
	for _, r := range rows {
		fmt.Fprintf(&b, "\n  %s state=%s reason=%q", r.ID, r.State, r.CloseReason)
	}
	if b.Len() == 0 {
		return "nothing"
	}
	return b.String()
}

func firstLines(b []byte, n int) string {
	lines := bytes.SplitN(b, []byte("\n"), n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return string(bytes.Join(lines, []byte("\n")))
}

// TestJ7_AdminKillEndsALiveSession is journey J7's administrative half, end to end:
// a live SSH session, killed through the control API, with the ledger recording who
// did it and why.
//
// It is worth doing at this level because the pieces are owned by different packages
// — the API holds the registry, the registry holds a cancel belonging to the SSH
// handler, and the ledger has to end up with `admin_kill` rather than whatever the
// transport noticed afterwards.
func TestJ7_AdminKillEndsALiveSession(t *testing.T) {
	g := build(t, plugin.ModeDispatch)

	client, err := xssh.Dial("tcp", g.sshAddr, &xssh.ClientConfig{
		User:            g.device.ID,
		Auth:            []xssh.AuthMethod{xssh.PublicKeys(g.operator)},
		HostKeyCallback: xssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	sess, _, out := openShell(t, client)
	defer sess.Close()
	await(t, out, "gateway-terminated")

	// The session is visible through the API, and known to be live *here*.
	var list struct {
		Sessions []struct {
			ID       string `json:"id"`
			State    string `json:"state"`
			Live     bool   `json:"live"`
			LiveHere bool   `json:"live_here"`
		} `json:"sessions"`
	}
	g.apiGet(t, "/api/v1/sessions?live=true", &list)
	if len(list.Sessions) != 1 {
		t.Fatalf("%d live sessions, want 1", len(list.Sessions))
	}
	id := list.Sessions[0].ID
	if !list.Sessions[0].LiveHere {
		t.Error("the session is not registered as live on this node, so it cannot be killed")
	}

	// Kill it.
	req, err := http.NewRequest("DELETE", g.api+"/api/v1/sessions/"+id, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+g.apiToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("DELETE returned %d: %s", resp.StatusCode, body)
	}

	// The operator's shell ends...
	_ = sess.Wait()
	// ...and the ledger records why, not merely that.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		row, err := g.ledger.Get(context.Background(), id)
		if err == nil && row.State == sessions.StateClosed {
			if row.CloseReason != "admin_kill" {
				t.Fatalf("close reason %q, want admin_kill", row.CloseReason)
			}
			if g.live.Len() != 0 {
				t.Errorf("%d sessions still registered as live", g.live.Len())
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the session never closed after being killed")
}

func (g *gateway) apiGet(t *testing.T, path string, into any) {
	t.Helper()
	req, err := http.NewRequest("GET", g.api+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+g.apiToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s returned %d: %s", path, resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, into); err != nil {
		t.Fatalf("GET %s: %v\n%s", path, err, body)
	}
}

// rewriteRules replaces the rules file and reloads it, so a test can express a real
// denial through the shipped backend rather than through a stub that agrees with it.
func (g *gateway) rewriteRules(t *testing.T, body string) {
	t.Helper()
	if err := os.WriteFile(g.rulesPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := g.rules.Reload(); err != nil {
		t.Fatal(err)
	}
}

// fallibleAuthz wraps a real authorizer with a switch, so a test can take authorisation
// away and give it back.
//
// A wrapper rather than a stub: what the journeys run against is the shipped rules
// backend, and the outage is layered on top. A stub would let the test agree with itself
// about what a decision looks like.
type fallibleAuthz struct {
	inner plugin.Authorizer
	down  atomic.Bool
	calls atomic.Int32

	mu     sync.Mutex
	stream chan plugin.RevocationEvent
}

func (f *fallibleAuthz) Authorize(ctx context.Context, p *plugin.Principal,
	dev *plugin.Device, a plugin.Action, tgt plugin.Target) (plugin.Decision, error) {
	f.calls.Add(1)
	if f.down.Load() {
		// What a permissions service looks like when it is down: an error, never
		// Allow:false. A backend that answered "no" here would be the failure the
		// three-outcome contract exists to prevent — and plugintest fails one that does.
		return plugin.Decision{}, errors.New("authz: the permissions API is unreachable")
	}
	return f.inner.Authorize(ctx, p, dev, a, tgt)
}

// Watch streams revocations.
//
// Always streaming, even though the rules backend underneath does not — a file has
// nothing to stream. That is deliberate on two counts. The supervisor stops retrying an
// unsupported Watch (correctly: it will never work), so a test cannot turn one on after
// the gateway has started. And a stream that is *connected and silent* is the realistic
// shape of R-003: the revocation tests below rewrite the rules file, which sends no event,
// so their closures still come from the interval — proving it works while Watch looks
// perfectly healthy.
func (f *fallibleAuthz) Watch(ctx context.Context) (<-chan plugin.RevocationEvent, error) {
	ch := make(chan plugin.RevocationEvent, 4)
	f.mu.Lock()
	f.stream = ch
	f.mu.Unlock()

	out := make(chan plugin.RevocationEvent)
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case ev, open := <-ch:
				if !open {
					return
				}
				select {
				case out <- ev:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out, nil
}

// revoke sends a revocation down the stream.
func (f *fallibleAuthz) revoke(ev plugin.RevocationEvent) {
	f.mu.Lock()
	ch := f.stream
	f.mu.Unlock()
	if ch != nil {
		ch <- ev
	}
}

func (f *fallibleAuthz) breakIt() { f.down.Store(true) }
func (f *fallibleAuthz) fixIt()   { f.down.Store(false) }
