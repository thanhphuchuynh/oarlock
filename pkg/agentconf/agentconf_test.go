package agentconf_test

// Testing the suite, which matters more than it sounds.
//
// A conformance suite that passes everything is worse than no suite: it converts "we did
// not check" into "we checked and it was fine", and hands an implementer a green result
// for an agent that will fail in the field. So the tests here come in two halves — the
// reference agent must pass, and an agent that is deliberately wrong must *fail on the
// case that names its fault*.
//
// This is the discipline pkg/plugin/plugintest set for the backend suites, for the same
// reason.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/oarlock/oarlock/agent"
	"github.com/oarlock/oarlock/internal/backoff"
	"github.com/oarlock/oarlock/internal/handshake"
	"github.com/oarlock/oarlock/pkg/agentconf"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/transport"
	"github.com/oarlock/oarlock/pkg/transport/websocket"
)

const deviceID = "conformance-device"

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// harness stands the suite up on a real HTTP server, so an agent reaches it the way one
// would in the field.
type harness struct {
	suite      *agentconf.Suite
	controlURL string
	sessionURL string
	key        ed25519.PrivateKey
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	base := "ws" + strings.TrimPrefix(srv.URL, "http")

	suite, err := agentconf.New(agentconf.Options{
		DeviceID:  deviceID,
		PublicKey: pub,
		GatewayID: "conformance-suite",
		// Short, because these tests drive the reconnect loop many times and the
		// defaults are sized for a real agent's documented backoff.
		CaseTimeout:    3 * time.Second,
		ConnectTimeout: 5 * time.Second,
		SessionURL:     base + "/ws/session",
	}, websocket.Upgrader{})
	if err != nil {
		t.Fatal(err)
	}
	mux.HandleFunc("/ws/control", suite.Control)
	mux.HandleFunc("/ws/session", suite.Session)

	return &harness{
		suite: suite, key: priv,
		controlURL: base + "/ws/control",
		sessionURL: base + "/ws/session",
	}
}

// result finds one case by a substring of its name.
func result(t *testing.T, r agentconf.Report, substr string) agentconf.Result {
	t.Helper()
	for _, res := range r.Results {
		if strings.Contains(res.Name, substr) {
			return res
		}
	}
	t.Fatalf("no case matching %q in:\n%s", substr, r)
	return agentconf.Result{}
}

// ── the reference agent must pass ───────────────────────────────────────────────

// TestTheReferenceAgentConforms.
//
// If this fails, either the agent is wrong or the suite is — and the suite is written
// against docs/protocol.md rather than against the agent, so the two disagreeing is
// exactly the signal it exists to produce.
func TestTheReferenceAgentConforms(t *testing.T) {
	h := newHarness(t)

	ctrl, err := agent.NewControl(agent.Config{
		Gateway:  h.controlURL,
		DeviceID: deviceID,
		Signer:   h.key,
		Dialer:   websocket.Dialer{},
		Caps:     []string{"shell", "exec"},
		Info:     frame.AgentInfo{Version: "conformance-test"},
		Log:      quiet(),
		// Tight, so the suite's ten connections do not spend a minute in backoff. The
		// GOAWAY case still asserts the gateway's delay wins over this.
		Backoff: backoff.Policy{Base: 20 * time.Millisecond, Cap: 100 * time.Millisecond, Factor: 1},
		// A shell it will never be asked to open: the DIAL case only checks the OPEN
		// frame, and an agent with no Shell would refuse before sending one.
		Shell: func(context.Context, agent.ShellRequest) (agent.PTY, error) {
			return nil, context.Canceled
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ctrl.Run(ctx) }()

	rep := h.suite.Run(context.Background())
	if !rep.Passed() {
		t.Fatalf("the reference agent does not pass its own conformance suite:\n%s", rep)
	}
	// A run where everything skipped is not a pass. Assert the cases that carry the
	// protocol actually ran.
	for _, want := range []string{"handshake completes", "ping is echoed", "session frame"} {
		if res := result(t, rep, want); res.Status != agentconf.Pass {
			t.Errorf("%q was %s, want pass: %s", res.Name, res.Status, res.Detail)
		}
	}
	t.Logf("report:\n%s", rep)
}

// ── a broken agent must fail ────────────────────────────────────────────────────

// tolerantAgent answers PING and never closes the connection for anything, which is the
// most plausible way to get the scope rules wrong: reading the frame type you know about
// and ignoring the rest.
//
// It is a whole agent in forty lines, which is itself worth knowing — the suite is
// reachable by an implementation that has not built any of the rest of Oarlock.
func tolerantAgent(t *testing.T, h *harness, ctx context.Context) {
	t.Helper()
	go func() {
		codec := frame.Codec{}
		for ctx.Err() == nil {
			conn, err := websocket.Dialer{}.Dial(ctx, h.controlURL, transport.Options{
				MaxMessageBytes: frame.MaxFrame,
			})
			if err != nil {
				time.Sleep(20 * time.Millisecond)
				continue
			}
			hs := &handshake.Agent{DeviceID: deviceID, Signer: h.key, Caps: []string{"shell"}}
			if _, err := hs.Perform(ctx, conn); err != nil {
				_ = conn.Close(transport.CloseNormal, "handshake failed")
				time.Sleep(20 * time.Millisecond)
				continue
			}
			// Serve until the peer hangs up, closing for nothing.
			for {
				msg, err := conn.Recv(ctx)
				if err != nil {
					break
				}
				f, derr := codec.Decode(msg)
				if derr != nil {
					continue // and carry on, which is the fault
				}
				if f.Type == frame.TypePing {
					stamp, serr := frame.ReadStamp(f)
					if serr != nil {
						continue
					}
					pong, _ := frame.Stamp(frame.TypePong, stamp)
					wire, _ := codec.Encode(nil, pong)
					_ = conn.Send(ctx, wire)
				}
			}
			_ = conn.Close(transport.CloseNormal, "peer gone")
		}
	}()
}

// TestAnAgentThatNeverClosesFailsTheScopeCases.
//
// The suite's whole value is here. An agent that answers the frames it knows and shrugs at
// everything else looks fine in casual use and is wrong in the way § 2.3 is about — and the
// report has to say which rule it broke, not merely that something went wrong.
func TestAnAgentThatNeverClosesFailsTheScopeCases(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tolerantAgent(t, h, ctx)

	rep := h.suite.Run(context.Background())
	if rep.Passed() {
		t.Fatalf("an agent that never closes a connection passed the suite:\n%s", rep)
	}

	// PING it does answer, so that case must still pass — a suite that failed everything
	// once anything was wrong would be useless for finding out *what* is wrong.
	if res := result(t, rep, "ping is echoed"); res.Status != agentconf.Pass {
		t.Errorf("the ping case was %s; this agent answers pings correctly: %s",
			res.Status, res.Detail)
	}
	for _, want := range []string{"session frame on the control channel", "unknown connection-scoped"} {
		res := result(t, rep, want)
		if res.Status != agentconf.Fail {
			t.Errorf("%q was %s, want fail", res.Name, res.Status)
		}
		if res.Detail == "" {
			t.Errorf("%q failed with no explanation", res.Name)
		}
	}
	t.Logf("report:\n%s", rep)
}

// TestAnAgentThatNeverConnectsIsReportedOnce.
//
// Nine timeouts for one cause is a report nobody reads. The suite runs the handshake case
// first and stops when it fails, so the answer is one line and a note saying why the rest
// did not run.
func TestAnAgentThatNeverConnectsIsReportedOnce(t *testing.T) {
	h := newHarness(t)
	// No agent at all.

	rep := h.suite.Run(context.Background())
	if rep.Passed() {
		t.Fatal("the suite passed with no agent connected")
	}
	if n := len(rep.Results); n != 1 {
		t.Fatalf("%d cases reported for one cause; want the run to stop after the "+
			"handshake:\n%s", n, rep)
	}
	res := rep.Results[0]
	if res.Status != agentconf.Timeout {
		t.Fatalf("status = %s, want timeout", res.Status)
	}
	if !strings.Contains(res.Detail, "control URL") {
		t.Fatalf("the detail does not tell the implementer what to check: %q", res.Detail)
	}
	var joined string
	for _, n := range rep.Notes {
		joined += n + "\n"
	}
	if !strings.Contains(joined, "did not run") {
		t.Fatalf("the notes do not say the rest of the suite was skipped:\n%s", joined)
	}
}

// ── the report ──────────────────────────────────────────────────────────────────

// TestTheReportNamesWhatItCannotCheck.
//
// A conformance report that implies coverage it does not have is the failure mode of every
// compliance exercise. Four things are invisible from the wire, and the report says so on
// every run rather than in a document somebody might read.
func TestTheReportNamesWhatItCannotCheck(t *testing.T) {
	h := newHarness(t)
	rep := h.suite.Run(context.Background())

	var joined string
	for _, n := range rep.Notes {
		joined += n + "\n"
	}
	for _, want := range []string{"private key", "pins the gateway certificate",
		"allow-lists", "session leg"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the report does not mention %q as unchecked:\n%s", want, joined)
		}
	}
	// And a skip is not counted as a pass.
	if strings.Contains(rep.String(), "0 skipped") && len(rep.Results) > 1 {
		t.Error("the summary does not separate skips from passes")
	}
}

// TestOptionsAreValidated. A suite told to trust no key would verify no signature and pass
// anything, which is the one configuration mistake that produces a green result for
// nothing at all.
func TestOptionsAreValidated(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	for name, o := range map[string]agentconf.Options{
		"no device id":  {PublicKey: pub},
		"no public key": {DeviceID: "d"},
		"a short key":   {DeviceID: "d", PublicKey: ed25519.PublicKey("too short")},
	} {
		if _, err := agentconf.New(o, websocket.Upgrader{}); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := agentconf.New(agentconf.Options{DeviceID: "d", PublicKey: pub}, nil); err == nil {
		t.Error("a suite with no upgrader was accepted")
	}
}
