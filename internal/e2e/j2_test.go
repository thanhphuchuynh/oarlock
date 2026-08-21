package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/sessions"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
	"github.com/oarlock/oarlock/pkg/transport"
	"github.com/oarlock/oarlock/pkg/transport/websocket"
)

// J2 — the operator with no terminal to hand.
//
// This is the browser journey driven from Go: a real `POST /api/v1/sessions`, a real
// WebSocket to `/ws/attach`, real frames, a real PTY at the far end. It is not a
// substitute for the front-end tests in `test-design-epic-3.md` — those cover what a
// *browser* does with the frames — but it is what proves the server side of the two-
// sided flow works, and it can run in CI today with no front-end toolchain.

type browser struct {
	conn    transport.Conn
	session string
	ready   frame.Ready
}

// openSession does what an integrator's backend does: one POST, and it gets back a
// session plus a single-use ticket.
func (g *gateway) openSession(t *testing.T, deviceID, reason string) (map[string]any, map[string]any) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"device_id": deviceID,
		"profile":   "shell",
		"pty":       map[string]any{"cols": 132, "rows": 38, "term": "xterm-256color"},
		"reason":    reason,
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("POST", g.api+"/api/v1/sessions", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+g.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /sessions returned %d: %s", resp.StatusCode, raw)
	}
	var out struct {
		Session map[string]any `json:"session"`
		Attach  map[string]any `json:"attach"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("%v\n%s", err, raw)
	}
	// The ticket is in the body and nowhere else.
	if strings.Contains(resp.Request.URL.String(), "ticket") {
		t.Error("a ticket appeared in the request URL")
	}
	return out.Session, out.Attach
}

// attach does what the browser component does.
func (g *gateway) attach(t *testing.T, attach map[string]any) *browser {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	url, _ := attach["url"].(string)
	tk, _ := attach["ticket"].(string)
	if url == "" || tk == "" {
		t.Fatalf("attach block is incomplete: %+v", attach)
	}
	conn, err := websocket.Dialer{}.Dial(ctx, url, transport.Options{})
	if err != nil {
		t.Fatalf("dial %s: %v", url, err)
	}
	t.Cleanup(func() { _ = conn.Close(transport.CloseNormal, "test over") })

	send(t, conn, mustFrame(t, frame.TypeOpen, frame.Open{
		Ticket: tk,
		PTY:    &frame.PTY{Cols: 132, Rows: 38, Term: "xterm-256color"},
	}))
	f := recvFrame(t, conn, 15*time.Second)
	if f.Type == frame.TypeError {
		var e frame.Error
		_ = frame.Unmarshal(f, &e)
		t.Fatalf("attach refused: %s: %s", e.Code, e.Message)
	}
	if f.Type != frame.TypeReady {
		t.Fatalf("first frame is %v, want READY", f.Type)
	}
	var ready frame.Ready
	if err := frame.Unmarshal(f, &ready); err != nil {
		t.Fatal(err)
	}
	return &browser{conn: conn, session: ready.SessionID, ready: ready}
}

// TestJ2_BrowserOperatorGetsAShell is the browser half of the product's core journey.
func TestJ2_BrowserOperatorGetsAShell(t *testing.T) {
	for _, mode := range []plugin.Mode{plugin.ModePersistent, plugin.ModeDispatch} {
		t.Run(string(mode), func(t *testing.T) {
			g := build(t, mode)

			session, attach := g.openSession(t, g.device.ID, "ticket AV-9182")
			if session["state"] == nil || session["id"] == "" {
				t.Fatalf("session block: %+v", session)
			}
			// The reason the operator gave is on the row, which is what turns a
			// session list into an explanation.
			if session["reason"] != "ticket AV-9182" {
				t.Errorf("reason %v", session["reason"])
			}
			if attach["expires_at"] == "" {
				t.Error("no attach expiry — the ticket is a deadline for connecting")
			}

			b := g.attach(t, attach)

			// READY carries the disclosure the browser has no banner channel for.
			// A component that renders a terminal without reading these is the risk
			// R-001 exists for.
			if !b.ready.Recording {
				t.Error("READY says the session is not recorded, but a recorder is configured")
			}
			if b.ready.Mode != "gateway" {
				t.Errorf("mode %q, want gateway", b.ready.Mode)
			}
			if b.ready.SessionID != session["id"] {
				t.Errorf("READY session %q, POST said %v", b.ready.SessionID, session["id"])
			}

			// Type a command, read the output — through the shaper, the recorder and
			// a real PTY.
			send(t, b.conn, frame.Data([]byte("printf 'BROWSER%s\\n' '-OK'\n")))
			out := readUntil(t, b.conn, "BROWSER-OK", 20*time.Second)
			if !strings.Contains(out, "BROWSER-OK") {
				t.Fatalf("never saw the command output:\n%s", out)
			}

			// Resize reaches the PTY.
			send(t, b.conn, mustFrame(t, frame.TypeResize, frame.Resize{Cols: 90, Rows: 30}))
			time.Sleep(300 * time.Millisecond)
			send(t, b.conn, frame.Data([]byte("stty size\n")))
			if got := readUntil(t, b.conn, "30 90", 20*time.Second); !strings.Contains(got, "30 90") {
				t.Errorf("the resize did not reach the PTY:\n%s", got)
			}

			// Leave, and the ledger records it with the browser as the surface.
			send(t, b.conn, mustFrame(t, frame.TypeClose, frame.Close{Reason: "operator_close"}))

			row := awaitRow(t, g, b.session, sessions.StateClosed, 15*time.Second)
			switch {
			case row.Principal != operatorID:
				t.Errorf("attributed to %q", row.Principal)
			case row.CloseReason != "operator_close":
				t.Errorf("close reason %q", row.CloseReason)
			case row.RecordingState != sessions.Recorded:
				t.Errorf("recording state %q", row.RecordingState)
			case row.BytesOut == 0:
				t.Error("no bytes accounted for")
			}

			// And the recording verifies, exactly as it does for an SSH session.
			v, err := g.recorder.Verify(context.Background(), b.session, g.recPub)
			if err != nil {
				t.Fatal(err)
			}
			if !v.OK {
				t.Fatalf("the browser session's recording did not verify: %s (%s)",
					v.Status, v.Detail)
			}
		})
	}
}

// TestJ2_AttachRefusals covers the ways a ticket can fail to open a session. Each is a
// distinct fact, and the browser needs to be able to tell them apart.
func TestJ2_AttachRefusals(t *testing.T) {
	t.Run("spent ticket", func(t *testing.T) {
		g := build(t, plugin.ModeDispatch)
		_, attach := g.openSession(t, g.device.ID, "first")
		b := g.attach(t, attach)
		send(t, b.conn, mustFrame(t, frame.TypeClose, frame.Close{Reason: "operator_close"}))
		awaitRow(t, g, b.session, sessions.StateClosed, 15*time.Second)

		// The same ticket again is indistinguishable from a replay, so it is treated
		// as one.
		code := attachExpectingError(t, attach)
		if code != "ticket_invalid" {
			t.Errorf("code %q, want ticket_invalid", code)
		}
	})

	t.Run("second attach while one is live", func(t *testing.T) {
		g := build(t, plugin.ModeDispatch)
		_, attach := g.openSession(t, g.device.ID, "first")
		first := g.attach(t, attach)
		defer first.conn.Close(transport.CloseNormal, "done")

		// A second operator must not be handed the same device connection: two
		// pumps on one connection would interleave keystrokes into one shell.
		_, attach2 := g.openSessionExpectingConflict(t, g.device.ID)
		if attach2 != nil {
			t.Error("a second session was opened on a device with a one-session cap")
		}
	})

	t.Run("unknown device does not leak", func(t *testing.T) {
		g := build(t, plugin.ModeDispatch)
		status, problem := g.postExpectingProblem(t, "no-such-device")
		if status != http.StatusNotFound {
			t.Fatalf("status %d, want 404", status)
		}
		if !strings.Contains(problem["title"].(string), "don't have access") {
			t.Errorf("title %q leaks whether the device exists", problem["title"])
		}
	})
}

// ── helpers ─────────────────────────────────────────────────────────────────────

func mustFrame(t *testing.T, ty frame.Type, v any) frame.Frame {
	t.Helper()
	f, err := frame.Marshal(ty, v)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func send(t *testing.T, c transport.Conn, f frame.Frame) {
	t.Helper()
	wire, err := frame.Codec{}.Encode(nil, f)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Send(ctx, wire); err != nil {
		t.Fatalf("send %s: %v", f.Type, err)
	}
}

func recvFrame(t *testing.T, c transport.Conn, within time.Duration) frame.Frame {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), within)
	defer cancel()
	msg, err := c.Recv(ctx)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	f, err := frame.Codec{}.Decode(msg)
	if err != nil {
		t.Fatal(err)
	}
	return f.Clone()
}

// readUntil accumulates DATA until want appears. Every sentinel this test waits on is
// assembled by the shell, so it cannot match the echo of the command that produced it.
func readUntil(t *testing.T, c transport.Conn, want string, within time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(within)
	var acc strings.Builder
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		msg, err := c.Recv(ctx)
		cancel()
		if err != nil {
			if strings.Contains(acc.String(), want) {
				return acc.String()
			}
			continue
		}
		f, derr := frame.Codec{}.Decode(msg)
		if derr != nil {
			t.Fatal(derr)
		}
		switch f.Type {
		case frame.TypeData:
			acc.Write(f.Payload)
		case frame.TypeThrottle:
			t.Fatal("THROTTLE on a shell session: it must backpressure, never drop")
		case frame.TypeError:
			var e frame.Error
			_ = frame.Unmarshal(f, &e)
			t.Fatalf("gateway error %s: %s", e.Code, e.Message)
		}
		if strings.Contains(acc.String(), want) {
			return acc.String()
		}
	}
	return acc.String()
}

func attachExpectingError(t *testing.T, attach map[string]any) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := websocket.Dialer{}.Dial(ctx, attach["url"].(string), transport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(transport.CloseNormal, "done")

	send(t, conn, mustFrame(t, frame.TypeOpen, frame.Open{Ticket: attach["ticket"].(string)}))
	f := recvFrame(t, conn, 10*time.Second)
	if f.Type != frame.TypeError {
		t.Fatalf("expected an ERROR, got %v", f.Type)
	}
	var e frame.Error
	if err := frame.Unmarshal(f, &e); err != nil {
		t.Fatal(err)
	}
	return e.Code
}

func (g *gateway) openSessionExpectingConflict(t *testing.T, deviceID string) (int, map[string]any) {
	t.Helper()
	status, problem := g.postExpectingProblem(t, deviceID)
	if status != http.StatusConflict {
		t.Fatalf("status %d, want 409: %v", status, problem)
	}
	if problem["code"] != "session_limit" {
		t.Errorf("code %v", problem["code"])
	}
	return status, nil
}

func (g *gateway) postExpectingProblem(t *testing.T, deviceID string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"device_id": deviceID, "profile": "shell"})
	req, err := http.NewRequest("POST", g.api+"/api/v1/sessions", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+g.apiToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var problem map[string]any
	if err := json.Unmarshal(raw, &problem); err != nil {
		t.Fatalf("not problem+json: %v\n%s", err, raw)
	}
	return resp.StatusCode, problem
}

func awaitRow(t *testing.T, g *gateway, id string, state sessions.State,
	within time.Duration) *sessions.Session {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		row, err := g.ledger.Get(context.Background(), id)
		if err == nil && row.State == state {
			return row
		}
		if err != nil && !errors.Is(err, sessions.ErrNotFound) {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("session %s never reached state %s", id, state)
	return nil
}

// awaitObservers reads until an OBSERVERS frame arrives.
func awaitObservers(t *testing.T, c transport.Conn, within time.Duration) []frame.Observer {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		msg, err := c.Recv(ctx)
		cancel()
		if err != nil {
			continue
		}
		f, derr := frame.Codec{}.Decode(msg)
		if derr != nil || f.Type != frame.TypeObservers {
			continue
		}
		var list frame.Observers
		if err := frame.Unmarshal(f, &list); err != nil {
			t.Fatal(err)
		}
		return list.Observers
	}
	t.Fatal("no OBSERVERS frame arrived")
	return nil
}

// renewAttach is what the component's renewal callback does when its ticket is gone.
func (g *gateway) renewAttach(t *testing.T, sessionID string) (map[string]any, int) {
	t.Helper()
	req, err := http.NewRequest("POST",
		g.api+"/api/v1/sessions/"+sessionID+"/attach", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+g.apiToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out, resp.StatusCode
}

// TestJ2_RenewedTicketGetsIn: the ordinary browser mishaps — a reload, a handshake that
// fails, a ticket held past its 60 s — leave an operator holding a live session and a
// spent credential. Renewal is what keeps single-use tickets survivable, and the
// per-device cap is why "just open another session" is not an answer.
func TestJ2_RenewedTicketGetsIn(t *testing.T) {
	g := build(t, plugin.ModePersistent)

	session, first := g.openSession(t, g.device.ID, "ticket AV-9183")
	id, _ := session["id"].(string)

	// The browser never gets to use `first` — the page reloaded.
	fresh, status := g.renewAttach(t, id)
	if status != http.StatusCreated {
		t.Fatalf("renewal returned %d: %+v", status, fresh)
	}
	if fresh["ticket"] == first["ticket"] {
		t.Error("renewal handed back the same ticket")
	}

	// The superseded ticket is dead, so a copy of the first response is not a way in.
	if code := attachExpectingError(t, first); code != "ticket_invalid" {
		t.Errorf("the superseded ticket was refused as %q, want ticket_invalid", code)
	}

	// The fresh one works, and the session is the same one — the device was already
	// waiting on it, and renewing did not disturb that.
	br := g.attach(t, fresh)
	if br.session != id {
		t.Errorf("attached to %s, want %s", br.session, id)
	}
	if !br.ready.Recording {
		t.Error("READY does not disclose recording")
	}
	send(t, br.conn, frame.Data([]byte("printf 'RENEWED%s\\n' '-OK'\n")))
	if out := readUntil(t, br.conn, "RENEWED-OK", 20*time.Second); !strings.Contains(out, "RENEWED-OK") {
		t.Fatalf("never saw the command output:\n%s", out)
	}

	send(t, br.conn, mustFrame(t, frame.TypeClose, frame.Close{Reason: "operator_close"}))
	awaitRow(t, g, br.session, sessions.StateClosed, 15*time.Second)

	if _, status := g.renewAttach(t, id); status != http.StatusConflict {
		t.Errorf("renewing a closed session returned %d, want 409", status)
	}
}

// TestJ2_ReattachAfterALostConnection is FR8 end to end: a browser loses its socket
// mid-session, comes back with a fresh ticket, and finds the session where it left it.
//
// The two moments the UX spec says carry the design are both here: the scrollback
// replaying, and the reattach being undramatic. A dropped connection is the normal case,
// not a failure — an operator who loses wifi mid-command should discover that nothing
// happened.
func TestJ2_ReattachAfterALostConnection(t *testing.T) {
	g := build(t, plugin.ModePersistent)

	session, attach := g.openSession(t, g.device.ID, "ticket AV-9184")
	id, _ := session["id"].(string)
	first := g.attach(t, attach)

	// Do some work, so there is something to come back to.
	send(t, first.conn, frame.Data([]byte("printf 'MARKER%s\\n' '-ONE'\n")))
	if out := readUntil(t, first.conn, "MARKER-ONE", 20*time.Second); !strings.Contains(out, "MARKER-ONE") {
		t.Fatalf("never saw the first command: %s", out)
	}

	// The wifi drops. Not a close: no CLOSE frame, just a dead socket.
	_ = first.conn.Close(transport.CloseGoingAway, "wifi")

	// Give the gateway a moment to notice the socket is gone and detach.
	time.Sleep(200 * time.Millisecond)

	// A fresh ticket, because the first one was single-use. This is the moment
	// authorisation is re-checked, for free.
	fresh, status := g.renewAttach(t, id)
	if status != http.StatusCreated {
		t.Fatalf("renewal returned %d: %+v", status, fresh)
	}

	back := g.attach(t, fresh)
	if back.session != id {
		t.Errorf("reattached to %s, want %s", back.session, id)
	}
	// READY still discloses, on every attach — the disclosure is not a one-off greeting.
	if !back.ready.Recording {
		t.Error("READY on reattach does not say the session is recorded")
	}
	// And it says how much is about to be replayed, so a browser can show "replaying
	// 12 KiB" instead of looking frozen.
	if back.ready.ScrollbackLen <= 0 {
		t.Errorf("READY says scrollback_len=%d on a reattach with history",
			back.ready.ScrollbackLen)
	}

	// The scrollback the operator missed. This is the half of FR8 that is easy to
	// leave out: a session that survives the drop but comes back with a blank screen
	// makes the operator re-run a command to find out where they were, which on a
	// device is exactly what they must not do.
	replay := readUntil(t, back.conn, "MARKER-ONE", 10*time.Second)
	if !strings.Contains(replay, "MARKER-ONE") {
		t.Errorf("the scrollback was not replayed on reattach: %q", replay)
	}

	// The session is the same one: the shell still has the state the first operator
	// left it in, which is the whole point of not closing on a dropped socket.
	send(t, back.conn, frame.Data([]byte("printf 'MARKER%s\\n' '-TWO'\n")))
	if out := readUntil(t, back.conn, "MARKER-TWO", 20*time.Second); !strings.Contains(out, "MARKER-TWO") {
		t.Fatalf("the reattached session is not live: %s", out)
	}

	// One session, one ledger row, one recording — a reattach is not a new session.
	send(t, back.conn, mustFrame(t, frame.TypeClose, frame.Close{Reason: "operator_close"}))
	row := awaitRow(t, g, id, sessions.StateClosed, 15*time.Second)
	if row.CloseReason != "operator_close" {
		t.Errorf("close reason %q", row.CloseReason)
	}

	v, err := g.recorder.Verify(context.Background(), id, g.recPub)
	if err != nil {
		t.Fatal(err)
	}
	if !v.OK {
		t.Fatalf("the recording of a reattached session did not verify: %s (%s)", v.Status, v.Detail)
	}
	// Both halves of the session are in the one recording: an auditor reading it should
	// not be able to tell that the operator's socket changed.
	rc, err := g.recorder.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	text, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"MARKER-ONE", "MARKER-TWO"} {
		if !strings.Contains(string(text), want) {
			t.Errorf("the recording is missing %q", want)
		}
	}
}

// TestJ2_ASecondOperatorCannotStealALiveSession: two operators writing into one shell
// would interleave their keystrokes. Watching one is a different feature (FR13).
func TestJ2_ASecondOperatorCannotStealALiveSession(t *testing.T) {
	g := build(t, plugin.ModePersistent)
	session, attach := g.openSession(t, g.device.ID, "ticket AV-9185")
	id, _ := session["id"].(string)
	live := g.attach(t, attach)
	defer live.conn.Close(transport.CloseNormal, "done")

	// A second, legitimately-issued ticket for the same session.
	fresh, status := g.renewAttach(t, id)
	if status != http.StatusCreated {
		t.Fatalf("renewal returned %d", status)
	}
	if code := attachExpectingError(t, fresh); code != "session_limit" {
		t.Errorf("a second operator was refused as %q, want session_limit", code)
	}

	// And the first operator is undisturbed.
	send(t, live.conn, frame.Data([]byte("printf 'STILL%s\\n' '-MINE'\n")))
	if out := readUntil(t, live.conn, "STILL-MINE", 20*time.Second); !strings.Contains(out, "STILL-MINE") {
		t.Errorf("the original operator lost their session: %s", out)
	}
}

// observeSession is what a console does when somebody presses Watch on a live session.
func (g *gateway) observeSession(t *testing.T, sessionID, bearer string) (map[string]any, int) {
	t.Helper()
	req, err := http.NewRequest("POST", g.api+"/api/v1/sessions/"+sessionID+"/observe", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out, resp.StatusCode
}

// TestJ2_AnObserverWatchesReadOnly is FR13 end to end.
//
// Two things have to be true at once: the watcher sees the session and cannot touch it,
// and the operator knows who is watching. The second is the one that fails quietly —
// nothing is broken when an indicator never arrives.
func TestJ2_AnObserverWatchesReadOnly(t *testing.T) {
	g := build(t, plugin.ModePersistent)
	session, attach := g.openSession(t, g.device.ID, "ticket AV-9186")
	id, _ := session["id"].(string)
	op := g.attach(t, attach)

	// The operator does some work before anybody is watching.
	send(t, op.conn, frame.Data([]byte("printf 'BEFORE%s\\n' '-WATCH'\n")))
	if out := readUntil(t, op.conn, "BEFORE-WATCH", 20*time.Second); !strings.Contains(out, "BEFORE-WATCH") {
		t.Fatalf("the session is not live: %s", out)
	}

	// Somebody else asks to watch. A different principal, and a different endpoint from
	// renewAttach: the two grant different things.
	watch, status := g.observeSession(t, id, g.observerToken)
	if status != http.StatusCreated {
		t.Fatalf("observe returned %d: %+v", status, watch)
	}

	ob := g.attach(t, watch)
	// The watcher's own READY tells them what they are, and whose session this is.
	if !ob.ready.ReadOnly {
		t.Error("READY does not tell the watcher they are read-only")
	}
	if ob.ready.Watching != operatorID {
		t.Errorf("watching %q, want %q", ob.ready.Watching, operatorID)
	}
	if len(ob.ready.Observers) != 1 || ob.ready.Observers[0].Principal != observerID {
		t.Errorf("the watcher is not in their own list: %+v", ob.ready.Observers)
	}

	// The operator is told, by name. Anonymous observation is not offered at any level.
	list := awaitObservers(t, op.conn, 20*time.Second)
	if len(list) != 1 || list[0].Principal != observerID {
		t.Fatalf("the operator was told %+v, want one watcher named %s", list, observerID)
	}
	if list[0].Since == "" {
		t.Error("no since — 'watched since before I ran that' has to be answerable")
	}

	// The watcher sees new output.
	send(t, op.conn, frame.Data([]byte("printf 'DURING%s\\n' '-WATCH'\n")))
	if out := readUntil(t, ob.conn, "DURING-WATCH", 20*time.Second); !strings.Contains(out, "DURING-WATCH") {
		t.Errorf("the watcher saw nothing: %s", out)
	}

	// And cannot type. Checked through the filesystem rather than through the echo: an
	// assertion that the *text* never appeared would also pass if the command ran and
	// its echo happened to be suppressed, which is the difference between "we did not
	// see it" and "it did not happen".
	marker := filepath.Join(t.TempDir(), "intruder")
	send(t, ob.conn, frame.Data([]byte("echo INTRUDER > "+marker+"\n")))
	time.Sleep(500 * time.Millisecond)

	send(t, op.conn, frame.Data([]byte("cat "+marker+" 2>&1; printf 'CHECK%s\\n' '-DONE'\n")))
	got := readUntil(t, op.conn, "CHECK-DONE", 20*time.Second)
	if strings.Contains(got, "INTRUDER") {
		t.Errorf("a watcher's command ran in the operator's shell:\n%s", got)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Errorf("a watcher's command created %s", marker)
	}

	// The watcher leaving clears the operator's indicator, without waiting for output —
	// a session sitting at a prompt produces none.
	_ = ob.conn.Close(transport.CloseNormal, "done watching")
	if empty := awaitObservers(t, op.conn, 20*time.Second); len(empty) != 0 {
		t.Errorf("after the watcher left, the operator still sees %+v", empty)
	}

	send(t, op.conn, mustFrame(t, frame.TypeClose, frame.Close{Reason: "operator_close"}))
	awaitRow(t, g, id, sessions.StateClosed, 15*time.Second)
}

func TestJ2_ObserveRefusals(t *testing.T) {
	g := build(t, plugin.ModePersistent)
	session, attach := g.openSession(t, g.device.ID, "ticket AV-9187")
	id, _ := session["id"].(string)
	op := g.attach(t, attach)
	defer op.conn.Close(transport.CloseNormal, "done")

	t.Run("watching your own session", func(t *testing.T) {
		// Not an error so much as the wrong verb: it would put a second read-only pane on
		// a shell you already have, and tell you that you are watching yourself.
		_, status := g.observeSession(t, id, g.apiToken)
		if status != http.StatusConflict {
			t.Errorf("status %d, want 409", status)
		}
	})

	t.Run("a session that does not exist", func(t *testing.T) {
		_, status := g.observeSession(t, "sess_nope", g.observerToken)
		if status != http.StatusNotFound {
			t.Errorf("status %d, want 404", status)
		}
	})

	t.Run("a watch ticket is not an attach ticket", func(t *testing.T) {
		watch, status := g.observeSession(t, id, g.observerToken)
		if status != http.StatusCreated {
			t.Fatalf("observe returned %d", status)
		}
		ob := g.attach(t, watch)
		defer ob.conn.Close(transport.CloseNormal, "done")
		// It got in — as a watcher. What it must not be is a way to take the keyboard.
		if !ob.ready.ReadOnly {
			t.Error("a watch ticket produced a writable session")
		}
	})
}
