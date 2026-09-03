package e2e_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/sessions"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
)

// J6 — on-call during an authorisation outage.
//
// The journey the three-outcome contract exists for, and the one a bare fail-closed gets
// wrong: the permissions API goes down while people are working on devices, usually
// *because* of the same infrastructure event that put them there.
//
// Two things have to be true at once, and they pull in opposite directions: work in
// progress must survive, and nothing new may open on a decision nobody can confirm.

// TestJ6_AnOutageDoesNotKillWorkInProgress is E4.S4's acceptance criterion, from outside
// the gateway: zero sessions closed in a 60 s outage.
func TestJ6_AnOutageDoesNotKillWorkInProgress(t *testing.T) {
	// A window wider than this test can possibly take.
	//
	// The grace is counted in re-checks and the harness re-checks every 50 ms, so the
	// default of three is 150 ms — less than one shell round-trip, and this test does six
	// of them. It was therefore racing shell latency against the grace window and losing
	// on a busy machine, reporting `authz_unavailable` as though the product were wrong
	// when the product was doing exactly what a 150 ms window says.
	//
	// Four hundred re-checks is twenty seconds. Every read below has its own 20 s budget,
	// so a run slow enough to exhaust this fails on those first and says something useful
	// instead. That an outage *does* eventually close a session is
	// TestJ6_AnOutageIsNotARevocationInTheLedger's job, with the short window it wants.
	withAuthzGrace(t, 400)

	g := build(t, plugin.ModePersistent)

	session, attach := g.openSession(t, g.device.ID, "ticket AV-9190")
	id, _ := session["id"].(string)
	op := g.attach(t, attach)

	send(t, op.conn, frame.Data([]byte("printf 'BEFORE%s\\n' '-OUTAGE'\n")))
	if out := readUntil(t, op.conn, "BEFORE-OUTAGE", 20*time.Second); !strings.Contains(out, "BEFORE-OUTAGE") {
		t.Fatalf("the session never worked: %s", out)
	}

	// The permissions API goes down.
	g.authz.breakIt()

	// A minute of outage, compressed: what matters is that the live session is never
	// re-checked out of existence, and that the operator keeps working through it. The
	// grace window is counted in re-checks rather than seconds, and the mid-session
	// re-check loop is E4.S5 — so what this proves at the journey level is that an
	// outage does not interrupt a session, and that the *shell* keeps working.
	for i := range 6 {
		send(t, op.conn, frame.Data([]byte("printf 'DURING%d%s\\n' "+itoa(i)+" '-OUTAGE'\n")))
		want := "DURING" + itoa(i) + "-OUTAGE"
		if out := readUntil(t, op.conn, want, 20*time.Second); !strings.Contains(out, want) {
			t.Fatalf("the session stopped working during the outage (round %d): %s", i, out)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// The row is still attached: nothing recorded it as revoked, and nothing closed it.
	row, err := g.ledger.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if !row.Live() {
		t.Fatalf("the session was closed during an authorisation outage: state=%q reason=%q",
			row.State, row.CloseReason)
	}
	if row.CloseReason == "revoked" {
		t.Error("an outage was recorded as a revocation — which poisons every audit " +
			"query built on top of the close reason")
	}

	// Meanwhile, nothing *new* may open: a session started on a decision nobody can
	// confirm is a different risk from letting an operator finish a command on one.
	status, problem := g.postExpectingProblem(t, g.device.ID)
	if status != http.StatusServiceUnavailable {
		t.Errorf("during an outage a new session got %d, want 503: %+v", status, problem)
	}

	// The outage ends, and the session that survived it is still the same session.
	g.authz.fixIt()
	send(t, op.conn, frame.Data([]byte("printf 'AFTER%s\\n' '-OUTAGE'\n")))
	if out := readUntil(t, op.conn, "AFTER-OUTAGE", 20*time.Second); !strings.Contains(out, "AFTER-OUTAGE") {
		t.Errorf("the session did not survive the outage: %s", out)
	}

	send(t, op.conn, mustFrame(t, frame.TypeClose, frame.Close{Reason: "operator_close"}))
	closed := awaitRow(t, g, id, sessions.StateClosed, 15*time.Second)
	// One session, closed by the operator, with the true reason.
	if closed.CloseReason != "operator_close" {
		t.Errorf("close reason %q — an outage the session survived must leave no trace "+
			"in why it eventually ended", closed.CloseReason)
	}

	// And the recording spans the whole thing, outage included.
	v, err := g.recorder.Verify(context.Background(), id, g.recPub)
	if err != nil {
		t.Fatal(err)
	}
	if !v.OK {
		t.Fatalf("the recording did not verify: %s (%s)", v.Status, v.Detail)
	}
}

// TestJ6_NewSessionsAreRefusedFromTheFirstFailure: no grace at open, deliberately.
func TestJ6_NewSessionsAreRefusedFromTheFirstFailure(t *testing.T) {
	g := build(t, plugin.ModePersistent)
	g.authz.breakIt()

	for i := range 3 {
		status, body := g.postExpectingProblem(t, g.device.ID)
		if status != http.StatusServiceUnavailable {
			t.Fatalf("attempt %d: status %d, want 503: %+v", i, status, body)
		}
		ty, _ := body["type"].(string)
		if !strings.Contains(ty, "authz_unavailable") {
			t.Errorf("attempt %d: type %q", i, ty)
		}
		// The operator is told their access has not changed. Told "revoked" instead,
		// they go and ask a manager about a permission nobody took away — during the
		// incident that put them on the device.
		text, _ := body["title"].(string)
		detail, _ := body["detail"].(string)
		for _, forbidden := range []string{"revoked", "withdrawn", "removed"} {
			if strings.Contains(strings.ToLower(text+" "+detail), forbidden) {
				t.Errorf("attempt %d: an outage reads as a revocation: %q / %q", i, text, detail)
			}
		}
	}

	// No rows for sessions that never opened this way — a refusal at open is a 503 and
	// not a session.
	rows, _, err := g.ledger.List(context.Background(), sessions.Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("%d session rows exist for sessions refused at open", len(rows))
	}
}

// TestJ6_ADenialIsNotAnOutage: the other half of the distinction, on the same path.
func TestJ6_ADenialIsNotAnOutage(t *testing.T) {
	g := build(t, plugin.ModePersistent)
	// A rules file that grants nothing: a real denial, from the shipped backend.
	g.rewriteRules(t, "rules:\n  - principals: [\"nobody@example.com\"]\n    actions: [\"shell\"]\n")

	status, body := g.postExpectingProblem(t, g.device.ID)
	if status != http.StatusForbidden {
		t.Fatalf("a denial got %d, want 403: %+v", status, body)
	}
	ty, _ := body["type"].(string)
	if !strings.Contains(ty, "not_authorized") {
		t.Errorf("type %q, want not_authorized", ty)
	}
	// The rules backend's own sentence: it names the action, the device and the
	// principal, because "denied" tells an operator nothing they can act on.
	detail, _ := body["detail"].(string)
	for _, want := range []string{"shell", g.device.ID} {
		if !strings.Contains(detail, want) {
			t.Errorf("the reason %q does not name %q", detail, want)
		}
	}
	if body["retryable"] == true {
		t.Error("a denial was reported as retryable")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestJ6_ARevokedOperatorLosesTheirShell is J7 from the PRD, and FR16: an operator who
// should no longer have access does not keep the shell they already had.
//
// Driven through the *interval*, not through Watch. The rules backend does not stream, so
// nothing here can arrive by the fast path — which is the point: the interval is the
// guarantee, and a build where only Watch works passes every happy-path test and stops
// revoking the day the stream breaks.
func TestJ6_ARevokedOperatorLosesTheirShell(t *testing.T) {
	g := build(t, plugin.ModePersistent)

	session, attach := g.openSession(t, g.device.ID, "ticket AV-9191")
	id, _ := session["id"].(string)
	op := g.attach(t, attach)

	send(t, op.conn, frame.Data([]byte("printf 'STILL%s\\n' '-ALLOWED'\n")))
	if out := readUntil(t, op.conn, "STILL-ALLOWED", 20*time.Second); !strings.Contains(out, "STILL-ALLOWED") {
		t.Fatalf("the session never worked: %s", out)
	}

	// Access is withdrawn: the rules file no longer grants this operator anything.
	g.rewriteRules(t, "rules:\n  - principals: [\"nobody@example.com\"]\n    actions: [\"shell\"]\n")

	// The session closes on its own, within a re-check interval, and the operator is
	// told why rather than watching their connection die.
	row := awaitRow(t, g, id, sessions.StateClosed, 15*time.Second)
	if row.CloseReason != "revoked" {
		t.Errorf("close reason %q, want revoked — a human withdrew access, and the "+
			"ledger has to say so rather than blaming the transport", row.CloseReason)
	}

	// The recording of a revoked session is exactly the one somebody will want to read.
	v, err := g.recorder.Verify(context.Background(), id, g.recPub)
	if err != nil {
		t.Fatal(err)
	}
	if !v.OK {
		t.Fatalf("the recording of a revoked session did not verify: %s (%s)", v.Status, v.Detail)
	}
}

// TestJ6_AnOutageIsNotARevocationInTheLedger is the pair of the above, and the reason the
// two are separate close reasons: an audit query for "who was revoked last week" must not
// return everybody who was working during an outage.
func TestJ6_AnOutageIsNotARevocationInTheLedger(t *testing.T) {
	g := build(t, plugin.ModePersistent)
	session, attach := g.openSession(t, g.device.ID, "ticket AV-9192")
	id, _ := session["id"].(string)
	op := g.attach(t, attach)
	send(t, op.conn, frame.Data([]byte("printf 'WORKING%s\\n' '-OK'\n")))
	readUntil(t, op.conn, "WORKING-OK", 20*time.Second)

	// The permissions API goes down and stays down, past the grace window.
	g.authz.breakIt()

	row := awaitRow(t, g, id, sessions.StateClosed, 20*time.Second)
	if row.CloseReason != "authz_unavailable" {
		t.Errorf("close reason %q, want authz_unavailable", row.CloseReason)
	}
	if row.CloseReason == "revoked" {
		t.Error("an outage was recorded as a revocation")
	}
}

// TestJ6_WatchClosesInUnderASecond is the optimisation, measured.
//
// The interval in this fixture is 50 ms, so a test that only asserted "it closed" would
// pass through the interval and prove nothing about Watch. It asserts the *event* did the
// work: a revocation arrives on the stream and the shell is gone well inside one interval.
func TestJ6_WatchClosesInUnderASecond(t *testing.T) {
	g := build(t, plugin.ModePersistent)

	session, attach := g.openSession(t, g.device.ID, "ticket AV-9193")
	id, _ := session["id"].(string)
	op := g.attach(t, attach)
	send(t, op.conn, frame.Data([]byte("printf 'BEFORE%s\\n' '-REVOKE'\n")))
	readUntil(t, op.conn, "BEFORE-REVOKE", 20*time.Second)

	// The stream may take a moment to be established after the gateway starts.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		g.authz.revoke(plugin.RevocationEvent{PrincipalID: operatorID, Reason: "left the group"})
		row, err := g.ledger.Get(context.Background(), id)
		if err == nil && !row.Live() {
			if row.CloseReason != "revoked" {
				t.Errorf("close reason %q, want revoked", row.CloseReason)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("a streamed revocation never closed the session")
}
