package apisrv_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"errors"
	"github.com/oarlock/oarlock/internal/apisrv"
	"github.com/oarlock/oarlock/internal/auth/statictoken"
	"github.com/oarlock/oarlock/internal/authz"
	"github.com/oarlock/oarlock/internal/invite"
	"github.com/oarlock/oarlock/internal/sessions"
	"github.com/oarlock/oarlock/internal/ticket"
	"github.com/oarlock/oarlock/pkg/condition"
	"github.com/oarlock/oarlock/pkg/plugin"
)

const token = "test-token-long-enough-to-pass"

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

type fixture struct {
	srv    *httptest.Server
	ledger *sessions.Memory
	live   *sessions.Registry
}

func newFixture(t *testing.T, ratePerMin int) *fixture {
	t.Helper()
	authn, err := statictoken.Open("test", map[string]string{token: "phuc@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{
		ledger: sessions.NewMemory(sessions.Limits{PerDevice: 1, PerPrincipal: 100}, nil),
		live:   sessions.NewRegistry(),
	}
	api, err := apisrv.New(apisrv.Options{
		Sessions: f.ledger, Live: f.live, Authenticator: authn,
		RatePerMinute: ratePerMin, Log: quiet(),
	})
	if err != nil {
		t.Fatal(err)
	}
	f.srv = httptest.NewServer(api)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fixture) do(t *testing.T, method, path, bearer string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, f.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := f.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, body
}

func (f *fixture) seed(t *testing.T, id, device, principal string) *sessions.Session {
	t.Helper()
	row := &sessions.Session{ID: id, DeviceID: device, Principal: principal,
		Profile: "shell", Mode: "dispatch", State: sessions.StateAttached,
		RecordingState: sessions.Recorded, Reason: "ticket AV-9182"}
	if err := f.ledger.Create(context.Background(), row); err != nil {
		t.Fatal(err)
	}
	return row
}

// ── the error envelope ──────────────────────────────────────────────────────────

// TestProblemJSON: one machine-readable vocabulary across the wire and the API, and a
// correlation id on every failure — because "quote the instance" only helps if the id
// is in the response, the header and the log.
func TestProblemJSON(t *testing.T) {
	f := newFixture(t, 0)
	resp, body := f.do(t, "GET", apisrv.Prefix+"/sessions/nope", token)

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d, want 404: %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/problem+json") {
		t.Errorf("content type %q, want application/problem+json", ct)
	}
	var p apisrv.Problem
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("body is not problem+json: %v\n%s", err, body)
	}
	switch {
	case p.Code != "not_found":
		t.Errorf("code %q", p.Code)
	case p.Status != 404:
		t.Errorf("status field %d", p.Status)
	case p.Instance == "":
		t.Error("no correlation id")
	case !strings.HasPrefix(p.Type, "https://oarlock.dev/errors/"):
		t.Errorf("type %q", p.Type)
	case p.Title == "":
		t.Error("no human-readable title")
	}
	// The same id in the header, so a caller that never parses the body can still
	// quote it.
	if got := resp.Header.Get(apisrv.HeaderRequestID); got != p.Instance {
		t.Errorf("header id %q, body instance %q — they must match", got, p.Instance)
	}
}

func TestUnauthenticatedRequestsAreRefused(t *testing.T) {
	f := newFixture(t, 0)
	for name, bearer := range map[string]string{
		"no token":    "",
		"wrong token": "definitely-not-the-right-token",
	} {
		t.Run(name, func(t *testing.T) {
			resp, body := f.do(t, "GET", apisrv.Prefix+"/sessions", bearer)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status %d, want 401: %s", resp.StatusCode, body)
			}
			var p apisrv.Problem
			_ = json.Unmarshal(body, &p)
			if p.Code != "auth_failed" {
				t.Errorf("code %q", p.Code)
			}
			// Nothing about which of the two problems it was.
			if strings.Contains(strings.ToLower(p.Detail), "unknown token") {
				t.Errorf("the response distinguishes a wrong token from a missing one: %q", p.Detail)
			}
			// An unauthenticated caller still gets an id, so a report about being
			// unable to authenticate is still traceable.
			if p.Instance == "" {
				t.Error("no correlation id on an auth failure")
			}
		})
	}
}

// TestBackendThatCannotAuthenticateHTTPSaysSo: an authorized_keys gateway refuses
// every API call, and the reason must be "this backend cannot", not "your token is
// wrong" — those send an operator to different places.
func TestBackendThatCannotAuthenticateHTTPSaysSo(t *testing.T) {
	api, err := apisrv.New(apisrv.Options{
		Sessions:      sessions.NewMemory(sessions.Limits{}, nil),
		Authenticator: unsupportedAuth{},
		Log:           quiet(),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+apisrv.Prefix+"/sessions", nil)
	req.Header.Set("Authorization", "Bearer whatever")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status %d, want 501: %s", resp.StatusCode, body)
	}
	var p apisrv.Problem
	_ = json.Unmarshal(body, &p)
	if p.Code != "auth_unsupported" {
		t.Errorf("code %q", p.Code)
	}
}

// ── listing ─────────────────────────────────────────────────────────────────────

func TestListAndFilter(t *testing.T) {
	f := newFixture(t, 0)
	f.seed(t, "s1", "dev-1", "phuc@example.com")
	f.seed(t, "s2", "dev-2", "other@example.com")
	f.seed(t, "s3", "dev-3", "phuc@example.com")
	if err := f.ledger.Finish(context.Background(), "s3",
		sessions.Result{CloseReason: "operator_close"}); err != nil {
		t.Fatal(err)
	}

	var all struct {
		Sessions   []map[string]any `json:"sessions"`
		NextCursor string           `json:"next_cursor"`
	}
	resp, body := f.do(t, "GET", apisrv.Prefix+"/sessions", token)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, &all); err != nil {
		t.Fatal(err)
	}
	if len(all.Sessions) != 3 {
		t.Fatalf("%d sessions, want 3", len(all.Sessions))
	}

	// Filters.
	for query, want := range map[string]int{
		"?live=true":                  2,
		"?device_id=dev-1":            1,
		"?principal=phuc@example.com": 2,
		"?state=closed":               1,
	} {
		var got struct {
			Sessions []map[string]any `json:"sessions"`
		}
		_, b := f.do(t, "GET", apisrv.Prefix+"/sessions"+query, token)
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		if len(got.Sessions) != want {
			t.Errorf("%s: %d sessions, want %d", query, len(got.Sessions), want)
		}
	}
}

func TestPaginationHeaderAndCursor(t *testing.T) {
	f := newFixture(t, 0)
	for i := range 5 {
		f.seed(t, "s"+strconv.Itoa(i), "dev-"+strconv.Itoa(i), "phuc@example.com")
	}

	resp, body := f.do(t, "GET", apisrv.Prefix+"/sessions?limit=2", token)
	var page struct {
		Sessions   []map[string]any `json:"sessions"`
		NextCursor string           `json:"next_cursor"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Sessions) != 2 || page.NextCursor == "" {
		t.Fatalf("page: %d rows, cursor %q", len(page.Sessions), page.NextCursor)
	}
	// Also in a header, so a caller can paginate without parsing the body.
	if got := resp.Header.Get(apisrv.HeaderCursor); got != page.NextCursor {
		t.Errorf("header cursor %q, body %q", got, page.NextCursor)
	}

	_, body2 := f.do(t, "GET", apisrv.Prefix+"/sessions?limit=2&cursor="+page.NextCursor, token)
	var page2 struct {
		Sessions []map[string]any `json:"sessions"`
	}
	if err := json.Unmarshal(body2, &page2); err != nil {
		t.Fatal(err)
	}
	if len(page2.Sessions) != 2 {
		t.Fatalf("page 2: %d rows", len(page2.Sessions))
	}
	if page2.Sessions[0]["id"] == page.Sessions[0]["id"] {
		t.Error("page 2 overlaps page 1")
	}
}

func TestLimitIsClampedNotRefused(t *testing.T) {
	f := newFixture(t, 0)
	f.seed(t, "s1", "dev-1", "a")
	// A caller asking for more than we will give should get a page, not a lecture —
	// the cursor is how they learn there is more.
	resp, body := f.do(t, "GET", apisrv.Prefix+"/sessions?limit=100000", token)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	// A nonsensical limit is a client bug worth reporting, though.
	resp2, _ := f.do(t, "GET", apisrv.Prefix+"/sessions?limit=-1", token)
	if resp2.StatusCode != http.StatusBadRequest {
		t.Errorf("limit=-1 gave %d, want 400", resp2.StatusCode)
	}
	resp3, _ := f.do(t, "GET", apisrv.Prefix+"/sessions?limit=abc", token)
	if resp3.StatusCode != http.StatusBadRequest {
		t.Errorf("limit=abc gave %d, want 400", resp3.StatusCode)
	}
}

func TestGetSessionShowsWhatMatters(t *testing.T) {
	f := newFixture(t, 0)
	f.seed(t, "s1", "dev-1", "phuc@example.com")

	resp, body := f.do(t, "GET", apisrv.Prefix+"/sessions/s1", token)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"id", "device_id", "profile", "mode", "principal",
		"state", "recording_state", "created_at", "live", "live_here"} {
		if _, ok := got[field]; !ok {
			t.Errorf("missing field %q", field)
		}
	}
	// recording_state is never blank: an unrecorded session must be a fact you can
	// query for, not an absence to interpret.
	if got["recording_state"] == "" {
		t.Error("blank recording_state")
	}
	// Not live on this node, because nothing registered it — which is what a session
	// running on another replica looks like.
	if got["live_here"] != false {
		t.Errorf("live_here is %v", got["live_here"])
	}
}

// ── killing ─────────────────────────────────────────────────────────────────────

func TestKillEndsALiveSession(t *testing.T) {
	f := newFixture(t, 0)
	f.seed(t, "s1", "dev-1", "phuc@example.com")

	var killed atomic.Int32
	var reason atomic.Value
	f.live.Add(&sessions.Handle{ID: "s1", DeviceID: "dev-1"}, func(r string) {
		killed.Add(1)
		reason.Store(r)
	})

	resp, body := f.do(t, "DELETE", apisrv.Prefix+"/sessions/s1", token)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if killed.Load() != 1 {
		t.Fatalf("kill called %d times", killed.Load())
	}
	if r, _ := reason.Load().(string); r != "admin_kill" {
		t.Errorf("reason %q, want admin_kill", r)
	}

	// Idempotent: the caller's intent is "this must not be running", and a retry
	// after a timeout must not look like a failure.
	if err := f.ledger.Finish(context.Background(), "s1",
		sessions.Result{CloseReason: "admin_kill"}); err != nil {
		t.Fatal(err)
	}
	resp2, body2 := f.do(t, "DELETE", apisrv.Prefix+"/sessions/s1", token)
	if resp2.StatusCode != 200 {
		t.Fatalf("second DELETE gave %d: %s", resp2.StatusCode, body2)
	}
	if killed.Load() != 1 {
		t.Errorf("the handle was killed again: %d", killed.Load())
	}
}

// TestKillOnTheWrongNodeSaysSo: live in the ledger but not here means it is running
// on another replica. A 404 would be a lie and a 500 would suggest we are broken.
func TestKillOnTheWrongNodeSaysSo(t *testing.T) {
	f := newFixture(t, 0)
	f.seed(t, "s1", "dev-1", "phuc@example.com") // live, but never registered here

	resp, body := f.do(t, "DELETE", apisrv.Prefix+"/sessions/s1", token)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status %d, want 409: %s", resp.StatusCode, body)
	}
	var p apisrv.Problem
	_ = json.Unmarshal(body, &p)
	if p.Code != "wrong_node" {
		t.Errorf("code %q", p.Code)
	}
	if !p.Retryable {
		t.Error("a wrong-node conflict should be marked retryable")
	}
}

func TestKillUnknownSession(t *testing.T) {
	f := newFixture(t, 0)
	resp, _ := f.do(t, "DELETE", apisrv.Prefix+"/sessions/nope", token)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status %d, want 404", resp.StatusCode)
	}
}

// ── rate limiting ───────────────────────────────────────────────────────────────

func TestRateLimitHeadersAndRetryAfter(t *testing.T) {
	f := newFixture(t, 3)

	for i := range 3 {
		resp, _ := f.do(t, "GET", apisrv.Prefix+"/sessions", token)
		if resp.StatusCode != 200 {
			t.Fatalf("request %d: status %d", i, resp.StatusCode)
		}
		if resp.Header.Get(apisrv.HeaderRateLimit) != "3" {
			t.Errorf("limit header %q", resp.Header.Get(apisrv.HeaderRateLimit))
		}
		want := strconv.Itoa(2 - i)
		if got := resp.Header.Get(apisrv.HeaderRateRemain); got != want {
			t.Errorf("request %d: remaining %q, want %q", i, got, want)
		}
	}

	resp, body := f.do(t, "GET", apisrv.Prefix+"/sessions", token)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429: %s", resp.StatusCode, body)
	}
	// Retry-After points at the window boundary rather than a guess, so a
	// well-behaved client stops for exactly as long as it needs to.
	ra := resp.Header.Get("Retry-After")
	if ra == "" {
		t.Fatal("no Retry-After on a 429")
	}
	n, err := strconv.Atoi(ra)
	if err != nil || n <= 0 || n > 60 {
		t.Errorf("Retry-After %q is not a sane number of seconds", ra)
	}
	var p apisrv.Problem
	_ = json.Unmarshal(body, &p)
	if p.Code != "rate_limited" || !p.Retryable {
		t.Errorf("problem: %+v", p)
	}
}

// TestUnauthenticatedCallersAreAlsoLimited: a token-guessing loop must be bounded
// too, or the rate limit only protects callers who already have credentials.
func TestUnauthenticatedCallersAreAlsoLimited(t *testing.T) {
	f := newFixture(t, 2)
	var got429 bool
	for range 6 {
		resp, _ := f.do(t, "GET", apisrv.Prefix+"/sessions", "wrong-token-here")
		if resp.StatusCode == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatal("a caller guessing tokens was never rate limited")
	}
}

func TestNewValidates(t *testing.T) {
	authn, _ := statictoken.Open("test", map[string]string{token: "a@example.com"})
	if _, err := apisrv.New(apisrv.Options{Authenticator: authn}); err == nil {
		t.Error("an API with no ledger was created")
	}
	if _, err := apisrv.New(apisrv.Options{
		Sessions: sessions.NewMemory(sessions.Limits{}, nil)}); err == nil {
		t.Error("an API with no authenticator was created")
	}
}

func TestStaticTokenRefusesProduction(t *testing.T) {
	// The gate that matters most about this backend is that it will not run outside
	// development, and it enforces that itself rather than relying on the operator.
	for _, env := range []string{"prod", "production", "staging", ""} {
		if _, err := statictoken.Open(env, map[string]string{token: "a@example.com"}); err == nil {
			t.Errorf("statictoken started in env %q", env)
		}
	}
	if _, err := statictoken.Open("test", map[string]string{"short": "a@example.com"}); err == nil {
		t.Error("a too-short token was accepted")
	}
	if _, err := statictoken.Open("test", map[string]string{token: ""}); err == nil {
		t.Error("a token with no principal was accepted")
	}
	if _, err := statictoken.Open("test", nil); err == nil {
		t.Error("an empty token set was accepted")
	}
}

// unsupportedAuth stands in for a backend that cannot authenticate HTTP callers —
// authorized_keys, for instance, which knows about SSH keys and nothing else.
type unsupportedAuth struct{}

func (unsupportedAuth) AuthPublicKey(context.Context, string, ssh.PublicKey) (*plugin.Principal, error) {
	return nil, plugin.ErrUnsupported
}
func (unsupportedAuth) AuthDelegated(context.Context, *plugin.Principal, string) (*plugin.Principal, error) {
	return nil, plugin.ErrUnsupported
}
func (unsupportedAuth) AuthHTTP(context.Context, *http.Request) (*plugin.Principal, error) {
	return nil, plugin.ErrUnsupported
}

// ── attach ticket renewal ───────────────────────────────────────────────────────

// renewFixture adds the parts POST /sessions/{id}/attach needs. The Inviter here is a
// real one over an in-memory ticket store, because the property under test — a renewal
// invalidates its predecessor — lives in the store, not in the handler.
func newRenewFixture(t *testing.T) (*fixture, *invite.Inviter) {
	t.Helper()
	authn, err := statictoken.Open("test", map[string]string{token: "phuc@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{
		ledger: sessions.NewMemory(sessions.Limits{PerDevice: 1, PerPrincipal: 100}, nil),
		live:   sessions.NewRegistry(),
	}
	inv := &invite.Inviter{
		Tickets:   ticket.NewMemory(time.Now),
		NodeURL:   "wss://gw.example.org/ws/session",
		AttachURL: "wss://gw.example.org/ws/attach",
		Log:       quiet(),
	}
	api, err := apisrv.New(apisrv.Options{
		Sessions: f.ledger, Live: f.live, Authenticator: authn,
		Registry: nil, Inviter: inv,
		AttachURL: "wss://gw.example.org/ws/attach",
		Log:       quiet(),
	})
	if err != nil {
		t.Fatal(err)
	}
	f.srv = httptest.NewServer(api)
	t.Cleanup(f.srv.Close)
	return f, inv
}

func (f *fixture) post(t *testing.T, path, bearer string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, f.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := f.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, body
}

// TestRenewGivesAWayBackIn: a browser spends its ticket on connect, so a reload with no
// renewal endpoint leaves a live session the operator cannot reach — and opening a
// second one hits the per-device cap.
func TestRenewGivesAWayBackIn(t *testing.T) {
	f, inv := newRenewFixture(t)
	f.seed(t, "sess_1", "dev-1", "phuc@example.com")

	resp, body := f.post(t, "/api/v1/sessions/sess_1/attach", token)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	var got struct {
		Ticket    string `json:"ticket"`
		URL       string `json:"url"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Ticket == "" {
		t.Fatal("no ticket")
	}
	if got.URL != "wss://gw.example.org/ws/attach" {
		t.Errorf("url %q", got.URL)
	}
	if got.ExpiresAt == "" {
		t.Error("no expiry")
	}

	// Scoped to this session, device and principal — NFR8, and the thing that stops a
	// renewal from being a general-purpose key.
	claims, err := inv.Redeem(context.Background(), got.Ticket, ticket.Want{Kind: ticket.KindAttach})
	if err != nil {
		t.Fatalf("the fresh ticket does not redeem: %v", err)
	}
	if claims.SessionID != "sess_1" || claims.DeviceID != "dev-1" ||
		claims.Principal != "phuc@example.com" || claims.Profile != "shell" {
		t.Errorf("claims %+v are not the session's", claims)
	}

	// And single-use still means single-use.
	if _, err := inv.Redeem(context.Background(), got.Ticket, ticket.Want{Kind: ticket.KindAttach}); err == nil {
		t.Error("the renewed ticket was spendable twice")
	}
}

// TestRenewingRevokesItsPredecessor: three reloads must not leave three live
// credentials for one session lying around.
func TestRenewingRevokesItsPredecessor(t *testing.T) {
	f, inv := newRenewFixture(t)
	f.seed(t, "sess_1", "dev-1", "phuc@example.com")

	var tickets []string
	for range 3 {
		resp, body := f.post(t, "/api/v1/sessions/sess_1/attach", token)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("status %d: %s", resp.StatusCode, body)
		}
		var got struct {
			Ticket string `json:"ticket"`
		}
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}
		tickets = append(tickets, got.Ticket)
	}
	if tickets[0] == tickets[1] || tickets[1] == tickets[2] {
		t.Fatal("renewal returned the same ticket twice")
	}

	for i, tk := range tickets[:2] {
		if _, err := inv.Redeem(context.Background(), tk, ticket.Want{Kind: ticket.KindAttach}); err == nil {
			t.Errorf("superseded ticket %d still redeems", i)
		}
	}
	if _, err := inv.Redeem(context.Background(), tickets[2], ticket.Want{Kind: ticket.KindAttach}); err != nil {
		t.Errorf("the newest ticket does not redeem: %v", err)
	}
}

func TestRenewRefusals(t *testing.T) {
	f, _ := newRenewFixture(t)
	f.seed(t, "sess_mine", "dev-1", "phuc@example.com")
	f.seed(t, "sess_theirs", "dev-2", "someone@example.com")
	closed := f.seed(t, "sess_over", "dev-3", "phuc@example.com")
	if err := f.ledger.Finish(context.Background(), closed.ID,
		sessions.Result{CloseReason: "operator_closed"}); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, path, bearer string
		want               int
		code               string
	}{
		{"unauthenticated", "/api/v1/sessions/sess_mine/attach", "", 401, "auth_failed"},
		// Somebody else's session and a session that never existed answer
		// identically: an authenticated caller must not be able to find live
		// sessions by trying ids.
		{"another principal's", "/api/v1/sessions/sess_theirs/attach", token, 404, "not_found"},
		{"unknown", "/api/v1/sessions/sess_nope/attach", token, 404, "not_found"},
		{"already ended", "/api/v1/sessions/sess_over/attach", token, 409, "session_closed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := f.post(t, tc.path, tc.bearer)
			if resp.StatusCode != tc.want {
				t.Fatalf("status %d, want %d: %s", resp.StatusCode, tc.want, body)
			}
			var prob struct{ Type, Title string }
			if err := json.Unmarshal(body, &prob); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(prob.Type, tc.code) {
				t.Errorf("type %q, want %q", prob.Type, tc.code)
			}
		})
	}
}

// TestEveryConditionHasADefensibleStatus.
//
// The old statusFor was a hand-written switch over four codes, which is how it came to
// answer 500 for three device conditions it had never heard of — a caller retrying on a
// 500 is a caller retrying on what looks like a gateway bug. Driving it from the
// condition table means a new condition gets a sane status the day it is added, and this
// asserts that none of them lands somewhere absurd.
func TestEveryConditionHasADefensibleStatus(t *testing.T) {
	for _, c := range condition.All() {
		got := apisrv.StatusFor(c.ID)
		if got < 400 || got > 599 {
			t.Errorf("%s → %d, which is not a failure status", c.ID, got)
		}
		switch c.Fault {
		case condition.FaultPrincipal:
			// Their problem, not ours: a 5xx here would tell a caller to retry
			// something that will never succeed.
			if got >= 500 {
				t.Errorf("%s blames the principal but answers %d", c.ID, got)
			}
		case condition.FaultDevice:
			if got >= 500 && got != http.StatusServiceUnavailable {
				t.Errorf("%s is a device condition but answers %d", c.ID, got)
			}
		}
	}
	// The specific regression: the three device conditions that used to share one code.
	for _, id := range []string{"device_not_connected", "device_offline", "device_unreachable"} {
		if got := apisrv.StatusFor(id); got != http.StatusServiceUnavailable {
			t.Errorf("%s → %d, want 503", id, got)
		}
	}
	if got := apisrv.StatusFor("doorbell_failed"); got != http.StatusBadGateway {
		t.Errorf("doorbell_failed → %d, want 502: it is our dependency, not the device", got)
	}
}

// ── the three-outcome contract, at the API's open path ──────────────────────────

// stubAuthz is controllable from a test.
type stubAuthz struct {
	allow  bool
	reason string
	err    error
}

func (s *stubAuthz) Authorize(context.Context, *plugin.Principal, *plugin.Device,
	plugin.Action) (plugin.Decision, error) {
	if s.err != nil {
		return plugin.Decision{}, s.err
	}
	return plugin.Decision{Allow: s.allow, Reason: s.reason}, nil
}

func (s *stubAuthz) Watch(context.Context) (<-chan plugin.RevocationEvent, error) {
	return nil, plugin.ErrUnsupported
}

func newAuthzFixture(t *testing.T, backend *stubAuthz) *fixture {
	t.Helper()
	authn, err := statictoken.Open("test", map[string]string{token: "phuc@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{
		ledger: sessions.NewMemory(sessions.Limits{PerDevice: 1, PerPrincipal: 100}, nil),
		live:   sessions.NewRegistry(),
	}
	inv := &invite.Inviter{
		Tickets: ticket.NewMemory(time.Now), NodeURL: "wss://gw/ws/session",
		AttachURL: "wss://gw/ws/attach", Log: quiet(),
	}
	api, err := apisrv.New(apisrv.Options{
		Sessions: f.ledger, Live: f.live, Authenticator: authn,
		Registry: staticRegistry{}, Inviter: inv,
		Authz:     &authz.Checker{Backend: backend, Log: quiet()},
		AttachURL: "wss://gw/ws/attach", Log: quiet(),
	})
	if err != nil {
		t.Fatal(err)
	}
	f.srv = httptest.NewServer(api)
	t.Cleanup(f.srv.Close)
	return f
}

type staticRegistry struct{}

func (staticRegistry) Get(_ context.Context, id string) (*plugin.Device, error) {
	if id != "treadmill-4821" {
		return nil, plugin.ErrNoDevice
	}
	return &plugin.Device{ID: id, Platform: plugin.PlatformLinux}, nil
}

func (staticRegistry) List(context.Context, plugin.DeviceQuery) ([]*plugin.Device, string, error) {
	return nil, "", nil
}

func (f *fixture) postJSON(t *testing.T, path, body string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, f.srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, raw
}

// TestADenialAndAnOutageAreDifferentAnswers is the contract, from the outside.
//
// The failure this guards is a 503 for a denial or a 403 for an outage: the first tells a
// caller to retry something that will never work, and the second tells an operator their
// access was withdrawn when nothing about it changed.
func TestADenialAndAnOutageAreDifferentAnswers(t *testing.T) {
	const body = `{"device_id":"treadmill-4821","reason":"ticket AV-1"}`

	t.Run("denied", func(t *testing.T) {
		f := newAuthzFixture(t, &stubAuthz{allow: false, reason: "not in the on-call group"})
		resp, raw := f.postJSON(t, "/api/v1/sessions", body)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status %d, want 403: %s", resp.StatusCode, raw)
		}
		var prob map[string]any
		if err := json.Unmarshal(raw, &prob); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(prob["type"].(string), "not_authorized") {
			t.Errorf("type %v", prob["type"])
		}
		// The backend's own sentence reaches the operator: it is what whoever wrote the
		// rule wrote for this moment, and it is more useful than our generic copy.
		if d, _ := prob["detail"].(string); !strings.Contains(d, "on-call group") {
			t.Errorf("detail %q lost the backend's reason", d)
		}
		// A denial is not retryable — a retry button on a withdrawn grant invites
		// somebody to keep pressing it at a decision that will not change.
		if prob["retryable"] == true {
			t.Error("a denial was reported as retryable")
		}
		// And no session row exists for a session that never opened this way.
		if rows, _, _ := f.ledger.List(context.Background(), sessions.Query{}); len(rows) != 0 {
			t.Errorf("a refused-at-open session left %d rows", len(rows))
		}
	})

	t.Run("unavailable", func(t *testing.T) {
		f := newAuthzFixture(t, &stubAuthz{err: errors.New("dial tcp: connection refused")})
		resp, raw := f.postJSON(t, "/api/v1/sessions", body)
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("status %d, want 503: %s", resp.StatusCode, raw)
		}
		var prob map[string]any
		if err := json.Unmarshal(raw, &prob); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(prob["type"].(string), "authz_unavailable") {
			t.Errorf("type %v", prob["type"])
		}
		// Never a revocation: the operator's access has not changed, and the copy has
		// to say so rather than leave them to fill in the worst reading.
		text := prob["title"].(string) + " " + prob["detail"].(string)
		for _, forbidden := range []string{"revoked", "withdrawn", "removed"} {
			if strings.Contains(strings.ToLower(text), forbidden) {
				t.Errorf("an outage reads as a revocation: %q", text)
			}
		}
		if !strings.Contains(text, "hasn’t changed") {
			t.Errorf("the copy does not say the operator's access is unchanged: %q", text)
		}
		// The backend's error is for logs, not for the caller: an operator cannot act
		// on "dial tcp: connection refused".
		if strings.Contains(string(raw), "connection refused") {
			t.Errorf("the backend's error reached the caller: %s", raw)
		}
		if prob["retryable"] != true {
			t.Error("an outage was reported as not retryable")
		}
	})

	t.Run("allowed", func(t *testing.T) {
		f := newAuthzFixture(t, &stubAuthz{allow: true})
		resp, raw := f.postJSON(t, "/api/v1/sessions", body)
		// The device is not connected in this fixture, so the open fails at the
		// invitation rather than at authorisation — which is the point: it got past
		// authorisation, and the refusal names the device rather than access.
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusServiceUnavailable {
			var prob map[string]any
			_ = json.Unmarshal(raw, &prob)
			if ty, _ := prob["type"].(string); strings.Contains(ty, "authz") ||
				strings.Contains(ty, "not_authorized") {
				t.Fatalf("an allowed request was refused by authorization: %s", raw)
			}
		}
	})
}

// TestWatchingIsItsOwnGrant: a grant to open sessions is not a grant to read other
// people's.
func TestWatchingIsItsOwnGrant(t *testing.T) {
	// The stub allows `shell` and nothing else, which is what a rules file that grants
	// shell access looks like.
	f := newAuthzFixture(t, &stubAuthz{allow: false, reason: "no observe grant"})
	f.seed(t, "sess_theirs", "treadmill-4821", "someone@example.com")

	resp, raw := f.postJSON(t, "/api/v1/sessions/sess_theirs/observe", "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, want 403: %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "not_authorized") {
		t.Errorf("body %s", raw)
	}
}
