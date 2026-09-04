package apisrv_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"errors"
	"github.com/oarlock/oarlock/internal/apisrv"
	"github.com/oarlock/oarlock/internal/audit"
	"github.com/oarlock/oarlock/internal/auth/statictoken"
	"github.com/oarlock/oarlock/internal/authz"
	"github.com/oarlock/oarlock/internal/hub"
	"github.com/oarlock/oarlock/internal/invite"
	"github.com/oarlock/oarlock/internal/recordpolicy"
	regsqlite "github.com/oarlock/oarlock/internal/registry/sqlite"
	"github.com/oarlock/oarlock/internal/sessions"
	"github.com/oarlock/oarlock/internal/sqlexplore"
	"github.com/oarlock/oarlock/internal/ticket"
	"github.com/oarlock/oarlock/pkg/condition"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
	authzsqlite "github.com/oarlock/oarlock/plugins/authz/sqlite"
)

const token = "test-token-long-enough-to-pass"

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

type fixture struct {
	srv    *httptest.Server
	ledger *sessions.Memory
	live   *sessions.Registry
	agents *agentControls
}

func newFixture(t *testing.T, ratePerMin int, opts ...func(*apisrv.Options)) *fixture {
	t.Helper()
	authn, err := statictoken.Open("test", map[string]string{token: "phuc@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{
		ledger: sessions.NewMemory(sessions.Limits{PerDevice: 1, PerPrincipal: 100}, nil),
		live:   sessions.NewRegistry(),
		agents: &agentControls{devices: []string{"rower-9001", "treadmill-4821"}},
	}
	o := apisrv.Options{
		Sessions: f.ledger, Live: f.live, Authenticator: authn,
		Agents: f.agents, RatePerMinute: ratePerMin, Log: quiet(),
		SSH: &apisrv.SSHConnection{
			Host: "127.0.0.1", Port: "2222", HostKey: "ssh-ed25519 AAAAtest",
			KnownHosts: "[127.0.0.1]:2222 ssh-ed25519 AAAAtest", Fingerprint: "SHA256:test",
		},
	}
	for _, opt := range opts {
		opt(&o)
	}
	api, err := apisrv.New(o)
	if err != nil {
		t.Fatal(err)
	}
	f.srv = httptest.NewServer(api)
	t.Cleanup(f.srv.Close)
	return f
}

func TestSSHConnectionReturnsOnlyPublicMaterial(t *testing.T) {
	f := newFixture(t, 0)
	resp, body := f.do(t, http.MethodGet, apisrv.Prefix+"/ssh", token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got["host"] != "127.0.0.1" || got["port"] != "2222" || got["principal"] != "phuc@example.com" {
		t.Fatalf("SSH connection = %+v", got)
	}
	if !strings.Contains(got["known_hosts"].(string), "ssh-ed25519") || got["fingerprint"] != "SHA256:test" {
		t.Fatalf("public host material = %+v", got)
	}
	for _, forbidden := range []string{"private_key", "identity", "passphrase"} {
		if _, exists := got[forbidden]; exists {
			t.Fatalf("response exposed %s", forbidden)
		}
	}
}

type sqlStub struct{}

func (sqlStub) Schema(context.Context) ([]sqlexplore.Table, error) {
	return []sqlexplore.Table{{Name: "sessions", Columns: []sqlexplore.Column{{Name: "id", Type: "TEXT"}}}}, nil
}

func (sqlStub) Query(_ context.Context, query string, _ int) (sqlexplore.Result, error) {
	if strings.Contains(query, "tokens") {
		return sqlexplore.Result{}, sqlexplore.ErrInvalidQuery
	}
	return sqlexplore.Result{Columns: []string{"id"}, Rows: [][]any{{"ses_1"}}}, nil
}

type sqlAuthorizer struct{ allow bool }

func (a sqlAuthorizer) Authorize(_ context.Context, _ *plugin.Principal, dev *plugin.Device, action plugin.Action, tgt plugin.Target) (plugin.Decision, error) {
	return plugin.Decision{Allow: a.allow && dev.ID == "gateway" && action == plugin.ActionSQLRead}, nil
}

func (sqlAuthorizer) Watch(context.Context) (<-chan plugin.RevocationEvent, error) {
	return nil, plugin.ErrUnsupported
}

type auditCapture struct{ events []plugin.AuditEvent }

func (a *auditCapture) Emit(_ context.Context, event plugin.AuditEvent) {
	a.events = append(a.events, event)
}

func newSQLHandler(t *testing.T, allow bool, capture *auditCapture) http.Handler {
	t.Helper()
	authn, err := statictoken.Open("test", map[string]string{token: "phuc@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	api, err := apisrv.New(apisrv.Options{
		Sessions: sessions.NewMemory(sessions.Limits{}, nil), Authenticator: authn,
		Authz: &authz.Checker{Backend: sqlAuthorizer{allow: allow}, Log: quiet()},
		SQL:   sqlStub{}, Audit: capture, Log: quiet(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return api
}

func TestSQLQueryIsAuthorizedBoundedAndAudited(t *testing.T) {
	capture := &auditCapture{}
	handler := newSQLHandler(t, true, capture)
	req := httptest.NewRequest(http.MethodPost, apisrv.Prefix+"/sql/query",
		strings.NewReader(`{"query":"SELECT id FROM sessions","limit":10}`))
	req.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d: %s", recorder.Code, recorder.Body.String())
	}
	if len(capture.events) != 1 {
		t.Fatalf("audit events = %d", len(capture.events))
	}
	event := capture.events[0]
	if event.Kind != plugin.AuditSQLQuery || event.Action != "sql:read" || event.Outcome != "ok" {
		t.Fatalf("audit event = %#v", event)
	}
	if event.Attrs["query_sha256"] == "" || strings.Contains(event.Attrs["query_sha256"], "SELECT") {
		t.Fatalf("unsafe query audit attributes = %#v", event.Attrs)
	}
}

func TestSQLQueryDenialIsAudited(t *testing.T) {
	capture := &auditCapture{}
	handler := newSQLHandler(t, false, capture)
	req := httptest.NewRequest(http.MethodPost, apisrv.Prefix+"/sql/query",
		strings.NewReader(`{"query":"SELECT id FROM sessions"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status %d: %s", recorder.Code, recorder.Body.String())
	}
	if len(capture.events) != 2 || capture.events[0].Kind != plugin.AuditSQLQuery || capture.events[0].Outcome != "denied" {
		t.Fatalf("audit events = %#v", capture.events)
	}
}

func TestSQLQueryRejectsHiddenData(t *testing.T) {
	capture := &auditCapture{}
	handler := newSQLHandler(t, true, capture)
	req := httptest.NewRequest(http.MethodPost, apisrv.Prefix+"/sql/query",
		strings.NewReader(`{"query":"SELECT token_hash FROM tokens"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status %d: %s", recorder.Code, recorder.Body.String())
	}
}

type agentControls struct {
	devices []string
	err     error
	killed  atomic.Value
	reason  atomic.Value
}

func (a *agentControls) Devices() []string {
	return append([]string(nil), a.devices...)
}

func (a *agentControls) Disconnect(_ context.Context, deviceID, reason string) error {
	if a.err != nil {
		return a.err
	}
	for i, id := range a.devices {
		if id == deviceID {
			a.killed.Store(deviceID)
			a.reason.Store(reason)
			a.devices = append(a.devices[:i], a.devices[i+1:]...)
			return nil
		}
	}
	return hub.ErrNotConnected
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

func newDeviceFixture(t *testing.T) *fixture {
	t.Helper()
	authn, err := statictoken.Open("test", map[string]string{token: "phuc@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := regsqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{
		ledger: sessions.NewMemory(sessions.Limits{PerDevice: 1, PerPrincipal: 100}, nil),
		live:   sessions.NewRegistry(),
		agents: &agentControls{devices: []string{"treadmill-4821"}},
	}
	inv := &invite.Inviter{
		Tickets: ticket.NewMemory(time.Now), NodeURL: "wss://gw/ws/session",
		AttachURL: "wss://gw/ws/attach", Log: quiet(),
	}
	api, err := apisrv.New(apisrv.Options{
		Sessions: f.ledger, Live: f.live, Authenticator: authn,
		Registry: reg, RegistryAdmin: reg,
		Agents: f.agents, Inviter: inv, AttachURL: "wss://gw/ws/attach", Log: quiet(),
	})
	if err != nil {
		t.Fatal(err)
	}
	f.srv = httptest.NewServer(api)
	t.Cleanup(func() {
		f.srv.Close()
		_ = reg.Close()
	})
	return f
}

func newPermissionFixture(t *testing.T) *fixture {
	t.Helper()
	authn, err := statictoken.Open("test", map[string]string{token: "phuc@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	permissions, err := authzsqlite.Open(filepath.Join(t.TempDir(), "oarlock.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{
		ledger: sessions.NewMemory(sessions.Limits{}, nil),
		live:   sessions.NewRegistry(),
		agents: &agentControls{},
	}
	api, err := apisrv.New(apisrv.Options{
		Sessions: f.ledger, Live: f.live, Authenticator: authn,
		Permissions: permissions, Log: quiet(),
	})
	if err != nil {
		t.Fatal(err)
	}
	f.srv = httptest.NewServer(api)
	t.Cleanup(func() {
		f.srv.Close()
		_ = permissions.Close()
	})
	return f
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

// ── connected agents ───────────────────────────────────────────────────────────

func TestListAgents(t *testing.T) {
	f := newFixture(t, 0)
	resp, body := f.do(t, "GET", apisrv.Prefix+"/agents", token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	var got struct {
		Agents []map[string]any `json:"agents"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Agents) != 2 {
		t.Fatalf("agents = %d: %s", len(got.Agents), body)
	}
	if got.Agents[0]["device_id"] != "rower-9001" ||
		got.Agents[1]["device_id"] != "treadmill-4821" {
		t.Fatalf("agents not sorted or wrong: %+v", got.Agents)
	}
	if got.Agents[0]["connected"] != true {
		t.Fatalf("connected = %v", got.Agents[0]["connected"])
	}
}

func TestDisconnectAgent(t *testing.T) {
	f := newFixture(t, 0)
	resp, body := f.do(t, "DELETE", apisrv.Prefix+"/agents/treadmill-4821", token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if got, _ := f.agents.killed.Load().(string); got != "treadmill-4821" {
		t.Fatalf("disconnected %q", got)
	}
	if got, _ := f.agents.reason.Load().(string); got != "admin_stop" {
		t.Fatalf("reason %q", got)
	}
}

func TestDisconnectUnknownAgent(t *testing.T) {
	f := newFixture(t, 0)
	resp, body := f.do(t, "DELETE", apisrv.Prefix+"/agents/nope", token)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d, want 404: %s", resp.StatusCode, body)
	}
	var p apisrv.Problem
	_ = json.Unmarshal(body, &p)
	if p.Code != "not_found" {
		t.Fatalf("code %q", p.Code)
	}
}

// ── device registry admin ──────────────────────────────────────────────────────

func TestDeviceRegistryAdminAPI(t *testing.T) {
	f := newDeviceFixture(t)
	create := `{
		"id":"treadmill-4821",
		"platform":"android",
		"mode":"dispatch",
		"tags":{"fleet":"qa"},
		"profiles":["shell"]
	}`
	resp, body := f.postJSON(t, apisrv.Prefix+"/devices", create)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	var created map[string]any
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if created["connected"] != true || created["resolved_mode"] != "dispatch" {
		t.Fatalf("created device = %+v", created)
	}
	if created["enabled"] != true {
		t.Fatalf("new device was not enabled: %+v", created)
	}

	resp, body = f.putJSON(t, apisrv.Prefix+"/devices/treadmill-4821", `{
		"id":"treadmill-4821",
		"platform":"android",
		"mode":"dispatch",
		"enabled":false,
		"profiles":["shell"]
	}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("disable status %d: %s", resp.StatusCode, body)
	}
	var disabled map[string]any
	if err := json.Unmarshal(body, &disabled); err != nil {
		t.Fatal(err)
	}
	if disabled["enabled"] != false || disabled["connected"] != false {
		t.Fatalf("disabled device = %+v", disabled)
	}
	if got, _ := f.agents.killed.Load().(string); got != "treadmill-4821" {
		t.Fatalf("disabled device did not stop agent: %q", got)
	}
	if got, _ := f.agents.reason.Load().(string); got != "admin_stop" {
		t.Fatalf("agent stop reason = %q", got)
	}

	resp, body = f.postJSON(t, apisrv.Prefix+"/sessions", `{
		"device_id":"treadmill-4821",
		"profile":"shell",
		"reason":"lifecycle test"
	}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("disabled device open status %d, want 404: %s", resp.StatusCode, body)
	}

	resp, body = f.postJSON(t, apisrv.Prefix+"/devices", create)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate status %d, want 409: %s", resp.StatusCode, body)
	}

	resp, body = f.do(t, "GET", apisrv.Prefix+"/devices?mode=dispatch", token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	var list struct {
		Devices []map[string]any `json:"devices"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Devices) != 1 || list.Devices[0]["id"] != "treadmill-4821" {
		t.Fatalf("devices = %+v", list.Devices)
	}

	resp, body = f.postJSON(t, apisrv.Prefix+"/devices", `{"id":"bad id","platform":"android"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400: %s", resp.StatusCode, body)
	}

	resp, body = f.do(t, "DELETE", apisrv.Prefix+"/devices/treadmill-4821", token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	resp, body = f.do(t, "GET", apisrv.Prefix+"/devices/treadmill-4821", token)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d, want 404: %s", resp.StatusCode, body)
	}
}

func TestPermissionAdminAPI(t *testing.T) {
	f := newPermissionFixture(t)
	create := `{
		"id":"support-shell","name":"Support shell","principals":["phuc@example.com"],
		"devices":["samsung-*"],"actions":["shell","exec"],"effect":"allow",
		"max_duration":"15m","enabled":true
	}`
	resp, body := f.postJSON(t, apisrv.Prefix+"/permissions", create)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status %d: %s", resp.StatusCode, body)
	}
	var created map[string]any
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if created["effect"] != "allow" || created["max_duration"] != "15m0s" || created["enabled"] != true {
		t.Fatalf("created permission = %+v", created)
	}

	resp, body = f.do(t, http.MethodGet, apisrv.Prefix+"/permissions", token)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "support-shell") {
		t.Fatalf("list status %d: %s", resp.StatusCode, body)
	}

	resp, body = f.putJSON(t, apisrv.Prefix+"/permissions/support-shell", `{
		"id":"support-shell","name":"Support shell","principals":["phuc@example.com"],
		"devices":["samsung-*"],"actions":["shell"],"effect":"deny",
		"reason":"maintenance","enabled":false
	}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update status %d: %s", resp.StatusCode, body)
	}
	var updated map[string]any
	_ = json.Unmarshal(body, &updated)
	if updated["effect"] != "deny" || updated["enabled"] != false {
		t.Fatalf("updated permission = %+v", updated)
	}

	resp, body = f.do(t, http.MethodDelete, apisrv.Prefix+"/permissions/support-shell", token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete status %d: %s", resp.StatusCode, body)
	}
	resp, _ = f.do(t, http.MethodGet, apisrv.Prefix+"/permissions/support-shell", token)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("get deleted status %d", resp.StatusCode)
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

// heldBy is an ownership locator with a fixed answer.
type heldBy string

func (h heldBy) Elsewhere(context.Context, string) string { return string(h) }

// TestKillOnTheWrongNodeSaysSo: live in the ledger, not running here, and another
// replica holds the device. A 404 would be a lie and a 500 would suggest we are broken.
//
// This test used to omit the locator, which made it assert that *any* row live in the
// ledger and absent here is remote. On a single-node gateway that is never true, and
// the assumption made a stale row unkillable — see the test below, which is the case
// this one was accidentally covering.
func TestKillOnTheWrongNodeSaysSo(t *testing.T) {
	f := newFixture(t, 0, func(o *apisrv.Options) {
		o.Owners = heldBy("wss://gw-b.example.org")
	})
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

// The bug this pair exists for, found by running the gateway locally.
//
// A session opened through the API whose operator never attached left a row saying
// `waking` while nothing ran. With sessions_per_device at 1 that device was then
// unusable: POST answered session_limit and DELETE answered wrong_node, on a gateway
// that had no other node. Only a restart cleared it.
func TestKillClosesAStaleRowOnASingleNodeGateway(t *testing.T) {
	f := newFixture(t, 0) // no locator: one node, so nothing is held anywhere else
	f.seed(t, "s1", "dev-1", "phuc@example.com")

	resp, body := f.do(t, "DELETE", apisrv.Prefix+"/sessions/s1", token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", resp.StatusCode, body)
	}
	var out struct {
		Killed bool   `json:"killed"`
		State  string `json:"state"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if !out.Killed || out.State != string(sessions.StateClosed) {
		t.Fatalf("killed=%v state=%q, want true/closed", out.Killed, out.State)
	}

	// The point of closing it: the ledger stops claiming the device is busy.
	row, err := f.ledger.Get(context.Background(), "s1")
	if err != nil {
		t.Fatal(err)
	}
	if row.Live() {
		t.Fatalf("the row is still live: state %q", row.State)
	}
	if row.CloseReason != "admin_kill" {
		t.Fatalf("close reason %q, want admin_kill", row.CloseReason)
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

type delegatingAuth struct {
	http      map[string]*plugin.Principal
	delegated map[string]*plugin.Principal
	err       map[string]error
}

func (a *delegatingAuth) AuthPublicKey(context.Context, string, ssh.PublicKey) (*plugin.Principal, error) {
	return nil, plugin.ErrUnsupported
}

func (a *delegatingAuth) AuthHTTP(_ context.Context, r *http.Request) (*plugin.Principal, error) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return nil, errors.New("no bearer token")
	}
	p := a.http[token]
	if p == nil {
		return nil, errors.New("unknown token")
	}
	out := *p
	return &out, nil
}

func (a *delegatingAuth) AuthDelegated(_ context.Context, svc *plugin.Principal, assertion string) (*plugin.Principal, error) {
	if err := a.err[assertion]; err != nil {
		return nil, err
	}
	p := a.delegated[svc.ID+"|"+assertion]
	if p == nil {
		return nil, errors.New("assertion rejected")
	}
	out := *p
	return &out, nil
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
	plugin.Action, plugin.Target) (plugin.Decision, error) {
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

func newDelegationFixture(t *testing.T, authn plugin.Authenticator, backend *stubAuthz) *fixture {
	return newDelegationFixtureWithOptions(t, authn, backend, false)
}

func newDelegationFixtureWithOptions(t *testing.T, authn plugin.Authenticator, backend *stubAuthz,
	allowUnattended bool) *fixture {
	t.Helper()
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
		AttachURL: "wss://gw/ws/attach", AllowUnattended: allowUnattended, Log: quiet(),
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

type taggedRegistry struct {
	tags map[string]string
}

func (r taggedRegistry) Get(_ context.Context, id string) (*plugin.Device, error) {
	if id != "treadmill-4821" {
		return nil, plugin.ErrNoDevice
	}
	return &plugin.Device{ID: id, Platform: plugin.PlatformLinux, Tags: r.tags}, nil
}

func (taggedRegistry) List(context.Context, plugin.DeviceQuery) ([]*plugin.Device, string, error) {
	return nil, "", nil
}

type acceptingHub struct{}

func (acceptingHub) Connected(string) bool { return true }

func (acceptingHub) Invite(context.Context, string, frame.Invitation) error { return nil }

func (acceptingHub) Cancel(context.Context, string, string, string) error { return nil }

type policyAuth struct {
	p *plugin.Principal
}

func (a policyAuth) AuthHTTP(_ context.Context, r *http.Request) (*plugin.Principal, error) {
	if r.Header.Get("Authorization") != "Bearer "+token {
		return nil, plugin.ErrNoDevice
	}
	return a.p, nil
}

func (policyAuth) AuthPublicKey(context.Context, string, ssh.PublicKey) (*plugin.Principal, error) {
	return nil, plugin.ErrUnsupported
}

func (policyAuth) AuthDelegated(context.Context, *plugin.Principal, string) (*plugin.Principal, error) {
	return nil, plugin.ErrUnsupported
}

func (f *fixture) postJSON(t *testing.T, path, body string) (*http.Response, []byte) {
	t.Helper()
	return f.postJSONWithHeaders(t, path, body, map[string]string{"Authorization": "Bearer " + token})
}

func (f *fixture) putJSON(t *testing.T, path, body string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, f.srv.URL+path, strings.NewReader(body))
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

func (f *fixture) postJSONWithHeaders(t *testing.T, path, body string, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, f.srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
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

func newRecordPolicyFixture(t *testing.T, principal *plugin.Principal,
	policy recordpolicy.RecordInput) (*fixture, *invite.Inviter, *audit.Memory) {
	t.Helper()
	f := &fixture{
		ledger: sessions.NewMemory(sessions.Limits{PerDevice: 1, PerPrincipal: 100}, nil),
		live:   sessions.NewRegistry(),
	}
	auditLog := &audit.Memory{}
	inv := &invite.Inviter{
		Tickets: ticket.NewMemory(time.Now), Hub: acceptingHub{},
		NodeURL: "wss://gw/ws/session", AttachURL: "wss://gw/ws/attach", Log: quiet(),
	}
	api, err := apisrv.New(apisrv.Options{
		Sessions: f.ledger, Live: f.live,
		Authenticator: policyAuth{p: principal},
		Registry:      taggedRegistry{tags: map[string]string{"pci_scope": "true"}},
		Inviter:       inv, Authz: &authz.Checker{Backend: &stubAuthz{allow: true}, Log: quiet()},
		RecordInput: policy,
		Audit:       auditLog,
		AttachURL:   "wss://gw/ws/attach", Log: quiet(),
	})
	if err != nil {
		t.Fatal(err)
	}
	f.srv = httptest.NewServer(api)
	t.Cleanup(f.srv.Close)
	return f, inv, auditLog
}

func TestRecordInputPolicyTravelsInAttachTicket(t *testing.T) {
	f, inv, _ := newRecordPolicyFixture(t,
		&plugin.Principal{ID: "phuc@example.com", Groups: []string{"apac-staff"}},
		recordpolicy.RecordInput{Rules: []recordpolicy.Rule{{
			Name:  "pci capture",
			When:  recordpolicy.Selector{DeviceTags: map[string]string{"pci_scope": "true"}},
			Value: true,
		}}},
	)
	resp, raw := f.postJSON(t, "/api/v1/sessions",
		`{"device_id":"treadmill-4821","reason":"ticket AV-1"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d, want 201: %s", resp.StatusCode, raw)
	}
	var got struct {
		Attach struct {
			Ticket string `json:"ticket"`
		} `json:"attach"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	claims, err := inv.Redeem(context.Background(), got.Attach.Ticket,
		ticket.Want{Kind: ticket.KindAttach})
	if err != nil {
		t.Fatal(err)
	}
	if !claims.RecordInput {
		t.Fatalf("attach claims RecordInput=false, want true: %+v", claims)
	}
}

func TestRecordInputPolicyConflictRefusesBeforeRow(t *testing.T) {
	f, _, auditLog := newRecordPolicyFixture(t,
		&plugin.Principal{ID: "ana@example.com", Groups: []string{"eu-staff"}},
		recordpolicy.RecordInput{Rules: []recordpolicy.Rule{
			{
				Name:  "pci capture",
				When:  recordpolicy.Selector{DeviceTags: map[string]string{"pci_scope": "true"}},
				Value: true,
			},
			{
				Authority: "employment-law",
				When:      recordpolicy.Selector{PrincipalGroups: []string{"eu-*"}},
				Value:     false,
			},
		}},
	)
	resp, raw := f.postJSON(t, "/api/v1/sessions",
		`{"device_id":"treadmill-4821","reason":"ticket AV-1"}`)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status %d, want 409: %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "policy_conflict") ||
		!strings.Contains(string(raw), "pci capture") ||
		!strings.Contains(string(raw), "employment-law") {
		t.Fatalf("conflict response did not name both rules: %s", raw)
	}
	if rows, _, _ := f.ledger.List(context.Background(), sessions.Query{}); len(rows) != 0 {
		t.Fatalf("policy conflict left %d session rows", len(rows))
	}
	events := auditLog.Snapshot()
	if len(events) == 0 {
		t.Fatal("no audit event for policy conflict")
	}
	last := events[len(events)-1]
	if last.Kind != plugin.AuditAPIError || last.Code != "policy_conflict" ||
		!strings.Contains(last.Reason, "pci capture") ||
		!strings.Contains(last.Reason, "employment-law") {
		t.Fatalf("audit event = %+v", last)
	}
}

func TestBareOnBehalfOfIsRefused(t *testing.T) {
	f := newAuthzFixture(t, &stubAuthz{allow: true})
	resp, raw := f.postJSONWithHeaders(t, "/api/v1/sessions",
		`{"device_id":"treadmill-4821","reason":"ticket AV-1"}`,
		map[string]string{
			"Authorization":         "Bearer " + token,
			apisrv.HeaderOnBehalfOf: "phuc@example.com",
		})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400: %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "delegation_missing_assertion") {
		t.Fatalf("body %s", raw)
	}
	if rows, _, _ := f.ledger.List(context.Background(), sessions.Query{}); len(rows) != 0 {
		t.Fatalf("bare On-Behalf-Of left %d session rows", len(rows))
	}
}

func TestDelegationUnsupportedIsExplicit(t *testing.T) {
	f := newAuthzFixture(t, &stubAuthz{allow: true})
	resp, raw := f.postJSONWithHeaders(t, "/api/v1/sessions",
		`{"device_id":"treadmill-4821","reason":"ticket AV-1"}`,
		map[string]string{
			"Authorization":            "Bearer " + token,
			apisrv.HeaderOnBehalfToken: "signed-assertion",
		})
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status %d, want 501: %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "delegation_unsupported") {
		t.Fatalf("body %s", raw)
	}
}

func TestDelegatedSessionIsAttributedToTheHumanAndOpenedByTheService(t *testing.T) {
	authn := &delegatingAuth{
		http: map[string]*plugin.Principal{
			"svc-token": {ID: "svc-crm"},
		},
		delegated: map[string]*plugin.Principal{
			"svc-crm|assert-phuc": {ID: "phuc@example.com", Groups: []string{"oncall"}},
		},
		err: map[string]error{},
	}
	f := newDelegationFixture(t, authn, &stubAuthz{allow: true})
	resp, raw := f.postJSONWithHeaders(t, "/api/v1/sessions",
		`{"device_id":"treadmill-4821","reason":"ticket AV-1"}`,
		map[string]string{
			"Authorization":            "Bearer svc-token",
			apisrv.HeaderOnBehalfOf:    "phuc@example.com",
			apisrv.HeaderOnBehalfToken: "assert-phuc",
		})
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized ||
		resp.StatusCode == http.StatusBadRequest {
		t.Fatalf("delegation was refused: status %d body %s", resp.StatusCode, raw)
	}
	rows, _, err := f.ledger.List(context.Background(), sessions.Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, body %s", len(rows), raw)
	}
	row := rows[0]
	if row.Principal != "phuc@example.com" || row.OpenedBy != "svc-crm" || row.Unattended {
		t.Fatalf("row attribution = principal %q opened_by %q unattended %v",
			row.Principal, row.OpenedBy, row.Unattended)
	}
}

func TestDelegatedSubjectHeaderMustMatchTheAssertion(t *testing.T) {
	authn := &delegatingAuth{
		http: map[string]*plugin.Principal{"svc-token": {ID: "svc-crm"}},
		delegated: map[string]*plugin.Principal{
			"svc-crm|assert-phuc": {ID: "phuc@example.com"},
		},
		err: map[string]error{},
	}
	f := newDelegationFixture(t, authn, &stubAuthz{allow: true})
	resp, raw := f.postJSONWithHeaders(t, "/api/v1/sessions",
		`{"device_id":"treadmill-4821","reason":"ticket AV-1"}`,
		map[string]string{
			"Authorization":            "Bearer svc-token",
			apisrv.HeaderOnBehalfOf:    "somebody-else@example.com",
			apisrv.HeaderOnBehalfToken: "assert-phuc",
		})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400: %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "delegation_subject_mismatch") {
		t.Fatalf("body %s", raw)
	}
}

func TestInvalidDelegatedAssertionIsDistinct(t *testing.T) {
	authn := &delegatingAuth{
		http:      map[string]*plugin.Principal{"svc-token": {ID: "svc-crm"}},
		delegated: map[string]*plugin.Principal{},
		err:       map[string]error{"expired": errors.New("expired assertion")},
	}
	f := newDelegationFixture(t, authn, &stubAuthz{allow: true})
	resp, raw := f.postJSONWithHeaders(t, "/api/v1/sessions",
		`{"device_id":"treadmill-4821","reason":"ticket AV-1"}`,
		map[string]string{
			"Authorization":            "Bearer svc-token",
			apisrv.HeaderOnBehalfToken: "expired",
		})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401: %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "delegation_invalid") {
		t.Fatalf("body %s", raw)
	}
}

func TestUnattendedSessionsAreQueryableSeparately(t *testing.T) {
	f := newFixture(t, 0)
	human := f.seed(t, "sess_human", "treadmill-4821", "phuc@example.com")
	robot := f.seed(t, "sess_robot", "bike-7", "svc-crm")
	robot.Unattended = true
	if err := f.ledger.Update(context.Background(), human.ID, func(row *sessions.Session) error {
		row.Unattended = false
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.ledger.Update(context.Background(), robot.ID, func(row *sessions.Session) error {
		row.Unattended = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	resp, raw := f.do(t, "GET", apisrv.Prefix+"/sessions?unattended=true", token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, raw)
	}
	var out struct {
		Sessions []apisrvTestSession `json:"sessions"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Sessions) != 1 || out.Sessions[0].ID != "sess_robot" || !out.Sessions[0].Unattended {
		t.Fatalf("sessions = %+v", out.Sessions)
	}
}

func TestUnattendedSessionRequiresExplicitAPIGate(t *testing.T) {
	authn := &delegatingAuth{
		http: map[string]*plugin.Principal{
			"svc-token": {ID: "svc-crm", Unattended: true},
		},
		delegated: map[string]*plugin.Principal{},
		err:       map[string]error{},
	}
	body := `{"device_id":"treadmill-4821","reason":"scheduled diagnostic"}`

	t.Run("refused by default", func(t *testing.T) {
		f := newDelegationFixtureWithOptions(t, authn, &stubAuthz{allow: true}, false)
		resp, raw := f.postJSONWithHeaders(t, "/api/v1/sessions", body,
			map[string]string{"Authorization": "Bearer svc-token"})
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status %d, want 403: %s", resp.StatusCode, raw)
		}
		if !strings.Contains(string(raw), "unattended_not_allowed") {
			t.Fatalf("body %s", raw)
		}
	})

	t.Run("tagged when allowed", func(t *testing.T) {
		f := newDelegationFixtureWithOptions(t, authn, &stubAuthz{allow: true}, true)
		resp, raw := f.postJSONWithHeaders(t, "/api/v1/sessions", body,
			map[string]string{"Authorization": "Bearer svc-token"})
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized ||
			resp.StatusCode == http.StatusBadRequest {
			t.Fatalf("unattended session was refused: status %d body %s", resp.StatusCode, raw)
		}
		rows, _, err := f.ledger.List(context.Background(), sessions.Query{})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].Principal != "svc-crm" || !rows[0].Unattended {
			t.Fatalf("rows = %+v", rows)
		}
	})
}

type apisrvTestSession struct {
	ID         string `json:"id"`
	Unattended bool   `json:"unattended"`
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
