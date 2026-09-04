package apisrv_test

// The administrative surface is authorised, not merely authenticated.
//
// The hole these tests were written against: every handler under /devices,
// /permissions and the two kill endpoints took the authenticated principal and threw
// it away. Under `authorizer.kind: sqlite` — where the store that answers
// authorisation questions is the same store the admin API writes to — that made every
// other check in the product advisory. A token refused `sql:read` could POST itself a
// wildcard allow and ask again.
//
// So the fixture here is deliberately the shipped wiring rather than a stub: one
// authzsqlite.Store as both the Authorizer behind the Checker and the PermissionAdmin
// behind the API, exactly as cmd/oarlockd/app builds it.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oarlock/oarlock/internal/apisrv"
	"github.com/oarlock/oarlock/internal/auth/statictoken"
	"github.com/oarlock/oarlock/internal/authz"
	regsqlite "github.com/oarlock/oarlock/internal/registry/sqlite"
	"github.com/oarlock/oarlock/internal/sessions"
	"github.com/oarlock/oarlock/pkg/plugin"
	authzsqlite "github.com/oarlock/oarlock/plugins/authz/sqlite"
)

const (
	// Principals, and the tokens that prove them.
	adminToken   = "admin-token-long-enough-to-pass"
	fleetToken   = "fleet-token-long-enough-to-pass"
	nobodyToken  = "nobody-token-long-enough-to-pass"
	adminID      = "root@example.com"
	fleetID      = "fleet@example.com"
	nobodyID     = "nobody@example.com"
	wildcardRule = `{"id":"pwn","principals":["*"],"devices":["*"],"actions":["*"],` +
		`"effect":"allow","enabled":true}`
)

// A registered device needs a key; which key is beside the point here, so it is one
// fixed key, spelled the way the API spells it.
var testDeviceKey = base64.StdEncoding.EncodeToString(
	ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize)).
		Public().(ed25519.PublicKey))

type adminFixture struct {
	srv    *httptest.Server
	store  *authzsqlite.Store
	reg    *regsqlite.Registry
	ledger *sessions.Memory
	live   *sessions.Registry
	agents *agentControls
	audit  *auditCapture
}

// newAdminFixture builds the API with a real policy store behind it. configAdmins
// declares the break-glass administrators from the gateway's config file.
func newAdminFixture(t *testing.T, configAdmins ...string) *adminFixture {
	t.Helper()
	authn, err := statictoken.Open("test", map[string]string{
		adminToken: adminID, fleetToken: fleetID, nobodyToken: nobodyID,
	})
	if err != nil {
		t.Fatal(err)
	}
	store, err := authzsqlite.Open(filepath.Join(t.TempDir(), "policy.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := regsqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	f := &adminFixture{
		store: store, reg: reg,
		ledger: sessions.NewMemory(sessions.Limits{PerDevice: 10, PerPrincipal: 10}, nil),
		live:   sessions.NewRegistry(),
		agents: &agentControls{devices: []string{"treadmill-4821", "rower-9001"}},
		audit:  &auditCapture{},
	}
	api, err := apisrv.New(apisrv.Options{
		Sessions: f.ledger, Live: f.live, Authenticator: authn,
		Authz:    &authz.Checker{Backend: store, Admins: configAdmins, Log: quiet()},
		Registry: reg, RegistryAdmin: reg, Permissions: store,
		Agents: f.agents, SQL: sqlStub{}, Audit: f.audit, Log: quiet(),
	})
	if err != nil {
		t.Fatal(err)
	}
	f.srv = httptest.NewServer(api)
	t.Cleanup(func() {
		f.srv.Close()
		_ = store.Close()
		_ = reg.Close()
	})
	return f
}

// deviceBody is a PUT body for a device that already exists.
func deviceBody(id string, enabled bool) string {
	return `{"id":"` + id + `","platform":"linux","enabled":` +
		map[bool]string{true: "true", false: "false"}[enabled] +
		`,"profiles":["shell"],"keys":["` + testDeviceKey + `"]}`
}

// grant writes a permission straight into the store, the way an administrator who
// already has access would through the API.
func (f *adminFixture) grant(t *testing.T, p *plugin.Permission) {
	t.Helper()
	p.Enabled = true
	if err := f.store.CreatePermission(context.Background(), p); err != nil {
		t.Fatal(err)
	}
}

func (f *adminFixture) device(t *testing.T, id string, tags map[string]string) {
	t.Helper()
	key, err := plugin.ParseDeviceKey(testDeviceKey)
	if err != nil {
		t.Fatal(err)
	}
	d := &plugin.Device{ID: id, Platform: plugin.PlatformLinux, Tags: tags,
		Keys: []ed25519.PublicKey{key}, Profiles: []string{"shell"}}
	if err := f.reg.Create(context.Background(), d); err != nil {
		t.Fatal(err)
	}
}

func (f *adminFixture) call(t *testing.T, method, path, bearer, body string) (int, []byte) {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, f.srv.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := make([]byte, 1<<16)
	n, _ := resp.Body.Read(out)
	return resp.StatusCode, out[:n]
}

// TestNoGrantNoAdministration: the whole surface, refused.
//
// Every one of these returned 2xx before the gate existed, on nothing but a valid
// bearer token.
func TestNoGrantNoAdministration(t *testing.T) {
	f := newAdminFixture(t)
	f.device(t, "treadmill-4821", nil)
	f.grant(t, &plugin.Permission{ID: "someone-elses", Principals: []string{fleetID},
		Devices: []string{"*"}, Actions: []string{"shell"}})
	f.ledger.Create(context.Background(), &sessions.Session{ID: "sess_other",
		DeviceID: "treadmill-4821", Principal: fleetID, Profile: "shell",
		Mode: "dispatch", State: sessions.StateAttached, RecordingState: sessions.Recorded})

	newDevice := `{"id":"mine","platform":"linux","profiles":["shell"],"keys":["` +
		testDeviceKey + `"]}`
	for _, tc := range []struct{ name, method, path, body string }{
		{"list policy", http.MethodGet, "/permissions", ""},
		{"read one rule", http.MethodGet, "/permissions/someone-elses", ""},
		{"write a rule", http.MethodPost, "/permissions", wildcardRule},
		{"edit a rule", http.MethodPut, "/permissions/someone-elses", wildcardRule},
		{"delete a rule", http.MethodDelete, "/permissions/someone-elses", ""},
		{"register a device", http.MethodPost, "/devices", newDevice},
		{"edit a device", http.MethodPut, "/devices/treadmill-4821",
			deviceBody("treadmill-4821", false)},
		{"delete a device", http.MethodDelete, "/devices/treadmill-4821", ""},
		{"stop an agent", http.MethodDelete, "/agents/treadmill-4821", ""},
		{"kill somebody else's session", http.MethodDelete, "/sessions/sess_other", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, body := f.call(t, tc.method, apisrv.Prefix+tc.path, nobodyToken, tc.body)
			if status != http.StatusForbidden {
				t.Fatalf("status %d, want 403: %s", status, body)
			}
			if !strings.Contains(string(body), "not_authorized") {
				t.Fatalf("refusal did not use the not_authorized condition: %s", body)
			}
		})
	}

	// Nothing happened. The device is still there, still enabled, and the rule that
	// was not the caller's to touch is unchanged.
	d, err := f.reg.Get(context.Background(), "treadmill-4821")
	if err != nil || d.Disabled {
		t.Fatalf("device after refused edits: %+v, err %v", d, err)
	}
	if _, err := f.store.GetPermission(context.Background(), "someone-elses"); err != nil {
		t.Fatalf("somebody else's rule after a refused delete: %v", err)
	}
	if _, err := f.store.GetPermission(context.Background(), "pwn"); err == nil {
		t.Fatal("a refused POST wrote the rule anyway")
	}
}

// TestTheEscalationIsClosed walks the exact path that worked before: refused an
// action, write yourself the action, ask again.
//
// It is a separate test from the table above because the table proves each endpoint
// refuses, and this proves the loop those endpoints closed.
func TestTheEscalationIsClosed(t *testing.T) {
	f := newAdminFixture(t)

	status, body := f.call(t, http.MethodPost, apisrv.Prefix+"/sql/query", nobodyToken,
		`{"query":"SELECT id FROM sessions"}`)
	if status != http.StatusForbidden {
		t.Fatalf("sql/query for an ungranted principal: %d %s", status, body)
	}

	status, body = f.call(t, http.MethodPost, apisrv.Prefix+"/permissions", nobodyToken,
		wildcardRule)
	if status != http.StatusForbidden {
		t.Fatalf("writing a wildcard allow: status %d, want 403: %s", status, body)
	}

	status, body = f.call(t, http.MethodPost, apisrv.Prefix+"/sql/query", nobodyToken,
		`{"query":"SELECT id FROM sessions"}`)
	if status != http.StatusForbidden {
		t.Fatalf("sql/query after the attempt: %d %s", status, body)
	}
}

// TestAdminGrantsAreDeviceScoped: `admin:devices` on part of a fleet administers that
// part of the fleet. Checked against the *stored* record, so a tag-scoped grant means
// what it says.
func TestAdminGrantsAreDeviceScoped(t *testing.T) {
	f := newAdminFixture(t)
	f.device(t, "treadmill-4821", nil)
	f.device(t, "rower-9001", nil)
	f.grant(t, &plugin.Permission{ID: "fleet-admin", Principals: []string{fleetID},
		Devices: []string{"treadmill-*"},
		Actions: []string{"admin:devices", "admin:kill"}})

	status, body := f.call(t, http.MethodPut, apisrv.Prefix+"/devices/treadmill-4821",
		fleetToken, deviceBody("treadmill-4821", false))
	if status != http.StatusOK {
		t.Fatalf("in-scope device edit: %d %s", status, body)
	}
	status, body = f.call(t, http.MethodPut, apisrv.Prefix+"/devices/rower-9001",
		fleetToken, deviceBody("rower-9001", false))
	if status != http.StatusForbidden {
		t.Fatalf("out-of-scope device edit: %d, want 403: %s", status, body)
	}
	if d, _ := f.reg.Get(context.Background(), "rower-9001"); d.Disabled {
		t.Fatal("a refused edit disabled the device anyway")
	}

	// Fleet admin over devices is not admin over policy: the two actions are separate
	// on purpose, because one is operations and the other is access.
	status, body = f.call(t, http.MethodGet, apisrv.Prefix+"/permissions", fleetToken, "")
	if status != http.StatusForbidden {
		t.Fatalf("device admin reading the policy: %d, want 403: %s", status, body)
	}
}

// TestTagScopedDenyReachesTheAdminSurface: a deny written against a device tag stops
// an administrative edit too, because the check runs against the stored record.
func TestTagScopedDenyReachesTheAdminSurface(t *testing.T) {
	f := newAdminFixture(t)
	f.device(t, "treadmill-4821", map[string]string{"pci_scope": "true"})
	f.device(t, "rower-9001", nil)
	f.grant(t, &plugin.Permission{ID: "fleet-admin", Principals: []string{fleetID},
		Devices: []string{"*"}, Actions: []string{"admin:devices"}})
	f.grant(t, &plugin.Permission{ID: "deny-pci", Principals: []string{"*"},
		Devices: []string{"*"}, Tags: map[string]string{"pci_scope": "true"},
		Actions: []string{"*"}, Deny: true,
		Reason: "PCI-scoped devices need a change ticket"})

	status, body := f.call(t, http.MethodDelete, apisrv.Prefix+"/devices/treadmill-4821",
		fleetToken, "")
	if status != http.StatusForbidden {
		t.Fatalf("deleting a PCI-scoped device: %d, want 403: %s", status, body)
	}
	if !strings.Contains(string(body), "change ticket") {
		t.Fatalf("the deny's own sentence did not reach the operator: %s", body)
	}
	status, _ = f.call(t, http.MethodDelete, apisrv.Prefix+"/devices/rower-9001", fleetToken, "")
	if status != http.StatusOK {
		t.Fatalf("deleting an untagged device: %d", status)
	}
}

// TestConfigAdminRepairsPolicyAndNothingElse is the break-glass, and its limit.
//
// The cycle it breaks: the policy store is edited through an API the policy store
// authorises, so an empty store has nobody who may write the first rule. The limit
// that keeps it from being a back door: `admin:*` only. A config administrator can
// hand themselves a shell, but only by writing a rule that shows up in the policy and
// in the audit trail.
func TestConfigAdminRepairsPolicyAndNothingElse(t *testing.T) {
	f := newAdminFixture(t, adminID)

	// An empty store, and the config administrator writes the first rule.
	status, body := f.call(t, http.MethodPost, apisrv.Prefix+"/permissions", adminToken,
		`{"id":"first","principals":["fleet@example.com"],"devices":["*"],`+
			`"actions":["shell"],"effect":"allow","enabled":true}`)
	if status != http.StatusCreated {
		t.Fatalf("bootstrap write: %d %s", status, body)
	}

	// And cannot use the gateway on the strength of the config entry alone.
	for _, tc := range []struct{ name, path, body string }{
		{"query the database", "/sql/query", `{"query":"SELECT id FROM sessions"}`},
	} {
		status, body := f.call(t, http.MethodPost, apisrv.Prefix+tc.path, adminToken, tc.body)
		if status != http.StatusForbidden {
			t.Fatalf("config admin may %s: %d %s", tc.name, status, body)
		}
	}

	// It is not a wildcard for the other admin actions either — those it does have,
	// and that is the whole of it.
	f.device(t, "treadmill-4821", nil)
	status, body = f.call(t, http.MethodPut, apisrv.Prefix+"/devices/treadmill-4821",
		adminToken, deviceBody("treadmill-4821", false))
	if status != http.StatusOK {
		t.Fatalf("config admin editing a device: %d %s", status, body)
	}
}

// TestTheBreakGlassStopsAtSessionActions is where the config-file administrator ends.
//
// Two halves, and the second is the one that matters.
//
// It does outrank the policy store for `admin:*`, deny rules included. That is not an
// oversight: whoever can edit the config file can also edit the rules file, repoint the
// database or restart with a different backend, so a deny row in a store cannot
// meaningfully constrain them, and pretending it can would buy nothing and cost the
// locked-room recovery this field exists for. It is logged at boot and on every use.
//
// It does not reach a session action, even one the store grants. A deny on `shell` holds
// against a config administrator, because the break-glass never enters that decision —
// which is what keeps `authorizer.admins` from being a quiet root account.
func TestTheBreakGlassStopsAtSessionActions(t *testing.T) {
	f := newAdminFixture(t, adminID)
	f.device(t, "treadmill-4821", map[string]string{"pci_scope": "true"})
	f.grant(t, &plugin.Permission{ID: "everything", Principals: []string{adminID},
		Devices: []string{"*"}, Actions: []string{"*"}})
	f.grant(t, &plugin.Permission{ID: "deny-reads", Principals: []string{"*"},
		Devices: []string{"*"}, Actions: []string{"sql:read"}, Deny: true,
		Reason: "the operational database is read through the reporting warehouse"})

	// Granted `*` by the store and denied `sql:read` by a later rule: the deny wins,
	// and being a config administrator does not enter into it.
	status, body := f.call(t, http.MethodPost, apisrv.Prefix+"/sql/query", adminToken,
		`{"query":"SELECT id FROM sessions"}`)
	if status != http.StatusForbidden {
		t.Fatalf("a deny on a session action did not hold: %d %s", status, body)
	}
	if !strings.Contains(string(body), "reporting warehouse") {
		t.Fatalf("the deny's own sentence did not reach the operator: %s", body)
	}

	// The documented other half, asserted so that a change to it has to be deliberate:
	// an administrative action goes through, deny or no deny.
	f.grant(t, &plugin.Permission{ID: "deny-everything", Principals: []string{"*"},
		Devices: []string{"*"}, Actions: []string{"*"}, Deny: true,
		Reason: "frozen for change control"})
	if status, body := f.call(t, http.MethodDelete,
		apisrv.Prefix+"/devices/treadmill-4821", adminToken, ""); status != http.StatusOK {
		t.Fatalf("the config break-glass could not reach past a blanket deny, so a bad "+
			"rule is now unrecoverable through the API: %d %s", status, body)
	}
}

// TestEndingYourOwnSessionIsNotAdministration. Killing your own shell is
// self-service; killing somebody else's is an intervention in their work.
func TestEndingYourOwnSessionIsNotAdministration(t *testing.T) {
	f := newAdminFixture(t)
	f.device(t, "treadmill-4821", nil)
	for id, principal := range map[string]string{"sess_mine": nobodyID, "sess_theirs": fleetID} {
		if err := f.ledger.Create(context.Background(), &sessions.Session{ID: id,
			DeviceID: "treadmill-4821", Principal: principal, Profile: "shell",
			Mode: "dispatch", State: sessions.StateAttached,
			RecordingState: sessions.Recorded}); err != nil {
			t.Fatal(err)
		}
		f.live.Add(&sessions.Handle{ID: id, DeviceID: "treadmill-4821"}, func(string) {})
	}

	if status, body := f.call(t, http.MethodDelete, apisrv.Prefix+"/sessions/sess_mine",
		nobodyToken, ""); status != http.StatusOK {
		t.Fatalf("ending my own session needed a grant: %d %s", status, body)
	}
	if status, body := f.call(t, http.MethodDelete, apisrv.Prefix+"/sessions/sess_theirs",
		nobodyToken, ""); status != http.StatusForbidden {
		t.Fatalf("ending somebody else's session: %d, want 403: %s", status, body)
	}
}

// TestPolicyChangesAreAuditedWithTheirShape. "perm_9f2c created" is not an audit
// trail: the row it names may since have been edited away. What the rule said when it
// was written is the part a reviewer needs.
func TestPolicyChangesAreAuditedWithTheirShape(t *testing.T) {
	f := newAdminFixture(t, adminID)
	status, body := f.call(t, http.MethodPost, apisrv.Prefix+"/permissions", adminToken,
		`{"id":"wide","principals":["*@example.com"],"devices":["treadmill-*"],`+
			`"actions":["shell","exec"],"effect":"allow","enabled":true}`)
	if status != http.StatusCreated {
		t.Fatalf("status %d: %s", status, body)
	}
	var found *plugin.AuditEvent
	for i := range f.audit.events {
		if f.audit.events[i].Kind == plugin.AuditAdminChange {
			found = &f.audit.events[i]
		}
	}
	if found == nil {
		t.Fatalf("no admin.change event in %#v", f.audit.events)
	}
	if found.Principal != adminID || found.Outcome != "created" ||
		found.Action != "admin:permissions" {
		t.Fatalf("audit event = %#v", found)
	}
	for key, want := range map[string]string{
		"permission": "wide", "effect": "allow", "grants": "shell,exec",
		"principals": "*@example.com", "devices": "treadmill-*",
	} {
		if found.Attrs[key] != want {
			t.Fatalf("audit attr %s = %q, want %q (all: %#v)", key, found.Attrs[key], want, found.Attrs)
		}
	}
}

// TestRefusedAdministrationIsAudited: the attempt that failed is the interesting one.
func TestRefusedAdministrationIsAudited(t *testing.T) {
	f := newAdminFixture(t)
	if status, _ := f.call(t, http.MethodPost, apisrv.Prefix+"/permissions", nobodyToken,
		wildcardRule); status != http.StatusForbidden {
		t.Fatalf("status %d", status)
	}
	for _, e := range f.audit.events {
		if e.Kind == plugin.AuditAdminChange && e.Outcome == "denied" &&
			e.Principal == nobodyID && e.Code == "not_authorized" {
			return
		}
	}
	t.Fatalf("a refused policy write left no audit line: %#v", f.audit.events)
}

// TestAdminActionsAreNotSessionActions guards the boundary the break-glass depends on.
// If a session action ever answered true here, a config administrator would silently
// gain the run of the fleet.
func TestAdminActionsAreNotSessionActions(t *testing.T) {
	admin := []plugin.Action{plugin.ActionAdminDevices, plugin.ActionAdminPermissions,
		plugin.ActionAdminKill}
	session := []plugin.Action{plugin.ActionShell, plugin.ActionExec,
		plugin.ActionFileRead, plugin.ActionFileWrite, plugin.ActionTCP,
		plugin.ActionPassthrough, plugin.ActionReplay, plugin.ActionObserve,
		plugin.ActionSQLRead}
	for _, a := range admin {
		if !a.Administrative() {
			t.Errorf("%s is not administrative", a)
		}
	}
	for _, a := range session {
		if a.Administrative() {
			t.Errorf("%s counts as administrative, so a config admin now has it", a)
		}
	}
}

// TestAdminEndpointsRefuseWithoutAuthentication keeps the gate from becoming the only
// thing standing there: an unauthenticated caller must still not reach a handler.
func TestAdminEndpointsRefuseWithoutAuthentication(t *testing.T) {
	f := newAdminFixture(t, adminID)
	req, err := http.NewRequest(http.MethodPost, f.srv.URL+apisrv.Prefix+"/permissions",
		strings.NewReader(wildcardRule))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := f.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", resp.StatusCode)
	}
}

// TestGrantedAdminCanStillWork is the other half: a gate that refuses everybody is not
// a fix. A principal granted admin:permissions in the policy administers the policy.
func TestGrantedAdminCanStillWork(t *testing.T) {
	f := newAdminFixture(t)
	f.grant(t, &plugin.Permission{ID: "policy-admin", Principals: []string{fleetID},
		Devices: []string{"gateway"}, Actions: []string{"admin:permissions"}})

	status, body := f.call(t, http.MethodPost, apisrv.Prefix+"/permissions", fleetToken,
		`{"id":"support","principals":["support@example.com"],"devices":["rower-*"],`+
			`"actions":["shell"],"effect":"allow","enabled":true}`)
	if status != http.StatusCreated {
		t.Fatalf("granted admin writing a rule: %d %s", status, body)
	}
	status, body = f.call(t, http.MethodGet, apisrv.Prefix+"/permissions", fleetToken, "")
	if status != http.StatusOK {
		t.Fatalf("granted admin listing policy: %d %s", status, body)
	}
	var listed struct {
		Permissions []struct{ ID string } `json:"permissions"`
	}
	if err := json.Unmarshal(body, &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Permissions) != 2 {
		t.Fatalf("listed %d permissions, want 2: %s", len(listed.Permissions), body)
	}
	status, body = f.call(t, http.MethodDelete, apisrv.Prefix+"/permissions/support",
		fleetToken, "")
	if status != http.StatusOK {
		t.Fatalf("granted admin deleting a rule: %d %s", status, body)
	}
}

// TestDeviceAccessAnswersWhoCanReachIt. The fleet view's question, answered on the
// server with the authorizer's own matcher rather than in the browser with a second copy
// of it.
func TestDeviceAccessAnswersWhoCanReachIt(t *testing.T) {
	f := newAdminFixture(t, adminID)
	f.device(t, "treadmill-4821", map[string]string{"pci_scope": "true"})
	f.device(t, "rower-9001", nil)

	f.grant(t, &plugin.Permission{ID: "oncall", Principals: []string{"*@oncall.example.com"},
		Devices: []string{"treadmill-*"}, Actions: []string{"shell", "exec"}})
	f.grant(t, &plugin.Permission{ID: "rowers-only", Principals: []string{"rower@example.com"},
		Devices: []string{"rower-*"}, Actions: []string{"shell"}})
	f.grant(t, &plugin.Permission{ID: "auditors", Principals: []string{"auditor@example.com"},
		Actions: []string{"replay", "observe"}}) // no devices: every device
	f.grant(t, &plugin.Permission{ID: "deny-pci", Principals: []string{"*"},
		Devices: []string{"*"}, Tags: map[string]string{"pci_scope": "true"},
		Actions: []string{"*"}, Deny: true, Reason: "PCI-scoped devices need a ticket"})

	type rule struct {
		ID     string `json:"id"`
		Effect string `json:"effect"`
	}
	read := func(device string) []rule {
		t.Helper()
		status, body := f.call(t, http.MethodGet,
			apisrv.Prefix+"/devices/"+device+"/access", adminToken, "")
		if status != http.StatusOK {
			t.Fatalf("%s access: %d %s", device, status, body)
		}
		var out struct {
			DeviceID string `json:"device_id"`
			Rules    []rule `json:"rules"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatal(err)
		}
		if out.DeviceID != device {
			t.Fatalf("device_id = %q", out.DeviceID)
		}
		return out.Rules
	}

	treadmill := read("treadmill-4821")
	var ids []string
	for _, r := range treadmill {
		ids = append(ids, r.ID)
	}
	// The deny first, because it outranks every allow and a list ordered any other way
	// reads like a precedence order it does not have.
	if len(ids) != 3 || ids[0] != "deny-pci" {
		t.Fatalf("treadmill rules = %v, want deny-pci first and three in total", ids)
	}
	if treadmill[0].Effect != "deny" {
		t.Fatalf("first rule effect = %q", treadmill[0].Effect)
	}
	for _, unwanted := range []string{"rowers-only"} {
		for _, r := range treadmill {
			if r.ID == unwanted {
				t.Fatalf("%s applies to the treadmill", unwanted)
			}
		}
	}

	// The untagged device: the tag-scoped deny does not reach it, and neither does the
	// treadmill glob.
	rower := read("rower-9001")
	ids = nil
	for _, r := range rower {
		ids = append(ids, r.ID)
	}
	if len(ids) != 2 {
		t.Fatalf("rower rules = %v, want rowers-only and auditors", ids)
	}
	for _, r := range rower {
		if r.ID == "deny-pci" || r.ID == "oncall" {
			t.Fatalf("%s applies to an untagged rower: %v", r.ID, ids)
		}
	}
}

// TestDeviceAccessIsPolicyInformation: it names who may reach a device, so it needs the
// same grant as reading the policy — not merely a token.
func TestDeviceAccessIsPolicyInformation(t *testing.T) {
	f := newAdminFixture(t)
	f.device(t, "treadmill-4821", nil)
	f.grant(t, &plugin.Permission{ID: "fleet-admin", Principals: []string{fleetID},
		Devices: []string{"*"}, Actions: []string{"admin:devices"}})

	// A fleet administrator may edit the device and still may not see who can reach it.
	if status, body := f.call(t, http.MethodGet,
		apisrv.Prefix+"/devices/treadmill-4821/access", fleetToken, ""); status != http.StatusForbidden {
		t.Fatalf("device admin reading access: %d, want 403: %s", status, body)
	}
	if status, body := f.call(t, http.MethodGet,
		apisrv.Prefix+"/devices/treadmill-4821/access", nobodyToken, ""); status != http.StatusForbidden {
		t.Fatalf("ungranted principal reading access: %d, want 403: %s", status, body)
	}
}

// TestDeviceAccessForAnUnknownDevice uses the operator-facing condition rather than a
// bare 404, because "no such device" is a thing an operator can act on.
func TestDeviceAccessForAnUnknownDevice(t *testing.T) {
	f := newAdminFixture(t, adminID)
	status, body := f.call(t, http.MethodGet,
		apisrv.Prefix+"/devices/not-a-device/access", adminToken, "")
	if status != http.StatusNotFound {
		t.Fatalf("status %d, want 404: %s", status, body)
	}
	if !strings.Contains(string(body), "device_unknown") {
		t.Fatalf("condition = %s", body)
	}
}

// The Person page's second question — "were they allowed to?" — answered by the gateway
// rather than by the console glob-matching principals for itself. A console that matched
// patterns on its own could show an answer the authorizer would not enforce.
func TestPrincipalAccessListsOnlyMatchingRules(t *testing.T) {
	f := newAdminFixture(t, adminID)
	f.grant(t, &plugin.Permission{
		ID: "oncall", Principals: []string{"*@oncall.example.com"},
		Devices: []string{"*"}, Actions: []string{"shell"},
	})
	f.grant(t, &plugin.Permission{
		ID: "just-sam", Principals: []string{"sam@example.com"},
		Devices: []string{"*"}, Actions: []string{"shell"},
	})

	status, body := f.call(t, http.MethodGet,
		apisrv.Prefix+"/principals/"+url.PathEscape("ana@oncall.example.com")+"/access",
		adminToken, "")
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	var out struct {
		Principal string `json:"principal"`
		Rules     []struct {
			ID string `json:"id"`
		} `json:"rules"`
		AdminActions []string `json:"admin_actions"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out.Principal != "ana@oncall.example.com" {
		t.Errorf("principal = %q", out.Principal)
	}
	// The glob matches; the exact rule for somebody else does not.
	ids := map[string]bool{}
	for _, r := range out.Rules {
		ids[r.ID] = true
	}
	if !ids["oncall"] {
		t.Error("the matching glob rule is missing")
	}
	if ids["just-sam"] {
		t.Error("another principal's rule leaked into the answer")
	}
	if len(out.AdminActions) == 0 {
		t.Error("admin_actions must travel with the answer, as it does for a device")
	}
}

// Reading policy is administrative, the same as it is for a device.
func TestPrincipalAccessNeedsTheAdminGrant(t *testing.T) {
	f := newAdminFixture(t) // no config-declared administrators
	status, _ := f.call(t, http.MethodGet,
		apisrv.Prefix+"/principals/"+url.PathEscape("ana@oncall.example.com")+"/access",
		nobodyToken, "")
	if status != http.StatusForbidden && status != http.StatusNotFound {
		t.Fatalf("status %d, want a refusal", status)
	}
}
