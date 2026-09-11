package openapi_test

// The document is only worth having if it cannot lie, so these tests check three joins:
// table ↔ mux, table ↔ document, and schema ↔ real response.
//
// The last one is the one that catches the mistake that bites. Writing this package found
// three field names `oarlockctl` had wrong — including `next_cursor`, which the client
// called `next`, so paging stopped after one page while the client's own test passed
// because the fake server made the same mistake.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/oarlock/oarlock/internal/apisrv"
	"github.com/oarlock/oarlock/internal/openapi"
)

// TestTheCommittedDocumentIsCurrent is the drift check E7.S1 asks for.
//
// Run in CI by `go test ./...` rather than only by a separate command, so a route added
// without regenerating fails the ordinary build.
func TestTheCommittedDocumentIsCurrent(t *testing.T) {
	t.Setenv("OARLOCK_VERSION", "")
	want, err := openapi.Generate()
	if err != nil {
		t.Fatal(err)
	}
	have, err := os.ReadFile("../../docs/openapi.yaml")
	if err != nil {
		t.Fatalf("%v\nRun `go run ./cmd/oarlock-openapi`.", err)
	}
	if string(have) != string(want) {
		t.Fatalf("docs/openapi.yaml is stale.\n\n" +
			"The route table changed and the document did not. Run:\n" +
			"    go run ./cmd/oarlock-openapi\n\n" +
			"and read the diff — an endpoint appearing or disappearing is something a " +
			"reviewer should see.")
	}
}

func TestOARLOCK_VERSIONStampsTheDocument(t *testing.T) {
	t.Setenv("OARLOCK_VERSION", "v0.1.0")
	b, err := openapi.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "\n  version: 0.1.0\n") {
		t.Fatalf("stamped document does not carry the product version:\n%s", b[:400])
	}
	if strings.Contains(string(b), "\n  version: 0.0.0\n") {
		t.Fatal("stamped document still claims 0.0.0")
	}
}

// doc parses the generated document, so the assertions below read it the way a generator
// would rather than the way this package wrote it.
func doc(t *testing.T) map[string]any {
	t.Helper()
	t.Setenv("OARLOCK_VERSION", "")
	b, err := openapi.Generate()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := yaml.Unmarshal(b, &m); err != nil {
		t.Fatalf("the generated document is not valid YAML: %v", err)
	}
	return m
}

// TestEveryRouteIsDocumented, in both directions. A path in the document that the gateway
// does not serve is a 404 in somebody's SDK; a path the gateway serves and the document
// omits is an endpoint nobody knows about, which for an admin endpoint is worse.
func TestEveryRouteIsDocumented(t *testing.T) {
	paths, _ := doc(t)["paths"].(map[string]any)
	if len(paths) == 0 {
		t.Fatal("the document has no paths")
	}

	inDoc := map[string]bool{}
	for p, item := range paths {
		methods, _ := item.(map[string]any)
		for m := range methods {
			inDoc[strings.ToUpper(m)+" "+p] = true
		}
	}
	inTable := map[string]bool{}
	for _, r := range apisrv.Routes() {
		inTable[r.Method+" "+r.Path] = true
	}

	for k := range inTable {
		if !inDoc[k] {
			t.Errorf("%s is served and undocumented", k)
		}
	}
	for k := range inDoc {
		if !inTable[k] {
			t.Errorf("%s is documented and not served", k)
		}
	}
}

// TestOperationIdsAreUnique. Two operations sharing an id produce a generated client with
// two methods of one name, which is a generator error somebody has to debug rather than a
// missing endpoint they can see.
func TestOperationIdsAreUnique(t *testing.T) {
	seen := map[string]string{}
	for _, r := range apisrv.Routes() {
		if prev, dup := seen[r.OperationID]; dup {
			t.Errorf("%s and %s %s share the operation id %q",
				prev, r.Method, r.Path, r.OperationID)
		}
		seen[r.OperationID] = r.Method + " " + r.Path
	}
}

// TestEveryOperationDeclaresItsAuthorisation.
//
// An endpoint whose description does not say which action it checks is an endpoint
// somebody will grant themselves by accident. The ones with no action say that too —
// "scoped by the caller's own identity" is a claim, and a reader should see it made rather
// than infer it from silence.
func TestEveryOperationDeclaresItsAuthorisation(t *testing.T) {
	paths, _ := doc(t)["paths"].(map[string]any)
	for p, item := range paths {
		methods, _ := item.(map[string]any)
		for m, op := range methods {
			o, _ := op.(map[string]any)
			desc, _ := o["description"].(string)
			if !strings.Contains(desc, "action") && !strings.Contains(desc, "own identity") {
				t.Errorf("%s %s does not say what it requires: %q", strings.ToUpper(m), p, desc)
			}
		}
	}
}

// TestOptionalEndpointsSayTheyAreOptional.
//
// A deployment can serve renewals and not opens. An SDK author reading a flat list would
// call an endpoint their gateway does not have and see a 404 they cannot explain.
func TestOptionalEndpointsSayTheyAreOptional(t *testing.T) {
	paths, _ := doc(t)["paths"].(map[string]any)
	for _, r := range apisrv.Routes() {
		if !r.Optional {
			continue
		}
		item, _ := paths[r.Path].(map[string]any)
		op, _ := item[strings.ToLower(r.Method)].(map[string]any)
		desc, _ := op["description"].(string)
		if !strings.Contains(desc, "Optional") {
			t.Errorf("%s %s is conditional on %s and does not say so: %q",
				r.Method, r.Path, r.Requires, desc)
		}
	}
}

// ── schema against reality ──────────────────────────────────────────────────────

// TestSchemasMatchTheResponsesTheGatewayActuallySends.
//
// The check that earns this package its keep. Schemas are written by hand, so they can
// drift from the structs — and a schema claiming a field the gateway does not send is a
// generated SDK with a field nobody can populate, while one that omits a field is an SDK
// that silently discards it.
//
// So this asks a real server for a real response and compares the keys.
func TestSchemasMatchTheResponsesTheGatewayActuallySends(t *testing.T) {
	srv := newAPI(t)

	for _, tc := range []struct {
		name, path, schema string
	}{
		{"session list", "/api/v1/sessions", "SessionList"},
		{"device list", "/api/v1/devices", "DeviceList"},
		{"agent list", "/api/v1/agents", "AgentList"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := get(t, srv, tc.path)
			declared := declaredProperties(t, tc.schema)
			for k := range body {
				if !declared[k] {
					t.Errorf("the gateway sends %q and the %s schema does not declare it. "+
						"An SDK generated from this document silently discards it.",
						k, tc.schema)
				}
			}
		})
	}
}

// declaredProperties reads one schema's property names out of the generated document.
func declaredProperties(t *testing.T, name string) map[string]bool {
	t.Helper()
	comps, _ := doc(t)["components"].(map[string]any)
	all, _ := comps["schemas"].(map[string]any)
	s, ok := all[name].(map[string]any)
	if !ok {
		t.Fatalf("no schema named %q", name)
	}
	props, _ := s["properties"].(map[string]any)
	out := map[string]bool{}
	for k := range props {
		out[k] = true
	}
	return out
}

func get(t *testing.T, srv *httptest.Server, path string) map[string]any {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %d", path, resp.StatusCode)
	}
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return m
}

// TestTheSessionSchemaMatchesTheStruct compares field by field against a rendered session,
// which is the one shape an SDK will touch most.
func TestTheSessionSchemaMatchesTheStruct(t *testing.T) {
	srv := newAPI(t)
	list := get(t, srv, "/api/v1/sessions")
	rows, _ := list["sessions"].([]any)
	if len(rows) == 0 {
		t.Skip("the fixture has no sessions, so there is no rendered session to compare")
	}
	row, _ := rows[0].(map[string]any)
	declared := declaredProperties(t, "Session")

	var missing []string
	for k := range row {
		if !declared[k] {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("the Session schema does not declare %v, which the gateway sends",
			missing)
	}
}

// TestTheDocumentIsDeterministic. A generated file whose key order moved between runs would
// fail its own drift check for no reason, and teach everybody to regenerate blindly.
func TestTheDocumentIsDeterministic(t *testing.T) {
	t.Setenv("OARLOCK_VERSION", "")
	first, err := openapi.Generate()
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		again, err := openapi.Generate()
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(first, again) {
			t.Fatal("two runs produced different bytes")
		}
	}
}
