package frame_test

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/oarlock/oarlock/pkg/frame"
)

var update = flag.Bool("update", false, "rewrite the shared wire vectors")

// The path is deliberately outside this package: the fixture is a contract between two
// implementations, not a Go test detail, and the TypeScript codec reads the same file.
const vectorPath = "../../tests/fixtures/frames.json"

type vector struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	// Wire is the whole message, base64, header byte included.
	Wire string `json:"wire"`
	// JSON is the decoded body for JSON-bodied frames, so the other implementation can
	// check its parse and not just its bytes.
	JSON json.RawMessage `json:"json,omitempty"`
	Text string          `json:"text,omitempty"`
}

func vectors(t *testing.T) []vector {
	t.Helper()
	must := func(f frame.Frame, err error) frame.Frame {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	enc := func(f frame.Frame) string {
		t.Helper()
		wire, err := frame.Codec{}.Encode(nil, f)
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(wire)
	}
	body := func(v any) json.RawMessage {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	ready := frame.Ready{SessionID: "sess_01J8Z", ScrollbackLen: 4096,
		Recording: true, Mode: "gateway", Limits: &frame.Limits{Rate: 262144}}
	unrecorded := frame.Ready{SessionID: "sess_02", Recording: false, Mode: "gateway"}
	passthrough := frame.Ready{SessionID: "sess_03", Recording: false, Mode: "passthrough"}
	resize := frame.Resize{Cols: 132, Rows: 38}
	closeMsg := frame.Close{Reason: "operator_close"}
	errMsg := frame.Error{Code: "revoked", Message: "Your access was removed.", Retryable: false}
	unavailable := frame.Error{Code: "authz_unavailable",
		Message: "We could not check your access.", Retryable: true}
	throttle := frame.Throttle{DroppedBytes: 8192, Profile: "logs"}
	exit := frame.Exit{Code: 130}
	watched := frame.Ready{SessionID: "sess_04", Recording: true, Mode: "gateway",
		Observers: []frame.Observer{{Principal: "sam@example.com", Since: "2026-08-21T10:14:02Z"}}}
	watcher := frame.Ready{SessionID: "sess_04", Recording: true, Mode: "gateway",
		ReadOnly: true, Watching: "phuc@example.com",
		Observers: []frame.Observer{{Principal: "sam@example.com", Since: "2026-08-21T10:14:02Z"}}}
	observers := frame.Observers{Observers: []frame.Observer{
		{Principal: "sam@example.com", Since: "2026-08-21T10:14:02Z"},
	}}
	nobody := frame.Observers{Observers: []frame.Observer{}}

	return []vector{
		{Name: "data-ascii", Type: int(frame.TypeData),
			Wire: enc(frame.Data([]byte("hi"))), Text: "hi"},
		{Name: "data-utf8", Type: int(frame.TypeData),
			Wire: enc(frame.Data([]byte("café ✓ 日本語"))), Text: "café ✓ 日本語"},
		{Name: "data-empty", Type: int(frame.TypeData), Wire: enc(frame.Data(nil))},
		{Name: "ready-recorded", Type: int(frame.TypeReady),
			Wire: enc(must(frame.Marshal(frame.TypeReady, ready))), JSON: body(ready)},
		{Name: "ready-unrecorded", Type: int(frame.TypeReady),
			Wire: enc(must(frame.Marshal(frame.TypeReady, unrecorded))), JSON: body(unrecorded)},
		{Name: "ready-passthrough", Type: int(frame.TypeReady),
			Wire: enc(must(frame.Marshal(frame.TypeReady, passthrough))), JSON: body(passthrough)},
		{Name: "resize", Type: int(frame.TypeResize),
			Wire: enc(must(frame.Marshal(frame.TypeResize, resize))), JSON: body(resize)},
		{Name: "close", Type: int(frame.TypeClose),
			Wire: enc(must(frame.Marshal(frame.TypeClose, closeMsg))), JSON: body(closeMsg)},
		{Name: "error-revoked", Type: int(frame.TypeError),
			Wire: enc(must(frame.Marshal(frame.TypeError, errMsg))), JSON: body(errMsg)},
		{Name: "error-authz-unavailable", Type: int(frame.TypeError),
			Wire: enc(must(frame.Marshal(frame.TypeError, unavailable))), JSON: body(unavailable)},
		{Name: "throttle", Type: int(frame.TypeThrottle),
			Wire: enc(must(frame.Marshal(frame.TypeThrottle, throttle))), JSON: body(throttle)},
		{Name: "exit", Type: int(frame.TypeExit),
			Wire: enc(must(frame.Marshal(frame.TypeExit, exit))), JSON: body(exit)},
		{Name: "ready-watched", Type: int(frame.TypeReady),
			Wire: enc(must(frame.Marshal(frame.TypeReady, watched))), JSON: body(watched)},
		{Name: "ready-watcher", Type: int(frame.TypeReady),
			Wire: enc(must(frame.Marshal(frame.TypeReady, watcher))), JSON: body(watcher)},
		{Name: "observers-one", Type: int(frame.TypeObservers),
			Wire: enc(must(frame.Marshal(frame.TypeObservers, observers))), JSON: body(observers)},
		// An empty list is a real message, not an omission: the indicator has to be able
		// to go away, so the encoding has to survive the round trip as an empty array
		// rather than as null.
		{Name: "observers-none", Type: int(frame.TypeObservers),
			Wire: enc(must(frame.Marshal(frame.TypeObservers, nobody))), JSON: body(nobody)},
	}
}

// TestSharedVectorsAreCurrent is the anti-drift test for having two codecs.
//
// A second implementation of a wire format is where a protocol forks quietly: the Go
// tests pass, the browser tests pass, and the two disagree in production. The fixture
// is generated from this side — Go is the reference — and the TypeScript suite asserts
// against the same bytes, so a change to either has to be deliberate.
//
// Regenerate with: go test ./pkg/frame/ -run TestSharedVectors -update
func TestSharedVectorsAreCurrent(t *testing.T) {
	want, err := json.MarshalIndent(map[string]any{
		"$comment": "GENERATED by pkg/frame/vectors_test.go -update. " +
			"Shared with the TypeScript codec in packages/terminal.",
		"vectors": vectors(t),
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n')

	path := filepath.Clean(vectorPath)
	if *update {
		if err := os.WriteFile(path, want, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", path)
		return
	}

	have, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v\n\nRegenerate with: go test ./pkg/frame/ -run TestSharedVectors -update", err)
	}
	if string(have) != string(want) {
		t.Errorf("%s is stale — the Go codec changed and the shared vectors did not.\n"+
			"The TypeScript codec reads this file, so leaving it stale means the two "+
			"implementations have forked.\n\n"+
			"Regenerate with: go test ./pkg/frame/ -run TestSharedVectors -update", path)
	}
}
