package apisrv_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/apisrv"
	"github.com/oarlock/oarlock/internal/auth/statictoken"
	"github.com/oarlock/oarlock/internal/idempotency"
	"github.com/oarlock/oarlock/internal/invite"
	regsqlite "github.com/oarlock/oarlock/internal/registry/sqlite"
	"github.com/oarlock/oarlock/internal/sessions"
	"github.com/oarlock/oarlock/internal/ticket"
	"github.com/oarlock/oarlock/pkg/plugin"
)

// fakeInviter answers every invitation, so these tests are about the key rather than
// about a device. It counts, because "how many times did the device get woken" is the
// thing idempotency is supposed to bound.
type fakeInviter struct {
	invites atomic.Int64
	mints   atomic.Int64

	// gate, when non-nil, holds Invite until it is closed — which is how a second
	// request can arrive while the first is still running.
	gate chan struct{}
	// entered is closed the first time Invite is reached, so a test can know the
	// first request is genuinely parked rather than hoping it got there first.
	entered chan struct{}
	once    sync.Once
}

func (f *fakeInviter) Invite(_ context.Context, _ *plugin.Device,
	req invite.Request) (*invite.Pending, error) {
	if f.entered != nil {
		f.once.Do(func() { close(f.entered) })
	}
	if f.gate != nil {
		<-f.gate
	}
	f.invites.Add(1)
	return &invite.Pending{
		SessionID: req.SessionID, DeviceID: "treadmill-4821",
		Attach: "tkt_" + req.SessionID, AttachExpiresAt: time.Now().Add(time.Minute),
	}, nil
}

func (f *fakeInviter) MintAttach(_ context.Context, c ticket.Claims,
	_ time.Duration) (string, time.Time, error) {
	f.mints.Add(1)
	return "tkt_renewed_" + c.SessionID, time.Now().Add(time.Minute), nil
}

func (f *fakeInviter) MintObserve(_ context.Context, c ticket.Claims,
	_ time.Duration) (string, time.Time, error) {
	return "obs_" + c.SessionID, time.Now().Add(time.Minute), nil
}

func (f *fakeInviter) Cancel(context.Context, string, string) {}

type keyFixture struct {
	srv     *httptest.Server
	inviter *fakeInviter
	keys    *idempotency.Memory
	ledger  sessions.Store
}

const keyToken = "idempotency-test-token-0123456789"

func newKeyFixture(t *testing.T, perDevice int) *keyFixture {
	t.Helper()
	return newKeyFixtureWithStore(t, sessions.NewMemory(
		sessions.Limits{PerDevice: perDevice, PerPrincipal: 100}, nil))
}

// newKeyFixtureWithStore lets a test supply the ledger, so the long-poll fallback can be
// exercised against a store that does not implement sessions.Waiter.
func newKeyFixtureWithStore(t *testing.T, ledger sessions.Store) *keyFixture {
	t.Helper()
	authn, err := statictoken.Open("test", map[string]string{keyToken: "admin@mail.com"})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := regsqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Create(context.Background(), &plugin.Device{
		ID: "treadmill-4821", Platform: plugin.PlatformLinux,
		Profiles: []string{"shell"},
		Keys:     []ed25519.PublicKey{devKey},
	}); err != nil {
		t.Fatal(err)
	}

	f := &keyFixture{
		inviter: &fakeInviter{},
		keys:    idempotency.NewMemory(0, nil),
		ledger:  ledger,
	}
	api, err := apisrv.New(apisrv.Options{
		Sessions:      f.ledger,
		Live:          sessions.NewRegistry(),
		Authenticator: authn,
		Registry:      reg,
		Inviter:       f.inviter,
		Idempotency:   f.keys,
		AttachURL:     "wss://gw-a.example.org/ws/attach",
		Log:           quiet(),
	})
	if err != nil {
		t.Fatal(err)
	}
	f.srv = httptest.NewServer(api)
	t.Cleanup(func() { f.srv.Close(); _ = reg.Close() })
	return f
}

// devKey satisfies the registry's rule that a persistent-mode device has an identity
// key. Nothing here authenticates a device, so its value does not matter.
var devKey = func() ed25519.PublicKey {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	return pub
}()

const openBody = `{"device_id":"treadmill-4821","profile":"shell","reason":"a retry test"}`

func (f *keyFixture) open(t *testing.T, key, body string) (*http.Response, map[string]any) {
	t.Helper()
	return f.request(t, http.MethodPost, apisrv.Prefix+"/sessions", body,
		func(r *http.Request) {
			r.Header.Set("Content-Type", "application/json")
			if key != "" {
				r.Header.Set(apisrv.IdempotencyHeader, key)
			}
		})
}

// request runs one authenticated call and decodes whatever came back, so a test that
// cares about a status can still print the body when it is not the one expected.
func (f *keyFixture) request(t *testing.T, method, path, body string,
	decorate ...func(*http.Request)) (*http.Response, map[string]any) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, f.srv.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+keyToken)
	for _, d := range decorate {
		d(req)
	}
	// Long enough to outlast a deliberate wait, short enough that a hang fails the test
	// rather than the package timeout.
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if out == nil {
		out = map[string]any{"_raw": string(raw)}
	}
	return resp, out
}

func sessionID(t *testing.T, body map[string]any) string {
	t.Helper()
	sess, ok := body["session"].(map[string]any)
	if !ok {
		t.Fatalf("no session in the response: %+v", body)
	}
	id, _ := sess["id"].(string)
	if id == "" {
		t.Fatalf("no session id: %+v", body)
	}
	return id
}

// The whole point: a client that retries a request it never saw the answer to gets its
// first session back, and the device is woken once.
func TestARetriedOpenReturnsTheFirstSessionAndWakesTheDeviceOnce(t *testing.T) {
	f := newKeyFixture(t, 10)

	resp1, body1 := f.open(t, "key-1", openBody)
	if resp1.StatusCode != http.StatusCreated {
		t.Fatalf("first open status %d: %+v", resp1.StatusCode, body1)
	}
	first := sessionID(t, body1)

	resp2, body2 := f.open(t, "key-1", openBody)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("replay status %d, want 200: %+v", resp2.StatusCode, body2)
	}
	if got := sessionID(t, body2); got != first {
		t.Fatalf("the retry opened session %q, want the first one %q", got, first)
	}
	if got := f.inviter.invites.Load(); got != 1 {
		t.Fatalf("the device was woken %d times, want 1", got)
	}
}

// Without a key the old behaviour is untouched: two requests, two sessions. Worth
// pinning, because the header is opt-in and a gateway that quietly deduplicated
// everything would break a caller who wants two shells.
func TestWithoutAKeyTwoRequestsOpenTwoSessions(t *testing.T) {
	f := newKeyFixture(t, 10)

	_, body1 := f.open(t, "", openBody)
	_, body2 := f.open(t, "", openBody)
	if sessionID(t, body1) == sessionID(t, body2) {
		t.Fatal("two keyless requests returned one session")
	}
	if got := f.inviter.invites.Load(); got != 2 {
		t.Fatalf("the device was woken %d times, want 2", got)
	}
}

// The replay must not hand back the ticket the first response carried: that one is
// 60 seconds old at best and dead at worst. A fresh one is minted instead.
func TestAReplayMintsAFreshTicketRatherThanReturningTheFirst(t *testing.T) {
	f := newKeyFixture(t, 10)

	_, body1 := f.open(t, "key-1", openBody)
	_, body2 := f.open(t, "key-1", openBody)

	ticket1 := body1["attach"].(map[string]any)["ticket"].(string)
	ticket2 := body2["attach"].(map[string]any)["ticket"].(string)
	if ticket1 == ticket2 {
		t.Fatalf("the replay returned the first request's ticket %q", ticket1)
	}
	if f.inviter.mints.Load() != 1 {
		t.Fatalf("the replay minted %d tickets, want 1", f.inviter.mints.Load())
	}
}

// Answering with the first request's session would hand somebody a shell on a device
// they did not ask for.
func TestTheSameKeyWithADifferentBodyIsRefused(t *testing.T) {
	f := newKeyFixture(t, 10)

	if resp, body := f.open(t, "key-1", openBody); resp.StatusCode != http.StatusCreated {
		t.Fatalf("first open status %d: %+v", resp.StatusCode, body)
	}
	resp, body := f.open(t, "key-1",
		`{"device_id":"treadmill-4821","profile":"shell","reason":"a different reason"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("reused key status %d, want 400: %+v", resp.StatusCode, body)
	}
	if !isProblem(body, "idempotency_key_reused") {
		t.Fatalf("reused key problem = %+v", body)
	}
}

// A retry that arrives while the first attempt is still running is told to wait, and is
// told so in a way an SDK can act on.
func TestAConcurrentRetryIsToldToWait(t *testing.T) {
	f := newKeyFixture(t, 10)
	f.inviter.gate = make(chan struct{})
	f.inviter.entered = make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		f.open(t, "key-1", openBody)
	}()

	// Wait for the first request to be genuinely inside Invite, holding the key.
	//
	// The first version of this test raced the goroutine against the loop below and
	// deadlocked when the loop won: its own request took the key, parked on the gate,
	// and nothing was left to close the gate. Waiting for the signal removes the race
	// rather than making it rarer.
	select {
	case <-f.inviter.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the first request never reached the inviter")
	}

	resp, body := f.open(t, "key-1", openBody)
	close(f.inviter.gate)
	wg.Wait()

	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("concurrent retry status %d, want 409: %+v", resp.StatusCode, body)
	}
	if !isProblem(body, "idempotency_in_flight") {
		t.Fatalf("concurrent retry problem = %+v", body)
	}
	if body["retryable"] != true {
		t.Fatalf("an in-flight conflict must be retryable: %+v", body)
	}
}

// A key is not consumed by a request that failed. The common failure is a device that
// did not answer — exactly when a caller should be able to try the same key again.
func TestAFailedOpenLeavesTheKeyUsable(t *testing.T) {
	f := newKeyFixture(t, 10)

	// An unknown device fails before any session exists.
	resp, _ := f.open(t, "key-1",
		`{"device_id":"no-such-device","profile":"shell"}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown device status %d, want 404", resp.StatusCode)
	}

	resp, body := f.open(t, "key-1", openBody)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("reusing the key after a failure gave %d: %+v", resp.StatusCode, body)
	}
}

func TestAnOverlongKeyIsRefused(t *testing.T) {
	f := newKeyFixture(t, 10)
	resp, body := f.open(t, strings.Repeat("k", 300), openBody)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("overlong key status %d, want 400: %+v", resp.StatusCode, body)
	}
}

// isProblem checks an RFC 9457 document's condition. The `type` is a URI, and the
// condition is its last segment — matched on the suffix so a change to the base URL
// does not silently turn these assertions into checks of nothing.
func isProblem(body map[string]any, code string) bool {
	t, ok := body["type"].(string)
	return ok && strings.HasSuffix(t, "/"+code)
}
