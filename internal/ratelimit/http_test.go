package ratelimit_test

// The middleware in front of the WebSocket doors.
//
// The property worth pinning is *where* the refusal happens. A limit applied after the
// upgrade would still cost a goroutine and a WebSocket handshake per attempt, which
// leaves an attacker setting the gateway's workload — the limit would be present and not
// doing its job. So these tests assert the wrapped handler is never entered, not merely
// that the status code is 429.

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/ratelimit"
)

// syncBuffer is a log sink a test can read while a handler is still writing to it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// counted wraps a handler that records how many requests actually reached it.
func counted() (http.Handler, *atomic.Int32) {
	var n atomic.Int32
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusSwitchingProtocols)
	}), &n
}

func request(remote string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/ws/session", nil)
	r.RemoteAddr = remote
	return r
}

// TestARefusedRequestNeverReachesTheHandler.
//
// The whole reason this is middleware rather than a check inside each endpoint: refusing
// costs a map lookup, and everything past it costs an upgrade.
func TestARefusedRequestNeverReachesTheHandler(t *testing.T) {
	logs := &syncBuffer{}
	next, reached := counted()
	h := ratelimit.Middleware(ratelimit.New(2, nil), "ws",
		slog.New(slog.NewTextHandler(logs, nil)))(next)

	for i := 1; i <= 2; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, request("203.0.113.7:51000"))
		if rec.Code != http.StatusSwitchingProtocols {
			t.Fatalf("request %d inside the budget got %d", i, rec.Code)
		}
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, request("203.0.113.7:51000"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the third request got %d, want 429", rec.Code)
	}
	if got := reached.Load(); got != 2 {
		t.Fatalf("%d requests reached the handler; the refusal was made after the upgrade", got)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("a refusal carries no Retry-After, so a client has to guess")
	}
}

// TestTheDoorsShareOneBudget.
//
// /ws/control, /ws/session and /ws/attach are wired through one limiter in app.go. A
// limiter per door would let a client that noticed spend three budgets, which is the same
// thing as raising the limit and calling it something else. The middleware is the seam
// where that would silently go wrong, so the test states it here.
func TestTheDoorsShareOneBudget(t *testing.T) {
	l := ratelimit.New(2, nil)
	mk := func(name string) (http.Handler, *atomic.Int32) {
		next, n := counted()
		return ratelimit.Middleware(l, name, slog.New(slog.NewTextHandler(&syncBuffer{}, nil)))(next), n
	}
	control, controlN := mk("control")
	session, sessionN := mk("session")
	attach, _ := mk("attach")

	control.ServeHTTP(httptest.NewRecorder(), request("203.0.113.7:1"))
	session.ServeHTTP(httptest.NewRecorder(), request("203.0.113.7:2"))

	rec := httptest.NewRecorder()
	attach.ServeHTTP(rec, request("203.0.113.7:3"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("a third door served the same client a fresh budget: got %d", rec.Code)
	}
	if controlN.Load() != 1 || sessionN.Load() != 1 {
		t.Fatal("the first two doors did not serve")
	}
}

// TestAForwardedHeaderCannotChooseTheKey.
//
// The one that would be easy to add and hard to notice. Trusting X-Forwarded-For here
// would hand every caller the ability to pick their own rate-limit bucket — and to spend
// somebody else's — on a door that is reachable before any authentication.
func TestAForwardedHeaderCannotChooseTheKey(t *testing.T) {
	next, reached := counted()
	h := ratelimit.Middleware(ratelimit.New(1, nil), "ws",
		slog.New(slog.NewTextHandler(&syncBuffer{}, nil)))(next)

	first := request("203.0.113.7:51000")
	h.ServeHTTP(httptest.NewRecorder(), first)

	// The same peer, now claiming to be somebody else in three different ways.
	for _, hdr := range []struct{ name, value string }{
		{"X-Forwarded-For", "198.51.100.4"},
		{"Forwarded", "for=198.51.100.4"},
		{"X-Real-IP", "198.51.100.4"},
	} {
		r := request("203.0.113.7:51000")
		r.Header.Set(hdr.name, hdr.value)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("%s bought a fresh budget: got %d", hdr.name, rec.Code)
		}
	}
	if got := reached.Load(); got != 1 {
		t.Fatalf("%d requests were served; a header chose the key", got)
	}
}

// TestClientsGetTheirOwnBudget. The failure mode that makes people disable rate limits.
func TestClientsGetTheirOwnBudget(t *testing.T) {
	next, _ := counted()
	h := ratelimit.Middleware(ratelimit.New(1, nil), "ws",
		slog.New(slog.NewTextHandler(&syncBuffer{}, nil)))(next)

	h.ServeHTTP(httptest.NewRecorder(), request("203.0.113.7:1"))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, request("198.51.100.4:1"))
	if rec.Code != http.StatusSwitchingProtocols {
		t.Fatalf("an unrelated client got %d because of somebody else's traffic", rec.Code)
	}
}

// TestADisabledLimiterIsNotWrapped. A nil limiter must return the handler untouched, so
// a deployment that has to turn this off pays nothing for it — not even an indirection.
func TestADisabledLimiterIsNotWrapped(t *testing.T) {
	next, reached := counted()
	h := ratelimit.Middleware(ratelimit.New(-1, nil), "ws", nil)(next)

	for i := range 500 {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, request("203.0.113.7:51000"))
		if rec.Code != http.StatusSwitchingProtocols {
			t.Fatalf("request %d was refused with the limit disabled: %d", i, rec.Code)
		}
	}
	if got := reached.Load(); got != 500 {
		t.Fatalf("%d of 500 requests reached the handler", got)
	}
}

// TestARefusalNamesTheClientAndTheDoor. From outside, a rate limit and a broken gateway
// are the same event, so the log is the only place the difference exists.
func TestARefusalNamesTheClientAndTheDoor(t *testing.T) {
	logs := &syncBuffer{}
	next, _ := counted()
	h := ratelimit.Middleware(ratelimit.New(1, nil), "control",
		slog.New(slog.NewTextHandler(logs, nil)))(next)

	h.ServeHTTP(httptest.NewRecorder(), request("[2001:db8:1:2::5]:51000"))
	h.ServeHTTP(httptest.NewRecorder(), request("[2001:db8:1:2::6]:51000"))

	out := logs.String()
	for _, want := range []string{"control", "2001:db8:1:2::/64", "connections_this_minute"} {
		if !strings.Contains(out, want) {
			t.Fatalf("the refusal does not mention %q:\n%s", want, out)
		}
	}
}

// TestAPrivateSourceIsFlagged is the load-balancer case, which is the most likely way for
// this control to hurt rather than help. Somebody reading the log during that outage
// needs the hint, because the limiter looks like it is working perfectly.
func TestAPrivateSourceIsFlagged(t *testing.T) {
	logs := &syncBuffer{}
	next, _ := counted()
	h := ratelimit.Middleware(ratelimit.New(1, nil), "ws",
		slog.New(slog.NewTextHandler(logs, nil)))(next)

	h.ServeHTTP(httptest.NewRecorder(), request("10.0.0.5:51000"))
	h.ServeHTTP(httptest.NewRecorder(), request("10.0.0.5:51001"))

	if !strings.Contains(logs.String(), "load balancer") {
		t.Fatalf("a private source was refused with no hint about a proxy:\n%s", logs.String())
	}

	// And a public source does not get the hint, or it becomes noise nobody reads.
	logs2 := &syncBuffer{}
	next2, _ := counted()
	h2 := ratelimit.Middleware(ratelimit.New(1, nil), "ws",
		slog.New(slog.NewTextHandler(logs2, nil)))(next2)
	h2.ServeHTTP(httptest.NewRecorder(), request("203.0.113.7:1"))
	h2.ServeHTTP(httptest.NewRecorder(), request("203.0.113.7:2"))
	if strings.Contains(logs2.String(), "load balancer") {
		t.Fatalf("a public source was given the proxy hint:\n%s", logs2.String())
	}
}

// TestTheWindowRollsForAWaitingClient. A device refused during a reconnect storm has to
// get back in on its own: the agent retries with backoff, and if the window never rolled
// the fleet would never return.
func TestTheWindowRollsForAWaitingClient(t *testing.T) {
	now := time.Now()
	next, _ := counted()
	h := ratelimit.Middleware(ratelimit.New(1, func() time.Time { return now }), "ws",
		slog.New(slog.NewTextHandler(&syncBuffer{}, nil)))(next)

	h.ServeHTTP(httptest.NewRecorder(), request("203.0.113.7:1"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, request("203.0.113.7:2"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatal("the second request was not refused")
	}

	now = now.Add(time.Minute)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, request("203.0.113.7:3"))
	if rec.Code != http.StatusSwitchingProtocols {
		t.Fatalf("still refused after the window rolled: %d", rec.Code)
	}
}
