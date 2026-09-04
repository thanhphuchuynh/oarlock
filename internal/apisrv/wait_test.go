package apisrv_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/apisrv"
	"github.com/oarlock/oarlock/internal/sessions"
)

// openOne opens a session through the API and returns its id, so these tests exercise
// the same rows a client would be waiting on.
func (f *keyFixture) openOne(t *testing.T) string {
	t.Helper()
	resp, body := f.open(t, "", openBody)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("open status %d: %+v", resp.StatusCode, body)
	}
	return sessionID(t, body)
}

func (f *keyFixture) get(t *testing.T, path string) (*http.Response, map[string]any) {
	t.Helper()
	return f.request(t, http.MethodGet, path, "")
}

// A wait that is never satisfied returns the unchanged session rather than an error:
// "still the same" is the ordinary outcome of a long-poll, and a client that had to
// special-case it would special-case its most common answer.
func TestAWaitThatTimesOutAnswersWithTheUnchangedSession(t *testing.T) {
	f := newKeyFixture(t, 10)
	id := f.openOne(t)

	started := time.Now()
	resp, body := f.get(t, apisrv.Prefix+"/sessions/"+id+"?wait=250ms")
	took := time.Since(started)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %+v", resp.StatusCode, body)
	}
	if body["state"] != string(sessions.StateWaking) {
		t.Fatalf("state = %v, want waking", body["state"])
	}
	if took < 200*time.Millisecond {
		t.Fatalf("the request returned after %v; it did not wait", took)
	}
}

// The point of the feature: the request is released by the transition, not by the
// timeout, and it is released promptly.
func TestAWaitIsReleasedByTheTransition(t *testing.T) {
	f := newKeyFixture(t, 10)
	id := f.openOne(t)

	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = f.ledger.Update(context.Background(), id, func(row *sessions.Session) error {
			row.State = sessions.StateAttached
			return nil
		})
	}()

	started := time.Now()
	resp, body := f.get(t, apisrv.Prefix+"/sessions/"+id+"?wait=30s")
	took := time.Since(started)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %+v", resp.StatusCode, body)
	}
	if body["state"] != string(sessions.StateAttached) {
		t.Fatalf("state = %v, want attached", body["state"])
	}
	// Generous, because this asserts "woken by the event" rather than "woken by the
	// 30s deadline", and the gap between those is three orders of magnitude.
	if took > 10*time.Second {
		t.Fatalf("the transition took %v to release the request", took)
	}
}

// The race that makes `state` worth sending. The caller last saw `waking`; the session
// has since moved. Without `state` this request would wait for the *next* transition
// and never report the one it missed.
func TestAStateTheCallerAlreadyPassedReturnsImmediately(t *testing.T) {
	f := newKeyFixture(t, 10)
	id := f.openOne(t)

	if err := f.ledger.Update(context.Background(), id, func(row *sessions.Session) error {
		row.State = sessions.StateAttached
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	started := time.Now()
	resp, body := f.get(t, apisrv.Prefix+"/sessions/"+id+"?wait=30s&state=waking")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %+v", resp.StatusCode, body)
	}
	if body["state"] != string(sessions.StateAttached) {
		t.Fatalf("state = %v, want attached", body["state"])
	}
	if took := time.Since(started); took > 5*time.Second {
		t.Fatalf("a transition the caller had already missed took %v to report", took)
	}
}

// A finished session will never move again, so waiting on one burns the caller's whole
// timeout to learn what the first read already told them.
func TestWaitingOnAFinishedSessionReturnsAtOnce(t *testing.T) {
	f := newKeyFixture(t, 10)
	id := f.openOne(t)

	if err := f.ledger.Finish(context.Background(), id,
		sessions.Result{CloseReason: "operator_close"}); err != nil {
		t.Fatal(err)
	}

	started := time.Now()
	resp, body := f.get(t, apisrv.Prefix+"/sessions/"+id+"?wait=30s")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %+v", resp.StatusCode, body)
	}
	if body["state"] != string(sessions.StateClosed) {
		t.Fatalf("state = %v, want closed", body["state"])
	}
	if took := time.Since(started); took > 5*time.Second {
		t.Fatalf("a closed session held the request for %v", took)
	}
}

// Without wait, the endpoint is what it always was. Worth pinning: every existing
// caller sends no wait, and none of them may start blocking.
func TestWithoutWaitTheRequestDoesNotBlock(t *testing.T) {
	f := newKeyFixture(t, 10)
	id := f.openOne(t)

	started := time.Now()
	resp, _ := f.get(t, apisrv.Prefix+"/sessions/"+id)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if took := time.Since(started); took > 2*time.Second {
		t.Fatalf("a plain GET took %v", took)
	}
}

func TestBadWaitParametersAreRefused(t *testing.T) {
	f := newKeyFixture(t, 10)
	id := f.openOne(t)

	for _, q := range []string{"?wait=soon", "?wait=-5s", "?state=sleeping"} {
		resp, body := f.get(t, apisrv.Prefix+"/sessions/"+id+q)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s gave status %d, want 400: %+v", q, resp.StatusCode, body)
		}
	}
}

// A caller asking for longer than the cap wants the longest wait available, not an
// error telling them to ask again for less.
func TestAnOverlongWaitIsClampedNotRefused(t *testing.T) {
	f := newKeyFixture(t, 10)
	id := f.openOne(t)

	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = f.ledger.Finish(context.Background(), id,
			sessions.Result{CloseReason: "operator_close"})
	}()

	resp, body := f.get(t, apisrv.Prefix+"/sessions/"+id+"?wait=10m")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %+v", resp.StatusCode, body)
	}
	if body["state"] != string(sessions.StateClosed) {
		t.Fatalf("state = %v, want closed", body["state"])
	}
}

// noWaiter hides the store's Waiter capability, which is what a SQL store shared with
// another process looks like: it cannot see writes it did not make, so the API falls
// back to polling. The behaviour a client sees must be the same either way — that is the
// whole claim the optional interface rests on.
// Not an embed: embedding would promote WaitForState and this would silently become a
// second test of the Waiter path. The methods are forwarded one at a time so the set is
// exactly sessions.Store and nothing else.
type noWaiter struct{ inner *sessions.Memory }

func (n noWaiter) Create(ctx context.Context, s *sessions.Session) error {
	return n.inner.Create(ctx, s)
}
func (n noWaiter) Update(ctx context.Context, id string, f func(*sessions.Session) error) error {
	return n.inner.Update(ctx, id, f)
}
func (n noWaiter) Finish(ctx context.Context, id string, r sessions.Result) error {
	return n.inner.Finish(ctx, id, r)
}
func (n noWaiter) Get(ctx context.Context, id string) (*sessions.Session, error) {
	return n.inner.Get(ctx, id)
}
func (n noWaiter) List(ctx context.Context, q sessions.Query) ([]*sessions.Session, string, error) {
	return n.inner.List(ctx, q)
}

var _ sessions.Store = noWaiter{}

func TestAStoreWithNoWaiterStillHonoursWait(t *testing.T) {
	ledger := sessions.NewMemory(
		sessions.Limits{PerDevice: 5, PerPrincipal: 5}, nil)
	if _, ok := any(noWaiter{inner: ledger}).(sessions.Waiter); ok {
		t.Fatal("noWaiter still exposes WaitForState; this test would prove nothing")
	}

	f := newKeyFixtureWithStore(t, noWaiter{inner: ledger})
	id := f.openOne(t)

	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = ledger.Update(context.Background(), id, func(row *sessions.Session) error {
			row.State = sessions.StateAttached
			return nil
		})
	}()

	started := time.Now()
	resp, body := f.get(t, apisrv.Prefix+"/sessions/"+id+"?wait=30s")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %+v", resp.StatusCode, body)
	}
	if body["state"] != string(sessions.StateAttached) {
		t.Fatalf("state = %v, want attached", body["state"])
	}
	if took := time.Since(started); took > 10*time.Second {
		t.Fatalf("the polling fallback took %v to notice a transition", took)
	}
}
