package apisrv

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/oarlock/oarlock/internal/sessions"
)

// Long-poll bounds.
const (
	// MaxWait is the longest a caller may ask to be held for.
	//
	// Sixty seconds because that is where the infrastructure between a client and this
	// gateway starts cutting connections anyway — most load balancers and ingress
	// controllers idle out at or below it — and a wait that outlives the connection
	// carrying it is a wait nobody receives the answer to.
	MaxWait = 60 * time.Second

	// pollInterval is how often a store with no Waiter is re-read.
	//
	// The fallback, not the design. It is still worth having: it turns N client
	// requests — each with a TLS handshake, an authentication and a rate-limit slot —
	// into one, and a local store read is orders of magnitude cheaper than any of that.
	pollInterval = 250 * time.Millisecond

	// maxWaiters caps how many requests may be parked at once, across all callers.
	//
	// Deliberately generous, and deliberately *not* a refusal: over the cap, a request
	// answers immediately with the current state instead of waiting. That degrades to
	// exactly the behaviour this endpoint had before long-poll existed, which is a
	// worse experience and not a broken one — whereas a 503 would turn load into an
	// error a client has to understand.
	maxWaiters = 1024
)

// waiters counts parked requests.
var waiters atomic.Int64

// waitParams is what a caller asked for on GET /sessions/{id}.
type waitParams struct {
	// For is how long to hold the request. Zero means answer now.
	For time.Duration
	// Since is the state the caller already has. Empty means "whatever it is when this
	// request arrives", which is well defined but races: a transition between the
	// caller's previous read and this request is one this request will not report, and
	// it will then wait for the *next* one. A caller that holds a state should send it.
	Since sessions.State
}

// parseWait reads the query parameters. ok is false when it has already answered.
func (s *Server) parseWait(w http.ResponseWriter, r *http.Request) (waitParams, bool) {
	var p waitParams
	q := r.URL.Query()

	if raw := q.Get("wait"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			s.problem(w, r, http.StatusBadRequest, "invalid_argument",
				"wait is not a duration",
				`use a Go duration such as "30s"`, false)
			return p, false
		}
		if d < 0 {
			s.problem(w, r, http.StatusBadRequest, "invalid_argument",
				"wait cannot be negative", "", false)
			return p, false
		}
		// Clamped rather than refused. A caller asking for five minutes wants the
		// longest wait available, and answering their question in sixty seconds serves
		// that better than making them read an error and ask again for less.
		p.For = min(d, MaxWait)
	}

	if raw := q.Get("state"); raw != "" {
		st := sessions.State(raw)
		if !validState(st) {
			s.problem(w, r, http.StatusBadRequest, "invalid_argument",
				"state is not a session state",
				"one of waking, opening, attached, closed, rejected", false)
			return p, false
		}
		p.Since = st
	}
	return p, true
}

func validState(s sessions.State) bool {
	switch s {
	case sessions.StateWaking, sessions.StateOpening, sessions.StateAttached,
		sessions.StateClosed, sessions.StateRejected:
		return true
	}
	return false
}

// awaitChange holds the request until the session leaves p.Since, and returns the
// session as it then is.
//
// It always returns a session and never an error for "nothing happened": a long-poll
// that times out is a successful answer meaning "still the same", and the caller
// re-issues. Turning a quiet minute into an error would make every client implement a
// special case for the ordinary outcome.
func (s *Server) awaitChange(ctx context.Context, row *sessions.Session,
	p waitParams) *sessions.Session {

	if p.For <= 0 {
		return row
	}
	// A finished session will never move again. Waiting on one burns the caller's
	// whole timeout to learn what the first read already said.
	if !row.Live() {
		return row
	}
	since := p.Since
	if since == "" {
		since = row.State
	}
	if row.State != since {
		// Already moved. This is the case that makes `state` worth sending: the caller
		// gets the transition it missed instead of waiting for the next one.
		return row
	}

	if n := waiters.Add(1); n > maxWaiters {
		waiters.Add(-1)
		s.log.Warn("too many parked long-polls; answering immediately",
			"waiting", n-1, "limit", maxWaiters)
		return row
	}
	defer waiters.Add(-1)

	ctx, cancel := context.WithTimeout(ctx, p.For)
	defer cancel()

	for {
		if wr, ok := s.o.Sessions.(sessions.Waiter); ok {
			if err := wr.WaitForState(ctx, row.ID, since); err != nil {
				// Timed out, the caller hung up, or the row went away. Every one of
				// those means "answer with what we have".
				return row
			}
		} else {
			select {
			case <-ctx.Done():
				return row
			case <-time.After(pollInterval):
			}
		}

		fresh, err := s.o.Sessions.Get(ctx, row.ID)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return row
			}
			// The row is gone, or the store failed. Answering with the last good copy
			// is better than a 500 for a request whose only job was to wait.
			return row
		}
		if fresh.State != since {
			return fresh
		}
		if ctx.Err() != nil {
			return fresh
		}
	}
}
