package apisrv

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/oarlock/oarlock/internal/ticket"
	"github.com/oarlock/oarlock/pkg/condition"
	"github.com/oarlock/oarlock/pkg/plugin"
)

// IdempotencyHeader is the header a client sends to make a retry safe.
//
// The spelling is the one every HTTP client already knows from Stripe and from the
// IETF draft, because a header nobody recognises is a header nobody sends.
const IdempotencyHeader = "Idempotency-Key"

// maxIdempotencyKey bounds what a caller may send.
//
// A key is an opaque token the client chooses — a uuid, a request id, a hash — and none
// of those is long. The bound exists because the key becomes a map key held for a day,
// so an unbounded one is a memory write an unauthenticated-shaped mistake can repeat.
const maxIdempotencyKey = 255

// idempotencyKey reads and validates the header. ok is false when it has already
// written a problem response.
func (s *Server) idempotencyKey(w http.ResponseWriter, r *http.Request) (string, bool) {
	key := strings.TrimSpace(r.Header.Get(IdempotencyHeader))
	if key == "" {
		return "", true
	}
	if len(key) > maxIdempotencyKey {
		s.problem(w, r, http.StatusBadRequest, "invalid_argument",
			"Idempotency-Key is too long", "", false)
		return "", false
	}
	// A key is joined to the principal with a NUL to namespace it, and a key that could
	// contain one could be crafted to land in somebody else's namespace. Refused here
	// rather than deep in the store, so the caller is told which header is wrong.
	if strings.ContainsRune(key, 0) {
		s.problem(w, r, http.StatusBadRequest, "invalid_argument",
			"Idempotency-Key contains an invalid byte", "", false)
		return "", false
	}
	return key, true
}

// fingerprint identifies the request a key was used for.
//
// Over the *decoded* request rather than the raw body. A client that re-serialises its
// retry — different key order, different whitespace, an omitted null — is sending the
// same request, and treating that as a different one would refuse exactly the retry this
// exists to serve. Marshalling a struct is deterministic in Go: fields come out in
// declaration order.
//
// Empty means "cannot fingerprint", which the caller treats as "no idempotency for this
// request" rather than as a match. Two requests that both failed to encode must never
// look identical to each other.
func fingerprint(req *openRequest) string {
	b, err := json.Marshal(req)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// problemFor answers with a condition from the closed set, so the code, the status and
// the sentence the operator reads cannot disagree.
func (s *Server) problemFor(w http.ResponseWriter, r *http.Request, code, detail string) {
	c := condition.Get(code)
	s.problem(w, r, statusFor(code), code, c.Headline, detail, c.Retryable)
}

// replaySession answers a retried request with the session the first one opened.
//
// It resolves the session as it is *now* and mints a fresh attach ticket rather than
// replaying a stored response. A response cached at open time carries a 60-second
// ticket, so replaying one two minutes later would hand the caller a dead credential
// and call it success.
//
// 200 rather than 201: nothing was created by this request, and a client that keys off
// the status to decide whether it caused the session should be told the truth.
func (s *Server) replaySession(w http.ResponseWriter, r *http.Request, p *plugin.Principal,
	sessionID string) {

	row, err := s.o.Sessions.Get(r.Context(), sessionID)
	if err != nil || row.Principal != p.ID {
		// The session named by the key is gone, or belongs to somebody else — which
		// only happens if a store handed back a record across principals, and answering
		// with it would be the worst possible bug. Same sentence either way, for the
		// same reason every other lookup here gives one: telling them apart is an
		// enumeration oracle.
		s.problem(w, r, http.StatusNotFound, "not_found",
			"No such session, or you don't have access", "", false)
		return
	}
	if !row.Live() {
		// The retry arrived after the session ended. Saying so is the honest answer:
		// the caller's next move is to open a new one, with a new key.
		s.problem(w, r, statusFor("session_closed"), "session_closed",
			"That session has ended", "open a new one", false)
		return
	}

	token, expires, err := s.o.Inviter.MintAttach(r.Context(), ticket.Claims{
		SessionID:   row.ID,
		DeviceID:    row.DeviceID,
		Profile:     row.Profile,
		Principal:   p.ID,
		OpenedBy:    row.OpenedBy,
		Unattended:  row.Unattended,
		RecordInput: row.RecordInput,
	}, 0)
	if err != nil {
		s.problem(w, r, http.StatusInternalServerError, "internal",
			"Could not issue an attach ticket", err.Error(), true)
		return
	}

	s.log.Info("a retried request replayed its session",
		"session", row.ID, "principal", p.ID, "request", requestID(r))
	s.writeJSON(w, http.StatusOK, openResponse{
		Session: s.render(row),
		Attach: attachJSON{
			Ticket:    token,
			URL:       s.o.AttachURL,
			ExpiresAt: expires.UTC().Format(time.RFC3339),
		},
	})
}
