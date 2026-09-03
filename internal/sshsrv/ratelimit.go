package sshsrv

// The per-client connection rate limit at the SSH front door.
//
// The counter and the keying live in internal/ratelimit, shared with the WebSocket
// doors. What is specific to this door — and what this file is for — is why the door
// needs one at all, and why its number is nothing like the WebSocket one.
//
// # Why the existing controls do not cover this
//
// The door already has two bounds, and a brute-force attempt walks past both.
//
// `MaxConnections` caps how many connections exist at once. An attacker making
// *sequential* connections — connect, try six keys, hang up, repeat — never holds more
// than one, so a concurrency ceiling of a thousand is not a ceiling on anything they
// are doing.
//
// `HandshakeBudget` (preauth.go) caps how long one connection may sit unauthenticated.
// It is a limit on *holding*, not on *trying*: a peer that authenticates and fails
// promptly is well inside the budget every time, and can repeat it as fast as the
// network allows.
//
// So the door had no answer at all to somebody trying keys. That is what this is, and
// it belongs next to the budget because both answer the same question — what an
// unauthenticated peer is allowed to do before proving anything.
//
// # This counts connections, and an attempt is not a connection
//
// What is visible at ConnCallback is a TCP connection and its source address. Nothing
// about authentication has happened yet, and there is no hook that fires per key
// offered — so this necessarily limits connections.
//
// x/crypto allows `MaxAuthTries` attempts on each one, which neither this package nor
// gliderlabs sets, so it is the library default of **six**. A limit of N connections a
// minute is therefore a limit of 6N key attempts a minute from that client, and the
// number in the configuration should be read that way. Lowering MaxAuthTries would
// tighten the multiplier and is a separate decision: an operator with several keys in
// their agent offers each of them, and a limit of one or two locks out somebody whose
// only mistake is owning more than one key.
//
// # Why this number is small and the WebSocket one is large
//
// One client here is one human at a terminal. On the WebSocket doors one client can
// legitimately be a whole NAT'd fleet reconnecting after a restart, and being refused
// there is a retry rather than a failure. Neither number belongs on the other door.
//
// # The deployment that breaks this
//
// **If the gateway sits behind a TCP load balancer that does not speak PROXY protocol,
// every connection arrives from the balancer.** There is no X-Forwarded-For for SSH.
// The limiter would then see one client, count the whole world against it, and lock
// everybody out — turning a brute-force control into a self-inflicted outage. A refusal
// says when the source is private for exactly that reason: the failure otherwise looks
// identical to the limit working. Such a deployment should terminate SSH ahead of the
// balancer, use PROXY protocol, or set `ssh.conn_rate_per_minute: -1`.

import (
	"net"
	"time"

	"github.com/oarlock/oarlock/internal/ratelimit"
)

// DefaultConnRatePerMinute is how many new connections one client may open per minute.
//
// Thirty, which is room for an operator opening a shell, a port forward and a file
// transfer at once several times over — and, at six auth tries each, caps a brute-force
// attempt at 180 key offers a minute from one /64. That is not a number that stops a
// determined attacker with a botnet; it is the number that makes a single source
// useless, which is what a per-client limit can honestly claim.
//
// Deliberately generous. This is an operator front door, and a limit low enough to bite
// during real use is a limit that locks out the person handling the incident.
const DefaultConnRatePerMinute = 30

// newConnLimiter returns the door's limiter, or nil when the limit is disabled.
func newConnLimiter(perMinute int, now func() time.Time) *ratelimit.Limiter {
	if perMinute == 0 {
		perMinute = DefaultConnRatePerMinute
	}
	return ratelimit.New(perMinute, now)
}

// admit applies the connection rate limit and reports whether this connection may
// proceed. A refusal is logged rather than silent: from the client's side a rate limit
// and a broken gateway look identical, so the gateway's log is the only place the
// difference exists.
func (s *Server) admit(conn net.Conn) bool {
	key := ratelimit.Key(conn.RemoteAddr())
	ok, count := s.rate.Allow(key)
	if ok {
		return true
	}
	attrs := []any{
		"client", key, "connections_this_minute", count,
		"limit", s.rate.PerMinute(),
	}
	if ratelimit.PrivateSource(key) {
		attrs = append(attrs, "note",
			"this source is private: if a proxy or load balancer fronts this listener, "+
				"every operator is being counted as one client. Terminate SSH ahead of "+
				"it, use PROXY protocol, or set ssh.conn_rate_per_minute: -1 and limit "+
				"at the edge")
	}
	s.log.Warn("refused an SSH connection: too many from this client", attrs...)
	return false
}
