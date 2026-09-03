package sshsrv

// The per-client connection rate limit at the SSH front door.
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
// # Why the key is a prefix and not an address
//
// Per-address is not a limit on IPv6. A residential or cloud host is routinely handed
// a /64 — eighteen quintillion addresses — and rotating the low half costs an attacker
// nothing, so an address-keyed counter would be defeated by a for-loop and would look
// like it was working the whole time. The unit that corresponds to "one client" is the
// /64, so that is what is counted.
//
// IPv4 is keyed on the full address: a /24 is not one client, and treating it as one
// would let a single misbehaving host lock out its neighbours.
//
// # What this cannot see, and the deployment that breaks it
//
// **If the gateway sits behind a TCP load balancer that does not speak PROXY protocol,
// every connection arrives from the balancer.** There is no X-Forwarded-For for SSH.
// The limiter would then see one client, count the whole world against it, and lock
// everybody out — turning a brute-force control into a self-inflicted outage.
//
// That is why a refusal logs the key it counted and says when the source is private:
// the failure is otherwise extremely hard to read from the outside, because it looks
// exactly like the limit working. A deployment in that shape should terminate SSH
// before the balancer, use PROXY protocol, or set `conn_rate_per_minute: -1` and rate
// limit at the edge instead.

import (
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// DefaultConnRatePerMinute is how many new connections one client may open per minute.
//
// Thirty, which is six a minute for an operator opening a shell, a port forward and a
// file transfer at once and still leaves room — and, at six auth tries each, caps a
// brute-force attempt at 180 key offers a minute from one /64. That is not a number
// that stops a determined attacker with a botnet; it is the number that makes a single
// source useless, which is what a per-client limit can honestly claim.
//
// Deliberately generous. This is an operator front door, and a limit low enough to bite
// during real use is a limit that locks out the person handling the incident.
const DefaultConnRatePerMinute = 30

// connLimiter is a fixed-window counter per client key.
//
// A fixed window rather than a token bucket, matching internal/apisrv: the boundary is
// a real instant that a log line can point at, and the door is not a hot path. The
// window's known weakness — twice the rate across a boundary — is uninteresting here,
// because the limit is already set well above legitimate use.
type connLimiter struct {
	perMinute int
	now       func() time.Time

	mu      sync.Mutex
	windows map[string]*connWindow
}

type connWindow struct {
	start time.Time
	count int
}

// newConnLimiter returns a limiter, or nil when the limit is disabled. A nil limiter
// allows everything, so callers do not need to branch twice.
func newConnLimiter(perMinute int, now func() time.Time) *connLimiter {
	if perMinute < 0 {
		return nil
	}
	if perMinute == 0 {
		perMinute = DefaultConnRatePerMinute
	}
	if now == nil {
		now = time.Now
	}
	return &connLimiter{perMinute: perMinute, now: now, windows: make(map[string]*connWindow)}
}

// allow records one connection from key and reports whether it is within the limit. It
// returns the count so a refusal can say how far over the client is, which is the
// difference between a log line an operator can act on and one that only says "no".
func (l *connLimiter) allow(key string) (bool, int) {
	if l == nil {
		return true, 0
	}
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	win, ok := l.windows[key]
	if !ok || now.Sub(win.start) >= time.Minute {
		win = &connWindow{start: now}
		l.windows[key] = win
		// Opportunistic sweep. Without it a gateway that has been scanned by a botnet
		// keeps a window per source address for as long as it runs, which is a slow
		// memory leak driven entirely by strangers.
		if len(l.windows) > 10000 {
			for k, v := range l.windows {
				if now.Sub(v.start) >= time.Minute {
					delete(l.windows, k)
				}
			}
		}
	}
	win.count++
	return win.count <= l.perMinute, win.count
}

// clientKey reduces a remote address to the unit the limit applies to: the address for
// IPv4, the /64 for IPv6. See the note above on why those differ.
//
// An address that cannot be parsed is used verbatim rather than dropped. Failing open
// on an unrecognised address would be a bypass for whatever produced it.
func clientKey(addr net.Addr) string {
	if addr == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	if host == "" {
		return "unknown"
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	// ::ffff:203.0.113.7 is an IPv4 client and must be counted as one. Without this it
	// would be treated as IPv6 and given a /64 — which for a v4-mapped address covers
	// every IPv4 address there is, collapsing the whole internet onto one counter.
	ip = ip.Unmap()
	if ip.Is4() {
		return ip.String()
	}
	p, err := ip.Prefix(64)
	if err != nil {
		return ip.String()
	}
	return p.String()
}

// privateSource reports whether a key names an address a proxy in front of the gateway
// would present. Used only to add a hint to a refusal: a limiter counting a load
// balancer looks identical to a limiter working, and that is an expensive hour to spend.
func privateSource(key string) bool {
	host := key
	if i := strings.IndexByte(host, '/'); i >= 0 { // a /64 key
		host = host[:i]
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// admit applies the connection rate limit and reports whether this connection may
// proceed. A refusal is logged rather than silent: from the client's side a rate limit
// and a broken gateway look identical, so the gateway's log is the only place the
// difference exists.
func (s *Server) admit(conn net.Conn) bool {
	key := clientKey(conn.RemoteAddr())
	ok, count := s.rate.allow(key)
	if ok {
		return true
	}
	attrs := []any{
		"client", key, "connections_this_minute", count,
		"limit", s.rate.perMinute,
	}
	if privateSource(key) {
		// The load-balancer case. Worth saying out loud at the moment it bites, because
		// the symptom — operators locked out for no reason — is otherwise indis-
		// tinguishable from the limit doing its job.
		attrs = append(attrs, "note",
			"this source is private: if a proxy or load balancer fronts this listener, "+
				"every operator is being counted as one client. Terminate SSH ahead of "+
				"it, use PROXY protocol, or set ssh.conn_rate_per_minute: -1 and limit "+
				"at the edge")
	}
	s.log.Warn("refused an SSH connection: too many from this client", attrs...)
	return false
}
