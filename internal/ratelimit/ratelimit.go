// Package ratelimit bounds how fast one client may open connections.
//
// It exists because the same control was needed on two unrelated front doors — the SSH
// listener and the three WebSocket endpoints — and the interesting part is not the
// counter. It is the key.
//
// # Why a key is a prefix on one family and an address on the other
//
// Per-address is not a limit on IPv6. A residential or cloud host is routinely handed a
// /64 — eighteen quintillion addresses — and rotating the low half costs an attacker
// nothing, so an address-keyed counter is defeated by a for-loop and goes on looking
// like it is working the whole time. The unit that corresponds to "one client" is the
// /64, so that is what is counted.
//
// IPv4 is keyed on the full address. A /24 is not one client, and treating it as one
// would let a single misbehaving host lock out its neighbours — a rate limit that
// becomes somebody else's outage is a rate limit that gets turned off.
//
// The trap is combining those two rules. `::ffff:203.0.113.7` is an IPv4 client wearing
// an IPv6 address and its high 64 bits are zero, so keying it as IPv6 yields `::/64` —
// which every v4-mapped address in existence shares, collapsing the whole IPv4 internet
// onto one counter. Unmap before deciding.
//
// # What this cannot see
//
// **A proxy in front of the listener makes every connection look like one client.** For
// SSH there is no X-Forwarded-For and no fix short of PROXY protocol; for HTTP the
// forwarded headers exist and are deliberately not read, because a header a caller
// controls is a rate-limit key a caller controls. So the limiter is keyed on the peer
// that actually connected, and a deployment that terminates elsewhere must disable it
// and limit at the edge instead. Refusals say when the source is private, because that
// misconfiguration otherwise looks exactly like the limit working.
package ratelimit

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Limiter is a fixed-window counter per client key.
//
// A fixed window rather than a token bucket: the boundary is a real instant a log line
// can point at, none of these doors is a hot path, and the window's known weakness —
// twice the rate across a boundary — is uninteresting when the limit is already set well
// above legitimate use.
//
// A nil *Limiter allows everything, so a caller that has the control disabled does not
// need to branch twice.
type Limiter struct {
	perMinute int
	now       func() time.Time

	mu      sync.Mutex
	windows map[string]*window
}

type window struct {
	start time.Time
	count int
}

// New returns a limiter admitting perMinute connections per key, or nil when perMinute
// is negative, which disables the control. A perMinute of zero is the caller's problem
// to default: the right number differs by door, and silently picking one here would hide
// that.
func New(perMinute int, now func() time.Time) *Limiter {
	if perMinute < 0 {
		return nil
	}
	if now == nil {
		now = time.Now
	}
	return &Limiter{perMinute: perMinute, now: now, windows: make(map[string]*window)}
}

// PerMinute is the configured budget, for a log line that wants to say what was exceeded.
func (l *Limiter) PerMinute() int {
	if l == nil {
		return 0
	}
	return l.perMinute
}

// Allow records one connection from key and reports whether it is within the budget. The
// count comes back so a refusal can say how far over the client is, which is the
// difference between a log an operator can act on and one that only says no.
func (l *Limiter) Allow(key string) (bool, int) {
	if l == nil {
		return true, 0
	}
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	win, ok := l.windows[key]
	if !ok || now.Sub(win.start) >= time.Minute {
		win = &window{start: now}
		l.windows[key] = win
		// Opportunistic sweep. Without it a gateway that has been scanned keeps a window
		// per source address for as long as it runs — a slow leak driven by strangers.
		// Only expired windows go: dropping a live one resets an attacker's counter,
		// which is the one thing the map is for.
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

// Key reduces a remote address to the unit the limit applies to.
//
// An address that cannot be parsed is used verbatim rather than dropped: failing open on
// something unrecognised would be a bypass for whatever produced it.
func Key(addr net.Addr) string {
	if addr == nil {
		return "unknown"
	}
	return KeyForAddr(addr.String())
}

// KeyForRequest is Key for an HTTP peer. It reads RemoteAddr and nothing else — no
// X-Forwarded-For, no Forwarded, deliberately. Those are set by the caller unless a
// trusted proxy overwrites them, and a rate-limit key the caller chooses is not a rate
// limit.
func KeyForRequest(r *http.Request) string { return KeyForAddr(r.RemoteAddr) }

// KeyForAddr is the shared implementation, on a `host:port` or bare-host string.
func KeyForAddr(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	if host == "" {
		return "unknown"
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	// See the package comment: a v4-mapped address is an IPv4 client, and giving it a
	// /64 would put every IPv4 address there is on one counter.
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

// PrivateSource reports whether a key names an address a proxy in front of the gateway
// would present. Used only to annotate a refusal: a limiter counting a load balancer is
// indistinguishable from a limiter working, and that is an expensive hour to spend.
func PrivateSource(key string) bool {
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
