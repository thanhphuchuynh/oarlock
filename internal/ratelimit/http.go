package ratelimit

// The WebSocket doors.
//
// # These are not guessing surfaces, and the limit is sized accordingly
//
// The SSH front door has a limit because keys can, in principle, be tried. Nothing here
// can: /ws/control is an Ed25519 challenge-response and /ws/session and /ws/attach redeem
// a 32-byte random ticket. Neither is brute-forceable at any rate, so this limit is not
// an anti-guessing control and pretending otherwise would set the number far too low.
//
// What it bounds is work. An unauthenticated peer that connects, sends a HELLO and hangs
// up costs the gateway a nonce, a goroutine and — once it sends anything shaped like an
// AUTH — an ed25519.Verify. The handshake budget (5 s) bounds how long one such peer may
// *hold*; nothing bounded how fast it could repeat. This does.
//
// # Why the number is large, and why being refused is safe
//
// The realistic legitimate burst is a fleet reconnecting after the gateway restarts, and
// a fleet is very often behind one NAT — so on this door "one client" can legitimately be
// several hundred devices. That is the opposite of the SSH door, where one client is one
// human.
//
// Being refused is not fatal here, which is what makes a bound acceptable at all. An
// agent treats a failed dial as a retry: it backs off, and because the backoff resets on
// a successful *handshake* rather than a successful dial, a throttled fleet spreads
// itself out instead of arriving together. The effect of hitting this limit is a slower
// reconnect, not an outage — and spreading a thundering herd is a thing worth doing on
// purpose.

import (
	"log/slog"
	"net/http"
)

// DefaultWSConnRatePerMinute is the budget for one client on the WebSocket doors.
//
// Two a second sustained. Far above one operator or one device, deliberately below what
// it costs to make the gateway do handshake work in a loop.
const DefaultWSConnRatePerMinute = 120

// Middleware refuses a request when its client is over budget, before next sees it.
//
// Before, and that is the point: refusing here costs a map lookup, where refusing after
// the upgrade would cost a goroutine and a WebSocket handshake per attempt and leave an
// attacker setting the gateway's workload. A refused caller gets 429 and never reaches
// the 101.
//
// A nil Limiter returns next unwrapped, so a disabled control costs nothing at all.
func Middleware(l *Limiter, name string, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if l == nil {
			return next
		}
		if log == nil {
			log = slog.Default()
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := KeyForRequest(r)
			ok, count := l.Allow(key)
			if ok {
				next.ServeHTTP(w, r)
				return
			}
			attrs := []any{
				"endpoint", name, "client", key,
				"connections_this_minute", count, "limit", l.PerMinute(),
			}
			if PrivateSource(key) {
				attrs = append(attrs, "note",
					"this source is private: if a proxy or load balancer fronts this "+
						"listener, every device and operator behind it is being counted "+
						"as one client. Terminate ahead of it or set "+
						"listen.ws_conn_rate_per_minute: -1 and limit at the edge")
			}
			log.Warn("refused a WebSocket connection: too many from this client", attrs...)

			// Retry-After points at the window boundary a caller would have to wait for
			// rather than a guess. A minute is the whole window, which is the honest
			// upper bound when the caller is already over.
			w.Header().Set("Retry-After", "60")
			http.Error(w, "too many connections from this client", http.StatusTooManyRequests)
		})
	}
}
