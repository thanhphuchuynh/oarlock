package metrics

// The golden signals, as this gateway can see them.
//
// Traffic, errors, latency and saturation — Google's four, and the reason FR43 names them
// rather than a list of counters is that a list grows and four questions do not.
//
// The mapping is worth stating, because "golden signals" is otherwise a phrase people put
// in a commit message:
//
//	traffic     sessions opened, API requests, connections accepted
//	errors      sessions closed by a reason that is not the operator leaving; refusals
//	latency     session open, and every plugin call
//	saturation  live sessions, connected agents, outstanding invitations, spool bytes
//
// Saturation is the one that is easy to leave out and the one that predicts an outage: a
// recorder spool that is filling has minutes left, and nothing else here says so.

import (
	"net/http"
	"time"
)

// Gateway is the gateway's own instrumentation.
type Gateway struct {
	SessionsOpened *Counter
	SessionsClosed *Counter
	SessionOpen    *Histogram

	APIRequests *Counter
	Refused     *Counter

	AuditDropped *Counter

	Plugins *Plugins
}

// NewGateway registers the gateway families.
//
// Gauges are attached separately by Bind, because the things worth gauging are owned by
// components this package must not import — the hub, the registry, the inviter — and a
// metrics package that imported half the gateway to read three numbers would be a metrics
// package nobody could test.
func NewGateway(r *Registry) *Gateway {
	return &Gateway{
		SessionsOpened: r.NewCounter("oarlock_sessions_opened_total",
			"Sessions that reached the point of carrying bytes.", "profile", "surface"),
		// Closed by reason, and the reason is the closed set from ARCHITECTURE § 6 — so
		// this is bounded, and `rate(...{reason!="operator_close"})` is the error signal.
		SessionsClosed: r.NewCounter("oarlock_sessions_closed_total",
			"Sessions that ended, by close reason.", "profile", "reason"),
		SessionOpen: r.NewHistogram("oarlock_session_open_duration_seconds",
			"From the operator asking to the session carrying bytes.",
			// Wider than the plugin bounds: NFR1 is a p50 under a second in persistent
			// mode and a p95 under ten in dispatch, and a histogram whose top bucket is
			// below the requirement cannot show whether the requirement is met.
			[]float64{0.1, 0.25, 0.5, 1, 2, 5, 10, 20, 30, 60},
			"profile", "mode"),

		APIRequests: r.NewCounter("oarlock_api_requests_total",
			"API requests, by status class.", "status"),
		// Every door's refusals in one family, because "are we refusing more than usual"
		// is one question and the door is how you narrow it.
		Refused: r.NewCounter("oarlock_connections_refused_total",
			"Connections refused before doing any work, by door and reason.",
			"door", "reason"),

		AuditDropped: r.NewCounter("oarlock_audit_events_dropped_total",
			"Audit events dropped because the queue was full. Any non-zero rate here "+
				"means the trail has holes."),

		Plugins: r.NewPlugins(),
	}
}

// Sources are the numbers the gateway already counts, which the gauges read at scrape time.
//
// Every one of these was already exposed with a comment saying "for metrics" and had no
// consumer. Nil is allowed for each: a gateway with no recorder has no spool.
type Sources struct {
	LiveSessions func() int
	Agents       func() int
	Outstanding  func() int
	SpoolBytes   func() int64
	Tickets      func() int
}

// Bind registers the saturation gauges against whatever owns the numbers.
func (g *Gateway) Bind(r *Registry, s Sources) {
	gauge := func(name, help string, f func() float64) {
		if f == nil {
			// A gauge that reports zero because nothing is wired is worse than an absent
			// one: a dashboard shows a flat line and a reader concludes there are no
			// sessions rather than no instrumentation.
			return
		}
		r.NewGauge(name, help, f)
	}
	gauge("oarlock_sessions_live", "Sessions running on this node.", intGauge(s.LiveSessions))
	gauge("oarlock_agents_connected", "Devices holding a control channel on this node.",
		intGauge(s.Agents))
	gauge("oarlock_invitations_outstanding",
		"Invitations sent to a device that has not dialled back yet.", intGauge(s.Outstanding))
	gauge("oarlock_tickets_outstanding",
		"Minted tickets that have not been redeemed or expired.", intGauge(s.Tickets))
	gauge("oarlock_recording_spool_bytes",
		"Recording bytes buffered but not yet written. A rising value has minutes in it.",
		int64Gauge(s.SpoolBytes))
}

func intGauge(f func() int) func() float64 {
	if f == nil {
		return nil
	}
	return func() float64 { return float64(f()) }
}

func int64Gauge(f func() int64) func() float64 {
	if f == nil {
		return nil
	}
	return func() float64 { return float64(f()) }
}

// ── call sites ──────────────────────────────────────────────────────────────────

// SessionOpened records a session that reached the point of carrying bytes, and how long
// getting there took.
func (g *Gateway) SessionOpened(profile, surface, mode string, took time.Duration) {
	if g == nil {
		return
	}
	g.SessionsOpened.Inc(Labels{"profile": profile, "surface": surface})
	g.SessionOpen.Observe(took.Seconds(), Labels{"profile": profile, "mode": mode})
}

// SessionClosed records how a session ended.
func (g *Gateway) SessionClosed(profile, reason string) {
	if g == nil {
		return
	}
	g.SessionsClosed.Inc(Labels{"profile": profile, "reason": reason})
}

// APIRequest records one request by status class.
//
// The class rather than the code: `404` and `403` are different events to a person and the
// same event to an alert, and a label per status code across every route is cardinality
// nobody asked for.
func (g *Gateway) APIRequest(status int) {
	if g == nil {
		return
	}
	g.APIRequests.Inc(Labels{"status": statusClass(status)})
}

func statusClass(status int) string {
	switch {
	case status >= 500:
		return "5xx"
	case status >= 400:
		return "4xx"
	case status >= 300:
		return "3xx"
	default:
		return "2xx"
	}
}

// ConnectionRefused records a refusal at a door, before any work was done.
func (g *Gateway) ConnectionRefused(door, reason string) {
	if g == nil {
		return
	}
	g.Refused.Inc(Labels{"door": door, "reason": reason})
}

// ── the endpoint ────────────────────────────────────────────────────────────────

// Handler serves the registry in Prometheus text format.
//
// The content type carries `version=0.0.4`, which is what tells a scraper this is the text
// exposition format rather than something it should guess at.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		// Deliberately not buffered into memory first. The exposition is a few kilobytes
		// and a scrape that half-writes is a scrape Prometheus discards, which is the
		// right outcome for a gateway that died mid-render.
		_, _ = r.WriteTo(w)
	})
}
