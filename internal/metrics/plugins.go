package metrics

// Every plugin's latency and error rate, which is the half of FR43 that names a mechanism.
//
// # Why decorators and not instrumentation inside each backend
//
// The backends are the part somebody else writes. `pkg/plugin` is public API and
// `docs/plugins.md` invites people to implement it, so instrumentation that lived inside
// each implementation would be instrumentation the third-party ones do not have — and the
// gateway operator would be able to see the latency of the backends they did not need to
// measure and none of the one they did.
//
// Wrapping at the seam measures whatever is behind it, including a backend written last
// week in another repository.
//
// # Three outcomes, not two
//
// The labels are `allow`, `deny` and `error`, and keeping the last separate is the same
// distinction `plugin.Decision` makes: a backend answering "no" and a backend that could
// not answer are different events, and an error rate that folded denials into it would
// alarm on an authorizer doing its job.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
)

// Plugins is the shared instrumentation for every backend seam.
type Plugins struct {
	calls   *Counter
	latency *Histogram
}

// NewPlugins registers the two families every decorator writes to.
//
// One pair for all backends rather than a pair each: an operator's question is "which of
// my dependencies is slow", and that is a `by (plugin)` away only if they share a metric.
func (r *Registry) NewPlugins() *Plugins {
	return &Plugins{
		calls: r.NewCounter("oarlock_plugin_calls_total",
			"Calls into a plugin backend, by outcome.", "plugin", "method", "outcome"),
		latency: r.NewHistogram("oarlock_plugin_duration_seconds",
			"How long a plugin backend took to answer.", nil, "plugin", "method"),
	}
}

// observe records one call. Returns the outcome so a caller can read as one expression.
func (p *Plugins) observe(pluginName, method string, started time.Time, outcome string) {
	if p == nil {
		return
	}
	p.latency.Observe(time.Since(started).Seconds(), Labels{"plugin": pluginName, "method": method})
	p.calls.Inc(Labels{"plugin": pluginName, "method": method, "outcome": outcome})
}

// outcomeOf maps an error to the closed outcome set.
func outcomeOf(err error) string {
	if err != nil {
		return "error"
	}
	return "ok"
}

// ── authorizer ──────────────────────────────────────────────────────────────────

// Authorizer wraps a backend so its latency and outcomes are visible.
func (p *Plugins) Authorizer(name string, inner plugin.Authorizer) plugin.Authorizer {
	if inner == nil {
		return nil
	}
	return &authzMetrics{name: name, inner: inner, p: p}
}

type authzMetrics struct {
	name  string
	inner plugin.Authorizer
	p     *Plugins
}

func (a *authzMetrics) Authorize(ctx context.Context, pr *plugin.Principal, dev *plugin.Device,
	act plugin.Action, tgt plugin.Target) (plugin.Decision, error) {

	started := time.Now()
	d, err := a.inner.Authorize(ctx, pr, dev, act, tgt)
	// The three outcomes, kept apart. A deny is the backend working.
	outcome := "deny"
	switch {
	case err != nil:
		outcome = "error"
	case d.Allow:
		outcome = "allow"
	}
	a.p.observe(a.name, "Authorize", started, outcome)
	return d, err
}

func (a *authzMetrics) Watch(ctx context.Context) (<-chan plugin.RevocationEvent, error) {
	started := time.Now()
	ch, err := a.inner.Watch(ctx)
	a.p.observe(a.name, "Watch", started, outcomeOf(err))
	return ch, err
}

func (a *authzMetrics) Close() error {
	if c, ok := a.inner.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// ── authenticator ───────────────────────────────────────────────────────────────

// Authenticator wraps a backend. The three methods are measured separately because they
// are three different dependencies in most deployments — a key file, an identity provider,
// a token store — behind one interface.
func (p *Plugins) Authenticator(name string, inner plugin.Authenticator) plugin.Authenticator {
	if inner == nil {
		return nil
	}
	return &authnMetrics{name: name, inner: inner, p: p}
}

type authnMetrics struct {
	name  string
	inner plugin.Authenticator
	p     *Plugins
}

func (a *authnMetrics) AuthPublicKey(ctx context.Context, user string,
	key ssh.PublicKey) (*plugin.Principal, error) {
	started := time.Now()
	pr, err := a.inner.AuthPublicKey(ctx, user, key)
	a.p.observe(a.name, "AuthPublicKey", started, authOutcome(err))
	return pr, err
}

func (a *authnMetrics) AuthDelegated(ctx context.Context, svc *plugin.Principal,
	assertion string) (*plugin.Principal, error) {
	started := time.Now()
	pr, err := a.inner.AuthDelegated(ctx, svc, assertion)
	a.p.observe(a.name, "AuthDelegated", started, authOutcome(err))
	return pr, err
}

func (a *authnMetrics) AuthHTTP(ctx context.Context, r *http.Request) (*plugin.Principal, error) {
	started := time.Now()
	pr, err := a.inner.AuthHTTP(ctx, r)
	a.p.observe(a.name, "AuthHTTP", started, authOutcome(err))
	return pr, err
}

// authOutcome keeps a refused credential apart from a broken backend.
//
// Both are errors on this interface, and folding them together would make an
// error-rate alert fire every time somebody mistyped a token — so the alert would be
// turned off, and then it would not fire when the identity provider went down.
func authOutcome(err error) string {
	switch {
	case err == nil:
		return "ok"
	case isUnsupported(err):
		// The backend saying "not my surface", which is the documented answer for a key
		// file asked about an HTTP request. Not a failure of anything.
		return "unsupported"
	default:
		return "refused"
	}
}

func isUnsupported(err error) bool {
	return errors.Is(err, plugin.ErrUnsupported)
}

// ── recorder ────────────────────────────────────────────────────────────────────

// Recorder wraps a recording backend.
//
// Open is the one that matters: it runs before the operator sees a prompt and a failure
// there refuses the session, so its latency is in the session-open path and its error rate
// is a count of sessions that did not happen.
func (p *Plugins) Recorder(name string, inner plugin.Recorder) plugin.Recorder {
	if inner == nil {
		return nil
	}
	return &recorderMetrics{name: name, inner: inner, p: p}
}

type recorderMetrics struct {
	name  string
	inner plugin.Recorder
	p     *Plugins
}

func (r *recorderMetrics) Open(ctx context.Context, m *plugin.SessionMeta) (plugin.RecordingWriter, error) {
	started := time.Now()
	w, err := r.inner.Open(ctx, m)
	r.p.observe(r.name, "Open", started, outcomeOf(err))
	return w, err
}

func (r *recorderMetrics) Get(ctx context.Context, sessionID string) (io.ReadCloser, error) {
	started := time.Now()
	rc, err := r.inner.Get(ctx, sessionID)
	r.p.observe(r.name, "Get", started, outcomeOf(err))
	return rc, err
}

func (r *recorderMetrics) URL(ctx context.Context, sessionID string, ttl time.Duration) (string, error) {
	started := time.Now()
	u, err := r.inner.URL(ctx, sessionID, ttl)
	if isUnsupported(err) {
		// A backend that cannot issue a direct link is not a backend that failed.
		r.p.observe(r.name, "URL", started, "unsupported")
		return u, err
	}
	r.p.observe(r.name, "URL", started, outcomeOf(err))
	return u, err
}

// ── dispatcher ──────────────────────────────────────────────────────────────────

// Dispatcher wraps a doorbell.
//
// The one backend whose latency an operator feels directly: in dispatch mode it is the
// wait between asking for a session and the device hearing about it, and NFR1's p95 is
// mostly this.
func (p *Plugins) Dispatcher(name string, inner plugin.Dispatcher) plugin.Dispatcher {
	if inner == nil {
		return nil
	}
	return &dispatchMetrics{name: name, inner: inner, p: p}
}

type dispatchMetrics struct {
	name  string
	inner plugin.Dispatcher
	p     *Plugins
}

func (d *dispatchMetrics) Wake(ctx context.Context, dev *plugin.Device, inv frame.Invitation) error {
	started := time.Now()
	err := d.inner.Wake(ctx, dev, inv)
	d.p.observe(d.name, "Wake", started, outcomeOf(err))
	return err
}
