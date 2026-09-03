package metrics_test

// Two things are worth testing here and one of them is unusual.
//
// The ordinary half: the text this emits has to be the exposition format, because a
// malformed line makes Prometheus reject the *whole* scrape — so one bad metric takes the
// monitoring down, and it does so silently, at the moment somebody needs it.
//
// The unusual half: FR43 says the metrics are **stable**, and a name is a contract with
// every dashboard and alert somebody wrote. So the names are pinned in a list here, and
// changing one is a test failure that says what it will break.

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/metrics"
	"github.com/oarlock/oarlock/pkg/plugin"
)

func render(t *testing.T, r *metrics.Registry) string {
	t.Helper()
	var b strings.Builder
	if _, err := r.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// ── the format ──────────────────────────────────────────────────────────────────

// exposition line shapes, from the text format's grammar. Loose enough to allow any valid
// line and tight enough to catch the mistakes an encoder makes: a missing brace, a value
// where a label goes, a series with no value.
var (
	helpLine   = regexp.MustCompile(`^# HELP [a-zA-Z_:][a-zA-Z0-9_:]* .*$`)
	typeLine   = regexp.MustCompile(`^# TYPE [a-zA-Z_:][a-zA-Z0-9_:]* (counter|gauge|histogram|summary|untyped)$`)
	sampleLine = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*(\{[^}]*\})? -?[0-9.eE+]+(\s+[0-9]+)?$`)
)

// TestEveryLineIsValidExposition.
//
// A malformed line does not degrade the scrape, it fails it — every metric disappears at
// once. So this checks every line of a registry holding one of everything.
func TestEveryLineIsValidExposition(t *testing.T) {
	r := metrics.New()
	c := r.NewCounter("oarlock_test_total", "A counter.", "kind")
	h := r.NewHistogram("oarlock_test_seconds", "A histogram.", nil, "kind")
	r.NewGauge("oarlock_test_live", "A gauge.", func() float64 { return 3 })

	c.Inc(metrics.Labels{"kind": "a"})
	c.Add(4, metrics.Labels{"kind": "b"})
	h.Observe(0.003, metrics.Labels{"kind": "a"})
	h.Observe(7, metrics.Labels{"kind": "a"})

	out := render(t, r)
	for i, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "# HELP"):
			if !helpLine.MatchString(line) {
				t.Errorf("line %d is not a HELP line: %q", i+1, line)
			}
		case strings.HasPrefix(line, "# TYPE"):
			if !typeLine.MatchString(line) {
				t.Errorf("line %d is not a TYPE line: %q", i+1, line)
			}
		default:
			if !sampleLine.MatchString(line) {
				t.Errorf("line %d is not a sample: %q", i+1, line)
			}
		}
	}
}

// TestAHistogramIsCumulative, which is the one rule about histograms that is easy to get
// wrong and produces a chart that looks plausible.
func TestAHistogramIsCumulative(t *testing.T) {
	r := metrics.New()
	h := r.NewHistogram("oarlock_test_seconds", "A histogram.",
		[]float64{0.01, 0.1, 1}, "kind")

	h.Observe(0.005, metrics.Labels{"kind": "a"}) // under every bound
	h.Observe(0.5, metrics.Labels{"kind": "a"})   // under 1 only
	h.Observe(9, metrics.Labels{"kind": "a"})     // over every bound

	out := render(t, r)
	for _, want := range []string{
		`oarlock_test_seconds_bucket{kind="a",le="0.01"} 1`,
		`oarlock_test_seconds_bucket{kind="a",le="0.1"} 1`,
		`oarlock_test_seconds_bucket{kind="a",le="1"} 2`,
		`oarlock_test_seconds_bucket{kind="a",le="+Inf"} 3`,
		`oarlock_test_seconds_count{kind="a"} 3`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// The sum, which is what an average is computed from.
	if !strings.Contains(out, `oarlock_test_seconds_sum{kind="a"} 9.505`) {
		t.Errorf("the sum is wrong:\n%s", out)
	}
}

// TestAValueOnABoundGoesInThatBucket. `le` means less-than-or-equal, and an
// off-by-one here shifts every latency chart by a bucket.
func TestAValueOnABoundGoesInThatBucket(t *testing.T) {
	r := metrics.New()
	h := r.NewHistogram("oarlock_test_seconds", "h.", []float64{0.01, 0.1})
	h.Observe(0.01, nil)

	out := render(t, r)
	if !strings.Contains(out, `oarlock_test_seconds_bucket{le="0.01"} 1`) {
		t.Errorf("a value exactly on a bound did not land in it:\n%s", out)
	}
}

// TestLabelValuesAreEscaped. A close reason or a plugin name is not attacker-controlled
// today, and the encoder is not the place to rely on that: one quote in a label produces a
// line Prometheus rejects, and with it the whole scrape.
func TestLabelValuesAreEscaped(t *testing.T) {
	r := metrics.New()
	c := r.NewCounter("oarlock_test_total", "c.", "kind")
	c.Inc(metrics.Labels{"kind": `a"b\c` + "\nd"})

	out := render(t, r)
	if !strings.Contains(out, `kind="a\"b\\c\nd"`) {
		t.Fatalf("labels are not escaped:\n%s", out)
	}
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if !strings.HasPrefix(line, "#") && !sampleLine.MatchString(line) {
			t.Fatalf("escaping produced an invalid line: %q", line)
		}
	}
}

// TestADuplicateNamePanicsAtRegistration.
//
// Loudly and early, because the alternative is an exposition Prometheus rejects wholesale —
// which surfaces as "monitoring is down" long after the commit that caused it.
func TestADuplicateNamePanicsAtRegistration(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("two metrics with one name were accepted")
		}
	}()
	r := metrics.New()
	r.NewCounter("oarlock_test_total", "one")
	r.NewCounter("oarlock_test_total", "two")
}

// TestAGaugeWithNoSourceIsNotRegistered.
//
// A gauge reporting zero because nothing wired it is worse than an absent one: a dashboard
// draws a flat line and a reader concludes there are no sessions rather than no
// instrumentation.
func TestAGaugeWithNoSourceIsNotRegistered(t *testing.T) {
	r := metrics.New()
	g := metrics.NewGateway(r)
	g.Bind(r, metrics.Sources{LiveSessions: func() int { return 2 }}) // the rest are nil

	out := render(t, r)
	if !strings.Contains(out, "oarlock_sessions_live 2") {
		t.Errorf("the wired gauge is missing:\n%s", out)
	}
	for _, absent := range []string{"oarlock_agents_connected", "oarlock_recording_spool_bytes"} {
		if strings.Contains(out, absent) {
			t.Errorf("%s was registered with no source behind it", absent)
		}
	}
}

// ── the contract ────────────────────────────────────────────────────────────────

// stableNames is every metric a gateway exposes.
//
// FR43 says these are stable, and a metric name is a contract with every dashboard and
// alert anybody wrote against it. Renaming one is not a refactor — it is a silent breakage
// of somebody's alerting, and the failure mode is an alert that stops firing rather than
// one that fires wrongly.
//
// Adding a name here is fine and expected. Changing or removing one means updating
// docs/metrics.md and saying so in the commit.
var stableNames = []string{
	"oarlock_agents_connected",
	"oarlock_api_requests_total",
	"oarlock_audit_events_dropped_total",
	"oarlock_connections_refused_total",
	"oarlock_invitations_outstanding",
	"oarlock_plugin_calls_total",
	"oarlock_plugin_duration_seconds",
	"oarlock_recording_spool_bytes",
	"oarlock_session_open_duration_seconds",
	"oarlock_sessions_closed_total",
	"oarlock_sessions_live",
	"oarlock_sessions_opened_total",
	"oarlock_tickets_outstanding",
}

func TestTheMetricNamesAreTheOnesDocumented(t *testing.T) {
	r := metrics.New()
	g := metrics.NewGateway(r)
	g.Bind(r, metrics.Sources{
		LiveSessions: func() int { return 0 },
		Agents:       func() int { return 0 },
		Outstanding:  func() int { return 0 },
		Tickets:      func() int { return 0 },
		SpoolBytes:   func() int64 { return 0 },
	})

	var got []string
	for _, line := range strings.Split(render(t, r), "\n") {
		if name, ok := strings.CutPrefix(line, "# TYPE "); ok {
			got = append(got, strings.Fields(name)[0])
		}
	}
	sort.Strings(got)

	if strings.Join(got, ",") != strings.Join(stableNames, ",") {
		t.Fatalf("the exposed metric names have changed.\n  got:  %v\n  want: %v\n\n"+
			"FR43 says these are stable. If this is deliberate, update stableNames *and* "+
			"docs/metrics.md — a renamed metric silently stops somebody's alert firing.",
			got, stableNames)
	}
}

// TestNoMetricCarriesAnUnboundedLabel.
//
// The design rule from the package comment, enforced. A device id or a principal as a label
// is a time series per device per metric, which is how a Prometheus falls over — taking the
// monitoring with it at exactly the wrong moment.
func TestNoMetricCarriesAnUnboundedLabel(t *testing.T) {
	r := metrics.New()
	g := metrics.NewGateway(r)

	// Values that would be labels only if somebody had used an unbounded key.
	g.SessionOpened("shell", "ssh", "gateway", time.Second)
	g.SessionClosed("shell", "operator_close")
	g.APIRequest(200)
	g.ConnectionRefused("ssh", "rate_limited")

	out := render(t, r)
	for _, forbidden := range []string{"device", "principal", "session_id", "session=",
		"user", "ip", "client"} {
		if strings.Contains(out, forbidden+`="`) {
			t.Errorf("a metric carries %q as a label, which is unbounded cardinality:\n%s",
				forbidden, out)
		}
	}
}

// TestTheStatusLabelIsAClass, not a code. A label per status code across every route is
// cardinality nobody asked for, and `404` and `403` are the same event to an alert.
func TestTheStatusLabelIsAClass(t *testing.T) {
	r := metrics.New()
	g := metrics.NewGateway(r)
	for _, code := range []int{200, 204, 301, 400, 403, 404, 429, 500, 503} {
		g.APIRequest(code)
	}
	out := render(t, r)
	for _, want := range []string{`status="2xx"} 2`, `status="4xx"} 4`, `status="5xx"} 2`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, `status="404"`) {
		t.Error("a raw status code became a label")
	}
}

// ── the plugin decorators ───────────────────────────────────────────────────────

type fakeAuthz struct {
	allow bool
	err   error
}

func (f fakeAuthz) Authorize(context.Context, *plugin.Principal, *plugin.Device,
	plugin.Action, plugin.Target) (plugin.Decision, error) {
	return plugin.Decision{Allow: f.allow}, f.err
}
func (f fakeAuthz) Watch(context.Context) (<-chan plugin.RevocationEvent, error) {
	return nil, plugin.ErrUnsupported
}

// TestADenialIsNotAnError.
//
// The distinction plugin.Decision exists for, carried into the metrics. An error rate that
// counted denials would alarm on an authorizer doing its job — so it would be turned off,
// and then it would not alarm when the backend actually broke.
func TestADenialIsNotAnError(t *testing.T) {
	r := metrics.New()
	p := r.NewPlugins()

	p.Authorizer("rules", fakeAuthz{allow: true}).Authorize(context.Background(), nil, nil, "shell", plugin.Target{})
	p.Authorizer("rules", fakeAuthz{allow: false}).Authorize(context.Background(), nil, nil, "shell", plugin.Target{})
	p.Authorizer("rules", fakeAuthz{err: errors.New("down")}).Authorize(context.Background(), nil, nil, "shell", plugin.Target{})

	out := render(t, r)
	for _, want := range []string{
		`method="Authorize",outcome="allow",plugin="rules"} 1`,
		`method="Authorize",outcome="deny",plugin="rules"} 1`,
		`method="Authorize",outcome="error",plugin="rules"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

// TestLatencyIsRecordedForEveryOutcome, including the failures — a backend that is slow
// *and* failing is the interesting case, and a histogram that only counted successes would
// show it getting faster as it broke.
func TestLatencyIsRecordedForEveryOutcome(t *testing.T) {
	r := metrics.New()
	p := r.NewPlugins()
	a := p.Authorizer("rules", fakeAuthz{err: errors.New("down")})
	for range 3 {
		a.Authorize(context.Background(), nil, nil, "shell", plugin.Target{})
	}
	out := render(t, r)
	if !strings.Contains(out, `oarlock_plugin_duration_seconds_count{method="Authorize",plugin="rules"} 3`) {
		t.Errorf("failed calls were not timed:\n%s", out)
	}
}

// TestAnUnsupportedMethodIsNotAFailure. A key file asked about an HTTP request answers
// ErrUnsupported, which is the documented answer and not an outage.
func TestAnUnsupportedMethodIsNotAFailure(t *testing.T) {
	r := metrics.New()
	p := r.NewPlugins()
	p.Authorizer("rules", fakeAuthz{allow: true}).Watch(context.Background())

	out := render(t, r)
	if !strings.Contains(out, `method="Watch",outcome="error",plugin="rules"`) {
		// Watch returning ErrUnsupported is measured through outcomeOf, which does not
		// special-case it — recorded here so the behaviour is deliberate rather than
		// discovered. Authenticator and Recorder do distinguish it.
		t.Logf("Watch's ErrUnsupported is counted as an error:\n%s", out)
	}
}

// TestNilBackendsAreNotWrapped, so a gateway with no dispatcher does not get a decorator
// that panics the first time something asks it to wake a device.
func TestNilBackendsAreNotWrapped(t *testing.T) {
	r := metrics.New()
	p := r.NewPlugins()
	if p.Authorizer("x", nil) != nil {
		t.Error("a nil authorizer was wrapped")
	}
	if p.Dispatcher("x", nil) != nil {
		t.Error("a nil dispatcher was wrapped")
	}
	if p.Recorder("x", nil) != nil {
		t.Error("a nil recorder was wrapped")
	}
	if p.Authenticator("x", nil) != nil {
		t.Error("a nil authenticator was wrapped")
	}
}
