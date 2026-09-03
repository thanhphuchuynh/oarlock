// Package metrics is the gateway's instrumentation, in Prometheus text format.
//
// # Why not client_golang
//
// The exposition format is a few lines of text and this needs counters, gauges and one
// histogram. The official client brings protobuf, a compression library and a process
// collector to do that, on a project whose whole dependency list is seven modules and
// whose threat model has a section about supply chain. The trade would be reasonable for
// an application that needed exemplars, native histograms or push; this one does not.
//
// What that costs is real and worth naming: no `promhttp` conveniences, no automatic Go
// runtime collector, and a text encoder somebody has to keep correct. The encoder is
// tested against the format's rules rather than against a library's output.
//
// # Cardinality is the design, not a detail
//
// **No metric here carries a device id, a principal, or a session id.** A fleet is tens of
// thousands of devices, and a label per device is a time series per device per metric —
// which is how a Prometheus falls over, taking the monitoring with it at the moment
// somebody needs it. Every label in this package comes from a closed set: a profile, a
// close reason, an outcome, a plugin method.
//
// The information that would have gone in a label lives in the ledger and the audit trail,
// which are built to be queried that way. "How many sessions closed as `revoked`" is a
// metric; "which sessions" is a SQL query.
package metrics

import (
	"fmt"
	"io"
	"maps"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Registry holds every metric a gateway exposes.
//
// One per gateway rather than a package-level default: a package global would make two
// gateways in one process — which is every test in this repository — share counters, and a
// test that asserted on a count would depend on what the previous test did.
type Registry struct {
	mu sync.RWMutex
	// ordered so the exposition is stable; a diff between two scrapes should be about
	// the numbers.
	names   []string
	metrics map[string]metric
}

// metric is what a family knows how to do.
type metric interface {
	name() string
	help() string
	kind() string
	// write emits every series in this family, sorted by label set.
	write(w io.Writer) error
}

func New() *Registry {
	return &Registry{metrics: map[string]metric{}}
}

func (r *Registry) register(m metric) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.metrics[m.name()]; dup {
		// A panic rather than an error return. Two metrics sharing a name produce an
		// exposition Prometheus rejects wholesale, so the scrape fails and every metric
		// disappears — a failure that shows up as "monitoring is down" long after the
		// commit that caused it. Better at startup, in a test, loudly.
		panic("metrics: duplicate metric " + m.name())
	}
	r.metrics[m.name()] = m
	r.names = append(r.names, m.name())
	sort.Strings(r.names)
}

// WriteTo renders the whole registry.
func (r *Registry) WriteTo(w io.Writer) (int64, error) {
	r.mu.RLock()
	names := slices.Clone(r.names)
	byName := maps.Clone(r.metrics)
	r.mu.RUnlock()

	cw := &countingWriter{w: w}
	for _, n := range names {
		m := byName[n]
		if _, err := fmt.Fprintf(cw, "# HELP %s %s\n# TYPE %s %s\n",
			m.name(), m.help(), m.name(), m.kind()); err != nil {
			return cw.n, err
		}
		if err := m.write(cw); err != nil {
			return cw.n, err
		}
	}
	return cw.n, nil
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// ── labels ──────────────────────────────────────────────────────────────────────

// Labels is one series' label set. Keys are fixed per family at construction, so a caller
// that invents a key is a compile-time-shaped mistake caught at the first write.
type Labels map[string]string

// key renders labels into the exposition's brace form, sorted so one series has one key.
func (l Labels) key(allowed []string) string {
	if len(l) == 0 {
		return ""
	}
	parts := make([]string, 0, len(l))
	for _, k := range allowed {
		v, ok := l[k]
		if !ok {
			v = ""
		}
		parts = append(parts, k+`="`+escapeLabel(v)+`"`)
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// escapeLabel applies the exposition format's three escapes.
//
// Backslash, double quote and newline, in that order — escaping the backslash second would
// double the ones the other two just added.
func escapeLabel(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return v
}

// ── counter ─────────────────────────────────────────────────────────────────────

// Counter is a monotonically increasing family.
type Counter struct {
	n, h   string
	labels []string

	mu     sync.RWMutex
	series map[string]*atomic.Int64
}

// NewCounter registers a counter. labelNames is the closed set of label keys; see the
// package comment on why none of them is a device or a principal.
func (r *Registry) NewCounter(name, help string, labelNames ...string) *Counter {
	c := &Counter{n: name, h: help, labels: labelNames, series: map[string]*atomic.Int64{}}
	sort.Strings(c.labels)
	r.register(c)
	return c
}

func (c *Counter) name() string { return c.n }
func (c *Counter) help() string { return c.h }
func (c *Counter) kind() string { return "counter" }

// Add increments one series.
func (c *Counter) Add(n int64, l Labels) {
	k := l.key(c.labels)
	c.mu.RLock()
	v, ok := c.series[k]
	c.mu.RUnlock()
	if !ok {
		c.mu.Lock()
		if v, ok = c.series[k]; !ok {
			v = &atomic.Int64{}
			c.series[k] = v
		}
		c.mu.Unlock()
	}
	v.Add(n)
}

// Inc adds one.
func (c *Counter) Inc(l Labels) { c.Add(1, l) }

func (c *Counter) write(w io.Writer) error {
	c.mu.RLock()
	keys := slices.Sorted(maps.Keys(c.series))
	vals := make([]int64, len(keys))
	for i, k := range keys {
		vals[i] = c.series[k].Load()
	}
	c.mu.RUnlock()

	for i, k := range keys {
		if _, err := fmt.Fprintf(w, "%s%s %d\n", c.n, k, vals[i]); err != nil {
			return err
		}
	}
	return nil
}

// Value returns one series' current count, for tests.
func (c *Counter) Value(l Labels) int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if v, ok := c.series[l.key(c.labels)]; ok {
		return v.Load()
	}
	return 0
}

// ── gauge ───────────────────────────────────────────────────────────────────────

// Gauge is a value read at scrape time.
//
// A function rather than a number, deliberately: the things worth gauging here — live
// sessions, connected agents, outstanding invitations — are already counted somewhere
// authoritative, and a mirrored copy is a copy that drifts. This asks the owner.
type Gauge struct {
	n, h string
	read func() float64
}

// NewGauge registers a gauge backed by read, which is called on every scrape.
func (r *Registry) NewGauge(name, help string, read func() float64) *Gauge {
	g := &Gauge{n: name, h: help, read: read}
	r.register(g)
	return g
}

func (g *Gauge) name() string { return g.n }
func (g *Gauge) help() string { return g.h }
func (g *Gauge) kind() string { return "gauge" }

func (g *Gauge) write(w io.Writer) error {
	v := 0.0
	if g.read != nil {
		v = g.read()
	}
	_, err := fmt.Fprintf(w, "%s %s\n", g.n, formatFloat(v))
	return err
}

// ── histogram ───────────────────────────────────────────────────────────────────

// Histogram is a cumulative bucket family, for latency.
type Histogram struct {
	n, h   string
	labels []string
	bounds []float64

	mu     sync.RWMutex
	series map[string]*histSeries
}

type histSeries struct {
	counts []atomic.Int64 // one per bound, plus +Inf at the end
	sum    atomic.Uint64  // float64 bits, so the whole series is lock-free on the hot path
	total  atomic.Int64
}

// DefaultLatencyBounds spans a plugin call: a local decision, a database, a network hop, a
// timeout.
//
// Chosen to make the questions answerable rather than to be evenly spaced. "Is the
// authorizer answering in under 10 ms" and "is anything taking more than a second" are the
// two an operator asks, so both have a boundary.
var DefaultLatencyBounds = []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// NewHistogram registers a histogram. bounds must be sorted ascending; nil means
// DefaultLatencyBounds.
func (r *Registry) NewHistogram(name, help string, bounds []float64, labelNames ...string) *Histogram {
	if len(bounds) == 0 {
		bounds = DefaultLatencyBounds
	}
	h := &Histogram{n: name, h: help, labels: labelNames, bounds: bounds,
		series: map[string]*histSeries{}}
	sort.Strings(h.labels)
	r.register(h)
	return h
}

func (h *Histogram) name() string { return h.n }
func (h *Histogram) help() string { return h.h }
func (h *Histogram) kind() string { return "histogram" }

// Observe records one value.
func (h *Histogram) Observe(v float64, l Labels) {
	k := l.key(h.labels)
	h.mu.RLock()
	s, ok := h.series[k]
	h.mu.RUnlock()
	if !ok {
		h.mu.Lock()
		if s, ok = h.series[k]; !ok {
			s = &histSeries{counts: make([]atomic.Int64, len(h.bounds)+1)}
			h.series[k] = s
		}
		h.mu.Unlock()
	}
	// The first bucket whose bound this value is under, then every wider one — the
	// exposition wants cumulative counts.
	i := sort.SearchFloat64s(h.bounds, v)
	if i < len(h.bounds) && h.bounds[i] < v {
		i++
	}
	for j := i; j < len(s.counts); j++ {
		s.counts[j].Add(1)
	}
	s.total.Add(1)
	addFloat(&s.sum, v)
}

// addFloat adds to a float64 held as bits, so an observation costs no lock.
func addFloat(u *atomic.Uint64, v float64) {
	for {
		old := u.Load()
		next := floatBits(floatFrom(old) + v)
		if u.CompareAndSwap(old, next) {
			return
		}
	}
}

func (h *Histogram) write(w io.Writer) error {
	h.mu.RLock()
	keys := slices.Sorted(maps.Keys(h.series))
	all := make([]*histSeries, len(keys))
	for i, k := range keys {
		all[i] = h.series[k]
	}
	h.mu.RUnlock()

	for i, k := range keys {
		s := all[i]
		inner := strings.TrimSuffix(strings.TrimPrefix(k, "{"), "}")
		for j, b := range h.bounds {
			if err := writeBucket(w, h.n, inner, formatFloat(b), s.counts[j].Load()); err != nil {
				return err
			}
		}
		if err := writeBucket(w, h.n, inner, "+Inf", s.counts[len(h.bounds)].Load()); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "%s_sum%s %s\n%s_count%s %d\n",
			h.n, k, formatFloat(floatFrom(s.sum.Load())), h.n, k, s.total.Load()); err != nil {
			return err
		}
	}
	return nil
}

func writeBucket(w io.Writer, name, inner, le string, count int64) error {
	labels := `le="` + le + `"`
	if inner != "" {
		labels = inner + "," + labels
	}
	_, err := fmt.Fprintf(w, "%s_bucket{%s} %d\n", name, labels, count)
	return err
}

// formatFloat renders without an exponent where it can, because a dashboard's legend is
// read by a person.
func formatFloat(v float64) string {
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// floatBits and floatFrom carry a float64 through an atomic.Uint64, so an observation
// costs a compare-and-swap rather than a mutex on the hot path.
func floatBits(f float64) uint64 { return math.Float64bits(f) }
func floatFrom(u uint64) float64 { return math.Float64frombits(u) }
