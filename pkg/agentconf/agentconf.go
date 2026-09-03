// Package agentconf is the conformance suite for a third-party Oarlock agent.
//
// It is the executable half of SC7: *an independent implementer passes the agent
// conformance suite using `docs/protocol.md` and `pkg/frame` only.* A document says what
// the protocol is; this says whether you built it.
//
// # Why it is a server and not a test helper
//
// pkg/plugin/plugintest is a Go test helper because a plugin backend is Go by
// construction — it implements a Go interface. An agent is not: the protocol exists so a
// device can speak it from Rust, from Kotlin inside an APK, from whatever the platform
// gives you. So this suite is a *gateway* that the agent under test dials, and the only
// thing it needs from the implementer is a URL.
//
// # The suite drives the agent's reconnect loop, on purpose
//
// Each case is one control channel: the suite accepts a connection, runs one case, and
// hangs up. The agent is expected to come back, which is why the cases can be a sequence
// at all — and which makes "you reconnect after the gateway drops you" the first thing the
// suite tests, before it tests anything else.
//
// An agent that does not reconnect fails everything after case one, and the report says
// so rather than reporting nine mysterious timeouts.
//
// # What it cannot check
//
// It sees the wire and nothing else. It cannot tell whether your private key left the
// device, whether your allow-lists are enforced, or whether you pinned the certificate —
// those are properties of your implementation, not of your traffic, and the report says
// so rather than implying coverage it does not have. `docs/protocol.md` § 3.1 and the
// threat model are where those live.
package agentconf

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Status is how one case came out.
type Status string

const (
	// Pass means the agent did what the protocol requires.
	Pass Status = "pass"
	// Fail means it did not. The Detail says what was expected and what arrived.
	Fail Status = "fail"
	// Skip means the case could not run — usually because the connection is not TLS, so
	// there is no channel to bind to. A skip is not a pass and the summary counts it
	// separately.
	Skip Status = "skip"
	// Timeout means the agent never produced what the case was waiting for. Reported
	// apart from Fail because the usual cause is different: an agent that stopped
	// reconnecting fails every later case this way, and one message saying that beats
	// nine saying "waited 10s".
	Timeout Status = "timeout"
)

// Result is one case's outcome.
type Result struct {
	Name string
	// Requirement points at the paragraph of docs/protocol.md the case comes from, so a
	// failure is actionable without reading this package.
	Requirement string
	Status      Status
	Detail      string
	Elapsed     time.Duration
}

// Report is the whole run.
type Report struct {
	Results []Result
	// Notes are things the reader should know that are not case outcomes — what the
	// suite could not check, and why.
	Notes []string
}

// Passed reports whether every case that ran passed. A skip does not fail the run; the
// caller decides whether an unrun case is acceptable, and the binary says how many there
// were.
func (r Report) Passed() bool {
	for _, res := range r.Results {
		if res.Status == Fail || res.Status == Timeout {
			return false
		}
	}
	return true
}

// Counts returns how many cases landed in each status.
func (r Report) Counts() map[Status]int {
	out := map[Status]int{}
	for _, res := range r.Results {
		out[res.Status]++
	}
	return out
}

// String renders the report for a terminal.
func (r Report) String() string {
	var b strings.Builder
	width := 0
	for _, res := range r.Results {
		width = max(width, len(res.Name))
	}
	for _, res := range r.Results {
		mark := map[Status]string{Pass: "ok  ", Fail: "FAIL", Skip: "skip", Timeout: "TIME"}[res.Status]
		fmt.Fprintf(&b, "%s  %-*s  %s\n", mark, width, res.Name, res.Requirement)
		if res.Detail != "" {
			fmt.Fprintf(&b, "        %s\n", res.Detail)
		}
	}
	c := r.Counts()
	fmt.Fprintf(&b, "\n%d passed, %d failed, %d timed out, %d skipped\n",
		c[Pass], c[Fail], c[Timeout], c[Skip])

	if len(r.Notes) > 0 {
		b.WriteString("\nWhat this suite did not check:\n")
		for _, n := range r.Notes {
			fmt.Fprintf(&b, "  - %s\n", n)
		}
	}
	return b.String()
}

// recorder collects results. Concurrent because a case may be driven from more than one
// goroutine — a session case runs while the control channel is still live.
type recorder struct {
	mu      sync.Mutex
	results []Result
	notes   []string
}

func (r *recorder) add(res Result) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.results = append(r.results, res)
}

func (r *recorder) note(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.notes = append(r.notes, fmt.Sprintf(format, args...))
}

func (r *recorder) report() Report {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Result, len(r.results))
	copy(out, r.results)
	// Stable order, so two runs of the same suite diff cleanly. Cases run in a fixed
	// order anyway; this survives one being driven concurrently.
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	notes := make([]string, len(r.notes))
	copy(notes, r.notes)
	return Report{Results: out, Notes: notes}
}

// The notes every run carries. Stated as things the suite cannot see rather than left for
// a reader to assume, because a conformance report that implies coverage it does not have
// is worse than no report.
var alwaysNotes = []string{
	"whether the device's private key ever leaves the device (NFR9) — not observable " +
		"from the wire",
	"whether the agent pins the gateway certificate (NFR10) — the suite is the gateway, " +
		"so it cannot tell whether you would have refused a different one",
	"whether the device's own exec/tcp/file/log allow-lists are enforced — the suite " +
		"asks for what your configuration published, and threat model § 6 is where that " +
		"contract lives",
	"the session leg beyond OPEN: this release covers the control channel and the " +
		"ticket, not the per-profile behaviour of a live session",
}
