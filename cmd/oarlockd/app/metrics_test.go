package app_test

// The metrics endpoint, from outside.
//
// The registry has its own tests; this is about the wiring: that the endpoint exists when
// configured, that it does not when it is not, and that it is not readable by anybody who
// can reach the port.

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/oarlock/oarlock/internal/config"
)

func TestMetricsAreServedWhenConfigured(t *testing.T) {
	withConfig(t, func(c *config.Config) { c.Listen.Metrics = "public" })
	d := deploy(t, quiet())
	d.serve(t)

	resp, err := http.Get("http://" + d.httpAddr + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "version=0.0.4") {
		t.Errorf("Content-Type = %q; a scraper needs the exposition version", ct)
	}
	b, _ := io.ReadAll(resp.Body)
	body := string(b)

	// The families a running gateway must be able to answer for, including the gauges
	// that read numbers the components already kept.
	for _, want := range []string{
		"oarlock_sessions_opened_total",
		"oarlock_sessions_live",
		"oarlock_agents_connected",
		"oarlock_plugin_calls_total",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s in the exposition:\n%s", want, body)
		}
	}
}

// TestMetricsAreOffByDefault. An endpoint describing the fleet's size and health should be
// something an operator turned on, not something they discover.
func TestMetricsAreOffByDefault(t *testing.T) {
	d := deploy(t, quiet())
	d.serve(t) // cfg.Listen.Metrics untouched

	resp, err := http.Get("http://" + d.httpAddr + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("/metrics answered on a gateway that did not enable it")
	}
}

// TestMetricsRequireACredentialByDefault.
//
// The numbers are reconnaissance: how many devices exist, how many refusals are happening,
// whether the recorder is falling behind. `public` is available and the boot gate refuses
// it in production.
func TestMetricsRequireACredentialByDefault(t *testing.T) {
	withConfig(t, func(c *config.Config) { c.Listen.Metrics = "authenticated" })
	d := deploy(t, quiet())
	d.serve(t)

	resp, err := http.Get("http://" + d.httpAddr + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("an unauthenticated scrape got %d:\n%s", resp.StatusCode, b)
	}
	if resp.Header.Get("WWW-Authenticate") == "" {
		t.Error("the refusal does not say what credential it wants")
	}
}
