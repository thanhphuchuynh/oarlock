# Metrics

`listen.metrics: authenticated` serves Prometheus metrics at `/metrics` on the HTTP
listener. Prometheus sends the same bearer token the API takes:

```yaml
scrape_configs:
  - job_name: oarlock
    authorization:
      credentials: <the same token you would give the API>
    static_configs:
      - targets: ["gateway.example.org:443"]
    scheme: https
```

`listen.metrics: public` serves them unauthenticated. That is reasonable on a private
interface and the boot gate refuses it in production, because the numbers describe the
fleet — how many devices exist, how many refusals are happening, whether the recorder is
falling behind. None of it is a credential and all of it is reconnaissance.

## What is *not* here, and why

**No device id, principal, or session id appears as a label.** A fleet is tens of thousands
of devices and a label per device is a time series per device per metric, which is how a
Prometheus falls over — taking the monitoring with it at the moment somebody needs it.
Every label below comes from a closed set.

The question a label would have answered belongs in the ledger, which is built for it.
*How many* sessions closed as `revoked` is a metric; *which* sessions is
`oarlockctl sessions list --state closed` or a SQL query.

## The names are stable

FR43 says so, and a metric name is a contract with every dashboard and alert written
against it. A renamed metric does not break loudly — somebody's alert quietly stops firing.
The names are pinned in a test (`internal/metrics/metrics_test.go`), and changing one fails
that test with a message saying what it will break.

## Golden signals

| metric | type | labels | what it is |
|---|---|---|---|
| `oarlock_sessions_opened_total` | counter | `profile`, `surface` | Sessions that reached the point of carrying bytes. **Traffic.** |
| `oarlock_sessions_closed_total` | counter | `profile`, `reason` | Sessions that ended. `reason` is the closed set from ARCHITECTURE § 6, so `reason!="operator_close"` is the **error** signal. |
| `oarlock_session_open_duration_seconds` | histogram | `profile`, `mode` | Operator asking → session carrying bytes. **Latency**, and what NFR1 is measured against. |
| `oarlock_api_requests_total` | counter | `status` | API requests by status *class* — `2xx`, `4xx`, `5xx`. A label per code across every route is cardinality nobody asked for. |
| `oarlock_connections_refused_total` | counter | `door`, `reason` | Refused before any work was done: rate limits, budgets, ceilings. |
| `oarlock_sessions_live` | gauge | — | Sessions running on this node. **Saturation.** |
| `oarlock_agents_connected` | gauge | — | Devices holding a control channel here. |
| `oarlock_invitations_outstanding` | gauge | — | Invitations sent to a device that has not dialled back. A rising value is devices not answering. |
| `oarlock_tickets_outstanding` | gauge | — | Minted, unredeemed, unexpired tickets. |
| `oarlock_recording_spool_bytes` | gauge | — | Recording bytes buffered and not yet written. **The saturation metric with minutes in it.** |
| `oarlock_audit_events_dropped_total` | counter | — | Audit events dropped because the queue was full. Any non-zero rate means the trail has holes. |

## Every plugin's latency and error rate

| metric | type | labels |
|---|---|---|
| `oarlock_plugin_calls_total` | counter | `plugin`, `method`, `outcome` |
| `oarlock_plugin_duration_seconds` | histogram | `plugin`, `method` |

`plugin` is the configured backend kind (`rules`, `sqlite`, `webhook`, `file`, `mqtt`, …).
Backends are wrapped at the `pkg/plugin` seam rather than instrumented inside themselves,
so a backend somebody else wrote is measured exactly like a built-in one.

`outcome` distinguishes three things where two would be misleading:

- **`allow` / `deny`** on the authorizer. A denial is the backend working.
- **`error`** — the backend could not answer. This is the one an alert should watch;
  folding denials into it would alarm on an authorizer doing its job, so the alert would be
  turned off, and then it would not fire when the backend actually broke.
- **`unsupported`** — the documented answer for a method a backend does not offer, like a
  key file asked about an HTTP request. Not a failure of anything.

Latency is recorded for failures too. A backend that is slow *and* failing is the
interesting case, and a histogram that counted only successes would show it getting faster
as it broke.

## A starter alert set

Thresholds are a starting point, not a recommendation: the right numbers depend on your
fleet's size and how much of it is usually asleep.

```yaml
groups:
  - name: oarlock
    rules:
      # The trail has holes. Nothing else here matters as much: an audit log that
      # silently dropped events is one nobody can rely on afterwards.
      - alert: OarlockAuditDropping
        expr: rate(oarlock_audit_events_dropped_total[5m]) > 0
        for: 0m
        labels: {severity: critical}

      # A dependency is down, as opposed to saying no.
      - alert: OarlockPluginErrors
        expr: |
          sum by (plugin) (rate(oarlock_plugin_calls_total{outcome="error"}[5m]))
            / sum by (plugin) (rate(oarlock_plugin_calls_total[5m])) > 0.05
        for: 5m
        labels: {severity: warning}

      # The recorder is falling behind. This one has minutes in it before sessions
      # start being refused, because a recorder that cannot start fails the session.
      - alert: OarlockRecordingSpoolGrowing
        expr: oarlock_recording_spool_bytes > 32 * 1024 * 1024
        for: 10m
        labels: {severity: warning}

      # Sessions ending for reasons that are not somebody leaving.
      - alert: OarlockSessionsFailing
        expr: |
          sum(rate(oarlock_sessions_closed_total{reason!~"operator_close|device_close"}[10m]))
            / sum(rate(oarlock_sessions_closed_total[10m])) > 0.1
        for: 10m
        labels: {severity: warning}

      # Devices are being invited and not answering.
      - alert: OarlockDevicesNotAnswering
        expr: oarlock_invitations_outstanding > 20
        for: 5m
        labels: {severity: warning}

      # NFR1: p95 session open under ten seconds in dispatch mode.
      - alert: OarlockSlowSessionOpen
        expr: |
          histogram_quantile(0.95,
            sum by (le, mode) (rate(oarlock_session_open_duration_seconds_bucket[10m]))) > 10
        for: 10m
        labels: {severity: warning}

      # The scrape itself. An alert set nobody notices has stopped is not an alert set.
      - alert: OarlockDown
        expr: up{job="oarlock"} == 0
        for: 2m
        labels: {severity: critical}
```

## What this deliberately does not use

`client_golang`. The exposition format is a few lines of text and this needs counters,
gauges and one histogram; the official client brings protobuf, a compression library and a
process collector to do that, on a project whose dependency list is seven modules and whose
threat model has a section about supply chain.

The cost is real: no `promhttp`, no automatic Go runtime collector — so **there are no
`go_*` or `process_*` metrics here** — and a text encoder this project has to keep correct.
The encoder is tested against the format's rules rather than against a library's output.
