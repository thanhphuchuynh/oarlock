// Package apisrv is the control API: /api/v1.
//
// # What is here and what is not
//
// Sessions: open, list, inspect, kill. `POST /api/v1/sessions` returns a single-use
// attach ticket for `/ws/attach`, so it only exists now that endpoint does.
//
// Not here yet: idempotency keys (E7.S2), long-poll state awaiting (E7.S3), and devices
// (E5). `POST` authenticates the API caller, verifies delegated authority when an
// On-Behalf-Of-Token is present, then authorises the effective human principal before a
// device is woken.
package apisrv

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oarlock/oarlock/internal/authz"
	"github.com/oarlock/oarlock/internal/hub"
	"github.com/oarlock/oarlock/internal/idempotency"
	"github.com/oarlock/oarlock/internal/invite"
	"github.com/oarlock/oarlock/internal/pump"
	"github.com/oarlock/oarlock/internal/recordpolicy"
	"github.com/oarlock/oarlock/internal/sessions"
	"github.com/oarlock/oarlock/internal/sqlexplore"
	"github.com/oarlock/oarlock/internal/ticket"
	"github.com/oarlock/oarlock/pkg/condition"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
)

// Prefix is the versioned root. Changes here are additive only: a v2 would run
// beside v1, not replace it.
const Prefix = "/api/v1"

// Pagination and rate-limit headers. Documented here because SDK authors will guess
// otherwise, and three SDKs guessing differently is three bugs.
const (
	HeaderCursor        = "Oarlock-Next-Cursor" // present when there is another page
	HeaderRequestID     = "Oarlock-Request-Id"  // matches problem+json "instance"
	HeaderRateLimit     = "Oarlock-RateLimit-Limit"
	HeaderRateRemain    = "Oarlock-RateLimit-Remaining"
	HeaderRateReset     = "Oarlock-RateLimit-Reset" // seconds until the window rolls
	HeaderOnBehalfOf    = "On-Behalf-Of"
	HeaderOnBehalfToken = "On-Behalf-Of-Token"
	DefaultPageSize     = 100
	MaxPageSize         = 500
	DefaultRatePerMin   = 120
)

// Options configure the API.
type Options struct {
	Sessions      sessions.Store
	Live          *sessions.Registry
	Authenticator plugin.Authenticator
	// Authz decides whether a caller may open, watch or replay. Nil allows everything.
	Authz *authz.Checker

	// Registry and Inviter are needed for POST /sessions. Leave them nil to serve
	// only the read surface — which is what an API-only replica would want.
	Registry      plugin.DeviceRegistry
	RegistryAdmin plugin.DeviceRegistryAdmin
	Permissions   plugin.PermissionAdmin
	SSH           *SSHConnection
	Inviter       Inviter
	// Agents lists and disconnects live agent control channels on this node.
	Agents AgentControls
	// Replays serves recordings to the console. Nil disables the endpoint, which is
	// what an API replica with no access to the recording store should do rather than
	// answering 500 for every replay.
	Replays Replays
	// SQL exposes the curated read-only operational database. Nil disables it.
	SQL SQLExplorer
	// RecordInput resolves whether a session recording captures keystrokes.
	RecordInput recordpolicy.RecordInput

	// Owners answers which node holds a device, in a deployment with more than one
	// replica. Nil is a single-node gateway — and there, a ledger row that claims to be
	// live while nothing on this node is running it is stale, not remote.
	Owners SessionLocator

	// Idempotency remembers which POST /sessions requests have already been done, so a
	// client that retries a timed-out request gets its first session back instead of a
	// second one. Nil makes the Idempotency-Key header a no-op rather than an error:
	// a header a deployment cannot honour must not refuse a request it would otherwise
	// have served.
	Idempotency idempotency.Store

	// The collaborators below are needed only by the exec endpoint, which is the one
	// place this server runs a session itself rather than handing back a ticket. Leaving
	// them unset is fine for an API-only replica; `POST /devices/{id}/exec` then records
	// nothing and uses the pump's defaults.
	Recorder        plugin.Recorder
	Limits          pump.Limits
	Deadlines       pump.Deadlines
	AuthzSupervisor *authz.Supervisor
	// Audit receives API and session-control events. Nil disables audit emission.
	Audit plugin.AuditSink

	// AttachURL is the operator endpoint on **this** node. Returned to the caller so
	// the browser reaches the replica holding the device rather than whichever one a
	// load balancer picks (ADR-025).
	AttachURL string

	// RatePerMinute is the per-principal request budget. Zero means the default.
	RatePerMinute int
	// AllowUnattended permits a service principal marked Unattended to open a session
	// without a delegated human subject.
	AllowUnattended bool
	Now             func() time.Time
	Log             *slog.Logger
}

// Server serves /api/v1.
type Server struct {
	o     Options
	mux   *http.ServeMux
	rate  *limiter
	log   *slog.Logger
	nowFn func() time.Time
}

var _ http.Handler = (*Server)(nil)

// New validates the configuration and wires the routes.
func New(o Options) (*Server, error) {
	switch {
	case o.Sessions == nil:
		return nil, errors.New("apisrv: Sessions is required")
	case o.Authenticator == nil:
		return nil, errors.New("apisrv: Authenticator is required")
	}
	if o.Live == nil {
		o.Live = sessions.NewRegistry()
	}
	if o.RatePerMinute <= 0 {
		o.RatePerMinute = DefaultRatePerMin
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	s := &Server{o: o, log: o.Log, nowFn: o.Now,
		rate: newLimiter(o.RatePerMinute, o.Now)}

	// Registered from the route table, so the OpenAPI document generated from it cannot
	// describe an API this gateway does not serve. See routes.go.
	//
	// A route whose deployment did not configure what it needs is simply absent, and the
	// mux answers 404 — which is the right answer: an API replica serving renewals but
	// not opens is a deployment shape this supports on purpose, and pretending the
	// endpoint exists in order to refuse it would be a worse lie than not having it.
	s.mux = http.NewServeMux()
	for _, r := range routes() {
		if !r.available(o) {
			continue
		}
		s.mux.HandleFunc(r.Method+" "+Prefix+r.Path, s.wrap(r.handler(s)))
	}
	return s, nil
}

// SSHConnection is public connection material safe to return to authenticated operators.
type SSHConnection struct {
	Host        string
	Port        string
	HostKey     string
	KnownHosts  string
	Fingerprint string
}

type sshConnectionJSON struct {
	Host        string `json:"host"`
	Port        string `json:"port"`
	Principal   string `json:"principal"`
	HostKey     string `json:"host_key"`
	KnownHosts  string `json:"known_hosts"`
	Fingerprint string `json:"fingerprint"`
}

func (s *Server) sshConnection(w http.ResponseWriter, r *http.Request, principal *plugin.Principal) {
	s.writeJSON(w, http.StatusOK, sshConnectionJSON{
		Host: s.o.SSH.Host, Port: s.o.SSH.Port, Principal: principal.ID,
		HostKey: s.o.SSH.HostKey, KnownHosts: s.o.SSH.KnownHosts,
		Fingerprint: s.o.SSH.Fingerprint,
	})
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

// ── the error envelope ──────────────────────────────────────────────────────────

// Problem is RFC 9457 application/problem+json.
//
// Code is the machine-readable value, and it comes from the same closed set the wire
// protocol uses (docs/protocol.md § 6) so that one vocabulary covers both surfaces.
// Instance is the correlation id: it appears in the response, in the header, and in
// the gateway's logs, and it is the one string worth quoting in a bug report.
type Problem struct {
	Type      string `json:"type"`
	Title     string `json:"title"`
	Status    int    `json:"status"`
	Code      string `json:"code"`
	Detail    string `json:"detail,omitempty"`
	Instance  string `json:"instance"`
	Retryable bool   `json:"retryable"`
}

const problemBase = "https://oarlock.dev/errors/"

func (s *Server) problem(w http.ResponseWriter, r *http.Request, status int,
	code, title, detail string, retryable bool) {
	id := requestID(r)
	p := Problem{
		Type: problemBase + code, Title: title, Status: status,
		Code: code, Detail: detail, Instance: id, Retryable: retryable,
	}
	w.Header().Set(HeaderRequestID, id)
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(p)

	// Logged at the same id, so "quote the instance" actually leads somewhere.
	s.log.Warn("api error", "request", id, "code", code, "status", status,
		"detail", detail, "path", r.URL.Path)
	if s.o.Audit != nil {
		s.o.Audit.Emit(r.Context(), plugin.AuditEvent{
			Kind: plugin.AuditAPIError, Code: code, Reason: detail,
			Outcome: strconv.Itoa(status), Retryable: retryable,
			Attrs: map[string]string{"request": id, "path": r.URL.Path},
		})
	}
}

type ctxKey struct{}

func requestID(r *http.Request) string {
	return requestIDFromContext(r.Context())
}

func requestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKey{}).(string); ok {
		return v
	}
	return "req_unknown"
}

func newRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "req_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return "req_" + hex.EncodeToString(b)
}

// ── middleware ──────────────────────────────────────────────────────────────────

type handler func(w http.ResponseWriter, r *http.Request, p *plugin.Principal)

// wrap adds a correlation id, authenticates, and applies the rate limit — in that
// order, so an unauthenticated caller still gets an id to quote and a rate limit
// still applies to a caller whose token is wrong.
func (s *Server) wrap(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := newRequestID()
		r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, id))
		w.Header().Set(HeaderRequestID, id)

		// Unauthenticated callers are limited by remote address, so a token-guessing
		// loop is bounded too.
		principal, err := s.o.Authenticator.AuthHTTP(r.Context(), r)
		key := clientIP(r)
		if err == nil && principal != nil {
			key = "p:" + principal.ID
		}
		if !s.rate.allow(key, w) {
			s.problem(w, r, http.StatusTooManyRequests, "rate_limited",
				"Too many requests", "slow down and retry after the reset", true)
			return
		}
		if err != nil || principal == nil {
			if errors.Is(err, plugin.ErrUnsupported) {
				// A backend that cannot authenticate HTTP callers refuses all of
				// them, and says which of the two problems it is.
				s.problem(w, r, http.StatusNotImplemented, "auth_unsupported",
					"This gateway's authenticator cannot authenticate API callers",
					"configure oidc or a static token backend for the API", false)
				return
			}
			s.problem(w, r, http.StatusUnauthorized, "auth_failed",
				"Authentication failed", "", false)
			return
		}
		principal = s.delegatedPrincipal(w, r, principal)
		if principal == nil {
			return
		}
		h(w, r, principal)
	}
}

func (s *Server) delegatedPrincipal(w http.ResponseWriter, r *http.Request,
	service *plugin.Principal) *plugin.Principal {
	name := strings.TrimSpace(r.Header.Get(HeaderOnBehalfOf))
	assertion := strings.TrimSpace(r.Header.Get(HeaderOnBehalfToken))
	if name != "" && assertion == "" {
		s.problem(w, r, http.StatusBadRequest, "delegation_missing_assertion",
			"On-Behalf-Of is not proof",
			"send On-Behalf-Of-Token; a bare subject header is refused", false)
		return nil
	}
	if assertion == "" {
		if service.Unattended && !s.o.AllowUnattended {
			s.problem(w, r, http.StatusForbidden, "unattended_not_allowed",
				"Unattended service sessions are not enabled",
				"send a delegated human assertion, or enable api.allow_unattended", false)
			return nil
		}
		return service
	}
	subject, err := s.o.Authenticator.AuthDelegated(r.Context(), service, assertion)
	if err != nil || subject == nil {
		if errors.Is(err, plugin.ErrUnsupported) {
			s.problem(w, r, http.StatusNotImplemented, "delegation_unsupported",
				"This gateway's authenticator cannot verify delegated assertions",
				"configure an authenticator that implements AuthDelegated", false)
			return nil
		}
		s.problem(w, r, http.StatusUnauthorized, "delegation_invalid",
			"Delegated assertion was rejected", "", false)
		return nil
	}
	if subject.ID == "" {
		s.problem(w, r, http.StatusUnauthorized, "delegation_invalid",
			"Delegated assertion was rejected", "the assertion did not name a subject", false)
		return nil
	}
	if name != "" && name != subject.ID {
		s.problem(w, r, http.StatusBadRequest, "delegation_subject_mismatch",
			"On-Behalf-Of does not match the assertion",
			"the header is only for logs; the token is authoritative", false)
		return nil
	}
	out := *subject
	out.OpenedBy = service.ID
	out.Unattended = false
	return &out
}

// clientIP is the rate-limit key for a caller who has not authenticated.
//
// net.SplitHostPort, not a cut at the first colon: RemoteAddr for an IPv6 peer is
// `[2001:db8::1]:51234`, and cutting at the first colon yields `[2001` — one bucket
// shared by a whole hextet, and `[` for anything in `::/16`. A shared bucket is not a
// tighter limit, it is a lever: one caller exhausts the window for every stranger who
// happens to share the prefix, on the surface where the limit exists to bound token
// guessing.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// Not host:port at all. Key on the whole string rather than a prefix of it:
		// over-specific costs an attacker one bucket, over-broad costs bystanders
		// theirs.
		return "ip:" + r.RemoteAddr
	}
	return "ip:" + host
}

// Replays is the part of the recorder this package needs.
//
// Verdict is separate from Cast because the two answer different questions and only one of
// them can be computed in a browser: verification needs the manifest and a public key the
// *deployment* trusts, so it happens here and travels with the recording. A console that
// verified for itself would be a console that could be lied to.
type Replays interface {
	Cast(ctx context.Context, sessionID string) ([]byte, error)
	Verdict(ctx context.Context, sessionID string) (ReplayVerdict, error)
	// Manifest returns the stored manifest bytes, for a caller who will verify the
	// recording themselves.
	//
	// The bytes rather than a struct, so this gateway is not a decode/encode hop in the
	// middle. The signature is over a canonical form recomputed from the struct, so a
	// round trip is safe *in a build that knows every field* — and a build that does not
	// would drop one, change the canonical form, and make a good recording unverifiable.
	// Not a risk worth taking on the path whose whole purpose is verification.
	Manifest(ctx context.Context, sessionID string) ([]byte, error)
}

// ReplayVerdict is what the verifier said, in the shape the browser renders.
type ReplayVerdict struct {
	Status             string `json:"status"`
	OK                 bool   `json:"ok"`
	EventsFound        int    `json:"events_found"`
	EventsExpected     int    `json:"events_expected"`
	LastGoodCheckpoint int    `json:"last_good_checkpoint"`
	Detail             string `json:"detail,omitempty"`
}

// Inviter is the part of internal/invite this package needs.
type Inviter interface {
	Invite(ctx context.Context, dev *plugin.Device, req invite.Request) (*invite.Pending, error)
	MintAttach(ctx context.Context, c ticket.Claims, ttl time.Duration) (string, time.Time, error)
	MintObserve(ctx context.Context, c ticket.Claims, ttl time.Duration) (string, time.Time, error)
	Cancel(ctx context.Context, sessionID, reason string)
}

// SessionLocator answers which *other* node holds a device, or "" for nobody this node
// knows of. Satisfied by *ownership.Keeper; declared here so this package does not have
// to import it to ask one question.
type SessionLocator interface {
	Elsewhere(ctx context.Context, deviceID string) string
}

// AgentControls is the administrative surface for live control channels.
type AgentControls interface {
	Devices() []string
	Disconnect(ctx context.Context, deviceID, reason string) error
}

// SQLExplorer is the bounded SQL surface used by the admin console.
type SQLExplorer interface {
	Schema(context.Context) ([]sqlexplore.Table, error)
	Query(context.Context, string, int) (sqlexplore.Result, error)
}

// gatewayDevice stands in for the gateway itself, for the actions that are about the
// gateway rather than about a device: reading the operational database, and reading or
// writing the policy. It is a real device id in a grant — `devices: ["gateway"]` — so
// these actions are written the same way as every other one.
var gatewayDevice = &plugin.Device{ID: "gateway", Platform: plugin.PlatformOther}

// authorizeAdmin gates one administrative request, and audits the refusal.
//
// Every administrative handler goes through here. That is the point: the hole this closes
// was not a missing check in one place, it was a whole surface where the principal was
// accepted at the door and then thrown away, so that a token which could be refused
// `sql:read` could grant itself `sql:read`.
func (s *Server) authorizeAdmin(w http.ResponseWriter, r *http.Request, p *plugin.Principal,
	dev *plugin.Device, act plugin.Action) bool {
	// Administrative actions name no target: they are about the gateway's own
	// configuration, not about a port, a path or an argv on a device.
	v := s.o.Authz.AtOpen(r.Context(), p, dev, act, plugin.Target{})
	if v.Allow() {
		return true
	}
	s.auditAdmin(r.Context(), p, dev.ID, act, "denied", v.Code)
	s.refuseByAuthz(w, r, v)
	return false
}

// adminDevice is the device an administrative request is checked against.
//
// The existing registry record, when there is one, because its tags are what a tag-scoped
// grant or deny is written against — and the submitted body is the caller's to choose. On
// create there is nothing to look up yet, so the submitted record is all there is; a
// caller who may create devices can therefore create one whose tags a deny rule would
// have matched. Scope `admin:devices` accordingly.
func (s *Server) adminDevice(ctx context.Context, id string, fallback *plugin.Device) *plugin.Device {
	if s.o.Registry != nil && id != "" {
		if d, err := s.o.Registry.Get(ctx, id); err == nil {
			return d
		}
	}
	if fallback != nil {
		return fallback
	}
	return &plugin.Device{ID: id}
}

// auditPermission records what a policy change actually granted.
//
// The id alone is not an audit trail: "perm_9f2c created" tells a reviewer nothing, and
// the row it names may since have been edited or deleted. What the change said at the
// moment it was made is the thing worth keeping.
func (s *Server) auditPermission(ctx context.Context, p *plugin.Principal,
	permission *plugin.Permission, outcome string) {
	if s.o.Audit == nil {
		return
	}
	effect := "allow"
	if permission.Deny {
		effect = "deny"
	}
	s.o.Audit.Emit(ctx, plugin.AuditEvent{
		Kind: plugin.AuditAdminChange, DeviceID: gatewayDevice.ID, Principal: p.ID,
		Surface: "api", Action: string(plugin.ActionAdminPermissions), Outcome: outcome,
		Attrs: map[string]string{
			"request":    requestIDFromContext(ctx),
			"permission": permission.ID,
			"effect":     effect,
			"grants":     strings.Join(permission.Actions, ","),
			"principals": strings.Join(permission.Principals, ","),
			"devices":    strings.Join(permission.Devices, ","),
			"enabled":    strconv.FormatBool(permission.Enabled),
		},
	})
}

func (s *Server) auditAdmin(ctx context.Context, p *plugin.Principal, deviceID string,
	act plugin.Action, outcome, code string) {
	if s.o.Audit == nil {
		return
	}
	s.o.Audit.Emit(ctx, plugin.AuditEvent{
		Kind: plugin.AuditAdminChange, DeviceID: deviceID, Principal: p.ID,
		Surface: "api", Action: string(act), Outcome: outcome, Code: code,
		Attrs: map[string]string{"request": requestIDFromContext(ctx)},
	})
}

func (s *Server) sqlSchema(w http.ResponseWriter, r *http.Request, p *plugin.Principal) {
	if v := s.o.Authz.AtOpen(r.Context(), p, gatewayDevice, plugin.ActionSQLRead, plugin.Target{}); !v.Allow() {
		s.refuseByAuthz(w, r, v)
		return
	}
	tables, err := s.o.SQL.Schema(r.Context())
	if err != nil {
		s.problem(w, r, http.StatusInternalServerError, "internal",
			"Could not inspect the operational database", err.Error(), true)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"tables": tables})
}

type sqlQueryRequest struct {
	Query string `json:"query"`
	Limit int    `json:"limit,omitempty"`
}

func (s *Server) sqlQuery(w http.ResponseWriter, r *http.Request, p *plugin.Principal) {
	if v := s.o.Authz.AtOpen(r.Context(), p, gatewayDevice, plugin.ActionSQLRead, plugin.Target{}); !v.Allow() {
		s.auditSQL(r.Context(), p, "denied", "", 0, false)
		s.refuseByAuthz(w, r, v)
		return
	}
	var request sqlQueryRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, sqlexplore.MaxQuerySize+1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		s.auditSQL(r.Context(), p, "invalid", "", 0, false)
		s.problem(w, r, http.StatusBadRequest, "invalid_argument",
			"The SQL request is invalid", err.Error(), false)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	result, err := s.o.SQL.Query(ctx, request.Query, request.Limit)
	if err != nil {
		outcome := "error"
		status, code, title := http.StatusBadRequest, "invalid_argument", "The query is not allowed"
		if errors.Is(err, context.DeadlineExceeded) {
			outcome, status, code, title = "timeout", http.StatusGatewayTimeout, "query_timeout", "The query took too long"
		} else if !errors.Is(err, sqlexplore.ErrInvalidQuery) {
			outcome, status, code, title = "error", http.StatusInternalServerError, "internal", "The query could not run"
		}
		s.auditSQL(r.Context(), p, outcome, request.Query, 0, false)
		s.problem(w, r, status, code, title, err.Error(), status >= 500)
		return
	}
	s.auditSQL(r.Context(), p, "ok", request.Query, len(result.Rows), result.Truncated)
	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) auditSQL(ctx context.Context, p *plugin.Principal, outcome, query string, rows int, truncated bool) {
	if s.o.Audit == nil {
		return
	}
	digest := ""
	if query != "" {
		digest = fmt.Sprintf("%x", sha256.Sum256([]byte(query)))
	}
	s.o.Audit.Emit(ctx, plugin.AuditEvent{
		Kind: plugin.AuditSQLQuery, DeviceID: gatewayDevice.ID, Principal: p.ID,
		Surface: "api", Action: string(plugin.ActionSQLRead), Outcome: outcome,
		Attrs: map[string]string{
			"request": requestIDFromContext(ctx), "query_sha256": digest,
			"rows": strconv.Itoa(rows), "truncated": strconv.FormatBool(truncated),
		},
	})
}

// ── handlers ────────────────────────────────────────────────────────────────────

type agentJSON struct {
	DeviceID  string `json:"device_id"`
	Connected bool   `json:"connected"`
}

type agentsResponse struct {
	Agents []agentJSON `json:"agents"`
}

type deviceJSON struct {
	ID               string            `json:"id"`
	Platform         string            `json:"platform"`
	Enabled          *bool             `json:"enabled,omitempty"`
	Mode             string            `json:"mode,omitempty"`
	ResolvedMode     string            `json:"resolved_mode"`
	Keys             []string          `json:"keys,omitempty"`
	RetiredKeys      []string          `json:"retired_keys,omitempty"`
	AllowPassthrough bool              `json:"allow_passthrough,omitempty"`
	Tags             map[string]string `json:"tags,omitempty"`
	Profiles         []string          `json:"profiles,omitempty"`
	Connected        bool              `json:"connected"`
}

type devicesResponse struct {
	Devices    []deviceJSON `json:"devices"`
	NextCursor string       `json:"next_cursor,omitempty"`
}

func (s *Server) renderDevice(d *plugin.Device) deviceJSON {
	enabled := !d.Disabled
	out := deviceJSON{
		ID: d.ID, Platform: string(d.Platform), Mode: string(d.Mode),
		Enabled:      &enabled,
		ResolvedMode: string(d.ResolvedMode()), AllowPassthrough: d.AllowPassthrough,
		Tags: d.Tags, Profiles: d.Profiles,
	}
	for _, k := range d.Keys {
		out.Keys = append(out.Keys, plugin.EncodeDeviceKey(k))
	}
	for _, k := range d.RetiredKeys {
		out.RetiredKeys = append(out.RetiredKeys, plugin.EncodeDeviceKey(k))
	}
	if s.o.Agents != nil {
		for _, id := range s.o.Agents.Devices() {
			if id == d.ID {
				out.Connected = true
				break
			}
		}
	}
	return out
}

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request, _ *plugin.Principal) {
	q := plugin.DeviceQuery{
		After:    r.URL.Query().Get("cursor"),
		Platform: plugin.Platform(r.URL.Query().Get("platform")),
		Mode:     plugin.Mode(r.URL.Query().Get("mode")),
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			s.problem(w, r, http.StatusBadRequest, "invalid_argument",
				"limit must be a positive integer", "got "+v, false)
			return
		}
		if n > MaxPageSize {
			n = MaxPageSize
		}
		q.Limit = n
	}
	devs, next, err := s.o.Registry.List(r.Context(), q)
	if err != nil {
		s.problem(w, r, http.StatusInternalServerError, "internal",
			"Could not list devices", err.Error(), true)
		return
	}
	out := devicesResponse{Devices: make([]deviceJSON, 0, len(devs)), NextCursor: next}
	for _, d := range devs {
		out.Devices = append(out.Devices, s.renderDevice(d))
	}
	if next != "" {
		w.Header().Set(HeaderCursor, next)
	}
	s.writeJSON(w, http.StatusOK, out)
}

func (s *Server) getDevice(w http.ResponseWriter, r *http.Request, _ *plugin.Principal) {
	d, err := s.o.Registry.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, plugin.ErrNoDevice) {
			s.problem(w, r, http.StatusNotFound, "not_found", "No such device", "", false)
			return
		}
		s.problem(w, r, http.StatusInternalServerError, "internal",
			"Could not read device", err.Error(), true)
		return
	}
	s.writeJSON(w, http.StatusOK, s.renderDevice(d))
}

func (s *Server) createDevice(w http.ResponseWriter, r *http.Request, p *plugin.Principal) {
	d, err := decodeDevice(r)
	if err != nil {
		s.problem(w, r, http.StatusBadRequest, "invalid_argument", "Invalid device", err.Error(), false)
		return
	}
	if !s.authorizeAdmin(w, r, p, d, plugin.ActionAdminDevices) {
		return
	}
	if err := s.o.RegistryAdmin.Create(r.Context(), d); err != nil {
		if errors.Is(err, plugin.ErrDeviceExists) {
			s.problem(w, r, http.StatusConflict, "already_exists", "Device already exists", err.Error(), false)
			return
		}
		s.problem(w, r, http.StatusBadRequest, "invalid_argument", "Invalid device", err.Error(), false)
		return
	}
	s.auditAdmin(r.Context(), p, d.ID, plugin.ActionAdminDevices, "created", "")
	s.writeJSON(w, http.StatusCreated, s.renderDevice(d))
}

func (s *Server) updateDevice(w http.ResponseWriter, r *http.Request, p *plugin.Principal) {
	d, err := decodeDevice(r)
	if err != nil {
		s.problem(w, r, http.StatusBadRequest, "invalid_argument", "Invalid device", err.Error(), false)
		return
	}
	if d.ID == "" {
		d.ID = r.PathValue("id")
	}
	if d.ID != r.PathValue("id") {
		s.problem(w, r, http.StatusBadRequest, "invalid_argument",
			"Device id mismatch", "path id and body id differ", false)
		return
	}
	if !s.authorizeAdmin(w, r, p, s.adminDevice(r.Context(), d.ID, d), plugin.ActionAdminDevices) {
		return
	}
	if err := s.o.RegistryAdmin.Update(r.Context(), d); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, plugin.ErrNoDevice) {
			status = http.StatusNotFound
		}
		s.problem(w, r, status, "invalid_argument", "Could not update device", err.Error(), false)
		return
	}
	if d.Disabled && s.o.Agents != nil {
		_ = s.o.Agents.Disconnect(r.Context(), d.ID, "admin_stop")
	}
	s.auditAdmin(r.Context(), p, d.ID, plugin.ActionAdminDevices, "updated", "")
	s.writeJSON(w, http.StatusOK, s.renderDevice(d))
}

func (s *Server) deleteDevice(w http.ResponseWriter, r *http.Request, p *plugin.Principal) {
	id := r.PathValue("id")
	if !s.authorizeAdmin(w, r, p, s.adminDevice(r.Context(), id, nil), plugin.ActionAdminDevices) {
		return
	}
	if err := s.o.RegistryAdmin.Delete(r.Context(), id); err != nil {
		if errors.Is(err, plugin.ErrNoDevice) {
			s.problem(w, r, http.StatusNotFound, "not_found", "No such device", "", false)
			return
		}
		s.problem(w, r, http.StatusInternalServerError, "internal",
			"Could not delete device", err.Error(), true)
		return
	}
	s.auditAdmin(r.Context(), p, id, plugin.ActionAdminDevices, "deleted", "")
	s.writeJSON(w, http.StatusOK, map[string]any{"id": id, "deleted": true})
}

func decodeDevice(r *http.Request) (*plugin.Device, error) {
	var in deviceJSON
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		return nil, err
	}
	d := &plugin.Device{
		ID: in.ID, Platform: plugin.Platform(in.Platform), Mode: plugin.Mode(in.Mode),
		AllowPassthrough: in.AllowPassthrough, Tags: in.Tags, Profiles: in.Profiles,
	}
	if in.Enabled != nil {
		d.Disabled = !*in.Enabled
	}
	for i, k := range in.Keys {
		pub, err := plugin.ParseDeviceKey(k)
		if err != nil {
			return nil, fmt.Errorf("keys[%d]: %w", i, err)
		}
		d.Keys = append(d.Keys, pub)
	}
	for i, k := range in.RetiredKeys {
		pub, err := plugin.ParseDeviceKey(k)
		if err != nil {
			return nil, fmt.Errorf("retired_keys[%d]: %w", i, err)
		}
		d.RetiredKeys = append(d.RetiredKeys, pub)
	}
	return d, nil
}

type permissionJSON struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Principals  []string          `json:"principals"`
	Devices     []string          `json:"devices"`
	Tags        map[string]string `json:"tags"`
	Actions     []string          `json:"actions"`
	Effect      string            `json:"effect"`
	Reason      string            `json:"reason"`
	Priority    int               `json:"priority"`
	Enabled     bool              `json:"enabled"`
	MaxDuration string            `json:"max_duration,omitempty"`
	Idle        string            `json:"idle,omitempty"`
	TTL         string            `json:"ttl,omitempty"`
	CreatedAt   string            `json:"created_at,omitempty"`
	UpdatedAt   string            `json:"updated_at,omitempty"`
}

type permissionInput struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Principals  []string          `json:"principals"`
	Devices     []string          `json:"devices"`
	Tags        map[string]string `json:"tags"`
	Actions     []string          `json:"actions"`
	Effect      string            `json:"effect"`
	Reason      string            `json:"reason"`
	Priority    int               `json:"priority"`
	Enabled     *bool             `json:"enabled"`
	MaxDuration string            `json:"max_duration"`
	Idle        string            `json:"idle"`
	TTL         string            `json:"ttl"`
}

func renderPermission(permission *plugin.Permission) permissionJSON {
	effect := "allow"
	if permission.Deny {
		effect = "deny"
	}
	out := permissionJSON{
		ID: permission.ID, Name: permission.Name,
		Principals: append([]string{}, permission.Principals...),
		Devices:    append([]string{}, permission.Devices...),
		Tags:       permission.Tags, Actions: append([]string{}, permission.Actions...),
		Effect: effect, Reason: permission.Reason, Priority: permission.Priority,
		Enabled: permission.Enabled,
	}
	if out.Tags == nil {
		out.Tags = map[string]string{}
	}
	if permission.MaxDuration > 0 {
		out.MaxDuration = permission.MaxDuration.String()
	}
	if permission.Idle > 0 {
		out.Idle = permission.Idle.String()
	}
	if permission.TTL > 0 {
		out.TTL = permission.TTL.String()
	}
	if !permission.CreatedAt.IsZero() {
		out.CreatedAt = permission.CreatedAt.UTC().Format(time.RFC3339Nano)
	}
	if !permission.UpdatedAt.IsZero() {
		out.UpdatedAt = permission.UpdatedAt.UTC().Format(time.RFC3339Nano)
	}
	return out
}

func decodePermission(r *http.Request) (*plugin.Permission, error) {
	var input permissionInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		return nil, err
	}
	enabled := true
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	permission := &plugin.Permission{
		ID: input.ID, Name: input.Name, Principals: input.Principals, Devices: input.Devices,
		Tags: input.Tags, Actions: input.Actions, Deny: input.Effect == "deny",
		Reason: input.Reason, Priority: input.Priority, Enabled: enabled,
	}
	if input.Effect != "" && input.Effect != "allow" && input.Effect != "deny" {
		return nil, errors.New(`effect must be "allow" or "deny"`)
	}
	for name, value := range map[string]string{
		"max_duration": input.MaxDuration, "idle": input.Idle, "ttl": input.TTL,
	} {
		if strings.TrimSpace(value) == "" {
			continue
		}
		duration, err := time.ParseDuration(value)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		switch name {
		case "max_duration":
			permission.MaxDuration = duration
		case "idle":
			permission.Idle = duration
		case "ttl":
			permission.TTL = duration
		}
	}
	return permission, nil
}

func newPermissionID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "perm_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return "perm_" + hex.EncodeToString(b)
}

func (s *Server) listPermissions(w http.ResponseWriter, r *http.Request, p *plugin.Principal) {
	if !s.authorizeAdmin(w, r, p, gatewayDevice, plugin.ActionAdminPermissions) {
		return
	}
	permissions, err := s.o.Permissions.ListPermissions(r.Context())
	if err != nil {
		s.problem(w, r, http.StatusInternalServerError, "internal", "Could not list permissions", err.Error(), true)
		return
	}
	out := make([]permissionJSON, 0, len(permissions))
	for _, permission := range permissions {
		out = append(out, renderPermission(permission))
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"permissions": out})
}

func (s *Server) getPermission(w http.ResponseWriter, r *http.Request, p *plugin.Principal) {
	if !s.authorizeAdmin(w, r, p, gatewayDevice, plugin.ActionAdminPermissions) {
		return
	}
	permission, err := s.o.Permissions.GetPermission(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, plugin.ErrNoPermission) {
			s.problem(w, r, http.StatusNotFound, "not_found", "No such permission", "", false)
			return
		}
		s.problem(w, r, http.StatusInternalServerError, "internal", "Could not read permission", err.Error(), true)
		return
	}
	s.writeJSON(w, http.StatusOK, renderPermission(permission))
}

func (s *Server) createPermission(w http.ResponseWriter, r *http.Request, p *plugin.Principal) {
	if !s.authorizeAdmin(w, r, p, gatewayDevice, plugin.ActionAdminPermissions) {
		return
	}
	permission, err := decodePermission(r)
	if err != nil {
		s.problem(w, r, http.StatusBadRequest, "invalid_argument", "Invalid permission", err.Error(), false)
		return
	}
	if permission.ID == "" {
		permission.ID = newPermissionID()
	}
	if err := s.o.Permissions.CreatePermission(r.Context(), permission); err != nil {
		if errors.Is(err, plugin.ErrPermissionExists) {
			s.problem(w, r, http.StatusConflict, "already_exists", "Permission already exists", err.Error(), false)
			return
		}
		s.problem(w, r, http.StatusBadRequest, "invalid_argument", "Invalid permission", err.Error(), false)
		return
	}
	s.auditPermission(r.Context(), p, permission, "created")
	s.writeJSON(w, http.StatusCreated, renderPermission(permission))
}

func (s *Server) updatePermission(w http.ResponseWriter, r *http.Request, p *plugin.Principal) {
	if !s.authorizeAdmin(w, r, p, gatewayDevice, plugin.ActionAdminPermissions) {
		return
	}
	permission, err := decodePermission(r)
	if err != nil {
		s.problem(w, r, http.StatusBadRequest, "invalid_argument", "Invalid permission", err.Error(), false)
		return
	}
	if permission.ID == "" {
		permission.ID = r.PathValue("id")
	}
	if permission.ID != r.PathValue("id") {
		s.problem(w, r, http.StatusBadRequest, "invalid_argument", "Permission id mismatch", "path id and body id differ", false)
		return
	}
	if err := s.o.Permissions.UpdatePermission(r.Context(), permission); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, plugin.ErrNoPermission) {
			status = http.StatusNotFound
		}
		s.problem(w, r, status, "invalid_argument", "Could not update permission", err.Error(), false)
		return
	}
	s.auditPermission(r.Context(), p, permission, "updated")
	s.writeJSON(w, http.StatusOK, renderPermission(permission))
}

func (s *Server) deletePermission(w http.ResponseWriter, r *http.Request, p *plugin.Principal) {
	if !s.authorizeAdmin(w, r, p, gatewayDevice, plugin.ActionAdminPermissions) {
		return
	}
	id := r.PathValue("id")
	if err := s.o.Permissions.DeletePermission(r.Context(), id); err != nil {
		if errors.Is(err, plugin.ErrNoPermission) {
			s.problem(w, r, http.StatusNotFound, "not_found", "No such permission", "", false)
			return
		}
		s.problem(w, r, http.StatusInternalServerError, "internal", "Could not delete permission", err.Error(), true)
		return
	}
	s.auditAdmin(r.Context(), p, gatewayDevice.ID, plugin.ActionAdminPermissions, "deleted",
		"")
	s.writeJSON(w, http.StatusOK, map[string]any{"id": id, "deleted": true})
}

// deviceAccess answers "who can reach this device", which is the question the fleet view
// asks and a flat rule list cannot.
//
// Evaluated on the server with plugin.Permission's own matcher, not in the browser: a
// second implementation of glob-and-tag matching one network hop from the real one would
// drift, and a console that says somebody cannot reach a device they can is worse than no
// console. Deny rules come first because they outrank every allow, and a list ordered by
// anything else reads top-to-bottom like a precedence order it does not have.
func (s *Server) deviceAccess(w http.ResponseWriter, r *http.Request, p *plugin.Principal) {
	if !s.authorizeAdmin(w, r, p, gatewayDevice, plugin.ActionAdminPermissions) {
		return
	}
	dev, err := s.o.Registry.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, plugin.ErrNoDevice) {
			s.problem(w, r, http.StatusNotFound, "device_unknown", "No such device", "", false)
			return
		}
		s.problem(w, r, http.StatusInternalServerError, "internal",
			"Could not read device", err.Error(), true)
		return
	}
	permissions, err := s.o.Permissions.ListPermissions(r.Context())
	if err != nil {
		s.problem(w, r, http.StatusInternalServerError, "internal",
			"Could not read the policy", err.Error(), true)
		return
	}
	denies := make([]permissionJSON, 0, 4)
	allows := make([]permissionJSON, 0, len(permissions))
	for _, permission := range permissions {
		if !permission.AppliesTo(dev) {
			continue
		}
		if permission.Deny {
			denies = append(denies, renderPermission(permission))
			continue
		}
		allows = append(allows, renderPermission(permission))
	}
	// The administrative vocabulary travels with the answer. A reader has to separate
	// "can open a shell on this" from "can change this device's record" — they are very
	// different sentences about a person — and the alternative is the console keeping its
	// own copy of which actions are which, which is the same drift this endpoint exists
	// to avoid.
	admin := make([]string, 0, 3)
	for _, action := range plugin.AdministrativeActions() {
		admin = append(admin, string(action))
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"device_id":     dev.ID,
		"rules":         append(denies, allows...),
		"admin_actions": admin,
	})
}

// principalAccess answers "were they allowed to", the Person page's second question,
// once "what did this person do" has already been answered from the audit log.
//
// Evaluated on the server with plugin.Permission's own matcher, not in the browser: a
// second implementation of glob matching one network hop from the real one would drift,
// and a console that tells an auditor somebody was allowed something the gateway would
// have refused is worse than no console. There is no registry lookup here, unlike
// deviceAccess: a principal is a string an authenticator issued, not a row to fetch.
func (s *Server) principalAccess(w http.ResponseWriter, r *http.Request, p *plugin.Principal) {
	if !s.authorizeAdmin(w, r, p, gatewayDevice, plugin.ActionAdminPermissions) {
		return
	}
	id := r.PathValue("id")
	permissions, err := s.o.Permissions.ListPermissions(r.Context())
	if err != nil {
		s.problem(w, r, http.StatusInternalServerError, "internal",
			"Could not read the policy", err.Error(), true)
		return
	}
	denies := make([]permissionJSON, 0, 4)
	allows := make([]permissionJSON, 0, len(permissions))
	for _, permission := range permissions {
		if !permission.MatchesPrincipal(id) {
			continue
		}
		if permission.Deny {
			denies = append(denies, renderPermission(permission))
			continue
		}
		allows = append(allows, renderPermission(permission))
	}
	// The administrative vocabulary travels with the answer. A reader has to separate
	// "can open a shell on this" from "can change this record" — they are very different
	// sentences about a person — and the alternative is the console keeping its own copy
	// of which actions are which, which is the same drift this endpoint exists to avoid.
	admin := make([]string, 0, 3)
	for _, action := range plugin.AdministrativeActions() {
		admin = append(admin, string(action))
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"principal":     id,
		"rules":         append(denies, allows...),
		"admin_actions": admin,
	})
}

func (s *Server) listAgents(w http.ResponseWriter, r *http.Request, _ *plugin.Principal) {
	devices := s.o.Agents.Devices()
	sort.Strings(devices)
	out := agentsResponse{Agents: make([]agentJSON, 0, len(devices))}
	for _, id := range devices {
		out.Agents = append(out.Agents, agentJSON{DeviceID: id, Connected: true})
	}
	s.writeJSON(w, http.StatusOK, out)
}

func (s *Server) disconnectAgent(w http.ResponseWriter, r *http.Request, p *plugin.Principal) {
	id := r.PathValue("id")
	if !s.authorizeAdmin(w, r, p, s.adminDevice(r.Context(), id, nil), plugin.ActionAdminKill) {
		return
	}
	if err := s.o.Agents.Disconnect(r.Context(), id, "admin_stop"); err != nil {
		if errors.Is(err, hub.ErrNotConnected) {
			s.problem(w, r, http.StatusNotFound, "not_found", "No connected agent",
				"there is no live control channel for "+id+" on this node", false)
			return
		}
		s.problem(w, r, http.StatusInternalServerError, "internal",
			"Could not disconnect the agent", err.Error(), true)
		return
	}
	s.log.Info("agent disconnected by an administrator", "device", id, "by", p.ID,
		"request", requestID(r))
	s.auditAdmin(r.Context(), p, id, plugin.ActionAdminKill, "disconnected", "")
	s.writeJSON(w, http.StatusOK, map[string]any{
		"device_id": id, "disconnected": true,
	})
}

type sessionJSON struct {
	ID             string  `json:"id"`
	DeviceID       string  `json:"device_id"`
	Profile        string  `json:"profile"`
	Mode           string  `json:"mode"`
	Principal      string  `json:"principal"`
	OpenedBy       string  `json:"opened_by,omitempty"`
	Unattended     bool    `json:"unattended,omitempty"`
	Reason         string  `json:"reason,omitempty"`
	State          string  `json:"state"`
	RecordingState string  `json:"recording_state"`
	CloseReason    string  `json:"close_reason,omitempty"`
	ExitCode       *int    `json:"exit_code"`
	BytesIn        int64   `json:"bytes_in"`
	BytesOut       int64   `json:"bytes_out"`
	BytesDropped   int64   `json:"bytes_dropped"`
	CreatedAt      string  `json:"created_at"`
	AttachedAt     *string `json:"attached_at"`
	ClosedAt       *string `json:"closed_at"`
	Live           bool    `json:"live"`
	// LiveHere says the session is running on *this* node. A session can be live in
	// the ledger and not here, which is what multi-node looks like.
	LiveHere bool `json:"live_here"`
}

func (s *Server) render(row *sessions.Session) sessionJSON {
	out := sessionJSON{
		ID: row.ID, DeviceID: row.DeviceID, Profile: row.Profile, Mode: row.Mode,
		Principal: row.Principal, OpenedBy: row.OpenedBy, Unattended: row.Unattended,
		Reason: row.Reason, State: string(row.State),
		RecordingState: string(row.RecordingState), CloseReason: row.CloseReason,
		ExitCode: row.ExitCode, BytesIn: row.BytesIn, BytesOut: row.BytesOut,
		BytesDropped: row.BytesDropped,
		CreatedAt:    row.CreatedAt.UTC().Format(time.RFC3339Nano),
		Live:         row.Live(),
	}
	if !row.AttachedAt.IsZero() {
		v := row.AttachedAt.UTC().Format(time.RFC3339Nano)
		out.AttachedAt = &v
	}
	if !row.ClosedAt.IsZero() {
		v := row.ClosedAt.UTC().Format(time.RFC3339Nano)
		out.ClosedAt = &v
	}
	if _, err := s.o.Live.Get(row.ID); err == nil {
		out.LiveHere = true
	}
	return out
}

type listResponse struct {
	Sessions []sessionJSON `json:"sessions"`
	// NextCursor is empty on the last page. Also in the Oarlock-Next-Cursor header,
	// so a caller can paginate without parsing the body.
	NextCursor string `json:"next_cursor,omitempty"`
}

func (s *Server) listSessions(w http.ResponseWriter, r *http.Request, _ *plugin.Principal) {
	q := sessions.Query{
		DeviceID:  r.URL.Query().Get("device_id"),
		Principal: r.URL.Query().Get("principal"),
		State:     sessions.State(r.URL.Query().Get("state")),
		After:     r.URL.Query().Get("cursor"),
	}
	if r.URL.Query().Get("live") == "true" {
		q.Live = true
	}
	// Oldest-first is the right default for a forward cursor (see sessions.Query.Newest);
	// a caller auditing "what happened" asks for the reverse explicitly.
	if r.URL.Query().Get("newest") == "true" {
		q.Newest = true
	}
	if v := r.URL.Query().Get("unattended"); v != "" {
		switch v {
		case "true":
			b := true
			q.Unattended = &b
		case "false":
			b := false
			q.Unattended = &b
		default:
			s.problem(w, r, http.StatusBadRequest, "invalid_argument",
				"unattended must be true or false", "got "+v, false)
			return
		}
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			s.problem(w, r, http.StatusBadRequest, "invalid_argument",
				"limit must be a positive integer", "got "+v, false)
			return
		}
		if n > MaxPageSize {
			// Clamped rather than refused: a caller asking for more than we will
			// give should get a page, not a lecture. The cursor tells them there is
			// more.
			n = MaxPageSize
		}
		q.Limit = n
	}
	if v := r.URL.Query().Get("since"); v != "" {
		since, err := time.Parse(time.RFC3339, v)
		if err != nil {
			s.problem(w, r, http.StatusBadRequest, "invalid_argument",
				"since must be RFC 3339", "got "+v, false)
			return
		}
		q.Since = since
	}
	if v := r.URL.Query().Get("until"); v != "" {
		until, err := time.Parse(time.RFC3339, v)
		if err != nil {
			s.problem(w, r, http.StatusBadRequest, "invalid_argument",
				"until must be RFC 3339", "got "+v, false)
			return
		}
		q.Until = until
	}

	rows, next, err := s.o.Sessions.List(r.Context(), q)
	if err != nil {
		s.problem(w, r, http.StatusInternalServerError, "internal",
			"Could not list sessions", err.Error(), true)
		return
	}
	out := listResponse{Sessions: make([]sessionJSON, 0, len(rows)), NextCursor: next}
	for _, row := range rows {
		out.Sessions = append(out.Sessions, s.render(row))
	}
	if next != "" {
		w.Header().Set(HeaderCursor, next)
	}
	s.writeJSON(w, http.StatusOK, out)
}

func (s *Server) getSession(w http.ResponseWriter, r *http.Request, _ *plugin.Principal) {
	wait, ok := s.parseWait(w, r)
	if !ok {
		return
	}
	row, err := s.o.Sessions.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, sessions.ErrNotFound) {
			s.problem(w, r, http.StatusNotFound, "not_found", "No such session", "", false)
			return
		}
		s.problem(w, r, http.StatusInternalServerError, "internal",
			"Could not read the session", err.Error(), true)
		return
	}
	// A session opens asynchronously — waking while the doorbell rings, opening while
	// the agent dials — so the interesting answer is usually the *next* one. `?wait=`
	// holds the request for it instead of making the caller ask again every 200 ms.
	row = s.awaitChange(r.Context(), row, wait)
	s.writeJSON(w, http.StatusOK, s.render(row))
}

// killSession ends a live session (FR19).
//
// It is idempotent by design: DELETE on an already-closed session succeeds, because
// the caller's intent — "this session must not be running" — is satisfied. Returning
// an error there would make a retry after a timeout look like a failure.
func (s *Server) killSession(w http.ResponseWriter, r *http.Request, p *plugin.Principal) {
	id := r.PathValue("id")
	row, err := s.o.Sessions.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, sessions.ErrNotFound) {
			s.problem(w, r, http.StatusNotFound, "not_found", "No such session", "", false)
			return
		}
		s.problem(w, r, http.StatusInternalServerError, "internal",
			"Could not read the session", err.Error(), true)
		return
	}

	// Ending your own session is not administration. Anything else is: closing somebody
	// else's shell is an intervention in their work, and it needs the grant that says so.
	if row.Principal != p.ID {
		if !s.authorizeAdmin(w, r, p, s.adminDevice(r.Context(), row.DeviceID, nil),
			plugin.ActionAdminKill) {
			return
		}
	}

	state := row.State
	if row.Live() {
		if err := s.o.Live.Kill(r.Context(), id, "admin_kill"); err != nil {
			// Live in the ledger, not running here. That used to be reported as
			// `wrong_node` unconditionally, on the assumption that another replica must
			// have it — and on a single-node gateway that assumption is a lie the
			// caller can never get past. A row left live by a session nobody collected,
			// or by a node that died, would then hold its device's only slot until the
			// gateway restarted: `POST /sessions` answered `session_limit` and `DELETE`
			// answered `wrong_node`, forever.
			if node := s.heldElsewhere(r.Context(), row.DeviceID); node != "" {
				s.problem(w, r, http.StatusConflict, "wrong_node",
					"That session is live on another gateway node",
					"retry against the node holding it, or wait for the ledger to catch up",
					true)
				return
			}
			// Nothing is running it, here or anywhere this gateway can see. The row is
			// stale, and the caller's intent — "this session must not be running" — is
			// already true of the world and merely absent from the ledger. Make the
			// ledger agree rather than refusing forever.
			if err := s.o.Sessions.Finish(r.Context(), id,
				sessions.Result{CloseReason: "admin_kill"}); err != nil {
				s.problem(w, r, http.StatusInternalServerError, "internal",
					"Could not close the session", err.Error(), true)
				return
			}
			state = sessions.StateClosed
			s.log.Info("closed a stale session row nothing was running",
				"session", id, "device", row.DeviceID, "was", row.State,
				"by", p.ID, "request", requestID(r))
			s.auditAdmin(r.Context(), p, row.DeviceID, plugin.ActionAdminKill,
				"closed_stale", "")
			s.writeJSON(w, http.StatusOK, map[string]any{
				"id": id, "killed": true, "state": string(state),
			})
			return
		}
		s.log.Info("session killed by an administrator",
			"session", id, "by", p.ID, "request", requestID(r))
		s.auditAdmin(r.Context(), p, row.DeviceID, plugin.ActionAdminKill, "killed", "")
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"id": id, "killed": row.Live(), "state": string(state),
	})
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ── rate limiting ───────────────────────────────────────────────────────────────

// limiter is a fixed-window counter per key.
//
// A fixed window rather than a token bucket: the API is not the hot path, the window
// boundary is what Retry-After can honestly point at, and a caller that can read the
// reset header can behave correctly without guessing.
type limiter struct {
	perMinute int
	now       func() time.Time

	mu      sync.Mutex
	windows map[string]*window
}

type window struct {
	start time.Time
	count int
}

func newLimiter(perMinute int, now func() time.Time) *limiter {
	return &limiter{perMinute: perMinute, now: now, windows: make(map[string]*window)}
}

func (l *limiter) allow(key string, w http.ResponseWriter) bool {
	now := l.now()
	l.mu.Lock()
	win, ok := l.windows[key]
	if !ok || now.Sub(win.start) >= time.Minute {
		win = &window{start: now}
		l.windows[key] = win
		// Opportunistic sweep: without it, a gateway that has seen a million client
		// addresses keeps a million windows.
		if len(l.windows) > 10000 {
			for k, v := range l.windows {
				if now.Sub(v.start) >= time.Minute {
					delete(l.windows, k)
				}
			}
		}
	}
	win.count++
	count, start := win.count, win.start
	l.mu.Unlock()

	remaining := l.perMinute - count
	if remaining < 0 {
		remaining = 0
	}
	reset := int(time.Minute.Seconds() - now.Sub(start).Seconds())
	if reset < 0 {
		reset = 0
	}
	w.Header().Set(HeaderRateLimit, strconv.Itoa(l.perMinute))
	w.Header().Set(HeaderRateRemain, strconv.Itoa(remaining))
	w.Header().Set(HeaderRateReset, strconv.Itoa(reset))

	if count > l.perMinute {
		// Retry-After in seconds, pointing at the window boundary rather than a
		// guess, so a well-behaved client stops exactly as long as it needs to.
		w.Header().Set("Retry-After", strconv.Itoa(max(reset, 1)))
		return false
	}
	return true
}

// Handler returns the mux, for mounting under a larger server.
func (s *Server) Handler() http.Handler { return s.mux }

// ── opening a session ───────────────────────────────────────────────────────────

type openRequest struct {
	DeviceID string `json:"device_id"`
	Profile  string `json:"profile"`
	PTY      *struct {
		Cols int    `json:"cols"`
		Rows int    `json:"rows"`
		Term string `json:"term"`
	} `json:"pty"`
	// Reason is free text from the operator — a ticket number, a sentence. It costs
	// the caller nothing and turns the session list from a log into an explanation.
	Reason string `json:"reason"`
}

type openResponse struct {
	Session sessionJSON `json:"session"`
	Attach  attachJSON  `json:"attach"`
}

type attachJSON struct {
	Ticket string `json:"ticket"`
	URL    string `json:"url"`
	// ExpiresAt is a deadline for *connecting*, not a session lifetime.
	ExpiresAt string `json:"expires_at"`
}

// openSession invites a device and returns a ticket the browser can attach with.
//
// It does **not** wait for the device. The two ends of a browser session arrive on two
// different requests, so this returns as soon as the invitation is delivered and
// /ws/attach does the pairing. A caller that wants to know whether the device answered
// watches the session's state.
func (s *Server) openSession(w http.ResponseWriter, r *http.Request, p *plugin.Principal) {
	var req openRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		s.problem(w, r, http.StatusBadRequest, "invalid_argument",
			"Body is not valid JSON", err.Error(), false)
		return
	}
	if req.DeviceID == "" {
		s.problem(w, r, http.StatusBadRequest, "invalid_argument",
			"device_id is required", "", false)
		return
	}
	if req.Profile == "" {
		req.Profile = "shell"
	}

	// Idempotency, before any work: a row, an invitation and a ticket are all real
	// effects, and the point is to not have two of each.
	//
	// complete is called once the session exists *and* the device answered. Completing
	// earlier would leave a consumed key naming a session that was rejected, and the
	// caller could never retry it.
	complete := func(string) {}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	if key != "" && s.o.Idempotency != nil {
		if fp := fingerprint(&req); fp != "" {
			rec, replay, err := s.o.Idempotency.Begin(r.Context(), p.ID, key, fp)
			switch {
			case errors.Is(err, idempotency.ErrFingerprintMismatch):
				s.problemFor(w, r, "idempotency_key_reused", "")
				return
			case errors.Is(err, idempotency.ErrInFlight):
				s.problemFor(w, r, "idempotency_in_flight", "")
				return
			case err != nil:
				// A store that cannot answer must not refuse the request. Losing
				// idempotency for one call costs a possible duplicate session; refusing
				// costs the operator their shell, and only one of those is recoverable
				// by trying again.
				s.log.Warn("the idempotency store could not be reached; serving without it",
					"principal", p.ID, "request", requestID(r), "error", err)
			case replay:
				s.replaySession(w, r, p, rec.SessionID)
				return
			default:
				// Release is deferred unconditionally. It is a no-op once the key has
				// been completed, so the success path needs no branch — and a branch
				// is what would eventually leak a key on some path nobody thought of.
				defer func() {
					ctx := context.WithoutCancel(r.Context())
					if err := s.o.Idempotency.Release(ctx, p.ID, key); err != nil {
						s.log.Warn("could not release an idempotency key",
							"principal", p.ID, "request", requestID(r), "error", err)
					}
				}()
				complete = func(sessionID string) {
					ctx := context.WithoutCancel(r.Context())
					if err := s.o.Idempotency.Complete(ctx, p.ID, key, sessionID); err != nil {
						s.log.Warn("could not record an idempotency key",
							"principal", p.ID, "session", sessionID, "error", err)
					}
				}
			}
		}
	}

	dev, err := s.o.Registry.Get(r.Context(), req.DeviceID)
	if err != nil || dev.Disabled {
		// `device_unknown` rather than a generic `not_found`: the console renders a
		// screen per condition, and the specific one tells an operator to check the
		// device id while the generic one told them their application was broken.
		//
		// The same answer either way — an authenticated caller must not be able to
		// enumerate the fleet by trying ids — which the condition's own copy carries by
		// naming both possibilities out loud.
		c, _ := condition.Lookup("device_unknown")
		s.problem(w, r, statusFor("device_unknown"), "device_unknown",
			c.Headline, c.NextAction, false)
		return
	}

	// Authorisation, before a row exists or a device is woken. A denial is a 403 with
	// no session row; an outage is a 503 — and the two are different screens because
	// "you don't have access" and "we couldn't check" send somebody to different places.
	if v := s.o.Authz.AtOpen(r.Context(), p, dev, plugin.ActionShell, plugin.Target{}); !v.Allow() {
		s.refuseByAuthz(w, r, v)
		return
	}
	recordInput, err := s.o.RecordInput.Resolve(p, dev)
	if err != nil {
		s.problem(w, r, statusFor("policy_conflict"), "policy_conflict",
			"record_input policy conflict", err.Error(), false)
		return
	}

	sessionID := newSessionID()
	row := &sessions.Session{
		ID: sessionID, DeviceID: dev.ID, Profile: req.Profile,
		Mode: string(dev.ResolvedMode()), Principal: p.ID, OpenedBy: p.OpenedBy,
		Unattended: p.Unattended, RecordInput: recordInput, Reason: req.Reason,
		State: sessions.StateWaking, RecordingState: sessions.NotRecorded,
	}
	if err := s.o.Sessions.Create(r.Context(), row); err != nil {
		if errors.Is(err, sessions.ErrLimit) {
			s.problem(w, r, http.StatusConflict, "session_limit",
				"That device already has a session open",
				"wait for it to end, or end it", true)
			return
		}
		s.problem(w, r, http.StatusInternalServerError, "internal",
			"Could not create the session", err.Error(), true)
		return
	}

	ireq := invite.Request{
		SessionID: sessionID, Profile: req.Profile, Principal: p.ID,
		OpenedBy: p.OpenedBy, Unattended: p.Unattended,
		RecordInput:  recordInput,
		AttachTicket: true,
	}
	if req.PTY != nil {
		ireq.PTY = &frame.PTY{Cols: req.PTY.Cols, Rows: req.PTY.Rows, Term: req.PTY.Term}
	}
	pending, err := s.o.Inviter.Invite(r.Context(), dev, ireq)
	if err != nil {
		var f *invite.Failure
		if errors.As(err, &f) {
			s.reject(r.Context(), sessionID, f.Code)
			// The operator-facing sentence, not the wire code: "device offline" and
			// "the wake-up service isn't responding" send someone to different places.
			s.problem(w, r, statusFor(f.Code), f.Code, f.Operator, err.Error(), f.Retryable)
			return
		}
		s.reject(r.Context(), sessionID, "internal")
		s.problem(w, r, http.StatusInternalServerError, "internal",
			"Could not open the session", err.Error(), true)
		return
	}

	fresh, err := s.o.Sessions.Get(r.Context(), sessionID)
	if err != nil {
		fresh = row
	}
	complete(sessionID)
	s.log.Info("session opened via the API",
		"session", sessionID, "device", dev.ID, "principal", p.ID,
		"request", requestID(r))
	// The ticket is in the body and nowhere else. Never a query string, never a
	// header: those end up in ingress logs, LB logs and browser history.
	s.writeJSON(w, http.StatusCreated, openResponse{
		Session: s.render(fresh),
		Attach: attachJSON{
			Ticket:    pending.Attach,
			URL:       s.o.AttachURL,
			ExpiresAt: pending.AttachExpiresAt.UTC().Format(time.RFC3339),
		},
	})
}

func (s *Server) reject(ctx context.Context, sessionID, reason string) {
	_ = s.o.Sessions.Update(ctx, sessionID, func(row *sessions.Session) error {
		row.State = sessions.StateRejected
		row.CloseReason = reason
		row.ClosedAt = time.Now()
		return nil
	})
}

// statusFor maps a wire code to an HTTP status, in one place, so the two operator
// surfaces cannot disagree about what "the device is offline" means.
// statusExceptions are the codes whose HTTP status is not implied by whose fault it is.
var statusExceptions = map[string]int{
	"auth_failed":      http.StatusUnauthorized,
	"device_unknown":   http.StatusNotFound,
	"not_found":        http.StatusNotFound,
	"invalid_argument": http.StatusBadRequest,
	"session_limit":    http.StatusConflict,
	"already_attached": http.StatusConflict,
	"session_closed":   http.StatusConflict,
	"wrong_node":       http.StatusConflict,
	"policy_conflict":  http.StatusConflict,
	// A duplicate request that is still running is a conflict, not a bad request: the
	// body was fine and the answer is to wait.
	"idempotency_in_flight": http.StatusConflict,
	"doorbell_failed":       http.StatusBadGateway,
	"gateway_shutdown":      http.StatusServiceUnavailable,
}

// statusFor maps a condition to an HTTP status.
//
// Driven from pkg/condition's fault attribution rather than from a hand-written switch,
// which is how it came to answer 500 for three device conditions it had never heard of.
// A new condition now gets a defensible status the day it is added, and the test in this
// package asserts every one of them lands in the 4xx/5xx range.
func statusFor(code string) int {
	if s, ok := statusExceptions[code]; ok {
		return s
	}
	c := condition.Get(code)
	switch c.Fault {
	case condition.FaultDevice:
		// The request was fine and the device is not there. 503 rather than 500: it is
		// a state of the world, and it may well work in a minute.
		return http.StatusServiceUnavailable
	case condition.FaultPrincipal:
		return http.StatusForbidden
	case condition.FaultClient:
		return http.StatusBadRequest
	case condition.FaultGateway:
		if c.Retryable {
			return http.StatusServiceUnavailable
		}
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}

func newSessionID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "sess_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
	out := make([]byte, len(b))
	for i, v := range b {
		out[i] = alphabet[int(v)%len(alphabet)]
	}
	return "sess_" + string(out)
}

// renewAttach issues a fresh attach ticket for a session that is already open.
//
// Tickets are single-use and short-lived (NFR8), which means the ordinary things a
// browser does — reload the page, lose the WebSocket handshake to a flaky network, sit
// on the ticket for longer than 60 s — all leave an operator with a live session and no
// credential to reach it. Without this endpoint their only recourse is to open a second
// session on the same device, which the per-device cap then refuses. So the renewal is
// not a loosening of the ticket rules; it is what makes single-use survivable.
//
// It is also the natural place to re-check authorisation, because a renewal is a fresh
// request from a principal who may have been revoked since the session opened.
func (s *Server) renewAttach(w http.ResponseWriter, r *http.Request, p *plugin.Principal) {
	id := r.PathValue("id")
	row, err := s.o.Sessions.Get(r.Context(), id)
	if err != nil {
		// Same answer as an unauthorised one, below: an authenticated caller must not
		// be able to discover session ids by trying them.
		s.problem(w, r, http.StatusNotFound, "not_found",
			"No such session, or you don't have access", "", false)
		return
	}

	// Only the operator who opened it. Sharing a session with a second operator is a
	// different feature with its own consent question (observers, E3.S5), and it must
	// not arrive by accident through a renewal endpoint.
	if row.Principal != p.ID {
		s.problem(w, r, http.StatusNotFound, "not_found",
			"No such session, or you don't have access", "", false)
		return
	}

	if !row.Live() {
		s.problem(w, r, http.StatusConflict, "session_closed",
			"That session has ended", "open a new one", false)
		return
	}

	token, expires, err := s.o.Inviter.MintAttach(r.Context(), ticket.Claims{
		SessionID:   row.ID,
		DeviceID:    row.DeviceID,
		Profile:     row.Profile,
		Principal:   p.ID,
		OpenedBy:    row.OpenedBy,
		Unattended:  row.Unattended,
		RecordInput: row.RecordInput,
	}, 0)
	if err != nil {
		s.problem(w, r, http.StatusInternalServerError, "internal",
			"Could not issue an attach ticket", err.Error(), true)
		return
	}

	s.log.Info("attach ticket renewed",
		"session", row.ID, "principal", p.ID, "request", requestID(r))
	// The ticket goes in the body and nowhere else: not the URL, not a log line.
	s.writeJSON(w, http.StatusCreated, attachJSON{
		Ticket:    token,
		URL:       s.o.AttachURL,
		ExpiresAt: expires.Format(time.RFC3339),
	})
}

// observeSession issues a ticket for watching a live session read-only (FR13).
//
// Deliberately a different endpoint from renewAttach rather than a flag on it. The two
// grant different things, and an endpoint that returned either depending on a boolean
// would be one an integrator could get wrong in the direction that matters: handing
// somebody a writable session when they asked to watch.
func (s *Server) observeSession(w http.ResponseWriter, r *http.Request, p *plugin.Principal) {
	id := r.PathValue("id")
	row, err := s.o.Sessions.Get(r.Context(), id)
	if err != nil {
		s.problem(w, r, http.StatusNotFound, "not_found",
			"No such session, or you don't have access", "", false)
		return
	}
	if !row.Live() {
		s.problem(w, r, http.StatusConflict, "session_closed",
			"That session has ended", "there is nothing to watch", false)
		return
	}
	// Watching your own session is not an error, but it is not observation either: it
	// would put a second read-only pane on a shell you already have, and tell you that
	// you are watching yourself.
	if row.Principal == p.ID {
		s.problem(w, r, http.StatusConflict, "already_attached",
			"That is your own session", "attach to it instead of watching it", false)
		return
	}

	// Watching somebody else's shell is its own action, and a grant to open sessions is
	// not a grant to read other people's. Checked against the *session's* device, which
	// is what a rules file scopes on.
	if v := s.o.Authz.AtOpen(r.Context(), p,
		&plugin.Device{ID: row.DeviceID}, plugin.ActionObserve, plugin.Target{}); !v.Allow() {
		s.refuseByAuthz(w, r, v)
		return
	}

	token, expires, err := s.o.Inviter.MintObserve(r.Context(), ticket.Claims{
		SessionID: row.ID,
		DeviceID:  row.DeviceID,
		Profile:   row.Profile,
		Principal: p.ID,
	}, 0)
	if err != nil {
		s.problem(w, r, http.StatusInternalServerError, "internal",
			"Could not issue a watch ticket", err.Error(), true)
		return
	}

	// Logged as its own event, at info. Somebody watching somebody else's shell is a
	// thing an auditor asks about later, and "who watched what" must not depend on a
	// debug level being on at the time.
	s.log.Info("watch ticket issued",
		"session", row.ID, "observer", p.ID, "watching", row.Principal,
		"device", row.DeviceID, "request", requestID(r))
	if s.o.Audit != nil {
		s.o.Audit.Emit(r.Context(), plugin.AuditEvent{
			Kind: plugin.AuditObserveIssued, SessionID: row.ID, DeviceID: row.DeviceID,
			Principal: row.Principal, Observer: p.ID, Action: string(plugin.ActionObserve),
			Attrs: map[string]string{"request": requestID(r)},
		})
	}

	s.writeJSON(w, http.StatusCreated, attachJSON{
		Ticket:    token,
		URL:       s.o.AttachURL,
		ExpiresAt: expires.Format(time.RFC3339),
	})
}

// refuseByAuthz turns an authorisation verdict into a problem document.
//
// One place, so the two surfaces cannot drift on the distinction that matters: a denial
// carries the backend's own actionable sentence, and an outage carries the copy that says
// the operator's access has not changed.
func (s *Server) refuseByAuthz(w http.ResponseWriter, r *http.Request, v authz.Result) {
	c, _ := condition.Lookup(v.Code)
	title := c.Headline
	detail := c.NextAction
	if v.Outcome == authz.Denied && v.Reason != "" {
		// "not in the on-call group" is worth more than the generic copy, and it is
		// what whoever wrote the rule wrote for exactly this moment.
		detail = v.Reason
	}
	if v.Err != nil {
		// The backend's error goes in the detail field of the log, never to the caller:
		// "dial tcp: connection refused" is not something an operator can act on.
		s.log.Warn("refused by authorization", "outcome", v.Outcome.String(),
			"code", v.Code, "error", v.Err, "request", requestID(r))
	}
	s.problem(w, r, statusFor(v.Code), v.Code, title, detail, c.Retryable)
}

// getRecording serves a recording and the verdict that says whether it can be trusted.
//
// The two travel together on purpose. A console that fetched the recording and verified it
// separately could render a player before the verdict arrived — and a player showing a
// tampered recording exactly like an intact one is a player that launders it.
//
// A production deployment would hand over a short-lived URL to object storage instead of
// proxying the bytes (docs/sdk.md § 6.1); this is the reference console's path, and the
// authorisation check is the same either way.
func (s *Server) getRecording(w http.ResponseWriter, r *http.Request, p *plugin.Principal) {
	id := r.PathValue("id")
	row, err := s.o.Sessions.Get(r.Context(), id)
	if err != nil {
		s.problem(w, r, http.StatusNotFound, "not_found",
			"No such session, or you don't have access", "", false)
		return
	}

	// Reading a recording is its own action. A grant to open sessions on a device is not
	// a grant to read what other people did on it.
	if v := s.o.Authz.AtOpen(r.Context(), p,
		&plugin.Device{ID: row.DeviceID}, plugin.ActionReplay, plugin.Target{}); !v.Allow() {
		s.refuseByAuthz(w, r, v)
		return
	}

	cast, err := s.o.Replays.Cast(r.Context(), id)
	if err != nil {
		s.problem(w, r, http.StatusNotFound, "not_found",
			"No recording for that session", err.Error(), false)
		return
	}
	verdict, verr := s.o.Replays.Verdict(r.Context(), id)
	if verr != nil {
		// A recording that cannot be verified is still served, with a verdict that says
		// so. Withholding it would be the wrong remedy: somebody reading an incident
		// needs to see what the file claims *and* be told it cannot be trusted.
		verdict = ReplayVerdict{
			Status: "malformed", OK: false,
			Detail: "the recording could not be verified: " + verr.Error(),
		}
		s.log.Warn("serving a recording that did not verify",
			"session", id, "error", verr, "request", requestID(r))
	}

	s.log.Info("recording read", "session", id, "principal", p.ID,
		"verdict", verdict.Status, "request", requestID(r))
	// The manifest travels with the recording so a reader can verify it *themselves*.
	//
	// That is the whole point of signing and hash-chaining these, and until this field
	// existed nothing outside the gateway could use either: the only verification on
	// offer was `verdict`, which is this gateway's opinion of its own file. Asking the
	// party that might have tampered with something whether it was tampered with is not
	// verification, and an operator holding the recorder's public key can now settle it
	// without trusting this endpoint at all.
	//
	// Base64 of the exact signed bytes, for the reason on Replays.Manifest.
	manifest, merr := s.o.Replays.Manifest(r.Context(), id)
	if merr != nil {
		// Not fatal. A recording whose manifest is missing is exactly the case somebody
		// investigating needs to see, and the verdict above already says it cannot be
		// verified.
		s.log.Warn("serving a recording with no manifest",
			"session", id, "error", merr, "request", requestID(r))
	}

	s.writeJSON(w, http.StatusOK, struct {
		Cast     string        `json:"cast"`
		Manifest []byte        `json:"manifest,omitempty"`
		Verdict  ReplayVerdict `json:"verdict"`
	}{Cast: string(cast), Manifest: manifest, Verdict: verdict})
}
