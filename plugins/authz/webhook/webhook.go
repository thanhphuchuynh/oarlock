// Package webhook is an Authorizer that asks an HTTP service for each decision.
//
// A non-2xx response is not silently converted into a denial. The service being down,
// misconfigured, or returning a bad response means "could not decide", which the gateway
// reports as authz_unavailable rather than revoked.
package webhook

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oarlock/oarlock/pkg/plugin"
)

// DefaultTimeout bounds one decision call or Watch connection attempt.
const DefaultTimeout = 5 * time.Second

// DefaultCacheTTL is deliberately shorter than the default re-check interval.
const DefaultCacheTTL = 5 * time.Second

// Authorizer POSTs authorization requests and optionally subscribes to revocations.
type Authorizer struct {
	URL      string
	WatchURL string
	Token    string
	Header   http.Header

	Client   *http.Client
	Timeout  time.Duration
	CacheTTL time.Duration
	Now      func() time.Time

	mu    sync.Mutex
	cache map[cacheKey]cached
}

var _ plugin.Authorizer = (*Authorizer)(nil)

type cacheKey struct {
	principal string
	device    string
	action    plugin.Action
	// target is the JSON encoding of the plugin.Target, not its String(): this is a
	// map key, so it has to be both comparable and injective. A cache keyed without it
	// would answer "may I forward port 3000" with the decision it cached for port 22 —
	// the cache would become the hole the target was added to close.
	target string
}

type cached struct {
	decision plugin.Decision
	expires  time.Time
}

// New validates a webhook authorizer.
func New(url, watchURL, token string, timeout, cacheTTL time.Duration) (*Authorizer, error) {
	if url == "" {
		return nil, errors.New("webhook authorizer: URL is required")
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if cacheTTL < 0 {
		return nil, errors.New("webhook authorizer: cache TTL is negative")
	}
	if cacheTTL == 0 {
		cacheTTL = DefaultCacheTTL
	}
	return &Authorizer{
		URL: url, WatchURL: watchURL, Token: token, Timeout: timeout, CacheTTL: cacheTTL,
		cache: make(map[cacheKey]cached),
	}, nil
}

type authorizeRequest struct {
	Principal principalDTO  `json:"principal"`
	Device    deviceDTO     `json:"device"`
	Action    plugin.Action `json:"action"`
	// Target is omitted entirely for an action that names none, so a backend written
	// before targets existed sees exactly the body it saw before.
	Target *targetDTO `json:"target,omitempty"`
}

type targetDTO struct {
	Port int      `json:"port,omitempty"`
	Path string   `json:"path,omitempty"`
	Argv []string `json:"argv,omitempty"`
}

type principalDTO struct {
	ID         string            `json:"id"`
	Email      string            `json:"email,omitempty"`
	Groups     []string          `json:"groups,omitempty"`
	Attrs      map[string]string `json:"attrs,omitempty"`
	Expiry     time.Time         `json:"expiry,omitempty"`
	OpenedBy   string            `json:"opened_by,omitempty"`
	Unattended bool              `json:"unattended,omitempty"`
}

type deviceDTO struct {
	ID               string            `json:"id"`
	Platform         plugin.Platform   `json:"platform,omitempty"`
	Mode             plugin.Mode       `json:"mode,omitempty"`
	ResolvedMode     plugin.Mode       `json:"resolved_mode,omitempty"`
	AllowPassthrough bool              `json:"allow_passthrough,omitempty"`
	Tags             map[string]string `json:"tags,omitempty"`
	Profiles         []string          `json:"profiles,omitempty"`
}

type decisionResponse struct {
	Allow  bool            `json:"allow"`
	Reason string          `json:"reason,omitempty"`
	Limits *limitsResponse `json:"limits,omitempty"`
	TTL    duration        `json:"ttl,omitempty"`
}

type limitsResponse struct {
	MaxDuration duration `json:"max_duration,omitempty"`
	Idle        duration `json:"idle,omitempty"`
	Rate        *int     `json:"rate,omitempty"`
}

// Authorize asks the webhook for a decision.
func (a *Authorizer) Authorize(ctx context.Context, p *plugin.Principal, dev *plugin.Device,
	act plugin.Action, tgt plugin.Target) (plugin.Decision, error) {
	if err := ctx.Err(); err != nil {
		return plugin.Decision{}, err
	}
	if a == nil || a.URL == "" {
		return plugin.Decision{}, errors.New("webhook authorizer: URL is required")
	}
	if p == nil || dev == nil {
		return plugin.Decision{Allow: false, Reason: "no principal or device"}, nil
	}

	dto := &targetDTO{Port: tgt.Port, Path: tgt.Path, Argv: tgt.Argv}
	if tgt.IsZero() {
		dto = nil
	}
	targetKey, err := json.Marshal(dto)
	if err != nil {
		return plugin.Decision{}, fmt.Errorf("webhook authorizer: encoding target: %w", err)
	}
	key := cacheKey{principal: p.ID, device: dev.ID, action: act, target: string(targetKey)}
	if d, ok := a.cached(key); ok {
		return d, nil
	}

	body, err := json.Marshal(authorizeRequest{
		Principal: principalDTO{
			ID: p.ID, Email: p.Email, Groups: p.Groups, Attrs: p.Attrs, Expiry: p.Expiry,
			OpenedBy: p.OpenedBy, Unattended: p.Unattended,
		},
		Device: deviceDTO{
			ID: dev.ID, Platform: dev.Platform, Mode: dev.Mode, ResolvedMode: dev.ResolvedMode(),
			AllowPassthrough: dev.AllowPassthrough, Tags: dev.Tags, Profiles: dev.Profiles,
		},
		Action: act,
		Target: dto,
	})
	if err != nil {
		return plugin.Decision{}, fmt.Errorf("webhook authorizer: encoding: %w", err)
	}

	timeout := a.timeout()
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(callCtx, http.MethodPost, a.URL, bytes.NewReader(body))
	if err != nil {
		return plugin.Decision{}, fmt.Errorf("webhook authorizer: building request: %w", err)
	}
	a.applyHeaders(req)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := a.client().Do(req)
	if err != nil {
		return plugin.Decision{}, fmt.Errorf("webhook authorizer: %w", err)
	}
	defer resp.Body.Close()
	excerpt, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode == http.StatusForbidden {
		d, err := decodeDecision(excerpt)
		if err != nil {
			text := strings.TrimSpace(string(excerpt))
			if text == "" {
				text = "not authorized by webhook"
			}
			d = plugin.Decision{Allow: false, Reason: text}
		}
		if d.Allow {
			d.Allow = false
		}
		if d.Reason == "" {
			d.Reason = "not authorized by webhook"
		}
		a.store(key, d)
		return d, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return plugin.Decision{}, fmt.Errorf("webhook authorizer: %s returned %d: %s",
			a.URL, resp.StatusCode, bytes.TrimSpace(excerpt))
	}

	d, err := decodeDecision(excerpt)
	if err != nil {
		return plugin.Decision{}, fmt.Errorf("webhook authorizer: decoding decision: %w", err)
	}
	if !d.Allow && d.Reason == "" {
		d.Reason = "not authorized by webhook"
	}
	a.store(key, d)
	return d, nil
}

func decodeDecision(b []byte) (plugin.Decision, error) {
	var r decisionResponse
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return plugin.Decision{}, err
	}
	d := plugin.Decision{Allow: r.Allow, Reason: r.Reason, TTL: time.Duration(r.TTL)}
	if r.Limits != nil {
		d.Limits = &plugin.GrantLimits{}
		if r.Limits.MaxDuration > 0 {
			v := time.Duration(r.Limits.MaxDuration)
			d.Limits.MaxDuration = &v
		}
		if r.Limits.Idle > 0 {
			v := time.Duration(r.Limits.Idle)
			d.Limits.Idle = &v
		}
		d.Limits.Rate = r.Limits.Rate
	}
	return d, nil
}

// Watch subscribes to an SSE stream of RevocationEvent objects.
func (a *Authorizer) Watch(ctx context.Context) (<-chan plugin.RevocationEvent, error) {
	if a == nil || a.WatchURL == "" {
		return nil, plugin.ErrUnsupported
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	callCtx, cancel := context.WithCancel(ctx)
	req, err := http.NewRequestWithContext(callCtx, http.MethodGet, a.WatchURL, nil)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("webhook authorizer: building watch request: %w", err)
	}
	a.applyHeaders(req)
	req.Header.Set("Accept", "text/event-stream")

	resp, err := a.watchClient().Do(req)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("webhook authorizer watch: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer resp.Body.Close()
		defer cancel()
		excerpt, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return nil, fmt.Errorf("webhook authorizer watch: %s returned %d: %s",
			a.WatchURL, resp.StatusCode, bytes.TrimSpace(excerpt))
	}

	out := make(chan plugin.RevocationEvent)
	go func() {
		defer close(out)
		defer cancel()
		defer resp.Body.Close()
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 1024), 1<<20)
		var data strings.Builder
		for sc.Scan() {
			line := sc.Text()
			if line == "" {
				emitSSE(ctx, out, data.String())
				data.Reset()
				continue
			}
			if strings.HasPrefix(line, ":") {
				continue
			}
			if strings.HasPrefix(line, "data:") {
				if data.Len() > 0 {
					data.WriteByte('\n')
				}
				data.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
			}
		}
		if data.Len() > 0 {
			emitSSE(ctx, out, data.String())
		}
	}()
	return out, nil
}

func emitSSE(ctx context.Context, out chan<- plugin.RevocationEvent, raw string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	var dto struct {
		PrincipalID string `json:"principal_id"`
		DeviceID    string `json:"device_id"`
		Reason      string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(raw), &dto); err != nil {
		return
	}
	ev := plugin.RevocationEvent{
		PrincipalID: dto.PrincipalID,
		DeviceID:    dto.DeviceID,
		Reason:      dto.Reason,
	}
	select {
	case out <- ev:
	case <-ctx.Done():
	}
}

func (a *Authorizer) cached(key cacheKey) (plugin.Decision, bool) {
	ttl := a.CacheTTL
	if ttl <= 0 {
		return plugin.Decision{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	c, ok := a.cache[key]
	if !ok || !a.now().Before(c.expires) {
		delete(a.cache, key)
		return plugin.Decision{}, false
	}
	return c.decision, true
}

func (a *Authorizer) store(key cacheKey, d plugin.Decision) {
	ttl := a.CacheTTL
	if d.TTL > 0 && d.TTL < ttl {
		ttl = d.TTL
	}
	if ttl <= 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cache == nil {
		a.cache = make(map[cacheKey]cached)
	}
	a.cache[key] = cached{decision: d, expires: a.now().Add(ttl)}
}

func (a *Authorizer) client() *http.Client {
	if a.Client != nil {
		return a.Client
	}
	return &http.Client{Timeout: a.timeout()}
}

func (a *Authorizer) watchClient() *http.Client {
	if a.Client != nil {
		return a.Client
	}
	tr, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return &http.Client{}
	}
	clone := tr.Clone()
	clone.ResponseHeaderTimeout = a.timeout()
	clone.TLSHandshakeTimeout = a.timeout()
	return &http.Client{Transport: clone}
}

func (a *Authorizer) timeout() time.Duration {
	if a.Timeout > 0 {
		return a.Timeout
	}
	return DefaultTimeout
}

func (a *Authorizer) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *Authorizer) applyHeaders(req *http.Request) {
	for k, vs := range a.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if a.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.Token)
	}
}

type duration time.Duration

func (d *duration) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, []byte("null")) {
		*d = 0
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		v, err := time.ParseDuration(s)
		if err != nil {
			return err
		}
		*d = duration(v)
		return nil
	}
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*d = duration(time.Duration(n))
	return nil
}

func (d duration) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(time.Duration(d).String())), nil
}
