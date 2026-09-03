package main

// The API client.
//
// Small on purpose. FR40 exists because the alternative was `curl` with a hand-made
// token, and the way to remove that is not to add a framework — it is to put the token
// resolution, the error shape and the paging in one place so no operator has to know them.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// client talks to one gateway.
type client struct {
	base  string
	token string
	http  *http.Client
}

func newClient(base, token string) (*client, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("%q is not a URL: %w", base, err)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return nil, fmt.Errorf("%q must be http or https", base)
	}
	if u.Scheme == "http" && !isLoopback(u.Hostname()) {
		// A bearer token over plain HTTP to somewhere that is not this machine is a
		// bearer token on the wire. Refused rather than warned: the CLI is where a token
		// is easiest to leak by accident, and the fix is one character.
		return nil, fmt.Errorf("%q is plain http to a remote host, which would send your "+
			"token in the clear. Use https", base)
	}
	return &client{
		base:  strings.TrimRight(base, "/"),
		token: token,
		http:  &http.Client{Timeout: 30 * time.Second},
	}, nil
}

func isLoopback(host string) bool {
	return host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "[::1]"
}

// problem is the RFC 9457 document the API returns for a failure.
type problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
	Status int    `json:"status"`
	// Request is the correlation id. Quoting it is how somebody gets help, so it is
	// printed on every failure rather than only when asked for.
	Request string `json:"request"`
}

func (p problem) Error() string {
	msg := p.Title
	if p.Detail != "" {
		msg += ": " + p.Detail
	}
	if msg == "" {
		msg = fmt.Sprintf("the gateway returned %d", p.Status)
	}
	if p.Request != "" {
		msg += " (request " + p.Request + ")"
	}
	return msg
}

// do makes one request and decodes into out, which may be nil.
func (c *client) do(ctx context.Context, method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("reaching the gateway: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var p problem
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if json.Unmarshal(raw, &p) == nil && (p.Title != "" || p.Type != "") {
			p.Status = resp.StatusCode
			return p
		}
		// Not a problem document. Say what arrived rather than inventing a reason —
		// this is usually a proxy in front of the gateway answering instead of it.
		snippet := strings.TrimSpace(string(raw))
		if len(snippet) > 200 {
			snippet = snippet[:200] + "…"
		}
		return fmt.Errorf("the gateway returned %d: %s", resp.StatusCode, snippet)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// ── the shapes the CLI reads ────────────────────────────────────────────────────

type sessionRow struct {
	ID             string `json:"id"`
	DeviceID       string `json:"device_id"`
	Profile        string `json:"profile"`
	Principal      string `json:"principal"`
	State          string `json:"state"`
	RecordingState string `json:"recording_state"`
	Mode           string `json:"mode"`
	CloseReason    string `json:"close_reason"`
	CreatedAt      string `json:"created_at"`
	AttachedAt     string `json:"attached_at"`
	ClosedAt       string `json:"closed_at"`
}

type sessionList struct {
	Sessions []sessionRow `json:"sessions"`
	// next_cursor, which is what the API actually sends. The first version of this said
	// `next`, so paging silently stopped after one page — and the test that was supposed
	// to catch it used a fake server built from the same wrong assumption. Writing the
	// OpenAPI document against the real response types is what found it.
	NextCursor string `json:"next_cursor"`
}

type deviceRow struct {
	ID               string            `json:"id"`
	Platform         string            `json:"platform"`
	ResolvedMode     string            `json:"resolved_mode"`
	Connected        bool              `json:"connected"`
	Disabled         bool              `json:"disabled"`
	AllowPassthrough bool              `json:"allow_passthrough"`
	Tags             map[string]string `json:"tags"`
	Profiles         []string          `json:"profiles"`
}

type deviceList struct {
	Devices    []deviceRow `json:"devices"`
	NextCursor string      `json:"next_cursor"`
}

// agentRow is what GET /agents returns, which is less than it sounds: the device id and
// whether it is connected. An earlier version of this struct expected `since`, `version`
// and `caps`, which the API does not send — so the table rendered three columns of dashes
// for fields that were never going to arrive.
type agentRow struct {
	DeviceID  string `json:"device_id"`
	Connected bool   `json:"connected"`
}

type agentList struct {
	Agents []agentRow `json:"agents"`
}

type recording struct {
	Cast     string `json:"cast"`
	Manifest []byte `json:"manifest"`
	Verdict  struct {
		Status             string `json:"status"`
		OK                 bool   `json:"ok"`
		EventsFound        int    `json:"events_found"`
		EventsExpected     int    `json:"events_expected"`
		LastGoodCheckpoint int    `json:"last_good_checkpoint"`
		Detail             string `json:"detail"`
	} `json:"verdict"`
}

// listSessions follows the cursor, so `list` means list rather than "the first page".
//
// A CLI that silently returned one page would be a CLI whose output an operator cannot
// count, and counting is most of what a list is for. limit of zero means every page.
func (c *client) listSessions(ctx context.Context, q url.Values, limit int) ([]sessionRow, error) {
	if q == nil {
		// url.Values is a map, and Set on a nil one panics — which would only ever happen
		// on the *second* page, so a caller passing nil worked right up until a fleet got
		// big enough to paginate.
		q = url.Values{}
	}
	var out []sessionRow
	for {
		var page sessionList
		path := "/api/v1/sessions"
		if len(q) > 0 {
			path += "?" + q.Encode()
		}
		if err := c.do(ctx, http.MethodGet, path, nil, &page); err != nil {
			return nil, err
		}
		out = append(out, page.Sessions...)
		if limit > 0 && len(out) >= limit {
			return out[:limit], nil
		}
		if page.NextCursor == "" {
			return out, nil
		}
		q.Set("cursor", page.NextCursor)
	}
}

func (c *client) listDevices(ctx context.Context) ([]deviceRow, error) {
	var out []deviceRow
	q := url.Values{}
	for {
		var page deviceList
		path := "/api/v1/devices"
		if len(q) > 0 {
			path += "?" + q.Encode()
		}
		if err := c.do(ctx, http.MethodGet, path, nil, &page); err != nil {
			return nil, err
		}
		out = append(out, page.Devices...)
		if page.NextCursor == "" {
			return out, nil
		}
		q.Set("cursor", page.NextCursor)
	}
}

var errNoRecording = errors.New("no recording for that session")
