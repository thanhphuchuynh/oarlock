// Package webhook is a Dispatcher that POSTs the invitation to a URL.
//
// The escape hatch for any push service: a mobile push gateway, an internal
// message bus with an HTTP front, a device-management backend that already knows
// how to reach the fleet.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
)

// DefaultTimeout bounds a wake.
const DefaultTimeout = 10 * time.Second

// UnreachableStatus is how a receiver says "the device is not there", as opposed to
// "I could not deliver". 404 is the natural code for it and 410 is accepted too.
const UnreachableStatus = http.StatusNotFound

// Dispatcher POSTs invitations.
type Dispatcher struct {
	// URL receives the POST. The invitation goes in the **body**; nothing is ever
	// appended to the query string, because a ticket in a URL ends up in ingress
	// logs, load-balancer logs and browser history.
	URL string

	// Secret, if set, signs the body: Oarlock-Signature: t=<unix>,v1=<hex hmac>
	// over "<t>.<body>". Reject anything older than five minutes on the receiving
	// side; without a timestamp in the signed material a captured request is
	// replayable forever.
	Secret []byte

	// Now is injectable for tests.
	Now     func() time.Time
	Client  *http.Client
	Timeout time.Duration
	Header  http.Header
}

var _ plugin.Dispatcher = (*Dispatcher)(nil)

// New validates the configuration.
func New(url string, secret []byte, timeout time.Duration) (*Dispatcher, error) {
	if url == "" {
		return nil, errors.New("webhook dispatcher: URL is required")
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Dispatcher{URL: url, Secret: secret, Timeout: timeout}, nil
}

// Wake POSTs the invitation.
func (d *Dispatcher) Wake(ctx context.Context, dev *plugin.Device, inv frame.Invitation) error {
	if d.URL == "" {
		return errors.New("webhook dispatcher: URL is required")
	}
	body, err := json.Marshal(struct {
		DeviceID   string           `json:"device_id"`
		Platform   plugin.Platform  `json:"platform,omitempty"`
		Invitation frame.Invitation `json:"invitation"`
	}{dev.ID, dev.Platform, inv})
	if err != nil {
		return fmt.Errorf("webhook dispatcher: encoding: %w", err)
	}

	timeout := d.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook dispatcher: building the request: %w", err)
	}
	for k, vs := range d.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Oarlock-Event", "device.wake")
	if len(d.Secret) > 0 {
		ts := strconv.FormatInt(d.now().Unix(), 10)
		mac := hmac.New(sha256.New, d.Secret)
		mac.Write([]byte(ts + "."))
		mac.Write(body)
		req.Header.Set("Oarlock-Signature", "t="+ts+",v1="+hex.EncodeToString(mac.Sum(nil)))
	}

	client := d.Client
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook dispatcher: %w", err)
	}
	defer resp.Body.Close()
	// Drain a little so the connection can be reused, and keep the excerpt short:
	// a doorbell that returns a megabyte of HTML must not put it in a log line.
	excerpt, _ := io.ReadAll(io.LimitReader(resp.Body, 200))

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == UnreachableStatus || resp.StatusCode == http.StatusGone:
		return fmt.Errorf("%w: %s said %d", plugin.ErrDeviceUnreachable, d.URL, resp.StatusCode)
	default:
		return fmt.Errorf("webhook dispatcher: %s returned %d: %s",
			d.URL, resp.StatusCode, bytes.TrimSpace(excerpt))
	}
}

func (d *Dispatcher) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}
