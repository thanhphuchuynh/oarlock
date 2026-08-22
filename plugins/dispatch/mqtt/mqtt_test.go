package mqtt_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
	"github.com/oarlock/oarlock/pkg/plugin/plugintest"
	"github.com/oarlock/oarlock/plugins/dispatch/mqtt"
)

const ticket = "mqtt-ticket-abcdefghijklmnop"

type publish struct {
	topic   string
	qos     byte
	payload []byte
}

type broker struct {
	url    string
	ln     net.Listener
	broken atomic.Bool
	got    chan publish
}

func startBroker(t *testing.T) *broker {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &broker{
		url: "mqtt://" + ln.Addr().String(),
		ln:  ln, got: make(chan publish, 128),
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go b.handle(conn)
		}
	}()
	return b
}

func (b *broker) handle(conn net.Conn) {
	defer conn.Close()
	if b.broken.Load() {
		return
	}
	header, body, err := readPacket(conn)
	if err != nil || header&0xF0 != 0x10 || !bytes.Contains(body, []byte("MQTT")) {
		return
	}
	_ = writePacket(conn, 0x20, []byte{0, 0})

	header, body, err = readPacket(conn)
	if err != nil || header&0xF0 != 0x30 {
		return
	}
	topic, rest, ok := readString(body)
	if !ok {
		return
	}
	qos := (header & 0x06) >> 1
	if qos > 0 {
		if len(rest) < 2 {
			return
		}
		packetID := rest[:2]
		rest = rest[2:]
		_ = writePacket(conn, 0x40, packetID)
	}
	b.got <- publish{topic: topic, qos: qos, payload: append([]byte(nil), rest...)}
}

func TestPublishesInvitationToPerDeviceTopic(t *testing.T) {
	b := startBroker(t)
	d, err := mqtt.New(b.url, "fleet/{device_id}/wake", "gw-a", "user", "pass", 1,
		2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Wake(context.Background(), dev(), inv()); err != nil {
		t.Fatal(err)
	}

	got := waitPublish(t, b)
	if got.topic != "fleet/treadmill-4821/wake" {
		t.Fatalf("topic = %q", got.topic)
	}
	if got.qos != 1 {
		t.Fatalf("qos = %d", got.qos)
	}
	if strings.Contains(got.topic, ticket) {
		t.Fatal("ticket leaked into the topic")
	}

	var payload struct {
		DeviceID   string           `json:"device_id"`
		Platform   plugin.Platform  `json:"platform"`
		Invitation frame.Invitation `json:"invitation"`
	}
	if err := json.Unmarshal(got.payload, &payload); err != nil {
		t.Fatalf("payload is not JSON: %v\n%s", err, got.payload)
	}
	if payload.DeviceID != "treadmill-4821" || payload.Platform != plugin.PlatformAndroid {
		t.Fatalf("payload = %+v", payload)
	}
	if payload.Invitation.Ticket != ticket {
		t.Fatalf("ticket did not arrive in the payload: %+v", payload.Invitation)
	}
}

func TestBrokenTransportIsNotDeviceUnreachableAndDoesNotLeakTicket(t *testing.T) {
	d, err := mqtt.New("mqtt://127.0.0.1:1", "", "", "", "", 1, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	err = d.Wake(context.Background(), dev(), inv())
	if err == nil {
		t.Fatal("expected failure")
	}
	if errors.Is(err, plugin.ErrDeviceUnreachable) {
		t.Fatalf("broken transport reported device unreachable: %v", err)
	}
	if strings.Contains(err.Error(), ticket) {
		t.Fatalf("ticket leaked into error: %v", err)
	}
}

func TestCancelledContextIsHonoured(t *testing.T) {
	d, err := mqtt.New("mqtt://127.0.0.1:1", "", "", "", "", 1, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := d.Wake(ctx, dev(), inv()); err == nil {
		t.Fatal("expected cancellation")
	}
}

func TestNewValidation(t *testing.T) {
	tests := []struct {
		name  string
		url   string
		topic string
		qos   int
	}{
		{"missing url", "", mqtt.DefaultTopic, 1},
		{"shared topic", "mqtt://127.0.0.1:1883", "fleet/wake", 1},
		{"bad qos", "mqtt://127.0.0.1:1883", mqtt.DefaultTopic, 2},
		{"password without username", "mqtt://127.0.0.1:1883", mqtt.DefaultTopic, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			username, password := "", ""
			if tc.name == "password without username" {
				password = "secret"
			}
			if _, err := mqtt.New(tc.url, tc.topic, "", username, password, tc.qos, 0); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestConformance(t *testing.T) {
	b := startBroker(t)
	plugintest.Dispatcher(t, plugintest.DispatcherHarness{
		New: func(t *testing.T) plugin.Dispatcher {
			d, err := mqtt.New(b.url, "", "conformance", "", "", 1, 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			return d
		},
		Device: func() *plugin.Device {
			return &plugin.Device{ID: "treadmill-4821", Mode: plugin.ModeDispatch}
		},
		Invitation: func() frame.Invitation {
			return frame.Invitation{
				SessionID: "sess_conformance",
				Ticket:    "conformance-ticket-abcdefghijklmnop",
				URL:       "wss://gw.example.org/ws/session",
				Profile:   "shell",
			}
		},
		BreakTransport: func(*testing.T) func() {
			b.broken.Store(true)
			return func() { b.broken.Store(false) }
		},
	})
}

func dev() *plugin.Device {
	return &plugin.Device{ID: "treadmill-4821", Platform: plugin.PlatformAndroid}
}

func inv() frame.Invitation {
	return frame.Invitation{
		SessionID: "sess_1", Ticket: ticket, URL: "wss://gw-a.example.org/ws/session",
		Profile: "shell",
	}
}

func waitPublish(t *testing.T, b *broker) publish {
	t.Helper()
	select {
	case got := <-b.got:
		return got
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for publish")
		return publish{}
	}
}

func readString(b []byte) (string, []byte, bool) {
	if len(b) < 2 {
		return "", nil, false
	}
	n := int(binary.BigEndian.Uint16(b[:2]))
	if len(b) < 2+n {
		return "", nil, false
	}
	return string(b[2 : 2+n]), b[2+n:], true
}

func writePacket(w io.Writer, header byte, body []byte) error {
	if _, err := w.Write([]byte{header}); err != nil {
		return err
	}
	if _, err := w.Write(encodeRemainingLength(len(body))); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

func readPacket(r io.Reader) (byte, []byte, error) {
	var header [1]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	n, err := readRemainingLength(r)
	if err != nil {
		return 0, nil, err
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	return header[0], body, nil
}

func encodeRemainingLength(n int) []byte {
	var out []byte
	for {
		encoded := byte(n % 128)
		n /= 128
		if n > 0 {
			encoded |= 128
		}
		out = append(out, encoded)
		if n == 0 {
			return out
		}
	}
}

func readRemainingLength(r io.Reader) (int, error) {
	multiplier, value := 1, 0
	for i := 0; i < 4; i++ {
		var b [1]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, err
		}
		value += int(b[0]&127) * multiplier
		if b[0]&128 == 0 {
			return value, nil
		}
		multiplier *= 128
	}
	return 0, errors.New("malformed remaining length")
}
