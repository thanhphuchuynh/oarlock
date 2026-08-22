// Package mqtt is a Dispatcher that publishes invitations to an MQTT broker.
//
// It intentionally implements the small MQTT 3.1.1 publish path it needs instead
// of pulling in a long-lived client: a wake is a short, bounded doorbell operation,
// and reconnect/session management belongs on the device side.
package mqtt

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
)

// DefaultTimeout bounds a wake.
const DefaultTimeout = 10 * time.Second

// DefaultTopic is per-device and carries no caller-controlled interpolation.
const DefaultTopic = "oarlock/devices/{device_id}/wake"

// Dispatcher publishes invitations to a per-device MQTT topic.
type Dispatcher struct {
	BrokerURL string
	Topic     string
	ClientID  string
	Username  string
	Password  string
	QoS       byte
	Timeout   time.Duration

	// Dial is injectable for tests. The network and address are derived from BrokerURL.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
}

var _ plugin.Dispatcher = (*Dispatcher)(nil)

// New validates the configuration.
func New(brokerURL, topic, clientID, username, password string, qos int, timeout time.Duration) (*Dispatcher, error) {
	if brokerURL == "" {
		return nil, errors.New("mqtt dispatcher: broker URL is required")
	}
	if topic == "" {
		topic = DefaultTopic
	}
	if !strings.Contains(topic, "{device_id}") {
		return nil, errors.New("mqtt dispatcher: topic must contain {device_id}")
	}
	if qos < 0 {
		qos = 1
	}
	if qos != 0 && qos != 1 {
		return nil, errors.New("mqtt dispatcher: QoS must be 0 or 1")
	}
	if password != "" && username == "" {
		return nil, errors.New("mqtt dispatcher: username is required when password is set")
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Dispatcher{
		BrokerURL: brokerURL, Topic: topic, ClientID: clientID,
		Username: username, Password: password, QoS: byte(qos), Timeout: timeout,
	}, nil
}

// Wake publishes the invitation to the device's topic.
func (d *Dispatcher) Wake(ctx context.Context, dev *plugin.Device, inv frame.Invitation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d.BrokerURL == "" {
		return errors.New("mqtt dispatcher: broker URL is required")
	}
	topic := d.topicFor(dev)
	if topic == "" {
		return errors.New("mqtt dispatcher: empty topic")
	}
	payload, err := json.Marshal(struct {
		DeviceID   string           `json:"device_id"`
		Platform   plugin.Platform  `json:"platform,omitempty"`
		Invitation frame.Invitation `json:"invitation"`
	}{dev.ID, dev.Platform, inv})
	if err != nil {
		return fmt.Errorf("mqtt dispatcher: encoding: %w", err)
	}

	timeout := d.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := d.dial(ctx)
	if err != nil {
		return fmt.Errorf("mqtt dispatcher: connect: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if err := d.connect(conn); err != nil {
		return err
	}
	if err := publish(conn, topic, payload, d.qos()); err != nil {
		return err
	}
	_, _ = conn.Write([]byte{0xE0, 0x00})
	return nil
}

func (d *Dispatcher) topicFor(dev *plugin.Device) string {
	tmpl := d.Topic
	if tmpl == "" {
		tmpl = DefaultTopic
	}
	return strings.ReplaceAll(tmpl, "{device_id}", dev.ID)
}

func (d *Dispatcher) qos() byte {
	switch d.QoS {
	case 0, 1:
		return d.QoS
	default:
		return 1
	}
}

func (d *Dispatcher) dial(ctx context.Context) (net.Conn, error) {
	u, err := url.Parse(d.BrokerURL)
	if err != nil {
		return nil, fmt.Errorf("parsing broker URL: %w", err)
	}
	network, address, tlsConn, err := brokerAddress(u)
	if err != nil {
		return nil, err
	}
	dial := d.Dial
	if dial == nil {
		nd := &net.Dialer{}
		dial = nd.DialContext
	}
	conn, err := dial(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if tlsConn {
		host := u.Hostname()
		tconn := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		if err := tconn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("tls handshake: %w", err)
		}
		conn = tconn
	}
	return conn, nil
}

func brokerAddress(u *url.URL) (network, address string, tlsConn bool, err error) {
	switch u.Scheme {
	case "mqtt", "tcp":
		tlsConn = false
	case "mqtts", "tls":
		tlsConn = true
	default:
		return "", "", false, fmt.Errorf("unsupported broker URL scheme %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return "", "", false, errors.New("broker URL host is required")
	}
	port := u.Port()
	if port == "" {
		if tlsConn {
			port = "8883"
		} else {
			port = "1883"
		}
	}
	return "tcp", net.JoinHostPort(host, port), tlsConn, nil
}

func (d *Dispatcher) connect(conn net.Conn) error {
	clientID := d.ClientID
	if clientID == "" {
		clientID = "oarlockd"
	}
	var vh bytes.Buffer
	writeString(&vh, "MQTT")
	vh.WriteByte(4) // MQTT 3.1.1
	flags := byte(0x02)
	if d.Password != "" {
		flags |= 0x40
	}
	if d.Username != "" {
		flags |= 0x80
	}
	vh.WriteByte(flags)
	_ = binary.Write(&vh, binary.BigEndian, uint16(30))
	writeString(&vh, clientID)
	if d.Username != "" {
		writeString(&vh, d.Username)
	}
	if d.Password != "" {
		writeString(&vh, d.Password)
	}
	if err := writePacket(conn, 0x10, vh.Bytes()); err != nil {
		return fmt.Errorf("mqtt dispatcher: connect packet: %w", err)
	}
	packetType, body, err := readPacket(conn)
	if err != nil {
		return fmt.Errorf("mqtt dispatcher: connack: %w", err)
	}
	if packetType != 0x20 || len(body) != 2 {
		return fmt.Errorf("mqtt dispatcher: unexpected CONNACK")
	}
	if body[1] != 0 {
		return fmt.Errorf("mqtt dispatcher: broker refused connection (%d)", body[1])
	}
	return nil
}

func publish(conn net.Conn, topic string, payload []byte, qos byte) error {
	var body bytes.Buffer
	writeString(&body, topic)
	packetID := uint16(1)
	if qos > 0 {
		_ = binary.Write(&body, binary.BigEndian, packetID)
	}
	body.Write(payload)
	header := byte(0x30 | (qos << 1))
	if err := writePacket(conn, header, body.Bytes()); err != nil {
		return fmt.Errorf("mqtt dispatcher: publish: %w", err)
	}
	if qos == 0 {
		return nil
	}
	packetType, ack, err := readPacket(conn)
	if err != nil {
		return fmt.Errorf("mqtt dispatcher: puback: %w", err)
	}
	if packetType != 0x40 || len(ack) != 2 || binary.BigEndian.Uint16(ack) != packetID {
		return fmt.Errorf("mqtt dispatcher: unexpected PUBACK")
	}
	return nil
}

func writeString(w io.Writer, s string) {
	_ = binary.Write(w, binary.BigEndian, uint16(len(s)))
	_, _ = io.WriteString(w, s)
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
	return header[0] & 0xF0, body, nil
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
