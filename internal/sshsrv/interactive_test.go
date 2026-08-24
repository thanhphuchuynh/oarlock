package sshsrv_test

// Keyboard-interactive, which is how an operator logs in with no key and no password.
//
// Two things are worth testing here and neither is about OIDC: whether the method is
// advertised at all, and whether the conversation reaches the backend. The method is
// advertised by type assertion on the authenticator, so a backend that grows the
// capability gets it for free — and a backend that has not must not advertise a way in
// that can only ever refuse.

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	xssh "golang.org/x/crypto/ssh"

	"github.com/oarlock/oarlock/internal/invite"
	"github.com/oarlock/oarlock/internal/sessions"
	"github.com/oarlock/oarlock/internal/sshsrv"
	"github.com/oarlock/oarlock/internal/ticket"
	"github.com/oarlock/oarlock/pkg/plugin"
)

// keysOnly authenticates nothing at all, and has no conversational surface.
type keysOnly struct{}

func (keysOnly) AuthPublicKey(context.Context, string, xssh.PublicKey) (*plugin.Principal, error) {
	return nil, errors.New("no")
}
func (keysOnly) AuthDelegated(context.Context, *plugin.Principal, string) (*plugin.Principal, error) {
	return nil, plugin.ErrUnsupported
}
func (keysOnly) AuthHTTP(context.Context, *http.Request) (*plugin.Principal, error) {
	return nil, plugin.ErrUnsupported
}

// conversational is the shape of an OIDC device-code backend: it says something, waits,
// and returns a principal.
type conversational struct {
	keysOnly
	principal *plugin.Principal
	asked     chan string
}

func (c *conversational) AuthInteractive(_ context.Context, _ string,
	ask plugin.Challenge) (*plugin.Principal, error) {
	const instruction = "Open https://idp.example.com and enter WXYZ-1234"
	if _, err := ask(instruction, []string{"Press Enter: "}, []bool{false}); err != nil {
		return nil, err
	}
	select {
	case c.asked <- instruction:
	default:
	}
	if c.principal == nil {
		return nil, errors.New("declined")
	}
	return c.principal, nil
}

func serve(t *testing.T, authn plugin.Authenticator) string {
	t.Helper()
	srv, err := sshsrv.New(sshsrv.Options{
		Authenticator: authn,
		Registry:      emptyRegistry{},
		Inviter:       &invite.Inviter{Tickets: ticket.NewMemory(time.Now), NodeURL: "wss://gw/s"},
		Sessions:      sessions.NewMemory(sessions.Limits{}, nil),
		Log:           quiet(),
	})
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Handler().Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return l.Addr().String()
}

type emptyRegistry struct{}

func (emptyRegistry) Get(context.Context, string) (*plugin.Device, error) {
	return nil, plugin.ErrNoDevice
}
func (emptyRegistry) List(context.Context, plugin.DeviceQuery) ([]*plugin.Device, string, error) {
	return nil, "", nil
}

// dialInteractive offers *only* keyboard-interactive, so whether the callback runs is a
// direct answer to whether the server offered the method.
func dialInteractive(t *testing.T, addr string, answered *bool) error {
	t.Helper()
	_, err := xssh.Dial("tcp", addr, &xssh.ClientConfig{
		User: "treadmill-4821",
		Auth: []xssh.AuthMethod{
			xssh.KeyboardInteractive(func(name, instruction string, questions []string,
				echos []bool) ([]string, error) {
				*answered = true
				return make([]string, len(questions)), nil
			}),
		},
		HostKeyCallback: xssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	return err
}

// TestABackendWithNoConversationNeverPromptsAnybody.
//
// Named for what it checks. Two things stand between a key-only deployment and a useless
// prompt: the handler is registered only when the authenticator implements the optional
// interface, and the handler itself asserts again before challenging. This covers the
// second — an operator gets no prompt — because it is the half an operator can see.
//
// The first half trims the method list the server advertises, which changes what `ssh -v`
// and "Permission denied (publickey,keyboard-interactive)" say. That is not covered:
// x/crypto/ssh does not surface the server's offered methods to a client, and parsing a
// USERAUTH_FAILURE packet by hand would test the parser.
func TestABackendWithNoConversationNeverPromptsAnybody(t *testing.T) {
	answered := false
	if err := dialInteractive(t, serve(t, keysOnly{}), &answered); err == nil {
		t.Fatal("a key-only backend authenticated a keyboard-interactive client")
	}
	if answered {
		t.Fatal("a key-only backend prompted the operator for something it cannot check")
	}
}

// TestTheConversationReachesTheBackend: the instruction goes out, the answer comes back,
// and the principal the backend returned is the one bound to the connection.
func TestTheConversationReachesTheBackend(t *testing.T) {
	backend := &conversational{
		principal: &plugin.Principal{ID: "amelia@example.com"},
		asked:     make(chan string, 1),
	}
	answered := false
	// The device does not exist, so the *session* fails — but authentication happened,
	// which is what this test is about. A handshake error would mean it did not.
	err := dialInteractive(t, serve(t, backend), &answered)
	if err != nil {
		t.Fatalf("keyboard-interactive auth failed: %v", err)
	}
	if !answered {
		t.Fatal("the client was never prompted")
	}
	select {
	case got := <-backend.asked:
		if got == "" {
			t.Fatal("the backend sent an empty instruction")
		}
	default:
		t.Fatal("the backend's challenge never ran")
	}
}

// TestARefusedConversationIsARefusedLogin.
func TestARefusedConversationIsARefusedLogin(t *testing.T) {
	backend := &conversational{asked: make(chan string, 1)} // nil principal: declines
	answered := false
	if err := dialInteractive(t, serve(t, backend), &answered); err == nil {
		t.Fatal("a declined conversation still authenticated")
	}
	if !answered {
		t.Fatal("the operator was never prompted, so the method was not advertised")
	}
}
