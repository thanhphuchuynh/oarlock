package authorizedkeys_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	xssh "golang.org/x/crypto/ssh"

	"github.com/oarlock/oarlock/internal/auth/authorizedkeys"
	"github.com/oarlock/oarlock/pkg/plugin"
)

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func newKey(t *testing.T) (xssh.PublicKey, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := xssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k, strings.TrimRight(string(xssh.MarshalAuthorizedKey(k)), "\n")
}

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCommentBecomesThePrincipal(t *testing.T) {
	key, line := newKey(t)
	a, err := authorizedkeys.Open(write(t, line+" admin@mail.com\n"), quiet())
	if err != nil {
		t.Fatal(err)
	}
	p, err := a.AuthPublicKey(context.Background(), "any-device", key)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "admin@mail.com" {
		t.Errorf("principal %q", p.ID)
	}
	if p.Email != "admin@mail.com" {
		t.Errorf("email %q", p.Email)
	}
}

func TestExplicitPrincipalWins(t *testing.T) {
	key, line := newKey(t)
	a, err := authorizedkeys.Open(
		write(t, line+" oarlock-principal=u-1234 some other words\n"), quiet())
	if err != nil {
		t.Fatal(err)
	}
	p, err := a.AuthPublicKey(context.Background(), "d", key)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "u-1234" {
		t.Errorf("principal %q", p.ID)
	}
	// Not an email, so the field stays empty rather than holding an id that looks
	// like one.
	if p.Email != "" {
		t.Errorf("email %q", p.Email)
	}
}

// TestKeyWithNoCommentIsRefused: a recording attributed to "key #3" is a recording
// nobody can act on, so a nameless key is a load error rather than a generated name.
func TestKeyWithNoCommentIsRefused(t *testing.T) {
	_, line := newKey(t)
	_, err := authorizedkeys.Open(write(t, line+"\n"), quiet())
	if err == nil {
		t.Fatal("a key with no comment was accepted")
	}
	if !strings.Contains(err.Error(), "no principal to attribute") {
		t.Errorf("unhelpful error: %v", err)
	}
}

func TestUnknownKeyIsRefusedWithoutDetail(t *testing.T) {
	key, line := newKey(t)
	other, _ := newKey(t)
	a, err := authorizedkeys.Open(write(t, line+" admin@mail.com\n"), quiet())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.AuthPublicKey(context.Background(), "d", other); err == nil {
		t.Fatal("an unregistered key was accepted")
	}
	if _, err := a.AuthPublicKey(context.Background(), "d", key); err != nil {
		t.Fatalf("a registered key was refused: %v", err)
	}
}

// TestTheSSHUserIsIgnoredForAuthentication: the username is the device id, and one
// operator's credentials address the whole fleet by design.
func TestTheSSHUserIsIgnoredForAuthentication(t *testing.T) {
	key, line := newKey(t)
	a, err := authorizedkeys.Open(write(t, line+" admin@mail.com\n"), quiet())
	if err != nil {
		t.Fatal(err)
	}
	for _, user := range []string{"treadmill-4821", "rower-1", "", "anything"} {
		p, err := a.AuthPublicKey(context.Background(), user, key)
		if err != nil || p.ID != "admin@mail.com" {
			t.Errorf("user %q: %v / %+v", user, err, p)
		}
	}
}

func TestDuplicateKeyIsRefused(t *testing.T) {
	_, line := newKey(t)
	body := line + " a@example.com\n" + line + " b@example.com\n"
	if _, err := authorizedkeys.Open(write(t, body), quiet()); err == nil {
		t.Fatal("the same key was accepted twice with different principals")
	}
}

func TestMultipleKeysAndBlankLines(t *testing.T) {
	k1, l1 := newKey(t)
	k2, l2 := newKey(t)
	body := l1 + " a@example.com\n" + l2 + " b@example.com\n\n"
	a, err := authorizedkeys.Open(write(t, body), quiet())
	if err != nil {
		t.Fatal(err)
	}
	if a.Len() != 2 {
		t.Fatalf("loaded %d keys, want 2", a.Len())
	}
	// Not a map keyed on the key: ssh.PublicKey is an interface over a slice, so it
	// is unhashable — which is exactly why the authenticator keys on the marshalled
	// bytes rather than on the interface value.
	for _, tc := range []struct {
		key  xssh.PublicKey
		want string
	}{{k1, "a@example.com"}, {k2, "b@example.com"}} {
		p, err := a.AuthPublicKey(context.Background(), "d", tc.key)
		if err != nil || p.ID != tc.want {
			t.Errorf("want %q, got %+v (%v)", tc.want, p, err)
		}
	}
}

func TestMalformedFileIsRefused(t *testing.T) {
	if _, err := authorizedkeys.Open(write(t, "this is not a key\n"), quiet()); err == nil {
		t.Fatal("a malformed file loaded")
	}
	if _, err := authorizedkeys.Open(filepath.Join(t.TempDir(), "nope"), quiet()); err == nil {
		t.Fatal("a missing file loaded")
	}
}

// TestDelegationIsRefused: a file of keys cannot verify an assertion about somebody
// else, and ErrUnsupported refuses every On-Behalf-Of call — which is the right
// answer rather than a weaker one.
func TestDelegationIsRefused(t *testing.T) {
	_, line := newKey(t)
	a, err := authorizedkeys.Open(write(t, line+" a@example.com\n"), quiet())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.AuthDelegated(context.Background(),
		&plugin.Principal{ID: "svc-crm"}, "some-token"); err == nil {
		t.Fatal("delegation was accepted")
	}
}

func TestPrincipalIsCopied(t *testing.T) {
	// A handler must not be able to mutate the shared entry for everyone else.
	key, line := newKey(t)
	a, _ := authorizedkeys.Open(write(t, line+" a@example.com\n"), quiet())
	p1, _ := a.AuthPublicKey(context.Background(), "d", key)
	p1.ID = "tampered"
	p2, _ := a.AuthPublicKey(context.Background(), "d", key)
	if p2.ID != "a@example.com" {
		t.Errorf("the shared entry was mutated: %q", p2.ID)
	}
}
