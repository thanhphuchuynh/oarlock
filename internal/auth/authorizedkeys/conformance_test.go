package authorizedkeys_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	xssh "golang.org/x/crypto/ssh"

	"github.com/oarlock/oarlock/internal/auth/authorizedkeys"
	"github.com/oarlock/oarlock/pkg/plugin"
	"github.com/oarlock/oarlock/pkg/plugin/plugintest"
)

// TestConformance runs the authorized_keys backend through the conformance suite.
//
// It is the backend most likely to be *copied* by somebody writing their own — it is the
// simplest one in the tree — so it had better be the one that passes.
func TestConformance(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")

	knownPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	known, err := xssh.NewPublicKey(knownPub)
	if err != nil {
		t.Fatal(err)
	}
	line := string(xssh.MarshalAuthorizedKey(known))
	if err := os.WriteFile(path, []byte(line[:len(line)-1]+" admin@mail.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	unknownPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := xssh.NewPublicKey(unknownPub)
	if err != nil {
		t.Fatal(err)
	}

	plugintest.Authenticator(t, plugintest.AuthenticatorHarness{
		New: func(t *testing.T) plugin.Authenticator {
			a, err := authorizedkeys.Open(path, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err != nil {
				t.Fatal(err)
			}
			return a
		},
		GoodKey: func(*testing.T) (xssh.PublicKey, string) {
			return known, "admin@mail.com"
		},
		BadKey: func(*testing.T) xssh.PublicKey { return unknown },
		// No GoodRequest: a file of SSH keys has no way to authenticate an HTTP caller,
		// and the suite asserts it says ErrUnsupported rather than making every API
		// request look like a bad password.
	})
}
