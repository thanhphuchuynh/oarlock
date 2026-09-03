package sshca_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oarlock/oarlock/internal/auth/sshca"
	"github.com/oarlock/oarlock/pkg/plugin"
	"github.com/oarlock/oarlock/pkg/plugin/plugintest"
)

// TestConformance runs the CA backend through the suite every authenticator runs.
//
// Unlike the rest of this file it uses real time, because the suite builds its own
// contexts and knows nothing about an injected clock — which is worth having: it is the
// one place the certificate is checked against the wall clock the gateway will actually
// use.
func TestConformance(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca_keys")

	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, ssh.MarshalAuthorizedKey(caSigner.PublicKey()), 0o600); err != nil {
		t.Fatal(err)
	}

	userPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	userKey, err := ssh.NewPublicKey(userPub)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	good := &ssh.Certificate{
		Key:             userKey,
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           "conformance",
		ValidPrincipals: []string{"phuc@example.com"},
		ValidAfter:      uint64(now.Add(-time.Minute).Unix()),
		ValidBefore:     uint64(now.Add(time.Hour).Unix()),
	}
	if err := good.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatal(err)
	}

	// A well-formed key the backend does not know. A bare key rather than a certificate
	// from another CA, because the interesting refusal for this backend is that a plain
	// key never authenticates at all.
	badPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bad, err := ssh.NewPublicKey(badPub)
	if err != nil {
		t.Fatal(err)
	}

	plugintest.Authenticator(t, plugintest.AuthenticatorHarness{
		New: func(t *testing.T) plugin.Authenticator {
			a, err := sshca.Open(sshca.Options{CAKeys: caPath, Log: quiet()})
			if err != nil {
				t.Fatal(err)
			}
			return a
		},
		GoodKey: func(*testing.T) (ssh.PublicKey, string) {
			return good, "phuc@example.com"
		},
		BadKey: func(*testing.T) ssh.PublicKey { return bad },
	})
}
