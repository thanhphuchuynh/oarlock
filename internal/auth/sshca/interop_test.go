package sshca_test

// Interop with real OpenSSH.
//
// Every other test in this package builds certificates with x/crypto's own SignCert,
// which means they all agree with each other by construction. What they cannot show is
// that a certificate `ssh-keygen -s` actually produces is accepted — and that is the only
// kind anybody will ever present, since no operator mints certificates with a Go program.
//
// The difference is not hypothetical: ssh-keygen adds extensions by default
// (permit-pty, permit-agent-forwarding and friends), sets ValidAfter to the current
// minute rather than the second, and writes the certificate in a wire format this code
// only ever reads. Any one of those could be refused by a backend that looked correct
// against its own output.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oarlock/oarlock/internal/auth/sshca"
)

func TestARealOpenSSHCertificateIsAccepted(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is unavailable; skipping the interop check")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command(keygen, args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen %v: %v\n%s", args, err, out)
		}
	}

	run("-q", "-t", "ed25519", "-f", "ca", "-N", "", "-C", "test-ca")
	run("-q", "-t", "ed25519", "-f", "user", "-N", "")
	run("-q", "-s", "ca", "-I", "admin@mail.com",
		"-n", "admin@mail.com,oncall", "-V", "+1h", "-z", "42", "user.pub")

	caKeys := filepath.Join(dir, "ca.pub")
	a, err := sshca.Open(sshca.Options{CAKeys: caKeys, Log: quiet()})
	if err != nil {
		t.Fatalf("opening with a real ssh-keygen CA key: %v", err)
	}

	certPEM, err := os.ReadFile(filepath.Join(dir, "user-cert.pub"))
	if err != nil {
		t.Fatal(err)
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(certPEM)
	if err != nil {
		t.Fatalf("parsing a real certificate: %v", err)
	}

	p, err := a.AuthPublicKey(context.Background(), "treadmill-4821", key)
	if err != nil {
		t.Fatalf("a certificate from real ssh-keygen was refused: %v", err)
	}
	if p.ID != "admin@mail.com" {
		t.Fatalf("principal = %q", p.ID)
	}
	if len(p.Groups) != 2 || p.Groups[1] != "oncall" {
		t.Fatalf("groups = %v, want both principals", p.Groups)
	}
	// ssh-keygen's default extensions (permit-pty and friends) are extensions, not
	// critical options, so they must not be refused the way an unknown critical option is.
	cert := key.(*ssh.Certificate)
	if len(cert.Extensions) == 0 {
		t.Fatal("expected ssh-keygen's default extensions; the test is not exercising them")
	}
	if p.Expiry.IsZero() || p.Expiry.After(time.Now().Add(2*time.Hour)) {
		t.Fatalf("expiry = %s, want roughly an hour out", p.Expiry)
	}
}

// TestARealCertificateFromAnotherCAIsRefused, so the test above is not passing because
// everything is accepted.
func TestARealCertificateFromAnotherCAIsRefused(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is unavailable; skipping the interop check")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command(keygen, args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen %v: %v\n%s", args, err, out)
		}
	}
	run("-q", "-t", "ed25519", "-f", "ca", "-N", "")
	run("-q", "-t", "ed25519", "-f", "rogue", "-N", "")
	run("-q", "-t", "ed25519", "-f", "user", "-N", "")
	run("-q", "-s", "rogue", "-I", "admin@mail.com", "-n", "admin@mail.com",
		"-V", "+1h", "user.pub")

	a, err := sshca.Open(sshca.Options{CAKeys: filepath.Join(dir, "ca.pub"), Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, "user-cert.pub"))
	if err != nil {
		t.Fatal(err)
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.AuthPublicKey(context.Background(), "treadmill-4821", key); err == nil {
		t.Fatal("a certificate from an untrusted CA was accepted")
	}
}
