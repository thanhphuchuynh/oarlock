package sshca_test

// What a certificate has to survive to become a principal.
//
// Almost every test here is a refusal, and that is the right shape for this file: the
// accept path is one certificate signed by a key we trust, and everything else is a way
// for a credential to look valid while carrying something this gateway has no business
// honouring. The ones that would be quietest if they broke — a host certificate accepted
// for user auth, a `source-address` restriction silently dropped, a certificate that never
// expires — are the ones worth reading.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oarlock/oarlock/internal/auth/sshca"
	"github.com/oarlock/oarlock/pkg/plugin"
)

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// ── a certificate authority, in a temp dir ──────────────────────────────────────

type ca struct {
	signer ssh.Signer
	dir    string
	path   string // the trusted-keys file
	now    time.Time
}

func newCA(t *testing.T) *ca {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	c := &ca{
		signer: signer,
		dir:    t.TempDir(),
		now:    time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC),
	}
	c.path = filepath.Join(c.dir, "ca_keys")
	c.write(t, signer.PublicKey())
	return c
}

func (c *ca) write(t *testing.T, keys ...ssh.PublicKey) {
	t.Helper()
	var b []byte
	for _, k := range keys {
		b = append(b, ssh.MarshalAuthorizedKey(k)...)
	}
	if err := os.WriteFile(c.path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// cert builds a user certificate for `principals`, valid for an hour around now, and
// signs it. tweak edits the certificate before signing, which is how every refusal case
// below produces a *validly signed* certificate that is still wrong.
func (c *ca) cert(t *testing.T, principals []string, tweak func(*ssh.Certificate)) ssh.PublicKey {
	t.Helper()
	return c.certSignedBy(t, c.signer, principals, tweak)
}

func (c *ca) certSignedBy(t *testing.T, by ssh.Signer, principals []string,
	tweak func(*ssh.Certificate)) ssh.PublicKey {
	t.Helper()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	userKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	cert := &ssh.Certificate{
		Key:             userKey,
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           "issued-to-phuc",
		ValidPrincipals: principals,
		ValidAfter:      uint64(c.now.Add(-time.Minute).Unix()),
		ValidBefore:     uint64(c.now.Add(time.Hour).Unix()),
	}
	if tweak != nil {
		tweak(cert)
	}
	if err := cert.SignCert(rand.Reader, by); err != nil {
		t.Fatal(err)
	}
	return cert
}

func (c *ca) open(t *testing.T, edit func(*sshca.Options)) *sshca.Authenticator {
	t.Helper()
	o := sshca.Options{CAKeys: c.path, Log: quiet(), Now: func() time.Time { return c.now }}
	if edit != nil {
		edit(&o)
	}
	a, err := sshca.Open(o)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	return a
}

// auth is the common call: no peer address recorded.
func auth(a *sshca.Authenticator, key ssh.PublicKey) (*plugin.Principal, error) {
	return a.AuthPublicKey(context.Background(), "treadmill-4821", key)
}

// authFrom records a peer address, as the SSH front door does.
func authFrom(a *sshca.Authenticator, key ssh.PublicKey, remote string) (*plugin.Principal, error) {
	addr, err := net.ResolveTCPAddr("tcp", remote)
	if err != nil {
		return nil, err
	}
	ctx := plugin.WithPeer(context.Background(), addr)
	return a.AuthPublicKey(ctx, "treadmill-4821", key)
}

// ── the accept path ─────────────────────────────────────────────────────────────

// TestAValidCertificateNamesItsOperator.
//
// The SSH username here is a device id — `treadmill-4821` — and it appears nowhere in the
// certificate. That is the whole difference between this backend and every other SSH CA
// integration: the identity comes from what the CA signed, not from what the client typed.
func TestAValidCertificateNamesItsOperator(t *testing.T) {
	c := newCA(t)
	a := c.open(t, nil)

	p, err := auth(a, c.cert(t, []string{"admin@mail.com", "oncall"}, nil))
	if err != nil {
		t.Fatalf("a valid certificate was refused: %v", err)
	}
	if p.ID != "admin@mail.com" {
		t.Fatalf("principal = %q, want the first valid principal", p.ID)
	}
	if p.Email != "admin@mail.com" {
		t.Fatalf("email = %q", p.Email)
	}
}

// TestEveryPrincipalBecomesAGroup.
//
// In a real CA deployment principals are roles, and this is what lets an authorisation
// rule match one. Dropping them would mean the CA can express `oncall` and the gateway
// cannot read it.
func TestEveryPrincipalBecomesAGroup(t *testing.T) {
	c := newCA(t)
	a := c.open(t, nil)

	p, err := auth(a, c.cert(t, []string{"admin@mail.com", "oncall", "dba"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"admin@mail.com": true, "oncall": true, "dba": true}
	if len(p.Groups) != len(want) {
		t.Fatalf("groups = %v, want all three principals", p.Groups)
	}
	for _, g := range p.Groups {
		if !want[g] {
			t.Fatalf("unexpected group %q in %v", g, p.Groups)
		}
	}
}

// TestTheSessionCannotOutliveTheCertificate is the point of the whole backend.
//
// Principal.Expiry is a ceiling on the session independent of the authorisation re-check
// interval. Without it a certificate expiring in ten minutes opens a shell that lasts all
// night, and "short-lived credential" describes the login rather than the access.
func TestTheSessionCannotOutliveTheCertificate(t *testing.T) {
	c := newCA(t)
	a := c.open(t, nil)

	p, err := auth(a, c.cert(t, []string{"admin@mail.com"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	want := c.now.Add(time.Hour)
	if !p.Expiry.Equal(want) {
		t.Fatalf("expiry = %s, want the certificate's valid_before %s", p.Expiry, want)
	}
}

// TestKeyIDCanBeTheIdentity. What `ssh-keygen -I` sets, and where Vault and Teleport put
// the username.
func TestKeyIDCanBeTheIdentity(t *testing.T) {
	c := newCA(t)
	a := c.open(t, func(o *sshca.Options) { o.PrincipalFrom = sshca.FromKeyID })

	p, err := auth(a, c.cert(t, []string{"oncall"}, func(cert *ssh.Certificate) {
		cert.KeyId = "admin@mail.com"
	}))
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "admin@mail.com" {
		t.Fatalf("principal = %q, want the key id", p.ID)
	}
}

// TestACertificateWhoseKeyIDIsNotAPrincipalStillVerifies.
//
// The subtle one. CheckCert wants a principal that appears in valid_principals, and a key
// id need not. Passing the key id straight through would fail certificates that are
// entirely valid — every Vault-issued one, for instance, where the key id is
// `vault-userpass-phuc` and the principals are roles.
func TestACertificateWhoseKeyIDIsNotAPrincipalStillVerifies(t *testing.T) {
	c := newCA(t)
	a := c.open(t, func(o *sshca.Options) { o.PrincipalFrom = sshca.FromKeyID })

	p, err := auth(a, c.cert(t, []string{"oncall", "dba"}, func(cert *ssh.Certificate) {
		cert.KeyId = "vault-userpass-phuc"
	}))
	if err != nil {
		t.Fatalf("a valid certificate was refused because its key id is not a principal: %v", err)
	}
	if p.ID != "vault-userpass-phuc" {
		t.Fatalf("principal = %q", p.ID)
	}
}

// TestARotatedCAKeepsBothKeysWorking. Publish the new key alongside the old, re-issue,
// then remove the old — which only works if both are trusted at once.
func TestARotatedCAKeepsBothKeysWorking(t *testing.T) {
	c := newCA(t)
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	second, err := ssh.NewSignerFromKey(priv2)
	if err != nil {
		t.Fatal(err)
	}
	c.write(t, c.signer.PublicKey(), second.PublicKey())
	a := c.open(t, nil)

	if a.Len() != 2 {
		t.Fatalf("loaded %d authorities, want 2", a.Len())
	}
	for name, signer := range map[string]ssh.Signer{"old": c.signer, "new": second} {
		if _, err := auth(a, c.certSignedBy(t, signer, []string{"admin@mail.com"}, nil)); err != nil {
			t.Fatalf("the %s CA's certificate was refused: %v", name, err)
		}
	}
}

// ── refusals ────────────────────────────────────────────────────────────────────

// TestABarePublicKeyIsRefused.
//
// No fallback, deliberately. CertChecker offers UserKeyFallback; wiring one would mean a
// deployment that believes it revokes by expiry while a plain key quietly still works —
// and the plain key is the one nobody is rotating.
func TestABarePublicKeyIsRefused(t *testing.T) {
	c := newCA(t)
	a := c.open(t, nil)

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth(a, key); err == nil {
		t.Fatal("a bare public key authenticated against a CA backend")
	}
}

// TestAHostCertificateCannotAuthenticateAnOperator.
//
// Where one CA signs both hosts and users — which is common — accepting a host
// certificate here would make every host key in the fleet an operator credential.
func TestAHostCertificateCannotAuthenticateAnOperator(t *testing.T) {
	c := newCA(t)
	a := c.open(t, nil)

	hostCert := c.cert(t, []string{"admin@mail.com"}, func(cert *ssh.Certificate) {
		cert.CertType = ssh.HostCert
	})
	_, err := auth(a, hostCert)
	if err == nil {
		t.Fatal("a host certificate authenticated an operator")
	}
	if !strings.Contains(err.Error(), "user certificate") {
		t.Fatalf("the refusal does not name the cause: %v", err)
	}
}

// TestAnUntrustedAuthorityIsRefused. The base case, and the one that would make everything
// else pointless.
func TestAnUntrustedAuthorityIsRefused(t *testing.T) {
	c := newCA(t)
	a := c.open(t, nil)

	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	other, err := ssh.NewSignerFromKey(otherPriv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth(a, c.certSignedBy(t, other, []string{"admin@mail.com"}, nil)); err == nil {
		t.Fatal("a certificate from an unknown CA was accepted")
	}
}

// TestAnExpiredOrNotYetValidCertificateIsRefused.
func TestAnExpiredOrNotYetValidCertificateIsRefused(t *testing.T) {
	c := newCA(t)
	a := c.open(t, nil)

	for name, tweak := range map[string]func(*ssh.Certificate){
		"expired an hour ago": func(cert *ssh.Certificate) {
			cert.ValidAfter = uint64(c.now.Add(-2 * time.Hour).Unix())
			cert.ValidBefore = uint64(c.now.Add(-time.Hour).Unix())
		},
		"valid from tomorrow": func(cert *ssh.Certificate) {
			cert.ValidAfter = uint64(c.now.Add(24 * time.Hour).Unix())
			cert.ValidBefore = uint64(c.now.Add(25 * time.Hour).Unix())
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := auth(a, c.cert(t, []string{"admin@mail.com"}, tweak)); err == nil {
				t.Fatalf("a certificate %s was accepted", name)
			}
		})
	}
}

// TestACertificateThatNeverExpiresIsRefused.
//
// CertTimeInfinity is a legal value and OpenSSH will issue one. It is also the one thing a
// short-lived credential must not be: a CA that can mint an eternal certificate has turned
// itself back into an authorized_keys file with extra steps. Refused even when the
// lifetime cap is disabled, which is the case somebody would reach for to "fix" this.
func TestACertificateThatNeverExpiresIsRefused(t *testing.T) {
	c := newCA(t)
	for name, edit := range map[string]func(*sshca.Options){
		"with the default cap": nil,
		"with the cap disabled": func(o *sshca.Options) {
			o.MaxLifetime = -1
		},
	} {
		t.Run(name, func(t *testing.T) {
			a := c.open(t, edit)
			cert := c.cert(t, []string{"admin@mail.com"}, func(cert *ssh.Certificate) {
				cert.ValidBefore = ssh.CertTimeInfinity
			})
			_, err := auth(a, cert)
			if err == nil {
				t.Fatal("a certificate that never expires was accepted")
			}
			if !strings.Contains(err.Error(), "never expires") {
				t.Fatalf("the refusal does not name the cause: %v", err)
			}
		})
	}
}

// TestACertificateIssuedForTooLongIsRefused.
//
// The cap is on the *issued* window, not the remaining one: what it bounds is the CA's
// policy, and a year-long certificate seen an hour in is exactly as wrong as one seen at
// the start.
func TestACertificateIssuedForTooLongIsRefused(t *testing.T) {
	c := newCA(t)
	a := c.open(t, func(o *sshca.Options) { o.MaxLifetime = time.Hour })

	cert := c.cert(t, []string{"admin@mail.com"}, func(cert *ssh.Certificate) {
		cert.ValidAfter = uint64(c.now.Add(-time.Minute).Unix())
		cert.ValidBefore = uint64(c.now.Add(48 * time.Hour).Unix())
	})
	_, err := auth(a, cert)
	if err == nil {
		t.Fatal("a certificate issued for 48h was accepted under a 1h cap")
	}
	if !strings.Contains(err.Error(), "at most") {
		t.Fatalf("the refusal does not say what the limit is: %v", err)
	}

	// And one inside the cap still works, or the check is just an outage. Note the
	// window is measured from valid_after, which CAs routinely backdate a little for
	// skew — so a "one hour" certificate is usually slightly more than one hour, and a
	// cap set to exactly the issuing TTL would refuse every certificate.
	short := c.cert(t, []string{"admin@mail.com"}, func(cert *ssh.Certificate) {
		cert.ValidAfter = uint64(c.now.Add(-time.Minute).Unix())
		cert.ValidBefore = uint64(c.now.Add(30 * time.Minute).Unix())
	})
	if _, err := auth(a, short); err != nil {
		t.Fatalf("a certificate inside the cap was refused: %v", err)
	}
}

// TestACertificateWithNoPrincipalsIsRefused.
//
// OpenSSH reads an empty principal list as "valid for every user". Here that would mean a
// session nobody can be held to — nothing to record, nothing for an authorisation rule to
// match — and an unattributable session is worse than no session.
func TestACertificateWithNoPrincipalsIsRefused(t *testing.T) {
	c := newCA(t)
	a := c.open(t, nil)

	_, err := auth(a, c.cert(t, nil, nil))
	if err == nil {
		t.Fatal("a certificate valid for every user was accepted")
	}
	if !strings.Contains(err.Error(), "nobody") {
		t.Fatalf("the refusal does not explain: %v", err)
	}
}

// TestAnUnknownCriticalOptionIsRefused.
//
// Critical means critical: an option this gateway does not implement is a restriction the
// CA operator believes is in force. Honouring the certificate and ignoring the option is
// the failure they would never find out about.
func TestAnUnknownCriticalOptionIsRefused(t *testing.T) {
	c := newCA(t)
	a := c.open(t, nil)

	cert := c.cert(t, []string{"admin@mail.com"}, func(cert *ssh.Certificate) {
		cert.CriticalOptions = map[string]string{"force-command": "/usr/bin/true"}
	})
	if _, err := auth(a, cert); err == nil {
		t.Fatal("a certificate carrying force-command was accepted by a gateway that " +
			"does not implement it")
	}
}

// TestARevokedSerialIsRefused, and reload picks up a new one.
func TestARevokedSerialIsRefused(t *testing.T) {
	c := newCA(t)
	revocations := filepath.Join(c.dir, "revoked")
	if err := os.WriteFile(revocations, []byte("# stolen\n7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := c.open(t, func(o *sshca.Options) { o.Revocations = revocations })

	revoked := c.cert(t, []string{"admin@mail.com"}, func(cert *ssh.Certificate) {
		cert.Serial = 7
	})
	if _, err := auth(a, revoked); err == nil {
		t.Fatal("a revoked certificate was accepted")
	}
	// Another serial from the same CA is unaffected.
	fine := c.cert(t, []string{"admin@mail.com"}, func(cert *ssh.Certificate) {
		cert.Serial = 8
	})
	if _, err := auth(a, fine); err != nil {
		t.Fatalf("an unrevoked certificate was refused: %v", err)
	}

	// Revoking 8 takes effect on reload, without a restart.
	if err := os.WriteFile(revocations, []byte("7\n8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, err := auth(a, fine); err == nil {
		t.Fatal("a newly revoked certificate was still accepted after reload")
	}
}

// TestAnUnreadableRevocationListRefusesToLoad.
//
// A revocation list with a line nobody noticed is a revocation that did not happen, so a
// malformed one fails loudly rather than loading the lines it could parse.
func TestAnUnreadableRevocationListRefusesToLoad(t *testing.T) {
	c := newCA(t)
	revocations := filepath.Join(c.dir, "revoked")
	if err := os.WriteFile(revocations, []byte("7\nnot-a-serial\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := sshca.Open(sshca.Options{
		CAKeys: c.path, Revocations: revocations, Log: quiet(),
	})
	if err == nil {
		t.Fatal("a malformed revocation list loaded anyway")
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("the error does not point at the line: %v", err)
	}
}

// ── source-address ──────────────────────────────────────────────────────────────

// TestSourceAddressIsEnforced.
//
// x/crypto skips this option in CheckCert because it enforces it from the Permissions its
// own callback returns — which this interface never produces. Enforced here or not at all,
// and "not at all" means a certificate restricted to one office works from anywhere while
// looking exactly like it is working correctly.
func TestSourceAddressIsEnforced(t *testing.T) {
	c := newCA(t)
	a := c.open(t, nil)

	cert := c.cert(t, []string{"admin@mail.com"}, func(cert *ssh.Certificate) {
		cert.CriticalOptions = map[string]string{"source-address": "198.51.100.0/24,203.0.113.7"}
	})

	for _, from := range []string{"198.51.100.9:5000", "203.0.113.7:5000"} {
		if _, err := authFrom(a, cert, from); err != nil {
			t.Fatalf("a permitted address %s was refused: %v", from, err)
		}
	}
	for _, from := range []string{"192.0.2.1:5000", "203.0.113.8:5000"} {
		if _, err := authFrom(a, cert, from); err == nil {
			t.Fatalf("address %s was accepted despite the restriction", from)
		}
	}
}

// TestSourceAddressIsRefusedWhenTheAddressIsUnknown.
//
// The fail-closed half. A surface that did not record the peer cannot check the
// restriction, and honouring the certificate anyway is the restriction quietly not
// applying — the exact failure this whole option exists to prevent.
func TestSourceAddressIsRefusedWhenTheAddressIsUnknown(t *testing.T) {
	c := newCA(t)
	a := c.open(t, nil)

	cert := c.cert(t, []string{"admin@mail.com"}, func(cert *ssh.Certificate) {
		cert.CriticalOptions = map[string]string{"source-address": "198.51.100.0/24"}
	})
	_, err := auth(a, cert) // no peer recorded
	if err == nil {
		t.Fatal("an address-restricted certificate was accepted with no address to check")
	}
	if !strings.Contains(err.Error(), "cannot be checked") {
		t.Fatalf("the refusal does not explain: %v", err)
	}
}

// TestAnEmptySourceAddressDeniesEverything, as OpenSSH does: present-but-empty is a
// deliberate lockout, not an absent restriction.
func TestAnEmptySourceAddressDeniesEverything(t *testing.T) {
	c := newCA(t)
	a := c.open(t, nil)

	cert := c.cert(t, []string{"admin@mail.com"}, func(cert *ssh.Certificate) {
		cert.CriticalOptions = map[string]string{"source-address": ""}
	})
	if _, err := authFrom(a, cert, "198.51.100.9:5000"); err == nil {
		t.Fatal("an empty source-address matched an address")
	}
}

// TestACertificateWithNoRestrictionIsUnaffectedByTheAddress. The common case must not
// need a peer address at all.
func TestACertificateWithNoRestrictionIsUnaffectedByTheAddress(t *testing.T) {
	c := newCA(t)
	a := c.open(t, nil)
	if _, err := auth(a, c.cert(t, []string{"admin@mail.com"}, nil)); err != nil {
		t.Fatalf("an unrestricted certificate needed a peer address: %v", err)
	}
}

// ── signature algorithms ────────────────────────────────────────────────────────

// TestASHA1SignedCertificateIsRefused.
//
// `ssh-rsa` names an RSA key *and* a SHA-1 signature. SHA-1 collisions are practical, and
// a CA signature is precisely what a collision would forge. The same rule the OIDC backend
// applies to JWT algorithms, for the same reason.
//
// The certificate here is signed properly and then relabelled, because the check runs
// before signature verification: what is under test is that the *claimed* algorithm is
// refused on its own, which is what stops a genuine SHA-1 certificate ever reaching the
// verifier.
func TestASHA1SignedCertificateIsRefused(t *testing.T) {
	c := newCA(t)
	a := c.open(t, nil)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaSigner, err := ssh.NewSignerFromKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	c.write(t, rsaSigner.PublicKey())
	a = c.open(t, nil)

	cert := c.certSignedBy(t, rsaSigner, []string{"admin@mail.com"}, nil).(*ssh.Certificate)
	// SignCert defaults an RSA authority to rsa-sha2-512, which is correct. Relabel it as
	// the SHA-1 algorithm a legacy CA would really produce.
	cert.Signature.Format = ssh.KeyAlgoRSA

	_, err = auth(a, cert)
	if err == nil {
		t.Fatal("a certificate claiming a SHA-1 signature was accepted")
	}
	if !strings.Contains(err.Error(), "SHA-1") {
		t.Fatalf("the refusal does not name the cause: %v", err)
	}
}

// TestAModernRSACertificateIsAccepted, so the rule above rejects the algorithm and not
// RSA itself.
func TestAModernRSACertificateIsAccepted(t *testing.T) {
	c := newCA(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaSigner, err := ssh.NewSignerFromKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	c.write(t, rsaSigner.PublicKey())
	a := c.open(t, nil)

	if _, err := auth(a, c.certSignedBy(t, rsaSigner, []string{"admin@mail.com"}, nil)); err != nil {
		t.Fatalf("an rsa-sha2 certificate was refused: %v", err)
	}
}

// ── configuration ───────────────────────────────────────────────────────────────

// TestOpenRefusesAnUnusableConfiguration. Each of these produces a gateway that looks
// configured and authenticates nobody, or — worse — trusts something it should not.
func TestOpenRefusesAnUnusableConfiguration(t *testing.T) {
	c := newCA(t)

	t.Run("no ca_keys", func(t *testing.T) {
		if _, err := sshca.Open(sshca.Options{Log: quiet()}); err == nil {
			t.Fatal("a backend with nothing to trust was accepted")
		}
	})
	t.Run("an empty ca_keys file", func(t *testing.T) {
		empty := filepath.Join(c.dir, "empty")
		if err := os.WriteFile(empty, []byte("\n# nothing here\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := sshca.Open(sshca.Options{CAKeys: empty, Log: quiet()}); err == nil {
			t.Fatal("an empty authority list was accepted")
		}
	})
	t.Run("a certificate where a CA key belongs", func(t *testing.T) {
		bad := filepath.Join(c.dir, "cert_as_ca")
		cert := c.cert(t, []string{"admin@mail.com"}, nil)
		if err := os.WriteFile(bad, ssh.MarshalAuthorizedKey(cert), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := sshca.Open(sshca.Options{CAKeys: bad, Log: quiet()})
		if err == nil {
			t.Fatal("a certificate was accepted as an authority, which would mean " +
				"trusting whatever signed it, one level removed")
		}
	})
	t.Run("an unknown principal source", func(t *testing.T) {
		_, err := sshca.Open(sshca.Options{
			CAKeys: c.path, PrincipalFrom: "whatever", Log: quiet(),
		})
		if err == nil {
			t.Fatal("an unknown principal_from was accepted")
		}
	})
}

// TestTheOtherSurfacesAreRefused. A certificate authenticates an SSH key; there is no
// honest way to turn an HTTP request or an On-Behalf-Of assertion into one.
func TestTheOtherSurfacesAreRefused(t *testing.T) {
	c := newCA(t)
	a := c.open(t, nil)

	if _, err := a.AuthHTTP(context.Background(), nil); err != plugin.ErrUnsupported {
		t.Fatalf("AuthHTTP returned %v, want ErrUnsupported", err)
	}
	if _, err := a.AuthDelegated(context.Background(), nil, "x"); err != plugin.ErrUnsupported {
		t.Fatalf("AuthDelegated returned %v, want ErrUnsupported", err)
	}
}
