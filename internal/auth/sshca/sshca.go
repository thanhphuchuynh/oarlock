// Package sshca authenticates operators from SSH certificates signed by a trusted CA.
//
// It is the answer to the question `authorized_keys` cannot answer: how do you take
// somebody's access away. A file of keys revokes by edit-on-every-replica, which is not
// a mechanism anybody wants to rely on the afternoon somebody leaves in a hurry. A CA
// revokes by *not issuing*, and every certificate already in the wild stops working on
// its own schedule.
//
// That property is only real if the schedule is short, which is why this package refuses
// certificates that never expire and caps how long an accepted one may have been issued
// for. A CA that can mint an eternal certificate has turned itself back into an
// authorized_keys file with extra steps.
//
// # The SSH username is not the certificate principal
//
// This is the one thing that makes this backend different from every SSH CA integration
// you have read. In Oarlock the SSH username is the **device id** — one operator's
// credentials address the whole fleet — so `ssh treadmill-4821@gateway` says nothing
// about who is connecting.
//
// x/crypto's CertChecker.Authenticate assumes the opposite: it calls CheckCert with
// conn.User() and requires the certificate to list it. Using it here would demand a
// certificate whose principals name every device in the fleet, which is both absurd and
// exactly backwards. So this package drives CheckCert itself, with the identity taken
// from the certificate rather than from the username the client happened to type.
//
// # What that means for principals
//
// The certificate's `valid_principals` are the identities the CA vouched for. The first
// becomes the Oarlock principal id — what is recorded, and what authorisation rules match
// — and **all** of them become groups, because in a real CA deployment principals are
// roles (`oncall`, `dba`, `ec2-user`) and a rule that can match one is a rule worth
// having. `principal_from: key_id` uses the certificate's key id instead, which is what
// OpenSSH's `-I` sets and what Vault and Teleport put the username in.
//
// A certificate with **no** principals is refused. In OpenSSH that means "valid for every
// user", which here would mean a session nobody can be held to: the recording would name
// nobody, and an authorisation rule would have nothing to match. An unattributable
// session is worse than no session.
//
// # A restriction that cannot be checked is refused, not ignored
//
// A certificate may carry critical options. x/crypto's CheckCert refuses any it does not
// know, with one exception: it skips `source-address`, because x/crypto enforces that one
// itself — from the `Permissions` its own callback returns. This interface returns a
// Principal instead, so nothing downstream would ever look at it.
//
// Left alone, that means a certificate restricted to one office would be accepted from
// anywhere, silently, and the CA operator would have no way to find out. So this package
// enforces it here, from the peer address the surface recorded — and when no address was
// recorded, refuses the certificate rather than skipping the check.
package sshca

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oarlock/oarlock/pkg/plugin"
)

// DefaultMaxLifetime caps how long a certificate may have been issued for.
//
// A day. Long enough that nobody is re-authenticating mid-incident, short enough that a
// stolen credential is a bounded problem rather than a permanent one — which is the whole
// reason to run a CA instead of a key file. Raise it deliberately, and know that the
// number you choose is how long a compromised operator credential keeps working.
const DefaultMaxLifetime = 24 * time.Hour

// DefaultSkew tolerates clock drift between this gateway and the CA that signed.
//
// Small on purpose. Skew widens the validity window at both ends, so it is not a free
// convenience: every second of it is a second a certificate works before it was issued
// and after it expired.
const DefaultSkew = 30 * time.Second

// PrincipalSource says where the principal id comes from.
type PrincipalSource string

const (
	// FromPrincipals uses the first entry in valid_principals. The default.
	FromPrincipals PrincipalSource = "principals"
	// FromKeyID uses the certificate's key id, which is what `ssh-keygen -I` sets.
	FromKeyID PrincipalSource = "key_id"
)

// Options configure the authenticator.
type Options struct {
	// CAKeys is a file of trusted CA public keys, in authorized_keys format. One per
	// line; a comment is allowed and ignored. More than one is how a CA is rotated:
	// publish the new key alongside the old, re-issue, then remove the old.
	CAKeys string

	// Revocations is an optional file of revoked certificate serial numbers, one per
	// line, `#` for comments.
	//
	// The primary revocation mechanism is the expiry, not this file — a list that has
	// to be pushed to every replica is the same problem authorized_keys has. This
	// exists for the case the expiry cannot cover: a certificate known to be stolen
	// while it is still valid.
	Revocations string

	// MaxLifetime caps `valid_before - valid_after`. Zero means DefaultMaxLifetime;
	// negative disables the cap, which gives up the property this backend exists for.
	//
	// Measured from valid_after, which CAs routinely backdate a minute or two to absorb
	// clock skew — so a certificate issued with a one-hour TTL usually has a window a
	// little over an hour, and a cap set to exactly the issuing TTL refuses every one of
	// them. Leave headroom.
	MaxLifetime time.Duration

	// Skew tolerates clock drift. Zero means DefaultSkew.
	Skew time.Duration

	// PrincipalFrom selects the principal id. Empty means FromPrincipals.
	PrincipalFrom PrincipalSource

	// Now is injectable so tests can stand at a chosen instant.
	Now func() time.Time

	Log *slog.Logger
}

// Authenticator verifies SSH certificates against a set of trusted CA keys.
type Authenticator struct {
	o   Options
	log *slog.Logger

	mu      sync.RWMutex
	cas     map[string]string // marshalled CA key -> its comment, for logs
	revoked map[uint64]bool
}

var _ plugin.Authenticator = (*Authenticator)(nil)

// Open loads the CA keys and any revocation list.
func Open(o Options) (*Authenticator, error) {
	if o.CAKeys == "" {
		return nil, errors.New("sshca: ca_keys is required: there is nothing to trust")
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.MaxLifetime == 0 {
		o.MaxLifetime = DefaultMaxLifetime
	}
	if o.Skew == 0 {
		o.Skew = DefaultSkew
	}
	if o.PrincipalFrom == "" {
		o.PrincipalFrom = FromPrincipals
	}
	switch o.PrincipalFrom {
	case FromPrincipals, FromKeyID:
	default:
		return nil, fmt.Errorf("sshca: principal_from %q is not %q or %q",
			o.PrincipalFrom, FromPrincipals, FromKeyID)
	}
	if o.Now == nil {
		o.Now = time.Now
	}

	a := &Authenticator{o: o, log: o.Log}
	if err := a.Reload(); err != nil {
		return nil, err
	}

	if o.MaxLifetime < 0 {
		a.log.Warn("sshca: max_lifetime is disabled, so this gateway will accept a " +
			"certificate issued for any duration. The reason to run a CA rather than a " +
			"key file is that credentials expire on their own; without a cap that is " +
			"the CA's promise rather than this gateway's check")
	}
	a.log.Info("operator authentication: sshca",
		"ca_keys", o.CAKeys, "authorities", a.Len(),
		"max_lifetime", o.MaxLifetime, "revoked", a.Revoked())
	return a, nil
}

// Reload re-reads the CA keys and the revocation list.
//
// All-or-nothing, like the device registry: a half-applied authority list would either
// lock every operator out or — worse — leave a withdrawn CA trusted.
func (a *Authenticator) Reload() error {
	cas, err := loadCAKeys(a.o.CAKeys)
	if err != nil {
		return err
	}
	if len(cas) == 0 {
		return fmt.Errorf("sshca: %s contains no CA keys", a.o.CAKeys)
	}
	revoked, err := loadRevocations(a.o.Revocations)
	if err != nil {
		return err
	}

	a.mu.Lock()
	a.cas, a.revoked = cas, revoked
	a.mu.Unlock()
	return nil
}

func loadCAKeys(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("sshca: reading %s: %w", path, err)
	}
	out := make(map[string]string)
	rest := b
	for len(rest) > 0 {
		key, comment, _, next, perr := ssh.ParseAuthorizedKey(rest)
		if perr != nil {
			if strings.TrimSpace(string(rest)) == "" {
				break
			}
			return nil, fmt.Errorf("sshca: %s: %w", path, perr)
		}
		// A certificate cannot be an authority. Accepting one would mean trusting
		// whatever signed *it*, one level removed and invisible.
		if _, isCert := key.(*ssh.Certificate); isCert {
			return nil, fmt.Errorf("sshca: %s contains a certificate where a CA public "+
				"key belongs", path)
		}
		if err := checkAuthorityAlgorithm(key); err != nil {
			return nil, fmt.Errorf("sshca: %s: %w", path, err)
		}
		out[string(key.Marshal())] = comment
		rest = next
	}
	return out, nil
}

// checkAuthorityAlgorithm refuses a CA key this gateway will not trust.
//
// DSA is 1024-bit and long dead. A plain `ssh-rsa` *key* is fine — what is not fine is a
// SHA-1 signature made with it, and that is checked per certificate below, because the key
// type does not tell you which signature algorithm the CA used.
func checkAuthorityAlgorithm(key ssh.PublicKey) error {
	if key.Type() == ssh.InsecureKeyAlgoDSA {
		return errors.New("a DSA CA key is refused: 1024-bit and long obsolete")
	}
	return nil
}

func loadRevocations(path string) (map[uint64]bool, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("sshca: reading %s: %w", path, err)
	}
	out := make(map[uint64]bool)
	for i, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		serial, perr := strconv.ParseUint(line, 10, 64)
		if perr != nil {
			// Loudly, and refusing to load. A revocation list with a line nobody
			// noticed is a revocation that did not happen.
			return nil, fmt.Errorf("sshca: %s line %d: %q is not a serial number",
				path, i+1, line)
		}
		out[serial] = true
	}
	return out, nil
}

// Len is the number of trusted authorities.
func (a *Authenticator) Len() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.cas)
}

// Revoked is the number of revoked serials loaded.
func (a *Authenticator) Revoked() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.revoked)
}

// AuthPublicKey verifies a certificate and returns the operator it names.
//
// The SSH user is the device id and is ignored, as everywhere on this interface. The
// identity comes from the certificate.
func (a *Authenticator) AuthPublicKey(ctx context.Context, _ string,
	key ssh.PublicKey) (*plugin.Principal, error) {

	cert, ok := key.(*ssh.Certificate)
	if !ok {
		// A bare key, deliberately refused rather than falling back. A CertChecker can
		// be given a UserKeyFallback; wiring one here would mean a deployment that
		// believes it revokes by expiry while a plain key quietly still works.
		return nil, errors.New("sshca: a certificate is required, not a bare public key")
	}
	if cert.CertType != ssh.UserCert {
		// A host certificate presented for user authentication. Worth refusing loudly:
		// where one CA signs both, every host key in the fleet would otherwise be an
		// operator credential.
		return nil, fmt.Errorf("sshca: certificate is type %d, not a user certificate",
			cert.CertType)
	}

	a.mu.RLock()
	_, trusted := a.cas[string(cert.SignatureKey.Marshal())]
	revoked := a.revoked[cert.Serial]
	a.mu.RUnlock()

	if !trusted {
		return nil, errors.New("sshca: certificate is not signed by a trusted authority")
	}
	if revoked {
		return nil, fmt.Errorf("sshca: certificate serial %d is revoked", cert.Serial)
	}
	if err := checkSignatureAlgorithm(cert); err != nil {
		return nil, err
	}
	if err := a.checkLifetime(cert); err != nil {
		return nil, err
	}
	if len(cert.ValidPrincipals) == 0 {
		// OpenSSH reads this as "valid for every user". Here it would mean a session
		// nobody can be held to: nothing to record, nothing for a rule to match.
		return nil, errors.New("sshca: certificate names no principals, so there is " +
			"nobody to attribute the session to")
	}
	if err := a.checkSourceAddress(ctx, cert); err != nil {
		return nil, err
	}

	// The identity is settled before CheckCert, because CheckCert wants a principal to
	// match and the SSH username cannot supply one here.
	id, err := a.principalID(cert)
	if err != nil {
		return nil, err
	}

	checker := ssh.CertChecker{
		Clock: a.o.Now,
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			a.mu.RLock()
			defer a.mu.RUnlock()
			_, ok := a.cas[string(auth.Marshal())]
			return ok
		},
	}
	// Everything above is a precondition; this is the signature, the validity window and
	// the critical options. Unknown critical options are refused by CheckCert, which is
	// the behaviour we want: a restriction this gateway does not implement must not be
	// silently dropped.
	if err := checker.CheckCert(matchable(cert, id), cert); err != nil {
		return nil, fmt.Errorf("sshca: %w", err)
	}

	p := &plugin.Principal{
		ID:     id,
		Groups: append([]string(nil), cert.ValidPrincipals...),
	}
	if strings.Contains(id, "@") && !strings.Contains(id, " ") {
		p.Email = id
	}
	// The point of the whole exercise: the session may not outlive the credential that
	// opened it. Without this a certificate expiring in ten minutes would open a shell
	// that lasted all night.
	if cert.ValidBefore != ssh.CertTimeInfinity {
		p.Expiry = time.Unix(int64(cert.ValidBefore), 0)
	}
	return p, nil
}

// matchable returns a principal CheckCert will accept.
//
// CheckCert requires its argument to appear in valid_principals. When the id came from
// valid_principals it does; when it came from the key id it may not, and passing the key
// id would fail a certificate that is perfectly valid. In that case the first principal is
// passed instead — the list is non-empty by the time this is called, and every entry in it
// is an identity the CA vouched for, so matching any of them is the same assertion.
func matchable(cert *ssh.Certificate, id string) string {
	for _, p := range cert.ValidPrincipals {
		if p == id {
			return id
		}
	}
	return cert.ValidPrincipals[0]
}

func (a *Authenticator) principalID(cert *ssh.Certificate) (string, error) {
	if a.o.PrincipalFrom == FromKeyID {
		id := strings.TrimSpace(cert.KeyId)
		if id == "" {
			return "", errors.New("sshca: principal_from is key_id and the certificate " +
				"has none, so the session would be unattributable")
		}
		return id, nil
	}
	id := strings.TrimSpace(cert.ValidPrincipals[0])
	if id == "" {
		return "", errors.New("sshca: the certificate's first principal is empty")
	}
	return id, nil
}

// checkLifetime bounds how long the certificate was issued for.
//
// On the *issued* window rather than the remaining one: what this bounds is the CA's
// policy, and a certificate seen an hour into a year-long window is exactly as wrong as
// one seen at the start.
func (a *Authenticator) checkLifetime(cert *ssh.Certificate) error {
	if cert.ValidBefore == ssh.CertTimeInfinity {
		// Always refused, whatever MaxLifetime says. A certificate that never expires
		// is an authorized_keys entry that also survives losing the file.
		return errors.New("sshca: certificate never expires, which is the one thing a " +
			"short-lived credential must not do")
	}
	if a.o.MaxLifetime < 0 {
		return nil
	}
	if cert.ValidBefore < cert.ValidAfter {
		return errors.New("sshca: certificate's validity window ends before it begins")
	}
	lifetime := time.Duration(cert.ValidBefore-cert.ValidAfter) * time.Second
	if lifetime > a.o.MaxLifetime {
		return fmt.Errorf("sshca: certificate was issued for %s, and this gateway "+
			"accepts at most %s", lifetime, a.o.MaxLifetime)
	}
	return nil
}

// checkSourceAddress enforces the `source-address` critical option.
//
// x/crypto skips this option in CheckCert because it enforces it elsewhere — from the
// Permissions its own callback returns, which this interface never produces. So it is
// enforced here or not at all, and "not at all" would mean a certificate restricted to one
// office silently working from anywhere.
func (a *Authenticator) checkSourceAddress(ctx context.Context, cert *ssh.Certificate) error {
	allowed, ok := cert.CriticalOptions["source-address"]
	if !ok {
		return nil
	}
	peer, known := plugin.PeerFrom(ctx)
	if !known {
		// Refused rather than skipped. The alternative is to honour a certificate on a
		// surface that cannot check its restriction, which is the restriction quietly
		// not applying.
		return errors.New("sshca: certificate restricts source-address and this surface " +
			"did not record the peer address, so the restriction cannot be checked")
	}
	host, _, err := net.SplitHostPort(peer.String())
	if err != nil {
		host = peer.String()
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("sshca: peer address %q is not an IP, so source-address "+
			"cannot be checked", peer)
	}
	// An empty value matches nothing and denies, as OpenSSH does — a present-but-empty
	// restriction is a deliberate lockout, not an absent one.
	for _, entry := range strings.Split(allowed, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			_, netw, perr := net.ParseCIDR(entry)
			if perr == nil && netw.Contains(ip) {
				return nil
			}
			continue
		}
		if other := net.ParseIP(entry); other != nil && other.Equal(ip) {
			return nil
		}
	}
	return fmt.Errorf("sshca: certificate does not permit source address %s", ip)
}

// checkSignatureAlgorithm refuses a certificate the CA signed with SHA-1.
//
// `ssh-rsa` names an RSA key *and* a SHA-1 signature. SHA-1 collisions are practical and
// have been for years, and a CA signature is precisely the thing a collision would forge.
// The RSA key is fine; `rsa-sha2-256` and `rsa-sha2-512` are what it should be signing
// with. This is the same rule the OIDC backend applies to JWT algorithms, for the same
// reason: the accepted set is a decision, not whatever the peer offers.
func checkSignatureAlgorithm(cert *ssh.Certificate) error {
	if cert.Signature == nil {
		return errors.New("sshca: certificate carries no signature")
	}
	switch cert.Signature.Format {
	case ssh.KeyAlgoRSA: // "ssh-rsa" — RSA with SHA-1
		return errors.New("sshca: certificate is signed with SHA-1 (ssh-rsa); " +
			"re-issue with rsa-sha2-256 or rsa-sha2-512")
	case ssh.InsecureKeyAlgoDSA:
		return errors.New("sshca: certificate is signed with DSA, which is obsolete")
	}
	return nil
}

// AuthDelegated is not supported. A CA vouches for who somebody is, not for one service's
// claim to act for another; returning ErrUnsupported refuses every On-Behalf-Of call,
// which is the right answer rather than a weaker one.
func (a *Authenticator) AuthDelegated(context.Context, *plugin.Principal, string) (*plugin.Principal, error) {
	return nil, plugin.ErrUnsupported
}

// AuthHTTP is not supported. A certificate authenticates an SSH public key, and there is
// no honest way to turn an HTTP request into one — inventing a mapping would be an
// authentication bypass wearing a convenience's clothes.
func (a *Authenticator) AuthHTTP(context.Context, *http.Request) (*plugin.Principal, error) {
	return nil, plugin.ErrUnsupported
}
