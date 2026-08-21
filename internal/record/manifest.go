package record

import (
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// ManifestVersion is the sidecar's own version.
const ManifestVersion = 1

// Signer signs a manifest.
//
// crypto.Signer, so the key can live in a KMS or an HSM without this package
// caring. It should not be the gateway's SSH host key: that key is presented to
// every operator on every connection, while this one attests that recordings have
// not been altered. Rotating one must not force rotating the other.
type Signer interface {
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
	Public() crypto.PublicKey
	// KeyID names the key, so a verifier can find the right public half years
	// later. A signature nobody can attribute to a key is a signature nobody can
	// check.
	KeyID() string
}

// ChainInfo describes the hash chain so a verifier need not guess its parameters.
type ChainInfo struct {
	Alg             string `json:"alg"`
	Domain          string `json:"domain"`
	Head            string `json:"head"`
	Events          int    `json:"events"`
	CheckpointEvery int    `json:"checkpoint_every"`
}

// Signature is the manifest's own signature.
type Signature struct {
	Alg   string `json:"alg"`
	KeyID string `json:"key_id"`
	Value string `json:"value"` // base64, standard encoding
}

// Manifest is the sidecar: everything needed to say what a recording is and whether
// it is intact.
//
// It is deliberately self-describing. A .cast copied out of its bucket and away
// from the ledger is still attributable and still verifiable, which matters because
// that is exactly how recordings travel when somebody is asked to produce one.
type Manifest struct {
	Manifest int    `json:"oarlock_manifest"`
	Format   string `json:"format"`

	SessionID  string `json:"session_id"`
	DeviceID   string `json:"device_id"`
	Profile    string `json:"profile"`
	Mode       string `json:"mode"`
	Principal  string `json:"principal"`
	OpenedBy   string `json:"opened_by,omitempty"`
	Unattended bool   `json:"unattended,omitempty"`

	RecordInput bool `json:"record_input"`

	StartedAt time.Time `json:"started_at"`
	ClosedAt  time.Time `json:"closed_at"`
	Duration  float64   `json:"duration_seconds"`

	CloseReason  string `json:"close_reason"`
	ExitCode     *int   `json:"exit_code"`
	BytesDropped int64  `json:"bytes_dropped"`

	Counts Counts    `json:"counts"`
	Chain  ChainInfo `json:"chain"`

	// Storage is what the store promised about immutability *at the time this
	// recording was written*.
	//
	// Recording it is the point: a chain proves the bytes have not changed, and this
	// says what stood between them and a change. An auditor reading a recording two
	// years later can otherwise only guess whether the bucket had object lock on in
	// 2026, and "we think it did" is not an answer.
	Storage Immutability `json:"storage"`

	Signature *Signature `json:"signature,omitempty"`
}

// signingBytes is the canonical form that gets signed: the manifest with its
// signature field absent.
//
// Determinism comes from marshalling a struct — Go emits fields in declaration
// order — rather than from a map, whose key order would be sorted but whose
// presence rules are easier to get subtly wrong.
func (m Manifest) signingBytes() ([]byte, error) {
	m.Signature = nil
	return json.Marshal(m)
}

// Sign fills in the signature.
func (m *Manifest) Sign(s Signer) error {
	if s == nil {
		return errors.New("record: no signer")
	}
	body, err := m.signingBytes()
	if err != nil {
		return fmt.Errorf("record: canonicalising the manifest: %w", err)
	}
	// Ed25519 signs the message itself, so the hash argument is zero.
	sig, err := s.Sign(nil, body, crypto.Hash(0))
	if err != nil {
		return fmt.Errorf("record: signing the manifest: %w", err)
	}
	m.Signature = &Signature{
		Alg:   "ed25519",
		KeyID: s.KeyID(),
		Value: base64.StdEncoding.EncodeToString(sig),
	}
	return nil
}

// VerifySignature checks the manifest against a public key.
func (m Manifest) VerifySignature(pub ed25519.PublicKey) error {
	if m.Signature == nil {
		return errors.New("record: manifest is unsigned")
	}
	if m.Signature.Alg != "ed25519" {
		return fmt.Errorf("record: unsupported signature algorithm %q", m.Signature.Alg)
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature.Value)
	if err != nil {
		return fmt.Errorf("record: signature is not base64: %w", err)
	}
	body, err := m.signingBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, body, sig) {
		return errors.New("record: manifest signature does not verify")
	}
	return nil
}

// EncodeManifest renders a manifest for storage.
func EncodeManifest(m Manifest) ([]byte, error) {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// DecodeManifest reads one back.
func DecodeManifest(b []byte) (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return Manifest{}, fmt.Errorf("record: reading the manifest: %w", err)
	}
	if m.Manifest != ManifestVersion {
		return Manifest{}, fmt.Errorf("record: manifest version %d, want %d",
			m.Manifest, ManifestVersion)
	}
	return m, nil
}

// ── a default signer ────────────────────────────────────────────────────────────

// KeySigner wraps an Ed25519 private key.
type KeySigner struct {
	Key ed25519.PrivateKey
	ID  string
}

var _ Signer = (*KeySigner)(nil)

func (k *KeySigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return k.Key.Sign(rand, digest, opts)
}
func (k *KeySigner) Public() crypto.PublicKey { return k.Key.Public() }
func (k *KeySigner) KeyID() string {
	if k.ID != "" {
		return k.ID
	}
	return "unnamed"
}
