package record_test

import (
	"crypto/ed25519"
	"os"
	"strings"
	"testing"

	"github.com/oarlock/oarlock/internal/record"
)

// TestVerifyARealRecording verifies a recording produced by the daemon, from disk.
//
// Skipped unless OARLOCK_VERIFY_CAST and OARLOCK_VERIFY_MANIFEST are set: it is a manual
// check on real output, not part of the suite. Pointing the verifier at a file the running
// gateway produced is the one thing the in-process tests cannot do — they verify what they
// just wrote in memory.
func TestVerifyARealRecording(t *testing.T) {
	castPath := os.Getenv("OARLOCK_VERIFY_CAST")
	manPath := os.Getenv("OARLOCK_VERIFY_MANIFEST")
	keyPath := os.Getenv("OARLOCK_VERIFY_PUBKEY")
	if castPath == "" || manPath == "" || keyPath == "" {
		t.Skip("set OARLOCK_VERIFY_CAST, OARLOCK_VERIFY_MANIFEST and OARLOCK_VERIFY_PUBKEY")
	}

	cast, err := os.ReadFile(castPath)
	if err != nil {
		t.Fatal(err)
	}
	manBytes, err := os.ReadFile(manPath)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("%s is %d bytes, want %d", keyPath, len(pub), ed25519.PublicKeySize)
	}

	m, err := record.DecodeManifest(manBytes)
	if err != nil {
		t.Fatal(err)
	}
	v, err := record.Verify(strings.NewReader(string(cast)), m, ed25519.PublicKey(pub))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	t.Logf("session %s: status=%s ok=%v events=%d/%d",
		m.SessionID, v.Status, v.OK, v.EventsFound, v.EventsExpected)
	if !v.OK {
		t.Fatalf("the recording did not verify: %s (%s)", v.Status, v.Detail)
	}
}
