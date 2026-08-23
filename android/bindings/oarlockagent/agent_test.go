package oarlockagent

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureKeyIsStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device.key")
	first, err := EnsureKey(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EnsureKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || !strings.HasPrefix(first, "ssh-ed25519 ") {
		t.Fatalf("public keys = %q and %q", first, second)
	}
}

func TestNewAgentRequiresPinOrExplicitInsecureMode(t *testing.T) {
	_, err := NewAgent("wss://gateway/ws/control", "vr-1", "key", "", "", false, nil)
	if err == nil || !strings.Contains(err.Error(), "pin") {
		t.Fatalf("error = %v", err)
	}
	if _, err := NewAgent("ws://gateway/ws/control", "vr-1", "key", "", "", true, nil); err != nil {
		t.Fatal(err)
	}
}
