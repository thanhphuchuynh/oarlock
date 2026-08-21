package plugin_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/oarlock/oarlock/pkg/plugin"
)

func TestValidDeviceID(t *testing.T) {
	ok := []string{"a", "treadmill-4821", "rower_1.2", "A0", strings.Repeat("x", 64)}
	bad := []string{
		"", "-leading", ".leading", "_leading",
		"has space", "has/slash", "has:colon", "../escape", "emoji🚣",
		strings.Repeat("x", 65),
	}
	for _, s := range ok {
		if !plugin.ValidDeviceID(s) {
			t.Errorf("%q should be valid", s)
		}
	}
	for _, s := range bad {
		if plugin.ValidDeviceID(s) {
			// A device id lands in a log line, a metric label, a filesystem path and
			// an SSH username. Anything that could change meaning in one of those is
			// not worth accepting for convenience.
			t.Errorf("%q should be rejected", s)
		}
	}
}

func sshWire(t *testing.T, algo string, key []byte) string {
	t.Helper()
	var b []byte
	for _, part := range [][]byte{[]byte(algo), key} {
		b = binary.BigEndian.AppendUint32(b, uint32(len(part)))
		b = append(b, part...)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestParseDeviceKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := base64.StdEncoding.EncodeToString(pub)

	t.Run("raw base64", func(t *testing.T) {
		got, err := plugin.ParseDeviceKey(raw)
		if err != nil || !got.Equal(pub) {
			t.Fatalf("got %v, %v", got, err)
		}
	})
	t.Run("unpadded base64", func(t *testing.T) {
		got, err := plugin.ParseDeviceKey(strings.TrimRight(raw, "="))
		if err != nil || !got.Equal(pub) {
			t.Fatalf("got %v, %v", got, err)
		}
	})
	t.Run("openssh form with a comment", func(t *testing.T) {
		// The form ssh-keygen produces, because requiring a bespoke encoding for no
		// reason is how a registry file becomes something only a script can write.
		line := "ssh-ed25519 " + sshWire(t, "ssh-ed25519", pub) + " operator@laptop"
		got, err := plugin.ParseDeviceKey(line)
		if err != nil || !got.Equal(pub) {
			t.Fatalf("got %v, %v", got, err)
		}
	})
	t.Run("surrounding whitespace", func(t *testing.T) {
		if _, err := plugin.ParseDeviceKey("  " + raw + "\n"); err != nil {
			t.Fatal(err)
		}
	})

	bad := map[string]string{
		"empty":               "",
		"not base64":          "!!!!",
		"wrong length":        base64.StdEncoding.EncodeToString([]byte("short")),
		"ssh with no body":    "ssh-ed25519",
		"ssh body not base64": "ssh-ed25519 !!!!",
		"ssh wrong algorithm": "ssh-ed25519 " + sshWire(t, "ssh-rsa", pub),
		"ssh short key":       "ssh-ed25519 " + sshWire(t, "ssh-ed25519", []byte("nope")),
	}
	for name, in := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := plugin.ParseDeviceKey(in); err == nil {
				t.Fatalf("%q was accepted", in)
			}
		})
	}

	t.Run("truncated ssh length prefix does not panic", func(t *testing.T) {
		// A four-byte length read out of a file the operator edited must not become
		// an index into nothing.
		for _, blob := range [][]byte{
			{0, 0, 0},
			{0xFF, 0xFF, 0xFF, 0xFF},
			binary.BigEndian.AppendUint32(nil, 1<<20),
		} {
			if _, err := plugin.ParseDeviceKey("ssh-ed25519 " +
				base64.StdEncoding.EncodeToString(blob)); err == nil {
				t.Errorf("blob %x was accepted", blob)
			}
		}
	})

	t.Run("trailing bytes rejected", func(t *testing.T) {
		blob, _ := base64.StdEncoding.DecodeString(sshWire(t, "ssh-ed25519", pub))
		blob = append(blob, 'x')
		if _, err := plugin.ParseDeviceKey("ssh-ed25519 " +
			base64.StdEncoding.EncodeToString(blob)); err == nil {
			t.Error("trailing bytes were accepted")
		}
	})
}

func TestEncodeDeviceKeyRoundTrips(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	got, err := plugin.ParseDeviceKey(plugin.EncodeDeviceKey(pub))
	if err != nil || !got.Equal(pub) {
		t.Fatalf("got %v, %v", got, err)
	}
}

// TestResolvedMode is the acceptance criterion for E1.S7: the default follows the
// platform, because the right default differs by platform rather than by
// deployment.
func TestResolvedMode(t *testing.T) {
	tests := []struct {
		platform  plugin.Platform
		explicit  plugin.Mode
		want      plugin.Mode
		defaulted bool
	}{
		{plugin.PlatformAndroid, "", plugin.ModeDispatch, true},
		{plugin.PlatformLinux, "", plugin.ModePersistent, true},
		{plugin.PlatformContainer, "", plugin.ModePersistent, true},
		{plugin.PlatformOther, "", plugin.ModePersistent, true},
		{"", "", plugin.ModePersistent, true},
		// An explicit mode always wins, on any platform.
		{plugin.PlatformAndroid, plugin.ModePersistent, plugin.ModePersistent, false},
		{plugin.PlatformLinux, plugin.ModeDispatch, plugin.ModeDispatch, false},
	}
	for _, tc := range tests {
		d := plugin.Device{Platform: tc.platform, Mode: tc.explicit}
		if got := d.ResolvedMode(); got != tc.want {
			t.Errorf("platform=%q mode=%q: got %q, want %q",
				tc.platform, tc.explicit, got, tc.want)
		}
		if got := d.ModeWasDefaulted(); got != tc.defaulted {
			t.Errorf("platform=%q mode=%q: defaulted=%v, want %v",
				tc.platform, tc.explicit, got, tc.defaulted)
		}
	}
}

func TestSupports(t *testing.T) {
	// An empty list means "the gateway's defaults", not "nothing".
	if !(plugin.Device{}).Supports("shell") {
		t.Error("an empty profile list must not deny everything")
	}
	d := plugin.Device{Profiles: []string{"shell", "log"}}
	if !d.Supports("shell") || d.Supports("tcp") {
		t.Error("profile matching is wrong")
	}
}

func TestHasKeySupportsRotation(t *testing.T) {
	old, _, _ := ed25519.GenerateKey(rand.Reader)
	new_, _, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)

	// Both keys live in the registry at once: publish the new one, let devices roll
	// over, retire the old. A single-key field would make rotation a flag day.
	d := plugin.Device{Keys: []ed25519.PublicKey{old, new_}}
	if !d.HasKey(old) || !d.HasKey(new_) {
		t.Error("a registered key was not recognised")
	}
	if d.HasKey(other) {
		t.Error("an unregistered key was accepted")
	}
}
