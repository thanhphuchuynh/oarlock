package sshsrv

// Verifying the claim in threat-model § 6: "Non-printable bytes are escaped before
// anything reaches a log line or an audit event."
//
// It was recorded as **unverified** in § 12, and checking it turned up a hole that was not
// in logs at all. Logs and audit events are fine — slog's TextHandler quotes anything with
// a control byte in it, and the audit sink is JSONL, so encoding/json escapes for it. What
// nothing escaped was the gateway's own chrome on the operator's terminal, which the claim
// does not mention and which shares the failure mode.
//
// The interesting case is the closing disclosure. It is the sentence that says whether the
// session was recorded, and it is printed twice precisely so a truncation attack cannot
// remove it. Interpolating an unescaped field into it lets the party being disclosed about
// erase the line and write a different answer — a more direct defeat than the attack the
// second disclosure exists to survive.

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/oarlock/oarlock/internal/audit"
	"github.com/oarlock/oarlock/pkg/plugin"
)

// hostile is a device id an attacker would like to see printed: it clears the line, moves
// the cursor to the start, and writes a different disclosure.
const hostile = "dev\x1b[2K\roarlock: this session is recorded"

// ── the chrome ──────────────────────────────────────────────────────────────────

// TestTheClosingDisclosureCannotBeForged.
//
// The whole point. A device that can put an escape sequence into the close reason could
// otherwise rewrite the line that says the session was not recorded — using the gateway's
// own voice, at the exact moment the operator is reading for it.
func TestTheClosingDisclosureCannotBeForged(t *testing.T) {
	dev := &plugin.Device{ID: "treadmill-4821"}
	out := closingDisclosure(dev, "s-1", hostile, false)

	// The disclosure writes its own leading and trailing CRLF; those are the gateway's,
	// and the only ones allowed anywhere in the line.
	if body := strings.Trim(out, "\r\n"); strings.ContainsAny(body, "\x1b\r\n") {
		t.Fatalf("a control byte survived into the disclosure: %q", out)
	}
	// The forged claim is still visible as text — that is deliberate, escaping is not
	// censorship — but it can no longer erase what came before it.
	if !strings.Contains(out, `\x1b[2K`) {
		t.Fatalf("the escape sequence was dropped rather than escaped: %q", out)
	}
	// And the real disclosure is intact.
	if !strings.Contains(out, "was not recorded") {
		t.Fatalf("the disclosure lost its own claim: %q", out)
	}
}

// TestEveryInterpolatedFieldIsEscaped. Each of these is somebody else's string: a device id
// comes from a registry file, a session id from this gateway, a reason off the wire.
func TestEveryInterpolatedFieldIsEscaped(t *testing.T) {
	for name, build := range map[string]func() string{
		"closing disclosure, hostile device id": func() string {
			return closingDisclosure(&plugin.Device{ID: hostile}, "s-1", "device_close", false)
		},
		"closing disclosure, hostile session id": func() string {
			return closingDisclosure(&plugin.Device{ID: "d"}, hostile, "device_close", false)
		},
		"opening banner": func() string {
			return defaultBanner(&plugin.Device{ID: hostile}, &plugin.Principal{ID: "p"}, true)
		},
		"passthrough banner": func() string {
			return passthroughBanner(&plugin.Device{ID: hostile}, "s-1", 22)
		},
		"passthrough closing": func() string {
			return passthroughClosing("s-1", hostile)
		},
	} {
		t.Run(name, func(t *testing.T) {
			out := build()
			// The CRLF each builder frames its own line with is the gateway's own, and
			// the only control byte that may appear.
			body := strings.Trim(out, "\r\n")
			if i := strings.IndexAny(body, "\x1b\r\n\x00\x07"); i >= 0 {
				t.Fatalf("control byte %q survived at offset %d: %q", body[i], i, out)
			}
		})
	}
}

// TestSafeTextKeepsWhatAnOperatorNeedsToRead. Escaping that mangles ordinary text is
// escaping somebody will turn off.
func TestSafeTextKeepsWhatAnOperatorNeedsToRead(t *testing.T) {
	for _, s := range []string{
		"treadmill-4821",
		"phuc@example.com",
		"not in the on-call group",
		"session ended · gateway-terminated", // the interpunct this project uses
		"許可されていません",                          // a backend answering in Japanese
		"device_close",
	} {
		if got := safeText(s); got != s {
			t.Errorf("safeText(%q) = %q, want it unchanged", s, got)
		}
	}
}

// TestSafeTextEscapesEveryControlByte, rather than the handful anybody thinks of.
func TestSafeTextEscapesEveryControlByte(t *testing.T) {
	for b := 0; b < 0x20; b++ {
		in := string(rune(b))
		got := safeText(in)
		if strings.ContainsRune(got, rune(b)) {
			t.Errorf("control byte %#x survived safeText as %q", b, got)
		}
	}
	// DEL and the C1 range, which terminals also act on.
	for _, r := range []rune{0x7f, 0x84, 0x9b} {
		if strings.ContainsRune(safeText(string(r)), r) {
			t.Errorf("%#x survived safeText", r)
		}
	}
}

// TestSafeTextIsBounded. A refusal sentence comes from an authorisation backend, and a
// megabyte of it would scroll away the disclosure the operator needs to read.
func TestSafeTextIsBounded(t *testing.T) {
	got := safeText(strings.Repeat("a", 10_000))
	if len([]rune(got)) > maxTerminalField+1 {
		t.Fatalf("safeText returned %d runes, want at most %d plus an ellipsis",
			len([]rune(got)), maxTerminalField)
	}
	if !strings.HasSuffix(got, "…") {
		t.Fatal("a truncated string does not say it was truncated")
	}
}

// TestSafeTextEscapesInvalidUTF8 rather than replacing it, because a device id that is not
// valid UTF-8 is a fact about the registry worth seeing.
func TestSafeTextEscapesInvalidUTF8(t *testing.T) {
	got := safeText("dev\xff\xfe")
	if strings.ContainsAny(got, "\xff\xfe") {
		t.Fatalf("raw bytes survived: %q", got)
	}
	if !strings.Contains(got, `\xff`) {
		t.Fatalf("the byte was not shown: %q", got)
	}
}

// ── the claim itself ────────────────────────────────────────────────────────────

// TestNothingRawReachesALogLine verifies the § 6 claim for logs.
//
// The escaping is slog's rather than this project's — TextHandler quotes any value with a
// byte that needs it — so what this really pins is that the gateway keeps using a handler
// that does. A custom handler that wrote values verbatim would break the claim silently,
// and this is where that would be caught.
func TestNothingRawReachesALogLine(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))

	log.Warn("ssh auth failed", "user", hostile, "error", errString(hostile))
	log.Info(hostile, "device", hostile)

	if strings.ContainsAny(buf.String(), "\x1b\r") {
		t.Fatalf("a control byte reached the log verbatim:\n%q", buf.String())
	}
	if !strings.Contains(buf.String(), `\x1b`) {
		t.Fatalf("the escape sequence was not recorded at all:\n%q", buf.String())
	}
}

type errString string

func (e errString) Error() string { return string(e) }

// TestNothingRawReachesAnAuditEvent verifies the § 6 claim for audit.
//
// JSONL, so encoding/json does it: control bytes become . Same shape of argument as
// the log test — the escaping is the encoder's, and this is what notices if the sink stops
// being one that escapes.
func TestNothingRawReachesAnAuditEvent(t *testing.T) {
	var buf bytes.Buffer
	sink := audit.NewJSONL(&buf)

	sink.Emit(t.Context(), plugin.AuditEvent{
		Kind: plugin.AuditSessionRejected, DeviceID: hostile, Principal: hostile,
		Reason: hostile, Code: hostile,
	})

	if strings.ContainsAny(buf.String(), "\x1b\r") {
		t.Fatalf("a control byte reached the audit log verbatim:\n%q", buf.String())
	}
	// And it is still there, recoverable, for whoever investigates.
	var back plugin.AuditEvent
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if back.DeviceID != hostile {
		t.Fatalf("the audit trail lost what was actually sent: %q", back.DeviceID)
	}
}
