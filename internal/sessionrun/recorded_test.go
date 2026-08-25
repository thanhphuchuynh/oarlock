package sessionrun_test

import (
	"testing"

	"github.com/oarlock/oarlock/internal/sessionrun"
)

// TestRecordedMatchesTheProfileTable pins § 9.4: `file`, `tcp` and `sshpass` are not
// recorded whatever the gateway is configured with, and everything else is.
//
// It exists because this answer is used in two places that must agree — the recorder,
// and the READY frame that tells the device before any bytes move. They used to
// disagree: READY answered "is a recorder configured", so a device on a `tcp` forward
// was told it was being recorded when nothing was recording it.
func TestRecordedMatchesTheProfileTable(t *testing.T) {
	for profile, want := range map[string]bool{
		"shell": true, "exec": true, "log": true,
		"file": false, "tcp": false, "sshpass": false,
		// An unrecognised profile records: failing towards a recording is the safe
		// direction, because the alternative is a session nobody knows was unrecorded.
		"something-new": true,
	} {
		if got := sessionrun.Recorded(profile); got != want {
			t.Errorf("Recorded(%q) = %v, want %v", profile, got, want)
		}
	}
}
