package transport_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/oarlock/oarlock/pkg/transport"
)

// TestCodeMapsEveryError keeps the transport's errors and the wire vocabulary in
// step. A transport failure with no code leaves the gateway nothing truthful to
// put in an ERROR frame, and "internal" on a client's mistake sends the wrong
// person looking.
func TestCodeMapsEveryError(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{nil, ""},
		{transport.ErrTooLarge, "frame_too_large"},
		{transport.ErrTextMessage, "protocol_error"},
		{transport.ErrClosed, "internal"},
		{errors.New("something else"), "internal"},
		{fmt.Errorf("wrapped: %w", transport.ErrTooLarge), "frame_too_large"},
	}
	for _, tc := range tests {
		if got := transport.Code(tc.err); got != tc.want {
			t.Errorf("Code(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

func TestCloseCodeStringsAreDistinct(t *testing.T) {
	codes := []transport.CloseCode{
		transport.CloseNormal, transport.CloseGoingAway, transport.CloseProtocolError,
		transport.ClosePolicyViolation, transport.CloseTooLarge, transport.CloseInternal,
	}
	seen := map[string]bool{}
	for _, c := range codes {
		s := c.String()
		if s == "" {
			t.Errorf("%d has an empty string", c)
		}
		if seen[s] {
			t.Errorf("%q is used twice", s)
		}
		seen[s] = true
	}
}
