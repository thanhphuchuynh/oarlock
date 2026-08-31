package app_test

import (
	"testing"

	"github.com/oarlock/oarlock/cmd/oarlockd/app"
	"github.com/oarlock/oarlock/internal/config"
)

// TestMaxSSHConnections pins the three cases apart, and in particular pins "unset"
// to the default rather than to zero. LimitListener treats a cap of zero as "accept
// nothing" and this package treats it as "no cap", so the two zeroes must never meet:
// the wrong branch here is either a gateway that refuses every operator or one that
// silently has no ceiling at all.
func TestMaxSSHConnections(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		set  int
		want int
	}{
		{"unset means the default", 0, app.DefaultMaxSSHConnections},
		{"a positive value is used as given", 64, 64},
		{"negative disables the cap", -1, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.SSH.MaxConnections = c.set
			if got := app.MaxSSHConnections(cfg); got != c.want {
				t.Errorf("MaxConnections=%d gave a cap of %d, want %d", c.set, got, c.want)
			}
		})
	}
}
