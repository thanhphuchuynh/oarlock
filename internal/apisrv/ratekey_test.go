package apisrv_test

import (
	"net/http"
	"testing"

	"github.com/oarlock/oarlock/internal/apisrv"
)

// TestClientIPSeparatesCallers asserts the property the rate limit depends on: two
// different peers get two different keys.
//
// The IPv6 cases are the point. A key derived by cutting at the first colon returns
// `ip:[2001` for every address in 2001:db8::/16 and `ip:[` for every loopback and
// link-local one, which does not tighten the limit — it hands one caller the ability
// to spend everybody else's window on the endpoint that bounds token guessing.
func TestClientIPSeparatesCallers(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		remote string
		want   string
	}{
		{"ipv4", "192.0.2.7:51234", "ip:192.0.2.7"},
		{"ipv4 other port, same peer", "192.0.2.7:9999", "ip:192.0.2.7"},
		{"ipv6", "[2001:db8::1]:51234", "ip:2001:db8::1"},
		{"ipv6 loopback", "[::1]:443", "ip:::1"},
		{"ipv6 zoned", "[fe80::1%eth0]:22", "ip:fe80::1%eth0"},
		{"no port", "192.0.2.7", "ip:192.0.2.7"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := &http.Request{RemoteAddr: c.remote}
			if got := apisrv.ClientIP(r); got != c.want {
				t.Errorf("ClientIP(%q) = %q, want %q", c.remote, got, c.want)
			}
		})
	}

	// The property, stated once over the whole table rather than case by case: no two
	// distinct peers may share a key, whatever family they arrive on.
	peers := []string{
		"192.0.2.7:1", "192.0.2.8:1",
		"[2001:db8::1]:1", "[2001:db8::2]:1",
		"[::1]:1", "[fe80::1]:1",
	}
	seen := make(map[string]string, len(peers))
	for _, addr := range peers {
		key := apisrv.ClientIP(&http.Request{RemoteAddr: addr})
		if prev, dup := seen[key]; dup {
			t.Errorf("%s and %s share the rate-limit key %q", prev, addr, key)
		}
		seen[key] = addr
	}
}
