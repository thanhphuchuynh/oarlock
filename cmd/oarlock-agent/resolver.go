package main

// Explicit DNS, because Android does not have /etc/resolv.conf.
//
// Go's pure resolver reads that file and, failing to find it, falls back to 127.0.0.1:53
// — where nothing on Android is listening. So a CGO-free build dialling
// `wss://gw.example.org/…` never resolves the name, and the failure looks like a network
// problem rather than a missing file. There are three ways out: put an IP in the gateway
// URL, build with cgo and the NDK so bionic's resolver is used, or name the servers.
// This is the third, and it is the one that keeps the build to a plain `go build`.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
)

// newResolver builds a resolver that talks to the given servers in order.
//
// No servers means no resolver: the caller keeps Go's default, which is correct
// everywhere that has a resolv.conf.
func newResolver(servers []string) (*net.Resolver, error) {
	if len(servers) == 0 {
		return nil, nil
	}
	addrs := make([]string, 0, len(servers))
	for _, s := range servers {
		s = strings.TrimSpace(s)
		if s == "" {
			return nil, errors.New("dns: an empty server address")
		}
		if _, _, err := net.SplitHostPort(s); err != nil {
			// A bare address is the common way to write this, and :53 is the only
			// port anybody means.
			s = net.JoinHostPort(s, "53")
		}
		host, _, err := net.SplitHostPort(s)
		if err != nil {
			return nil, fmt.Errorf("dns: %q is not an address: %w", s, err)
		}
		if net.ParseIP(host) == nil {
			// A hostname here cannot work: resolving it is the thing this resolver
			// exists to do.
			return nil, fmt.Errorf("dns: %q must be an IP address, not a name — a name "+
				"here would have to be resolved by the resolver being configured", host)
		}
		addrs = append(addrs, s)
	}

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// The address Go picked is discarded on purpose: it is the resolv.conf
			// default we are here to replace. The network — udp or tcp — is honoured,
			// because a truncated answer has to be retried over tcp.
			var last error
			for _, addr := range addrs {
				var d net.Dialer
				conn, err := d.DialContext(ctx, network, addr)
				if err == nil {
					return conn, nil
				}
				last = err
			}
			return nil, fmt.Errorf("dns: no configured server answered: %w", last)
		},
	}, nil
}
