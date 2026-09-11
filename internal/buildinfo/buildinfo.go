// Package buildinfo is the product version, stamped at link time.
//
// It is not the wire protocol version (that is an integer in HELLO/WELCOME) and it is
// not the handshake domain (oarlock-control-v0 / v1). Those clocks move independently
// because an agent can stay on wire 0 long after this number has moved.
//
//	-ldflags "-X github.com/oarlock/oarlock/internal/buildinfo.Version=v0.1.0"
//
// Unstamped builds stay "dev" so a binary from `go build` is never mistaken for a release.
package buildinfo

// Version is the product version. make binaries / make release set it from
// `git describe --tags`.
var Version = "dev"
