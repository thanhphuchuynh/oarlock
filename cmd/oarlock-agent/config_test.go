package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/oarlock/oarlock/agent"
)

func write(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestConfigRoundTrip(t *testing.T) {
	path := write(t, "agent.conf", `
gateway: wss://gw.example.org/ws/control
device: treadmill-4821
key: /data/vendor/oarlock/device.key
shell: /system/bin/sh
pins: ["abc123", "def456"]
dns: ["1.1.1.1"]
sessions:
  user: "2000:2000"
  groups: [1007, 3003]
  per_profile:
    exec: "9999"
`)
	c, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Gateway != "wss://gw.example.org/ws/control" || c.Device != "treadmill-4821" {
		t.Fatalf("config = %+v", c)
	}
	if len(c.Pins) != 2 || c.Pins[0] != "abc123" {
		t.Fatalf("pins = %v", c.Pins)
	}
	if c.Sessions.User != "2000:2000" || len(c.Sessions.Groups) != 2 {
		t.Fatalf("sessions = %+v", c.Sessions)
	}
}

// TestUnknownKeysAreRefused. `insecure_skip_pen: true` that quietly stays false is a
// security setting somebody believes they set — the same reason the gateway refuses
// unknown keys.
func TestUnknownKeysAreRefused(t *testing.T) {
	path := write(t, "agent.conf", "gateway: wss://x/ws\ninsecure_skip_pen: true\n")
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("a misspelled security setting was accepted")
	}
}

// TestDeviceFile is the fleet case: one image, one config, ten thousand ids.
func TestDeviceFile(t *testing.T) {
	dir := t.TempDir()
	idPath := filepath.Join(dir, "device-id")
	if err := os.WriteFile(idPath, []byte("  treadmill-4821\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := write(t, "agent.conf", "gateway: wss://x/ws\ndevice_file: "+idPath+"\n")
	c, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Device != "treadmill-4821" {
		t.Fatalf("device = %q, want the trimmed contents of the file", c.Device)
	}

	// An empty file is worse than a missing one: it would register the device as "".
	empty := filepath.Join(dir, "blank")
	if err := os.WriteFile(empty, []byte("\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(write(t, "b.conf", "device_file: "+empty+"\n")); err == nil {
		t.Fatal("an empty device_file was accepted")
	}

	// Both is ambiguous, and guessing which one wins is how a fleet ends up with one
	// device id on ten thousand machines.
	both := write(t, "c.conf", "device: a\ndevice_file: "+idPath+"\n")
	if _, err := LoadConfig(both); err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("device and device_file together: %v", err)
	}
}

func TestIdentityParsing(t *testing.T) {
	for _, tc := range []struct {
		name     string
		spec     string
		groups   []uint32
		wantUID  uint32
		wantGID  uint32
		wantNil  bool
		wantFail bool
	}{
		{name: "empty inherits", spec: "", wantNil: true},
		{name: "uid and gid", spec: "2000:2000", wantUID: 2000, wantGID: 2000},
		{name: "a bare uid takes the matching gid", spec: "2000", wantUID: 2000, wantGID: 2000},
		{name: "whitespace is tolerated", spec: " 2000 : 1007 ", wantUID: 2000, wantGID: 1007},
		{name: "root is allowed but is the one worth naming", spec: "0:0"},
		{name: "not a number and not a user", spec: "definitely-not-a-user", wantFail: true},
		{name: "a bad gid", spec: "2000:definitely-not-a-group", wantFail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, err := parseIdentity(tc.spec, tc.groups)
			if tc.wantFail {
				if err == nil {
					t.Fatalf("%q was accepted", tc.spec)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantNil {
				if id != nil {
					t.Fatalf("empty spec produced %+v, want nil so the session inherits", id)
				}
				return
			}
			if id == nil {
				t.Fatal("nil identity")
			}
			if id.UID != tc.wantUID || id.GID != tc.wantGID {
				t.Fatalf("uid:gid = %d:%d, want %d:%d", id.UID, id.GID, tc.wantUID, tc.wantGID)
			}
		})
	}

	// The error for a name has to say why a name may not work, because on the platform
	// this feature exists for there is no passwd file at all.
	_, err := parseIdentity("shell-but-not-really", nil)
	if err == nil || !strings.Contains(err.Error(), "passwd") {
		t.Fatalf("error = %v; it should explain that Android has no passwd file", err)
	}
}

func TestPerProfileIdentities(t *testing.T) {
	s := Sessions{
		User:       "2000:2000",
		Groups:     []uint32{1007, 3003},
		PerProfile: map[string]string{"exec": "9999:9999"},
	}
	pick, err := s.identities()
	if err != nil {
		t.Fatal(err)
	}
	if pick == nil {
		t.Fatal("no identity hook was built")
	}
	if got := pick("exec"); got == nil || got.UID != 9999 {
		t.Fatalf("exec = %+v, want the per-profile override", got)
	}
	// A profile with no entry falls back rather than inheriting the agent's identity:
	// silently running as root because nobody listed a profile is the failure this
	// whole mechanism exists to prevent.
	if got := pick("shell"); got == nil || got.UID != 2000 {
		t.Fatalf("shell = %+v, want the default", got)
	}
	if got := pick("something-new"); got == nil || got.UID != 2000 {
		t.Fatalf("an unknown profile = %+v, want the default", got)
	}
	if got := pick("shell"); len(got.Groups) != 2 {
		t.Fatalf("groups = %v, want the configured supplementary groups", got.Groups)
	}
}

func TestNoSessionConfigMeansInherit(t *testing.T) {
	pick, err := (Sessions{}).identities()
	if err != nil {
		t.Fatal(err)
	}
	if pick != nil {
		t.Fatal("an empty sessions block built an identity hook; it must inherit instead")
	}

	// Groups without a user is a config that looks like it does something and does not.
	if _, err := (Sessions{Groups: []uint32{1007}}).identities(); err == nil {
		t.Fatal("sessions.groups without sessions.user was accepted")
	}

	// A blank per-profile entry is the same trap, one level down.
	_, err = (Sessions{User: "2000", PerProfile: map[string]string{"exec": ""}}).identities()
	if err == nil || !strings.Contains(err.Error(), "remove the entry") {
		t.Fatalf("a blank per_profile entry: %v", err)
	}
}

// TestCanDropToRefusesAtBootNotAtExec. Thirty seconds after an operator clicks Open is
// the wrong moment to discover the agent was never privileged enough.
func TestCanDropToRefusesAtBootNotAtExec(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: every drop is possible")
	}
	other := func(string) *agent.Identity { return &agent.Identity{UID: 2000, GID: 2000} }
	err := canDropTo(other, []string{"shell", "exec"})
	if err == nil {
		t.Fatal("an unprivileged agent accepted a configuration it cannot honour")
	}
	for _, want := range []string{"uid 2000", "not root", "start the agent as root"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}

	// Dropping to the uid we already are is a no-op, not a failure. This is the shape
	// an `init` service takes when init has already set `user shell`.
	self := uint32(os.Geteuid())
	same := func(string) *agent.Identity { return &agent.Identity{UID: self, GID: self} }
	if err := canDropTo(same, []string{"shell"}); err != nil {
		t.Fatalf("dropping to our own uid was refused: %v", err)
	}
	if err := canDropTo(nil, []string{"shell"}); err != nil {
		t.Fatalf("inheriting was refused: %v", err)
	}
}

func TestResolverDialsTheConfiguredServers(t *testing.T) {
	// A listener stands in for a DNS server: all that is under test here is which
	// address the resolver dials, not what it says once connected.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accepted <- struct{}{}
			c.Close()
		}
	}()

	// The first server is a closed port, so this also covers falling through.
	dead := "127.0.0.1:1"
	r, err := newResolver([]string{dead, ln.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := r.Dial(context.Background(), "tcp", "192.0.2.1:53")
	if err != nil {
		t.Fatalf("the resolver reached neither server: %v", err)
	}
	conn.Close()
	// Blocking, not a non-blocking check: Dial returns when the client side connects,
	// which can be before the server goroutine has run Accept at all.
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("the resolver did not dial the configured server")
	}
}

func TestResolverConfiguration(t *testing.T) {
	if r, err := newResolver(nil); err != nil || r != nil {
		t.Fatalf("no servers should mean no resolver: %v %v", r, err)
	}
	// A bare address gets :53, which is the only port anybody means here.
	if _, err := newResolver([]string{"1.1.1.1"}); err != nil {
		t.Fatalf("a bare address was refused: %v", err)
	}
	// A name cannot work: resolving it is the job this resolver exists to do.
	_, err := newResolver([]string{"dns.example.org:53"})
	if err == nil || !strings.Contains(err.Error(), "not a name") {
		t.Fatalf("a hostname server was accepted: %v", err)
	}
	if _, err := newResolver([]string{""}); err == nil {
		t.Fatal("an empty server was accepted")
	}
}

// TestDroppingToOurOwnIdentityIsNotADrop.
//
// The bug this pins: changing identity goes through setgroups, which needs CAP_SETGID
// even when the uid is unchanged. So configuring `sessions.user` to the user the agent
// already is passed the boot check and then failed every session at exec with
// "operation not permitted" — which reads like a broken shell path, not a permissions
// decision. There is nothing to drop in that case, so the hook must say so.
func TestDroppingToOurOwnIdentityIsNotADrop(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: setgroups is permitted, so there is nothing to collapse")
	}
	self := strconv.Itoa(os.Geteuid()) + ":" + strconv.Itoa(os.Getegid())
	pick, err := Sessions{User: self}.identities()
	if err != nil {
		t.Fatal(err)
	}
	if pick == nil {
		t.Fatal("no hook was built at all")
	}
	if got := pick("shell"); got != nil {
		t.Fatalf("asked to run sessions as our own identity and got a credential %+v; "+
			"unprivileged, that fails at exec", got)
	}

	// A different uid still produces one, so the collapse is narrow. The boot check is
	// what refuses this configuration; the hook's job is only to describe it.
	other := os.Geteuid() + 1
	pick, err = Sessions{User: strconv.Itoa(other)}.identities()
	if err != nil {
		t.Fatal(err)
	}
	if got := pick("shell"); got == nil || got.UID != uint32(other) {
		t.Fatalf("a genuinely different uid = %+v, want a credential", got)
	}
}

// TestExecIsOptInAndExact.
//
// Empty by default, because a device that offers `exec` with nothing on its list makes the
// gateway accept a session the device then refuses — a round trip to learn what the
// handshake could have said.
func TestExecIsOptInAndExact(t *testing.T) {
	none, err := LoadConfig(write(t, "a.conf", "gateway: wss://x/ws\ndevice: d1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(none.Exec) != 0 {
		t.Fatalf("exec = %v, want empty by default", none.Exec)
	}

	c, err := LoadConfig(write(t, "b.conf", `
gateway: wss://x/ws
device: d1
exec_timeout: 5s
exec:
  - ["/system/bin/logcat", "-d", "-t", "500"]
  - ["/system/bin/getprop", "ro.build.version.release"]
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Exec) != 2 {
		t.Fatalf("exec = %v", c.Exec)
	}
	if c.Exec[0][0] != "/system/bin/logcat" || len(c.Exec[0]) != 4 {
		t.Fatalf("the first argv did not survive: %v", c.Exec[0])
	}
	if c.ExecTimeout != 5*time.Second {
		t.Fatalf("exec_timeout = %v", c.ExecTimeout)
	}
}
