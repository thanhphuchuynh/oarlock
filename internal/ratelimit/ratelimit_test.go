package ratelimit

// The limiter's own arithmetic, tested from inside the package.
//
// Most of the value here is in clientKey rather than the counter. A counter that is
// wrong fails visibly the first time somebody looks; a key that is wrong makes the whole
// control silently useless while every test of the counter still passes.

import (
	"net"
	"strconv"
	"testing"
	"time"
)

type addr string

func (a addr) Network() string { return "tcp" }
func (a addr) String() string  { return string(a) }

// ── the key ─────────────────────────────────────────────────────────────────────

// TestAnIPv6ClientIsCountedByItsSixtyFour.
//
// The whole reason this limit is not keyed on the address. A host is routinely handed a
// /64, so rotating the low half is free — an address-keyed counter would be defeated by
// a for-loop, and would go on looking like it was working.
func TestAnIPv6ClientIsCountedByItsSixtyFour(t *testing.T) {
	first := Key(addr("[2001:db8:1:2::1]:52000"))
	// Same /64, eighteen quintillion addresses to choose from.
	for _, other := range []string{
		"[2001:db8:1:2::2]:52001",
		"[2001:db8:1:2:ffff:ffff:ffff:ffff]:52002",
		"[2001:db8:1:2:dead:beef:cafe:1]:52003",
	} {
		if got := Key(addr(other)); got != first {
			t.Fatalf("%s keyed as %q, want %q — rotating the host half evades the limit",
				other, got, first)
		}
	}
	// A different /64 is a different client.
	if got := Key(addr("[2001:db8:1:3::1]:52000")); got == first {
		t.Fatalf("a separate /64 shares the key %q", got)
	}
}

// TestAnIPv4ClientIsCountedByItsAddress. The mirror of the rule above: a /24 is not one
// client, and treating it as one would let a single misbehaving host lock out its
// neighbours — a rate limit that becomes somebody else's outage.
func TestAnIPv4ClientIsCountedByItsAddress(t *testing.T) {
	a := Key(addr("203.0.113.7:52000"))
	b := Key(addr("203.0.113.8:52000"))
	if a == b {
		t.Fatalf("two IPv4 neighbours share the key %q", a)
	}
	if a != "203.0.113.7" {
		t.Fatalf("key = %q, want the bare address", a)
	}
	// The port must not be part of it, or every connection is its own client and the
	// limit counts to one forever.
	if Key(addr("203.0.113.7:52001")) != a {
		t.Fatal("the source port changed the key")
	}
}

// TestAnIPv4MappedAddressIsNotGivenASixtyFour is the trap in combining the two rules
// above.
//
// ::ffff:203.0.113.7 is an IPv4 client wearing an IPv6 address, and its high 64 bits are
// zero. Keyed as IPv6 it would come out as ::/64 — which every v4-mapped address in
// existence shares. The limit would then count the entire IPv4 internet on one counter
// and lock everybody out after thirty connections.
func TestAnIPv4MappedAddressIsNotGivenASixtyFour(t *testing.T) {
	got := Key(addr("[::ffff:203.0.113.7]:52000"))
	if got != "203.0.113.7" {
		t.Fatalf("key = %q, want 203.0.113.7", got)
	}
	other := Key(addr("[::ffff:198.51.100.4]:52000"))
	if got == other {
		t.Fatalf("two unrelated IPv4 clients collapsed onto one key %q", got)
	}
}

// TestAnUnparseableAddressStillGetsAKey. Failing open on an address we do not recognise
// would be a bypass for whatever produced it.
func TestAnUnparseableAddressStillGetsAKey(t *testing.T) {
	for _, a := range []net.Addr{addr("not-an-address"), addr("")} {
		if Key(a) == "" {
			t.Fatalf("%q produced an empty key, which every such client would share", a)
		}
	}
	if Key(nil) != "unknown" {
		t.Fatal("a nil address produced no key")
	}
}

// ── the counter ─────────────────────────────────────────────────────────────────

func TestTheLimitAdmitsExactlyItsBudget(t *testing.T) {
	now := time.Now()
	l := newTestLimiter(3, func() time.Time { return now })

	for i := 1; i <= 3; i++ {
		if ok, n := l.Allow("c"); !ok {
			t.Fatalf("connection %d refused at count %d, inside a budget of 3", i, n)
		}
	}
	ok, n := l.Allow("c")
	if ok {
		t.Fatal("a fourth connection was admitted on a budget of three")
	}
	if n != 4 {
		t.Fatalf("count = %d, want 4 — a refusal has to say how far over the client is", n)
	}
}

// TestTheWindowRolls. A client that is refused must not be refused forever: the point is
// to slow an attacker down, and an operator who tripped it during an incident needs to
// get back in without an administrator.
func TestTheWindowRolls(t *testing.T) {
	now := time.Now()
	l := newTestLimiter(2, func() time.Time { return now })

	l.Allow("c")
	l.Allow("c")
	if ok, _ := l.Allow("c"); ok {
		t.Fatal("the third connection was admitted")
	}

	now = now.Add(time.Minute)
	if ok, n := l.Allow("c"); !ok {
		t.Fatalf("still refused after the window rolled (count %d)", n)
	}
}

// TestClientsAreCountedSeparately. One noisy client must not close the door on everybody
// else, which is the failure mode that makes people turn rate limits off.
func TestClientsAreCountedSeparately(t *testing.T) {
	now := time.Now()
	l := newTestLimiter(1, func() time.Time { return now })

	if ok, _ := l.Allow("noisy"); !ok {
		t.Fatal("the first connection was refused")
	}
	if ok, _ := l.Allow("noisy"); ok {
		t.Fatal("the noisy client got a second connection")
	}
	if ok, _ := l.Allow("quiet"); !ok {
		t.Fatal("an unrelated client was refused because of somebody else's traffic")
	}
}

// TestANegativeLimitDisablesTheControl. The documented escape hatch for a deployment
// behind a load balancer, where this limit would count every operator as one client.
func TestANegativeLimitDisablesTheControl(t *testing.T) {
	l := newTestLimiter(-1, nil)
	if l != nil {
		t.Fatal("a negative limit produced a limiter")
	}
	for range 1000 {
		if ok, _ := l.Allow("c"); !ok {
			t.Fatal("a disabled limiter refused a connection")
		}
	}
}

func TestZeroMeansTheDefault(t *testing.T) {
	l := newTestLimiter(0, nil)
	if l == nil || l.perMinute != DefaultWSConnRatePerMinute {
		t.Fatalf("zero produced %+v, want the default of %d", l, DefaultWSConnRatePerMinute)
	}
}

// TestTheSweepDoesNotDropALiveWindow.
//
// The sweep exists so a scanned gateway does not keep a window per source address for as
// long as it runs. It must drop only expired windows: dropping a live one resets an
// attacker's counter, which is the one thing the map is for.
func TestTheSweepDoesNotDropALiveWindow(t *testing.T) {
	now := time.Now()
	l := newTestLimiter(2, func() time.Time { return now })

	// A gateway that has been scanned: one window per source address, past the
	// threshold that arms the sweep.
	for i := range 10_001 {
		l.Allow("scanner-" + strconv.Itoa(i))
	}
	now = now.Add(2 * time.Minute) // all of those are now expired

	// A real client arrives and reaches its limit. Its first connection is the
	// insertion that finds the map over the threshold and runs the sweep.
	l.Allow("victim")
	l.Allow("victim")

	if got := len(l.windows); got > 10 {
		t.Fatalf("the sweep did not run: %d windows remain", got)
	}
	if ok, n := l.Allow("victim"); ok {
		t.Fatalf("the sweep dropped a live counter: the client was admitted at count %d", n)
	}
}

// ── the load-balancer hint ──────────────────────────────────────────────────────

// TestPrivateSourcesAreRecognised. Only a log hint, but it is the difference between an
// operator finding a misconfigured proxy in a minute and spending an hour reading a
// limiter that appears to be working perfectly.
func TestPrivateSourcesAreRecognised(t *testing.T) {
	for _, key := range []string{"127.0.0.1", "10.1.2.3", "192.168.0.5", "172.16.9.9",
		"fd00:1:2:3::/64", "169.254.1.1"} {
		if !PrivateSource(key) {
			t.Errorf("%s was not recognised as a private source", key)
		}
	}
	for _, key := range []string{"203.0.113.7", "2001:db8:1:2::/64", "8.8.8.8"} {
		if PrivateSource(key) {
			t.Errorf("%s was called private", key)
		}
	}
}

// newTestLimiter is what a door does with its configured number: default a zero to the
// door's own constant, then build. New itself deliberately does not default, because the
// right number differs per door and hiding that here is how the two would drift together.
func newTestLimiter(perMinute int, now func() time.Time) *Limiter {
	if perMinute == 0 {
		perMinute = DefaultWSConnRatePerMinute
	}
	return New(perMinute, now)
}
