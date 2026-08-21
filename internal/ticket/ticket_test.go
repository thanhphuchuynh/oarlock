package ticket_test

import (
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/ticket"
)

func claims() ticket.Claims {
	return ticket.Claims{
		SessionID: "sess_1", DeviceID: "treadmill-4821",
		Profile: "shell", Principal: "phuc@example.com", Kind: ticket.KindDevice,
	}
}

func TestMintAndRedeem(t *testing.T) {
	ctx := context.Background()
	s := ticket.NewMemory(nil)

	tok, err := s.Mint(ctx, claims(), 0)
	if err != nil {
		t.Fatal(err)
	}
	// 32 bytes of crypto/rand is 43 base64url characters. Guessing is not the
	// threat model; single use plus a short deadline is the defence.
	if len(tok) != 43 {
		t.Errorf("token is %d chars, want 43: %q", len(tok), tok)
	}
	if _, err := base64.RawURLEncoding.DecodeString(tok); err != nil {
		t.Errorf("token is not base64url: %v", err)
	}

	got, err := s.Redeem(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	if got.SessionID != "sess_1" || got.DeviceID != "treadmill-4821" || got.Profile != "shell" {
		t.Errorf("claims changed: %+v", got)
	}
	if s.Outstanding() != 0 {
		t.Error("a redeemed ticket is still outstanding")
	}
}

func TestTokensAreDistinct(t *testing.T) {
	ctx := context.Background()
	s := ticket.NewMemory(nil)
	seen := map[string]bool{}
	for range 2000 {
		tok, err := s.Mint(ctx, claims(), 0)
		if err != nil {
			t.Fatal(err)
		}
		if seen[tok] {
			t.Fatalf("duplicate token %q", tok)
		}
		seen[tok] = true
	}
}

// TestSecondRedemptionFails is the property the whole design rests on. A ticket
// that can be spent twice is one an attacker can race the real agent for — and the
// race is winnable, because the attacker knows when the invitation was sent: they
// are the one who intercepted it.
func TestSecondRedemptionFails(t *testing.T) {
	ctx := context.Background()
	s := ticket.NewMemory(nil)
	tok, _ := s.Mint(ctx, claims(), 0)

	if _, err := s.Redeem(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Redeem(ctx, tok); !errors.Is(err, ticket.ErrInvalid) {
		t.Fatalf("second redemption returned %v, want ErrInvalid", err)
	}
}

// TestConcurrentRedemptionHasExactlyOneWinner races redeemers, which is what
// "atomic compare-and-delete, never read-then-delete" has to mean under -race.
func TestConcurrentRedemptionHasExactlyOneWinner(t *testing.T) {
	ctx := context.Background()
	s := ticket.NewMemory(nil)

	for round := range 200 {
		tok, err := s.Mint(ctx, claims(), 0)
		if err != nil {
			t.Fatal(err)
		}
		const racers = 8
		var wins atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for range racers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if _, err := s.Redeem(ctx, tok); err == nil {
					wins.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()
		if got := wins.Load(); got != 1 {
			t.Fatalf("round %d: %d redeemers succeeded, want exactly 1", round, got)
		}
	}
}

func TestUnknownTokenIsIndistinguishableFromSpent(t *testing.T) {
	ctx := context.Background()
	s := ticket.NewMemory(nil)
	tok, _ := s.Mint(ctx, claims(), 0)
	_, _ = s.Redeem(ctx, tok)

	spent := errText(func() error { _, err := s.Redeem(ctx, tok); return err })
	unknown := errText(func() error { _, err := s.Redeem(ctx, "not-a-real-token"); return err })
	expired := func() string {
		now := time.Now()
		st := ticket.NewMemory(func() time.Time { return now })
		tk, _ := st.Mint(ctx, claims(), time.Second)
		now = now.Add(2 * time.Second)
		_, err := st.Redeem(ctx, tk)
		return errText(func() error { return err })
	}()

	// Telling a caller which one it was would confirm that a token existed.
	if spent != unknown || unknown != expired {
		t.Errorf("the three failures are distinguishable:\n spent=%q\n unknown=%q\n expired=%q",
			spent, unknown, expired)
	}
}

func TestExpiryIsADeadlineForConnecting(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	s := ticket.NewMemory(func() time.Time { return now })

	tok, _ := s.Mint(ctx, claims(), 10*time.Second)
	now = now.Add(9 * time.Second)
	if _, err := s.Redeem(ctx, tok); err != nil {
		t.Fatalf("a ticket inside its TTL was refused: %v", err)
	}

	tok2, _ := s.Mint(ctx, claims(), 10*time.Second)
	now = now.Add(11 * time.Second)
	if _, err := s.Redeem(ctx, tok2); !errors.Is(err, ticket.ErrInvalid) {
		t.Fatalf("an expired ticket was accepted: %v", err)
	}
	// Expired means spent, not left for later.
	if s.Outstanding() != 0 {
		t.Error("an expired token survived the redemption attempt")
	}
}

func TestScopeChecks(t *testing.T) {
	c := &ticket.Claims{DeviceID: "dev-1", Profile: "shell", Kind: ticket.KindDevice}

	if err := c.Check(ticket.Want{DeviceID: "dev-1", Profile: "shell", Kind: ticket.KindDevice}); err != nil {
		t.Errorf("a matching scope was refused: %v", err)
	}
	for name, want := range map[string]ticket.Want{
		"wrong device":  {DeviceID: "dev-2"},
		"wrong profile": {Profile: "log"},
		"wrong kind":    {Kind: ticket.KindAttach},
	} {
		if err := c.Check(want); !errors.Is(err, ticket.ErrScope) {
			t.Errorf("%s: got %v, want ErrScope", name, err)
		}
	}
	// Redemption proves the token existed; Check proves it is being spent on what
	// it was minted for. Without it, a ticket for a log stream would open a shell.
	if err := c.Check(ticket.Want{Profile: "shell", Kind: ticket.KindDevice}); err != nil {
		t.Errorf("partial scope check failed: %v", err)
	}
}

func TestAttachTicketCannotBeSpentAsADevice(t *testing.T) {
	ctx := context.Background()
	s := ticket.NewMemory(nil)
	c := claims()
	c.Kind = ticket.KindAttach
	tok, _ := s.Mint(ctx, c, 0)

	got, err := s.Redeem(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Check(ticket.Want{Kind: ticket.KindDevice}); !errors.Is(err, ticket.ErrScope) {
		t.Fatal("a leaked attach ticket was accepted on the device leg")
	}
}

func TestRevoke(t *testing.T) {
	ctx := context.Background()
	s := ticket.NewMemory(nil)
	tok, _ := s.Mint(ctx, claims(), 0)

	if err := s.Revoke(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Redeem(ctx, tok); !errors.Is(err, ticket.ErrInvalid) {
		t.Errorf("a revoked ticket was redeemable: %v", err)
	}
	// Revoking something that never existed must not report anything.
	if err := s.Revoke(ctx, "nope"); err != nil {
		t.Errorf("Revoke leaked existence: %v", err)
	}
}

func TestMintValidates(t *testing.T) {
	ctx := context.Background()
	s := ticket.NewMemory(nil)
	for name, c := range map[string]ticket.Claims{
		"no kind":    {SessionID: "s", DeviceID: "d"},
		"no session": {DeviceID: "d", Kind: ticket.KindDevice},
		"no device":  {SessionID: "s", Kind: ticket.KindDevice},
	} {
		if _, err := s.Mint(ctx, c, 0); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// TestSweepBoundsMemory: lazy expiry is enough for correctness, but an
// abandoned-invitation storm would otherwise be a slow leak.
func TestSweepBoundsMemory(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	s := ticket.NewMemory(func() time.Time { return now })

	for range 50 {
		if _, err := s.Mint(ctx, claims(), 10*time.Second); err != nil {
			t.Fatal(err)
		}
	}
	live, _ := s.Mint(ctx, claims(), time.Hour)

	now = now.Add(30 * time.Second)
	if n := s.Sweep(); n != 50 {
		t.Errorf("swept %d, want 50", n)
	}
	if s.Outstanding() != 1 {
		t.Errorf("%d outstanding after the sweep, want 1", s.Outstanding())
	}
	if _, err := s.Redeem(ctx, live); err != nil {
		t.Errorf("the sweep took a live ticket: %v", err)
	}
}

func errText(f func() error) string {
	if err := f(); err != nil {
		return err.Error()
	}
	return ""
}
