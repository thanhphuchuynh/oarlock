package delegated_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oarlock/oarlock/internal/auth/delegated"
	"github.com/oarlock/oarlock/pkg/plugin"
)

var secret = []byte("0123456789abcdef0123456789abcdef")

type base struct{}

func (base) AuthPublicKey(context.Context, string, ssh.PublicKey) (*plugin.Principal, error) {
	return nil, plugin.ErrUnsupported
}
func (base) AuthDelegated(context.Context, *plugin.Principal, string) (*plugin.Principal, error) {
	return nil, plugin.ErrUnsupported
}
func (base) AuthHTTP(context.Context, *http.Request) (*plugin.Principal, error) {
	return &plugin.Principal{ID: "svc-crm"}, nil
}

func TestServiceSignedAssertion(t *testing.T) {
	now := time.Unix(1000, 0)
	a, err := delegated.New(base{}, secret, "oarlock-api",
		map[string][]string{"svc-crm": {"*@example.com", "group:oncall"}}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	a.Now = func() time.Time { return now }
	token, err := delegated.Sign(delegated.Assertion{
		Subject: "admin@mail.com", Email: "admin@mail.com", Groups: []string{"oncall"},
		Audience: "oarlock-api", Expires: now.Add(30 * time.Second).Unix(), ID: "jti-1",
	}, secret)
	if err != nil {
		t.Fatal(err)
	}
	p, err := a.AuthDelegated(context.Background(), &plugin.Principal{ID: "svc-crm"}, token)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "admin@mail.com" || p.Email != "admin@mail.com" || !p.Expiry.Equal(now.Add(30*time.Second)) {
		t.Fatalf("principal = %+v", p)
	}
}

func TestRejectsBadAssertions(t *testing.T) {
	now := time.Unix(1000, 0)
	a, err := delegated.New(base{}, secret, "oarlock-api",
		map[string][]string{"svc-crm": {"admin@mail.com"}}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	a.Now = func() time.Time { return now }

	cases := []struct {
		name string
		in   delegated.Assertion
	}{
		{
			name: "expired",
			in: delegated.Assertion{
				Subject: "admin@mail.com", Audience: "oarlock-api",
				Expires: now.Add(-time.Second).Unix(), ID: "expired",
			},
		},
		{
			name: "wrong audience",
			in: delegated.Assertion{
				Subject: "admin@mail.com", Audience: "somewhere-else",
				Expires: now.Add(time.Second).Unix(), ID: "aud",
			},
		},
		{
			name: "too long",
			in: delegated.Assertion{
				Subject: "admin@mail.com", Audience: "oarlock-api",
				Expires: now.Add(2 * time.Minute).Unix(), ID: "long",
			},
		},
		{
			name: "outside may act for",
			in: delegated.Assertion{
				Subject: "somebody@example.net", Audience: "oarlock-api",
				Expires: now.Add(time.Second).Unix(), ID: "outside",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token, err := delegated.Sign(tc.in, secret)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := a.AuthDelegated(context.Background(), &plugin.Principal{ID: "svc-crm"}, token); err == nil {
				t.Fatal("assertion accepted")
			}
		})
	}
}

func TestReplayIsRejected(t *testing.T) {
	now := time.Unix(1000, 0)
	a, err := delegated.New(base{}, secret, "oarlock-api",
		map[string][]string{"svc-crm": {"admin@mail.com"}}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	a.Now = func() time.Time { return now }
	token, err := delegated.Sign(delegated.Assertion{
		Subject: "admin@mail.com", Audience: "oarlock-api",
		Expires: now.Add(time.Second).Unix(), ID: "same-jti",
	}, secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.AuthDelegated(context.Background(), &plugin.Principal{ID: "svc-crm"}, token); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AuthDelegated(context.Background(), &plugin.Principal{ID: "svc-crm"}, token); err == nil {
		t.Fatal("replay accepted")
	}
}
