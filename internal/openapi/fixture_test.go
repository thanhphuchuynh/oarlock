package openapi_test

// A real gateway API, so the schema tests can compare against a real response rather than
// against what this package believes the response looks like.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/apisrv"
	"github.com/oarlock/oarlock/internal/auth/statictoken"
	"github.com/oarlock/oarlock/internal/sessions"
	"github.com/oarlock/oarlock/pkg/plugin"
)

const testToken = "openapi-test-token-long-enough"

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// registry is a device registry holding one device, so /devices returns a rendered one.
type registry struct{ dev *plugin.Device }

func (r registry) Get(_ context.Context, id string) (*plugin.Device, error) {
	if id == r.dev.ID {
		return r.dev, nil
	}
	return nil, plugin.ErrNoDevice
}
func (r registry) List(context.Context, plugin.DeviceQuery) ([]*plugin.Device, string, error) {
	return []*plugin.Device{r.dev}, "", nil
}

// agents reports one connected device.
type agents struct{}

func (agents) Devices() []string { return []string{"treadmill-4821"} }
func (agents) Disconnect(context.Context, string, string) error {
	return nil
}

func newAPI(t *testing.T) *httptest.Server {
	t.Helper()
	authn, err := statictoken.Open("test", map[string]string{testToken: "admin@mail.com"})
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ledger := sessions.NewMemory(sessions.Limits{PerDevice: 2, PerPrincipal: 10}, nil)

	// One session, so the Session schema is compared against a rendered row rather than
	// skipped. A schema test with no data is a test that passes for the wrong reason.
	if err := ledger.Create(context.Background(), &sessions.Session{
		ID: "sess_openapi_1", DeviceID: "treadmill-4821", Profile: "shell",
		Mode: "gateway", Principal: "admin@mail.com",
		State: sessions.StateAttached, RecordingState: sessions.Recorded,
	}); err != nil {
		t.Fatal(err)
	}
	_ = ledger.Update(context.Background(), "sess_openapi_1", func(s *sessions.Session) error {
		s.AttachedAt = time.Now()
		return nil
	})

	api, err := apisrv.New(apisrv.Options{
		Sessions:      ledger,
		Live:          sessions.NewRegistry(),
		Authenticator: authn,
		Registry: registry{dev: &plugin.Device{
			ID: "treadmill-4821", Platform: plugin.PlatformAndroid,
			Keys: []ed25519.PublicKey{pub},
			Tags: map[string]string{"site": "gym-4"},
		}},
		Agents: agents{},
		Log:    quiet(),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	return srv
}
