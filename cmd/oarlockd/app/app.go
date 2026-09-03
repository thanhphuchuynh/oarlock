// Package app builds and runs a gateway from a configuration file.
//
// It is a package rather than just a main so that a deployment can link its own plugins
// in and still get the standard wiring:
//
//	package main
//
//	import (
//	    "github.com/oarlock/oarlock/cmd/oarlockd/app"
//	    _ "example.com/our-stack/ourauthz"
//	)
//
//	func main() { app.Main() }
//
// # What this file is for
//
// Everything it assembles was already tested — the codec, the pump, the recorder, the
// authorisation contract — but none of it could be *started*. The gateway existed only
// inside its own test harness, which is a real gap and not a cosmetic one: a harness
// arranges components in whatever order the test needs, and nothing forced the arrangement
// to be one a process could actually boot. The boot gate in internal/safety was the
// clearest symptom, sitting fully tested with no caller.
package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	encPEM "encoding/pem"

	gssh "github.com/gliderlabs/ssh"
	xssh "golang.org/x/crypto/ssh"
	"golang.org/x/net/netutil"

	"github.com/oarlock/oarlock/cmd/oarlockd/app/ui"
	"github.com/oarlock/oarlock/internal/apisrv"
	"github.com/oarlock/oarlock/internal/attachsrv"
	"github.com/oarlock/oarlock/internal/audit"
	"github.com/oarlock/oarlock/internal/auth/authorizedkeys"
	"github.com/oarlock/oarlock/internal/auth/delegated"
	"github.com/oarlock/oarlock/internal/auth/oidc"
	"github.com/oarlock/oarlock/internal/auth/sshca"
	"github.com/oarlock/oarlock/internal/auth/statictoken"
	"github.com/oarlock/oarlock/internal/authsrv"
	"github.com/oarlock/oarlock/internal/authz"
	"github.com/oarlock/oarlock/internal/config"
	"github.com/oarlock/oarlock/internal/controlsrv"
	"github.com/oarlock/oarlock/internal/handshake"
	"github.com/oarlock/oarlock/internal/hub"
	"github.com/oarlock/oarlock/internal/invite"
	"github.com/oarlock/oarlock/internal/ratelimit"
	"github.com/oarlock/oarlock/internal/record"
	"github.com/oarlock/oarlock/internal/registry/file"
	regsqlite "github.com/oarlock/oarlock/internal/registry/sqlite"
	"github.com/oarlock/oarlock/internal/safety"
	"github.com/oarlock/oarlock/internal/sessionrun"
	"github.com/oarlock/oarlock/internal/sessions"
	"github.com/oarlock/oarlock/internal/sessions/sqlitestore"
	"github.com/oarlock/oarlock/internal/sessionsrv"
	"github.com/oarlock/oarlock/internal/sqlexplore"
	"github.com/oarlock/oarlock/internal/sshsrv"
	"github.com/oarlock/oarlock/internal/ticket"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
	"github.com/oarlock/oarlock/pkg/transport/websocket"
	"github.com/oarlock/oarlock/plugins/authz/rules"
	authzsqlite "github.com/oarlock/oarlock/plugins/authz/sqlite"
	authzwebhook "github.com/oarlock/oarlock/plugins/authz/webhook"
	dispatchexec "github.com/oarlock/oarlock/plugins/dispatch/exec"
	dispatchmqtt "github.com/oarlock/oarlock/plugins/dispatch/mqtt"
	dispatchwebhook "github.com/oarlock/oarlock/plugins/dispatch/webhook"
)

// Version is stamped at build time with -ldflags.
var Version = "dev"

// Main is the entry point. It never returns; it exits.
func Main() {
	var (
		cfgPath = flag.String("config", "oarlock.yaml", "path to the configuration file")
		check   = flag.Bool("check", false,
			"validate the configuration and the boot gate, then exit")
		showVersion = flag.Bool("version", false, "print the version and exit")
		logLevel    = flag.String("log-level", "info", "debug, info, warn or error")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("oarlockd", Version)
		return
	}

	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		fmt.Fprintf(os.Stderr, "oarlockd: -log-level %q: %v\n", *logLevel, err)
		os.Exit(2)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(log)

	code, err := run(*cfgPath, *check, log)
	if err != nil {
		log.Error("oarlockd", "error", err)
	}
	os.Exit(code)
}

func run(cfgPath string, checkOnly bool, log *slog.Logger) (int, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return 2, err
	}

	g, err := Build(cfg, log)
	if err != nil {
		return 2, err
	}
	defer g.Close()

	// The boot gate, at last with a caller. It reports every problem at once, because a
	// deployment with three unsafe settings should take one edit to fix rather than
	// three boots.
	problems, gateErr := safety.Check(g.Settings, log)
	for _, p := range problems {
		if p.Fatal {
			log.Error("boot refused", "setting", p.Setting, "problem", p.Message)
		} else {
			log.Warn("unsafe configuration", "setting", p.Setting, "problem", p.Message)
		}
	}
	if gateErr != nil {
		return 3, gateErr
	}

	if checkOnly {
		log.Info("configuration and boot gate are satisfied", "config", cfgPath)
		return 0, nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := g.Serve(ctx); err != nil {
		return 1, err
	}
	return 0, nil
}

// Gateway is an assembled gateway.
type Gateway struct {
	Cfg      *config.Config
	Settings safety.Settings
	Log      *slog.Logger

	ledger     *sqlitestore.Store
	sql        *sqlexplore.SQLite
	live       *sessions.Registry
	hub        *hub.Hub
	inviter    *invite.Inviter
	supervisor *authz.Supervisor
	registry   interface{ Close() error }
	authorizer interface{ Close() error }
	audit      interface {
		plugin.AuditSink
		Close() error
	}
	ssh     *sshsrv.Server
	httpMux *http.ServeMux

	sshListener  net.Listener
	httpListener net.Listener
}

// Build assembles a gateway without starting it. Exported so a test can boot the real
// thing rather than a hand-arranged approximation of it.
func Build(cfg *config.Config, log *slog.Logger) (*Gateway, error) {
	if log == nil {
		log = slog.Default()
	}
	g := &Gateway{Cfg: cfg, Log: log}
	g.audit = buildAuditSink(cfg, log)

	// ── the device registry ──
	reg, closer, err := buildDeviceRegistry(cfg)
	if err != nil {
		return nil, err
	}
	g.registry = closer

	// ── the session ledger ──
	dbPath := sessionDBPath(cfg)
	if dbPath != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
			return nil, fmt.Errorf("oarlockd: creating %s: %w", filepath.Dir(dbPath), err)
		}
	}
	ledger, err := sqlitestore.Open(dbPath, sessions.Limits{
		PerDevice:         cfg.Limits.SessionsPerDevice,
		PerPrincipal:      cfg.Limits.SessionsPerPrincipal,
		TCPConnsPerDevice: cfg.Limits.TCPConnsPerDevice,
	}, nil)
	if err != nil {
		return nil, err
	}
	g.ledger = ledger
	g.live = sessions.NewRegistry()
	if cfg.Store.Kind == "sqlite" && dbPath != ":memory:" {
		explorer, err := sqlexplore.Open(dbPath)
		if err != nil {
			return nil, err
		}
		g.sql = explorer
	}

	// ── the recorder ──
	var recorder plugin.Recorder
	var replays apisrv.Replays
	var recStoreMode, recStoreDetail string
	recProtected := false
	if cfg.Recorder.Dir != "" {
		if err := os.MkdirAll(cfg.Recorder.Dir, 0o700); err != nil {
			return nil, fmt.Errorf("oarlockd: creating %s: %w", cfg.Recorder.Dir, err)
		}
		signer, pub, err := loadOrGenerateRecordingKey(cfg, log)
		if err != nil {
			return nil, err
		}
		fr, err := record.NewFileRecorder(cfg.Recorder.Dir, signer)
		if err != nil {
			return nil, err
		}
		recorder = fr
		replays = &fileReplays{rec: fr, pub: pub}
		imm := fr.Immutability()
		recStoreMode, recStoreDetail = string(imm.Mode), imm.Detail
		recProtected = imm.Mode != "mutable"
	}

	// ── authorisation ──
	var backend plugin.Authorizer
	var permissionAdmin plugin.PermissionAdmin
	switch cfg.Authz.Kind {
	case "rules":
		ra, err := rules.Open(cfg.Authz.Path, log)
		if err != nil {
			return nil, err
		}
		backend, g.authorizer = ra, ra
	case "sqlite":
		sa, err := authzsqlite.Open(cfg.Store.Path, nil)
		if err != nil {
			return nil, err
		}
		backend, permissionAdmin, g.authorizer = sa, sa, sa
	case "webhook":
		wa, err := authzwebhook.New(cfg.Authz.URL, cfg.Authz.WatchURL, cfg.Authz.Token,
			cfg.Authz.Timeout, cfg.Authz.CacheTTL)
		if err != nil {
			return nil, err
		}
		backend = wa
	case "none":
		// Refused in production by the boot gate below. Allowed here so that somebody
		// evaluating the gateway is not forced to write a rules file before their first
		// shell — authentication still applies.
		log.Warn("running with no authorizer: every authenticated operator may open a " +
			"session on any device in the registry, change the device registry and the " +
			"policy store, and query the operational database")
	}
	if len(cfg.Authz.Admins) > 0 {
		// Said out loud at every boot. A standing administrative grant that lives in a
		// file rather than in the policy store is the kind of thing that gets added for
		// an afternoon and found two years later.
		log.Info("config-declared administrators may change devices, policy and live "+
			"sessions; they may not open a session without a grant of their own",
			"admins", strings.Join(cfg.Authz.Admins, ","))
	}
	checker := &authz.Checker{Backend: backend, Grace: cfg.Authz.Grace,
		Admins: cfg.Authz.Admins, Log: log}
	g.supervisor = &authz.Supervisor{
		Checker: checker, Live: g.live,
		Interval: cfg.Authz.RecheckInterval, Log: log,
	}

	// ── tickets, the hub, invitations ──
	dispatcher, err := buildDispatcher(cfg)
	if err != nil {
		return nil, err
	}
	g.hub = hub.New(hub.Options{Log: log})
	g.inviter = &invite.Inviter{
		Tickets:    ticket.NewMemory(time.Now),
		Hub:        g.hub,
		Dispatcher: dispatcher,
		NodeURL:    strings.TrimRight(cfg.URL, "/") + "/ws/session",
		AttachURL:  strings.TrimRight(cfg.URL, "/") + "/ws/attach",
		Log:        log,
	}

	// ── operator authentication ──
	authn, oidcAuthn, authnKind, err := buildAuthenticator(cfg, log)
	if err != nil {
		return nil, err
	}
	if cfg.API.DelegationSecret != "" {
		authn, err = delegated.New(authn, []byte(cfg.API.DelegationSecret),
			cfg.API.DelegationAudience, cfg.API.MayActFor, cfg.API.DelegationMaxTTL)
		if err != nil {
			return nil, err
		}
		authnKind += "+delegated"
	}
	hostKey, generated, err := loadOrGenerateHostKey(cfg, log)
	if err != nil {
		return nil, err
	}
	sshInfo, err := sshConnection(cfg, hostKey)
	if err != nil {
		return nil, err
	}

	runner := &sessionrun.Runner{
		Sessions: ledger, Live: g.live, Recorder: recorder,
		Limits: cfg.PumpLimits(), Deadlines: cfg.Deadlines(),
		Scrollback: cfg.Limits.Scrollback, Authz: g.supervisor, Audit: g.audit, Log: log,
	}

	// ── the HTTP surface ──
	api, err := apisrv.New(apisrv.Options{
		Sessions: ledger, Live: g.live, Authenticator: authn, Authz: checker,
		Registry: reg, RegistryAdmin: registryAdmin(reg), Inviter: g.inviter,
		Permissions: permissionAdmin,
		SSH:         sshInfo,
		Agents:      g.hub, Replays: replays, SQL: g.sql,
		// The exec endpoint runs a session itself, so it needs the same collaborators
		// the SSH front door has.
		Recorder: recorder, Limits: cfg.PumpLimits(), Deadlines: cfg.Deadlines(),
		AuthzSupervisor: g.supervisor,
		RecordInput:     cfg.Policy.RecordInput,
		Audit:           g.audit,
		AttachURL:       strings.TrimRight(cfg.URL, "/") + "/ws/attach",
		RatePerMinute:   cfg.API.RatePerMinute,
		AllowUnattended: cfg.API.AllowUnattended,
		Log:             log,
	})
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()

	// One limiter across all three WebSocket doors, so a client cannot spend a fresh
	// budget on each. They are the same peer arriving at the same gateway, and counting
	// them separately would triple the ceiling for anybody who noticed.
	wsRate := cfg.Listen.WSConnRatePerMinute
	if wsRate == 0 {
		wsRate = ratelimit.DefaultWSConnRatePerMinute
	}
	wsLimit := ratelimit.Middleware(ratelimit.New(wsRate, nil), "ws", log)

	mux.Handle("/ws/control", wsLimit(&controlsrv.Server{
		Upgrader: websocket.Upgrader{},
		Handshake: &handshake.Gateway{
			Registry: reg, GatewayID: cfg.URL, Log: log,
		},
		Hub: g.hub, Log: log,
	}))
	// The two browser-facing sockets honour browser_origins; /ws/control above does
	// not, because a device sends no Origin header and never should.
	browserWS := websocket.Upgrader{OriginPatterns: cfg.BrowserOrigins}
	mux.Handle("/ws/session", wsLimit(&sessionsrv.Server{
		Upgrader: browserWS, Inviter: g.inviter, Log: log,
		Ready: func(c *ticket.Claims) frame.Ready {
			// Whether *this session* is recorded, not whether a recorder exists. A
			// `file` transfer and a `tcp` forward are never recorded however the
			// gateway is configured, and telling the device otherwise is a false
			// disclosure in the dangerous direction.
			return frame.Ready{
				SessionID: c.SessionID, Mode: "gateway",
				Recording: recorder != nil && sessionrun.Recorded(c.Profile),
			}
		},
	}))
	mux.Handle("/ws/attach", wsLimit(&attachsrv.Server{
		Upgrader: browserWS, Inviter: g.inviter,
		Runner: runner, Live: g.live, Log: log,
	}))
	mux.Handle("/api/", api)

	// The browser login, when a provider is configured and a callback is registered.
	// Without redirect_url there is nothing to mount: the console then expects a pasted
	// token, which is what a development gateway with static tokens wants.
	if oidcAuthn != nil && cfg.Auth.RedirectURL != "" {
		login, err := authsrv.New(authsrv.Options{
			OIDC:        oidcAuthn,
			RedirectURL: cfg.Auth.RedirectURL,
			Audit:       g.audit,
			Log:         log,
		})
		if err != nil {
			return nil, err
		}
		mux.Handle(authsrv.Prefix+"/", login)
		log.Info("browser login is available", "at", authsrv.Prefix+"/login",
			"callback", cfg.Auth.RedirectURL)
	}
	// The console. Optional: a binary built without the front-end assets is a working
	// gateway, and the handler says so rather than serving a blank page.
	mux.Handle("/ui/", ui.Handler("/ui"))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/ui/", http.StatusFound)
			return
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		// Ready means "can serve a session", which is not the same as "the process is
		// up": a gateway whose ledger is unreachable should be taken out of rotation
		// rather than left to refuse every session it is handed.
		// A query rather than a flag: a gateway whose ledger is unreachable should be
		// taken out of rotation rather than left to refuse every session it is handed.
		if _, err := ledger.Len(r.Context()); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprintf(w, "ledger: %v\n", err)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "ok live=%d watch=%s\n",
			g.live.Len(), g.supervisor.WatchStatus())
	})
	g.httpMux = mux

	// ── the SSH front door ──
	ssh, err := sshsrv.New(sshsrv.Options{
		Addr: cfg.Listen.SSH, Authenticator: authn, Authz: checker,
		AuthzSupervisor: g.supervisor, Registry: reg, Inviter: g.inviter,
		Sessions: ledger, Live: g.live, Recorder: recorder,
		Limits: cfg.PumpLimits(), Deadlines: cfg.Deadlines(),
		RecordInput:       cfg.Policy.RecordInput,
		Audit:             g.audit,
		HandshakeBudget:   cfg.SSH.HandshakeBudget,
		ConnRatePerMinute: cfg.SSH.ConnRatePerMinute,
		HostKey:           hostKey, Log: log,
	})
	if err != nil {
		return nil, err
	}
	g.ssh = ssh

	// ── what the boot gate is asked about ──
	devices, _, _ := reg.List(context.Background(), plugin.DeviceQuery{})
	passthrough := 0
	for _, d := range devices {
		if d.AllowPassthrough {
			passthrough++
		}
	}
	grace := authz.DefaultGrace
	if cfg.Authz.Grace != nil {
		grace = *cfg.Authz.Grace
	}
	g.Settings = safety.Settings{
		Env:                        cfg.SafetyEnv(),
		AuthenticatorKind:          authnKind,
		RecordInputDefault:         cfg.Policy.RecordInput.Default,
		RecorderConfigured:         recorder != nil,
		RecordingStoreProtected:    recProtected,
		RecordingStoreMode:         recStoreMode,
		DevicesAllowingPassthrough: passthrough,
		SSHHostKeyConfigured:       !generated,
		AuthzGrace:                 grace,
		AuthzKind:                  cfg.Authz.Kind,
	}
	_ = recStoreDetail
	return g, nil
}

func sshConnection(cfg *config.Config, signer xssh.Signer) (*apisrv.SSHConnection, error) {
	host, port, err := net.SplitHostPort(cfg.Listen.SSH)
	if err != nil {
		return nil, fmt.Errorf("oarlockd: parsing SSH listen address: %w", err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		advertised, err := url.Parse(cfg.URL)
		if err != nil || advertised.Hostname() == "" {
			return nil, errors.New("oarlockd: cannot derive the SSH hostname from url")
		}
		host = advertised.Hostname()
	}
	public := strings.TrimSpace(string(xssh.MarshalAuthorizedKey(signer.PublicKey())))
	knownHost := host
	if port != "22" || strings.Contains(host, ":") {
		knownHost = net.JoinHostPort(host, port)
	}
	return &apisrv.SSHConnection{
		Host: host, Port: port, HostKey: public,
		KnownHosts:  knownHost + " " + public,
		Fingerprint: xssh.FingerprintSHA256(signer.PublicKey()),
	}, nil
}

func buildDispatcher(cfg *config.Config) (plugin.Dispatcher, error) {
	switch cfg.Dispatch.Kind {
	case "", "none":
		return nil, nil
	case "exec":
		return dispatchexec.New(cfg.Dispatch.Command, cfg.Dispatch.Timeout)
	case "webhook":
		return dispatchwebhook.New(cfg.Dispatch.URL, []byte(cfg.Dispatch.Secret), cfg.Dispatch.Timeout)
	case "mqtt":
		return dispatchmqtt.New(cfg.Dispatch.URL, cfg.Dispatch.Topic, cfg.Dispatch.ClientID,
			cfg.Dispatch.Username, cfg.Dispatch.Password, dispatchQoS(cfg), cfg.Dispatch.Timeout)
	default:
		return nil, fmt.Errorf("dispatcher.kind %q is not known", cfg.Dispatch.Kind)
	}
}

func dispatchQoS(cfg *config.Config) int {
	if cfg.Dispatch.QoS == nil {
		return 1
	}
	return *cfg.Dispatch.QoS
}

func sessionDBPath(cfg *config.Config) string {
	if cfg.Store.Kind == "sqlite" && cfg.Store.Path != "" {
		return cfg.Store.Path
	}
	if cfg.Recorder.Dir != "" {
		return filepath.Join(cfg.Recorder.Dir, "sessions.db")
	}
	return filepath.Join(filepath.Dir(cfg.Devices.Path), "sessions.db")
}

func buildDeviceRegistry(cfg *config.Config) (plugin.DeviceRegistry, interface{ Close() error }, error) {
	switch cfg.Devices.Kind {
	case "file":
		reg, err := file.Open(cfg.Devices.Path)
		return reg, nil, err
	case "sqlite":
		reg, err := regsqlite.Open(cfg.Store.Path)
		return reg, reg, err
	case "postgres":
		return nil, nil, errors.New("devices.kind postgres is not implemented yet")
	default:
		return nil, nil, fmt.Errorf("devices.kind %q is not known", cfg.Devices.Kind)
	}
}

func registryAdmin(reg plugin.DeviceRegistry) plugin.DeviceRegistryAdmin {
	admin, _ := reg.(plugin.DeviceRegistryAdmin)
	return admin
}

// Serve runs until the context ends, then drains.
func (g *Gateway) Serve(ctx context.Context) error {
	if err := g.Listen(); err != nil {
		return err
	}
	// Owning both listeners means this process owns the local SQLite ledger. Rows left
	// live by a crash have no corresponding in-memory handle and would otherwise hold
	// device concurrency slots forever.
	if n, err := g.ledger.FinishLive(ctx, "gateway_shutdown"); err != nil {
		return fmt.Errorf("oarlockd: recovering sessions: %w", err)
	} else if n > 0 {
		g.Log.Warn("closed sessions left live by a previous gateway", "sessions", n)
	}
	g.Log.Info("oarlockd is listening",
		"ssh", g.sshListener.Addr().String(),
		"http", g.httpListener.Addr().String(),
		"url", g.Cfg.URL, "env", g.Cfg.Env, "version", Version,
		"console", ui.Built())
	if !ui.Built() {
		g.Log.Info("the console is not built into this binary; " +
			"run `pnpm build:ui` and rebuild to serve /ui")
	}

	errs := make(chan error, 2)
	httpSrv := &http.Server{
		Handler: g.httpMux,
		// A slow or absent OPEN must not hold a connection open indefinitely; the
		// session handlers apply their own budgets on top.
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		var err error
		if g.Cfg.Listen.TLSCert != "" {
			err = httpSrv.ServeTLS(g.httpListener, g.Cfg.Listen.TLSCert, g.Cfg.Listen.TLSKey)
		} else {
			err = httpSrv.Serve(g.httpListener)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- fmt.Errorf("http: %w", err)
		}
	}()
	go func() {
		if err := g.ssh.Handler().Serve(g.sshListener); err != nil &&
			!errors.Is(err, gssh.ErrServerClosed) {
			errs <- fmt.Errorf("ssh: %w", err)
		}
	}()
	go g.supervisor.WatchRevocations(ctx)

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
	}

	// ── drain ──
	//
	// Stop accepting first, then tell live sessions why. An operator whose session ends
	// during a deploy should see `gateway_shutdown` rather than a dropped connection:
	// one is a deploy and the other is a bug they will report.
	g.Log.Info("draining", "live_sessions", g.live.Len())
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	_ = g.ssh.Close()
	if n := g.live.KillAll("gateway_shutdown"); n > 0 {
		g.Log.Info("closed live sessions for a drain", "sessions", n)
	}
	// A moment for the CLOSE frames to land before the process goes.
	select {
	case <-time.After(500 * time.Millisecond):
	case <-shutdownCtx.Done():
	}
	g.Log.Info("stopped")
	return nil
}

// Listen binds the listeners without serving, so a test can learn the ports.
func (g *Gateway) Listen() error {
	if g.sshListener != nil {
		return nil
	}
	sl, err := net.Listen("tcp", g.Cfg.Listen.SSH)
	if err != nil {
		return fmt.Errorf("oarlockd: listening on %s: %w", g.Cfg.Listen.SSH, err)
	}
	// A ceiling on concurrent connections at the front door, authenticated or not.
	//
	// The pre-authentication budget in internal/sshsrv is what actually bounds this —
	// it is what makes a slot come back — but a budget alone still lets a peer hold
	// budget×rate connections at once, and each one is a goroutine and a descriptor.
	// LimitListener stops accepting past the cap and leaves the rest in the kernel's
	// accept queue, so the cost of the surplus is the queue rather than the process.
	if n := maxSSHConnections(g.Cfg); n > 0 {
		sl = netutil.LimitListener(sl, n)
	}
	hl, err := net.Listen("tcp", g.Cfg.Listen.HTTP)
	if err != nil {
		_ = sl.Close()
		return fmt.Errorf("oarlockd: listening on %s: %w", g.Cfg.Listen.HTTP, err)
	}
	g.sshListener, g.httpListener = sl, hl
	return nil
}

// DefaultMaxSSHConnections is the ceiling when the configuration does not set one.
//
// Deliberately generous. The SSH front door serves operators, not the public: a fleet
// with a hundred people on call does not approach this, and a limit that bites during
// an incident locks out the person handling it. Combined with the 15s handshake
// budget, saturating it requires sustaining roughly seventy new connections a second.
const DefaultMaxSSHConnections = 1024

func maxSSHConnections(cfg *config.Config) int {
	switch {
	case cfg.SSH.MaxConnections < 0:
		return 0 // explicitly uncapped
	case cfg.SSH.MaxConnections == 0:
		return DefaultMaxSSHConnections
	default:
		return cfg.SSH.MaxConnections
	}
}

// Addrs are the bound addresses, for tests and for logging.
func (g *Gateway) Addrs() (ssh, http string) {
	if g.sshListener == nil {
		return "", ""
	}
	return g.sshListener.Addr().String(), g.httpListener.Addr().String()
}

// Close releases everything Build acquired.
func (g *Gateway) Close() {
	if g.sql != nil {
		_ = g.sql.Close()
	}
	if g.registry != nil {
		_ = g.registry.Close()
	}
	if g.authorizer != nil {
		_ = g.authorizer.Close()
	}
	if g.audit != nil {
		_ = g.audit.Close()
	}
	if g.ledger != nil {
		_ = g.ledger.Shutdown()
	}
}

func buildAuditSink(cfg *config.Config, log *slog.Logger) interface {
	plugin.AuditSink
	Close() error
} {
	var sink plugin.AuditSink
	switch cfg.Audit.Kind {
	case "none":
		sink = audit.Discard{}
	default:
		sink = audit.NewJSONL(os.Stderr)
	}
	return audit.NewAsync(sink, cfg.Audit.Buffer, log)
}

// buildAuthenticator returns the authenticator, the concrete OIDC client when there is
// one — the browser login needs the code-flow methods, which are not on the interface —
// and a name for the boot gate and the log.
func buildAuthenticator(cfg *config.Config, log *slog.Logger) (plugin.Authenticator,
	*oidc.Authenticator, string, error) {
	// OIDC answers both surfaces on its own — a bearer token on the API, a device-code
	// login over SSH keyboard-interactive — so when it is configured it is the whole
	// answer rather than one half of a pair.
	if cfg.Auth.Kind == "oidc" {
		a, err := oidc.Open(context.Background(), oidc.Config{
			Issuer:       cfg.Auth.Issuer,
			ClientID:     cfg.Auth.ClientID,
			ClientSecret: cfg.Auth.ClientSecret,
			Audience:     cfg.Auth.Audience,
			Scopes:       cfg.Auth.Scopes,
			Claims: oidc.ClaimMap{
				Subject: cfg.Auth.SubjectClaim,
				Email:   cfg.Auth.EmailClaim,
				Groups:  cfg.Auth.GroupsClaim,
			},
			Skew:          cfg.Auth.Skew,
			JWKSRefresh:   cfg.Auth.JWKSRefresh,
			DeviceTimeout: cfg.Auth.DeviceTimeout,
			Log:           log,
		})
		if err != nil {
			return nil, nil, "", err
		}
		// Keys alongside OIDC are legitimate — a break-glass account, or an automation
		// that cannot do a browser flow — so they are combined rather than refused. What
		// is *not* combined is static tokens: a long-lived shared secret next to a real
		// identity provider is the weakest link deciding the strength of the chain.
		if len(cfg.API.Tokens) > 0 {
			return nil, nil, "", errors.New("oarlockd: api.tokens is set alongside auth.kind: " +
				"oidc. A static token is a long-lived shared secret that cannot be " +
				"revoked without a config push; next to an identity provider it is " +
				"simply the easier way in. Remove api.tokens")
		}
		if cfg.SSH.AuthorizedKeys != "" {
			ak, err := authorizedkeys.Open(cfg.SSH.AuthorizedKeys, log)
			if err != nil {
				return nil, nil, "", err
			}
			log.Warn("both oidc and ssh.authorized_keys are configured; an operator " +
				"whose key is in that file does not need to log in, so revoking their " +
				"access means editing the file on every replica as well")
			return &interactivePair{
				pair:        pair{keys: ak, tokens: a},
				interactive: a,
			}, a, "oidc+authorized_keys", nil
		}
		return a, a, "oidc", nil
	}

	if cfg.Auth.Kind == "sshca" {
		ca, err := sshca.Open(sshca.Options{
			CAKeys:        cfg.Auth.CAKeys,
			Revocations:   cfg.Auth.Revocations,
			MaxLifetime:   cfg.Auth.MaxLifetime,
			PrincipalFrom: sshca.PrincipalSource(cfg.Auth.PrincipalFrom),
			Log:           log,
		})
		if err != nil {
			return nil, nil, "", err
		}
		// A CA authenticates the SSH front door and nothing else: a certificate is an
		// SSH credential, and there is no honest way to turn an HTTP request into one.
		// So the API still needs its own backend, and static tokens are the only one
		// available without OIDC.
		if cfg.SSH.AuthorizedKeys != "" {
			// Not combined, unlike oidc + keys. There the key file is a break-glass path
			// beside a different kind of credential; here it is the *same* kind, and it
			// is the one that does not expire — so it is not a fallback, it is the way
			// in that survives the CA refusing to issue.
			return nil, nil, "", errors.New("oarlockd: ssh.authorized_keys is set " +
				"alongside auth.kind: sshca. A key in that file authenticates without a " +
				"certificate and never expires, which is the one thing running a CA is " +
				"meant to remove. Remove ssh.authorized_keys")
		}
		var tokens plugin.Authenticator
		if len(cfg.API.Tokens) > 0 {
			st, err := statictoken.Open(cfg.Env, cfg.API.Tokens)
			if err != nil {
				return nil, nil, "", err
			}
			tokens = st
		}
		if tokens == nil {
			return ca, nil, "sshca", nil
		}
		return &pair{keys: ca, tokens: tokens}, nil, "sshca+static_token", nil
	}

	// An SSH key file authenticates operators at the front door; static tokens
	// authenticate the API. A deployment needs both surfaces, so the two are combined
	// rather than chosen between.
	var keys plugin.Authenticator
	if cfg.SSH.AuthorizedKeys != "" {
		ak, err := authorizedkeys.Open(cfg.SSH.AuthorizedKeys, log)
		if err != nil {
			return nil, nil, "", err
		}
		keys = ak
	}
	var tokens plugin.Authenticator
	if len(cfg.API.Tokens) > 0 {
		st, err := statictoken.Open(cfg.Env, cfg.API.Tokens)
		if err != nil {
			return nil, nil, "", err
		}
		tokens = st
	}
	switch {
	case keys == nil && tokens == nil:
		return nil, nil, "", errors.New("oarlockd: no authenticator configured: set " +
			"ssh.authorized_keys, api.tokens, or both")
	case tokens == nil:
		return keys, nil, "authorized_keys", nil
	case keys == nil:
		return tokens, nil, "static_token", nil
	default:
		return &pair{keys: keys, tokens: tokens}, nil, "authorized_keys+static_token", nil
	}
}

// pair routes each surface to the backend that can answer for it.
//
// Deliberately not a general-purpose chain: each method has exactly one backend that can
// answer it, so "try both and take the first that succeeds" would only add a way for an
// SSH key to be accepted as an API token by a future backend that guesses.
type pair struct {
	keys   plugin.Authenticator
	tokens plugin.Authenticator
}

// interactivePair is a pair whose token half can also hold a conversation.
//
// A separate type rather than a nil-able field on pair, because the optional interface is
// discovered by type assertion: a pair that carried the method unconditionally would
// advertise keyboard-interactive to SSH clients even in a keys-and-tokens deployment,
// where it can only ever refuse. An operator would be prompted, have nothing useful to
// type, and be turned away twice.
type interactivePair struct {
	pair
	interactive plugin.InteractiveAuthenticator
}

func (p *interactivePair) AuthInteractive(ctx context.Context, user string,
	ask plugin.Challenge) (*plugin.Principal, error) {
	return p.interactive.AuthInteractive(ctx, user, ask)
}

func (p *pair) AuthPublicKey(ctx context.Context, user string, key xssh.PublicKey) (*plugin.Principal, error) {
	return p.keys.AuthPublicKey(ctx, user, key)
}

func (p *pair) AuthDelegated(ctx context.Context, svc *plugin.Principal, assertion string) (*plugin.Principal, error) {
	return p.tokens.AuthDelegated(ctx, svc, assertion)
}

func (p *pair) AuthHTTP(ctx context.Context, r *http.Request) (*plugin.Principal, error) {
	return p.tokens.AuthHTTP(ctx, r)
}

func loadOrGenerateHostKey(cfg *config.Config, log *slog.Logger) (xssh.Signer, bool, error) {
	b, err := os.ReadFile(cfg.SSH.HostKey)
	if err == nil {
		signer, perr := xssh.ParsePrivateKey(b)
		if perr != nil {
			return nil, false, fmt.Errorf("oarlockd: parsing %s: %w", cfg.SSH.HostKey, perr)
		}
		return signer, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, fmt.Errorf("oarlockd: reading %s: %w", cfg.SSH.HostKey, err)
	}
	if !cfg.SSH.GenerateHostKey {
		return nil, false, fmt.Errorf("oarlockd: %s does not exist. Generate one and "+
			"distribute it to every replica, or set ssh.generate_host_key for a "+
			"throwaway one — the boot gate refuses a generated key outside dev, because "+
			"a key that changes on restart warns operators every time",
			cfg.SSH.HostKey)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, false, err
	}
	block, err := xssh.MarshalPrivateKey(priv, "oarlockd generated host key")
	if err != nil {
		return nil, false, err
	}
	if err := os.WriteFile(cfg.SSH.HostKey, encPEM.EncodeToMemory(block), 0o600); err != nil {
		return nil, false, fmt.Errorf("oarlockd: writing %s: %w", cfg.SSH.HostKey, err)
	}
	signer, err := xssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, false, err
	}
	log.Warn("generated an SSH host key",
		"path", cfg.SSH.HostKey,
		"note", "every replica must present the same key, and a key generated at boot "+
			"warns every operator on every restart")
	return signer, true, nil
}

// fileReplays adapts the file recorder to what the API serves.
//
// Verification happens here rather than in the browser because it needs the manifest and a
// public key the deployment trusts — neither of which a page can be given without also
// giving it the ability to be lied to about them.
type fileReplays struct {
	rec *record.Recorder
	pub ed25519.PublicKey
}

func (f *fileReplays) Cast(ctx context.Context, sessionID string) ([]byte, error) {
	rc, err := f.rec.Get(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func (f *fileReplays) Verdict(ctx context.Context, sessionID string) (apisrv.ReplayVerdict, error) {
	v, err := f.rec.Verify(ctx, sessionID, f.pub)
	if err != nil {
		return apisrv.ReplayVerdict{}, err
	}
	return apisrv.ReplayVerdict{
		Status:             string(v.Status),
		OK:                 v.OK,
		EventsFound:        v.EventsFound,
		EventsExpected:     v.EventsExpected,
		LastGoodCheckpoint: v.LastGoodCheckpoint,
		Detail:             v.Detail,
	}, nil
}

func loadOrGenerateRecordingKey(cfg *config.Config, log *slog.Logger) (record.Signer, ed25519.PublicKey, error) {
	b, err := os.ReadFile(cfg.Recorder.SigningKey)
	if err == nil {
		key, perr := parseEd25519Seed(b)
		if perr != nil {
			return nil, nil, fmt.Errorf("oarlockd: reading %s: %w", cfg.Recorder.SigningKey, perr)
		}
		return &record.KeySigner{Key: key, ID: cfg.Recorder.KeyID},
			key.Public().(ed25519.PublicKey), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("oarlockd: reading %s: %w", cfg.Recorder.SigningKey, err)
	}
	if !cfg.Recorder.GenerateSigningKey {
		return nil, nil, fmt.Errorf("oarlockd: %s does not exist. Generate a recording key "+
			"and keep it apart from the SSH host key — one is presented to every "+
			"operator and the other attests that recordings were not altered, so "+
			"rotating one must not force rotating the other. Set "+
			"recorder.generate_signing_key for a throwaway one",
			cfg.Recorder.SigningKey)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(cfg.Recorder.SigningKey, priv.Seed(), 0o600); err != nil {
		return nil, nil, err
	}
	pubPath := cfg.Recorder.SigningKey + ".pub"
	if err := os.WriteFile(pubPath, pub, 0o644); err != nil {
		return nil, nil, err
	}
	log.Warn("generated a recording signing key",
		"path", cfg.Recorder.SigningKey, "public", pubPath,
		"note", "recordings signed by a key that changes on restart cannot be verified "+
			"afterwards")
	return &record.KeySigner{Key: priv, ID: cfg.Recorder.KeyID}, pub, nil
}

func parseEd25519Seed(b []byte) (ed25519.PrivateKey, error) {
	if len(b) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(b), nil
	}
	if len(b) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(b), nil
	}
	return nil, fmt.Errorf("not an ed25519 key: %d bytes, want %d or %d",
		len(b), ed25519.SeedSize, ed25519.PrivateKeySize)
}
