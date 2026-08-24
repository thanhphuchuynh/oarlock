// Command oarlock-agent is the reference device agent.
//
// It exists to be run: the agent library was exercised only from the gateway's own tests,
// and a library nobody can start is a library nobody can try.
//
// # Where this binary actually runs
//
// Three places, and they differ in what a session can touch.
//
// A laptop, for trying it. An `init` service on a device whose system image you control —
// `/system/bin/oarlock-agent`, started as `shell`, which is the identity `adb shell` runs
// as and the one Android's SELinux policy has been hardened around. And inside an app, as
// a library, when the image is not yours: Android 10 forbids executing a binary from app
// storage, which is why the agent is a library first.
//
// The third case is the constrained one — an app-sandbox session sees the app's own files
// and very little else. The second is why -config and `sessions:` exist: a service
// started by init has a fixed argv baked into a system image, and if it starts as root
// then every session is root unless the agent drops.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	xssh "golang.org/x/crypto/ssh"

	"github.com/oarlock/oarlock/agent"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/transport/websocket"
)

var version = "dev"

func main() {
	var (
		gateway  = flag.String("gateway", "", "control-channel URL, e.g. wss://gw.example.org/ws/control")
		device   = flag.String("device", "", "this device's id, as it appears in the registry")
		keyPath  = flag.String("key", "device.key", "path to the device's ed25519 key")
		genKey   = flag.Bool("generate-key", false, "write a new key at -key if it is absent")
		shell    = flag.String("shell", defaultShell(), "the shell to open for a session")
		pin      = flag.String("pin", "", "comma-separated SHA-256 pins for the gateway's key")
		insecure = flag.Bool("insecure-skip-pin", false,
			"connect without pinning the gateway's key")
		showVersion = flag.Bool("version", false, "print the version and exit")
		configPath  = flag.String("config", "",
			"path to an agent config file; flags given here win over it")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("oarlock-agent", version)
		return
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Generating a key is a setup step, not a connection. It used to require -gateway and
	// -device and a decision about pinning, none of which it needs — which showed up as a
	// README telling people to pass `-gateway x` to get past the checks.
	if *genKey {
		key, err := loadOrGenerateKey(*keyPath, true, log)
		if err != nil {
			log.Error("device key", "error", err)
			os.Exit(2)
		}
		line, err := publicKeyLine(key.Public().(ed25519.PublicKey))
		if err != nil {
			log.Error("device key", "error", err)
			os.Exit(2)
		}
		// On stdout, so it can be piped into a registry file.
		fmt.Print(line)
		return
	}

	// The file first, then flags over the top: a flag is something somebody typed just
	// now, and a config file is something a system image shipped six months ago.
	cfg := &Config{}
	if *configPath != "" {
		loaded, err := LoadConfig(*configPath)
		if err != nil {
			log.Error("agent config", "error", err)
			os.Exit(2)
		}
		cfg = loaded
	}
	flagsSet := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { flagsSet[f.Name] = true })
	if flagsSet["gateway"] || cfg.Gateway == "" {
		cfg.Gateway = *gateway
	}
	if flagsSet["device"] || cfg.Device == "" {
		cfg.Device = *device
	}
	if flagsSet["key"] || cfg.Key == "" {
		cfg.Key = *keyPath
	}
	if flagsSet["shell"] || cfg.Shell == "" {
		cfg.Shell = *shell
	}
	if flagsSet["pin"] && *pin != "" {
		cfg.Pins = strings.Split(*pin, ",")
	}
	if flagsSet["insecure-skip-pin"] {
		cfg.InsecureSkipPin = *insecure
	}

	if cfg.Gateway == "" || cfg.Device == "" {
		log.Error("both -gateway and -device are required (or gateway and device/" +
			"device_file in -config)")
		os.Exit(2)
	}

	// Named resolvers before anything dials, because the first thing that resolves a
	// name is the control channel itself.
	if resolver, err := newResolver(cfg.DNS); err != nil {
		log.Error("dns", "error", err)
		os.Exit(2)
	} else if resolver != nil {
		net.DefaultResolver = resolver
		log.Info("resolving through the configured servers rather than the system's",
			"servers", strings.Join(cfg.DNS, ","))
	}

	// Which identity a session runs as, and whether this process could possibly manage
	// it. Checked at boot: a session that fails at exec time fails thirty seconds after
	// an operator asked for it, with nothing legible to look at.
	identities, err := cfg.Sessions.identities()
	if err != nil {
		log.Error("agent config: sessions", "error", err)
		os.Exit(2)
	}
	if err := canDropTo(identities, []string{"shell", "exec"}); err != nil {
		log.Error("sessions cannot run as the configured user", "error", err)
		os.Exit(2)
	}
	// Asking the hook rather than trusting the config: it collapses a drop to our own
	// identity into "inherit", so the config and the behaviour can differ and the log
	// has to report the behaviour.
	if identities == nil || identities("shell") == nil {
		// Said out loud, because it is the difference between a recorded shell that can
		// read one app's files and a recorded shell that can do anything.
		log.Info("sessions will run as this process's own user",
			"uid", os.Geteuid(), "gid", os.Getegid())
	} else {
		log.Info("sessions will run as a separate user", "default", cfg.Sessions.User,
			"per_profile", cfg.Sessions.PerProfile, "groups", cfg.Sessions.Groups)
	}

	signer, err := loadOrGenerateKey(cfg.Key, false, log)
	if err != nil {
		log.Error("device key", "error", err)
		os.Exit(2)
	}

	// The key first, so that generating one is a setup step rather than something that
	// requires deciding about pinning on the way past.
	if len(cfg.Pins) == 0 && !cfg.InsecureSkipPin {
		// Wire version v0 has no channel binding, so pinning is what stands between the
		// handshake and a TLS-terminating middlebox relaying it. Refusing rather than
		// defaulting to unpinned: an agent that connects without a pin because nobody
		// passed one is an agent nobody decided about.
		log.Error("no -pin given. Wire v0 has no channel binding, so pinning the " +
			"gateway's key is what stands between the handshake and a middlebox " +
			"relaying it. Pass -pin, or -insecure-skip-pin if you have decided that is " +
			"acceptable")
		os.Exit(2)
	}

	// `exec` is offered only when the device has an allow-list. Advertising a capability
	// with nothing on the list would mean the gateway accepted such a session and the
	// device refused every command in it — a round trip to learn what the handshake
	// could have said.
	caps := []string{"shell"}
	var execFn agent.ExecFunc
	if len(cfg.Exec) > 0 {
		opts := []agent.ExecOption{}
		if cfg.ExecTimeout > 0 {
			opts = append(opts, agent.ExecTimeout(cfg.ExecTimeout))
		}
		if identities != nil {
			if id := identities("exec"); id != nil {
				opts = append(opts, agent.ExecAs(id))
			}
		}
		execFn = agent.Exec(cfg.Exec, opts...)
		caps = append(caps, "exec")
		log.Info("exec is available on this device", "commands", len(cfg.Exec))
	}

	// `file` likewise: offered only when a root is configured.
	var fileFn agent.FileFunc
	if cfg.FileRoot != "" {
		opts := []agent.FileOption{}
		if cfg.FileWritable {
			opts = append(opts, agent.FileWritable())
		}
		if cfg.FileMaxBytes > 0 {
			opts = append(opts, agent.FileMaxBytes(cfg.FileMaxBytes))
		}
		fileFn, err = agent.File(cfg.FileRoot, opts...)
		if err != nil {
			log.Error("file root", "error", err)
			os.Exit(2)
		}
		caps = append(caps, "file")
		log.Info("file transfer is available on this device",
			"root", cfg.FileRoot, "writable", cfg.FileWritable)
	}

	control, err := agent.NewControl(agent.Config{
		Gateway:   cfg.Gateway,
		DeviceID:  cfg.Device,
		Signer:    signer,
		Dialer:    websocket.Dialer{},
		PinSHA256: cfg.Pins,
		Caps:      caps,
		Info: frame.AgentInfo{
			Version:  version,
			Platform: platform(),
		},
		Shell: agent.ForkptyWith(strings.Fields(cfg.Shell), agent.ShellOptions{
			Identity: identities,
		}),
		Exec: execFn,
		File: fileFn,
		Log:  log,
	})
	if err != nil {
		log.Error("agent", "error", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// The merged configuration, not the flags: with -config the flags are mostly empty,
	// and a startup line reading gateway="" from a process that is about to connect to
	// one is worse than no line at all.
	log.Info("oarlock-agent starting",
		"device", cfg.Device, "gateway", cfg.Gateway, "shell", cfg.Shell,
		"pinned", len(cfg.Pins) > 0, "version", version)
	if err := control.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("control channel", "error", err)
		os.Exit(1)
	}
	log.Info("stopped")
}

func loadOrGenerateKey(path string, generate bool, log *slog.Logger) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		switch len(b) {
		case ed25519.SeedSize:
			return ed25519.NewKeyFromSeed(b), nil
		case ed25519.PrivateKeySize:
			return ed25519.PrivateKey(b), nil
		default:
			return nil, fmt.Errorf("%s is %d bytes, not an ed25519 key", path, len(b))
		}
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if !generate {
		return nil, fmt.Errorf("%s does not exist. Run with -generate-key to create one, "+
			"then add the public half it prints to the gateway's device registry", path)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, priv.Seed(), 0o600); err != nil {
		return nil, err
	}
	// The public half in the form the registry wants, so setting a device up is a copy
	// and paste rather than a conversion.
	pubPath := path + ".pub"
	line, err := publicKeyLine(pub)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(pubPath, []byte(line), 0o644); err != nil {
		return nil, err
	}
	log.Warn("generated a device key",
		"path", path, "public", pubPath,
		"next", "add the public half to the gateway's devices.yaml under this device's keys")
	return priv, nil
}

// publicKeyLine renders the public half in the form the device registry parses.
//
// Via x/crypto/ssh rather than by hand: the wire form is a length-prefixed algorithm name
// followed by a length-prefixed key, and the library that already parses it is the right
// thing to produce it.
func publicKeyLine(pub ed25519.PublicKey) (string, error) {
	key, err := xssh.NewPublicKey(pub)
	if err != nil {
		return "", err
	}
	return string(xssh.MarshalAuthorizedKey(key)), nil
}

func defaultShell() string {
	if s := os.Getenv("SHELL"); s != "" {
		return s
	}
	return "/bin/sh"
}

func platform() string { return runtimeOS() + "/" + runtimeArch() }
