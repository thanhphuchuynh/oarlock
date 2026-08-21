// Command oarlock-agent is the reference device agent.
//
// It exists to be run: the agent library was exercised only from the gateway's own tests,
// and a library nobody can start is a library nobody can try. On a real device this would
// be embedded rather than shipped as a binary — Android 10 forbids executing a binary from
// app storage, which is why the agent is a library first — but a binary is what makes the
// thing testable on a laptop.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log/slog"
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

	if *gateway == "" || *device == "" {
		log.Error("both -gateway and -device are required")
		os.Exit(2)
	}
	signer, err := loadOrGenerateKey(*keyPath, false, log)
	if err != nil {
		log.Error("device key", "error", err)
		os.Exit(2)
	}

	// The key first, so that generating one is a setup step rather than something that
	// requires deciding about pinning on the way past.
	if *pin == "" && !*insecure {
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

	var pins []string
	if *pin != "" {
		pins = strings.Split(*pin, ",")
	}

	control, err := agent.NewControl(agent.Config{
		Gateway:   *gateway,
		DeviceID:  *device,
		Signer:    signer,
		Dialer:    websocket.Dialer{},
		PinSHA256: pins,
		Caps:      []string{"shell"},
		Info: frame.AgentInfo{
			Version:  version,
			Platform: platform(),
		},
		Shell: agent.Forkpty(strings.Fields(*shell)),
		Log:   log,
	})
	if err != nil {
		log.Error("agent", "error", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("oarlock-agent starting",
		"device", *device, "gateway", *gateway, "shell", *shell, "version", version)
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
