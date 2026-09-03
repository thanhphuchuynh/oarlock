// Command oarlock-conformance runs the agent conformance suite.
//
// It is a gateway that exists to be wrong at your agent in specific ways. Point your
// agent at it, and it reports which paragraphs of docs/protocol.md your implementation
// honours.
//
//	oarlock-conformance -device rower-1 -key rower-1.pub
//	  control channel: ws://127.0.0.1:9440/ws/control
//
// Then start your agent against that URL. The suite waits, drives ten cases, prints a
// report and exits non-zero if any failed.
//
// # Serve it over TLS to check channel binding
//
// Protocol v1 binds the handshake to the TLS connection underneath it, so over plain
// `ws://` there is nothing to bind and those cases are reported as skipped rather than
// passed. Pass -cert and -key-file to serve `wss://` and check them.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	xssh "golang.org/x/crypto/ssh"

	"github.com/oarlock/oarlock/pkg/agentconf"
	"github.com/oarlock/oarlock/pkg/transport/websocket"
)

func main() {
	var (
		addr     = flag.String("listen", "127.0.0.1:9440", "address to serve on")
		device   = flag.String("device", "", "the device id your agent identifies as")
		keyPath  = flag.String("key", "", "file holding that device's Ed25519 public key")
		gateway  = flag.String("gateway-id", "conformance-suite", "gateway id, which is inside the signed input")
		certFile = flag.String("cert", "", "TLS certificate, to serve wss:// and check channel binding")
		keyFile  = flag.String("key-file", "", "TLS private key")
		wait     = flag.Duration("connect-timeout", agentconf.DefaultConnectTimeout,
			"how long to wait for the agent to (re)connect between cases")
		caseTO = flag.Duration("case-timeout", agentconf.DefaultCaseTimeout,
			"how long one case waits for the agent")
	)
	flag.Parse()

	if *device == "" || *keyPath == "" {
		fmt.Fprintln(os.Stderr, "oarlock-conformance: -device and -key are required")
		flag.Usage()
		os.Exit(2)
	}
	pub, err := readPublicKey(*keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "oarlock-conformance: %v\n", err)
		os.Exit(2)
	}

	scheme := "ws"
	if *certFile != "" {
		scheme = "wss"
	}
	base := scheme + "://" + *addr

	suite, err := agentconf.New(agentconf.Options{
		DeviceID:       *device,
		PublicKey:      pub,
		GatewayID:      *gateway,
		SessionURL:     base + "/ws/session",
		CaseTimeout:    *caseTO,
		ConnectTimeout: *wait,
	}, websocket.Upgrader{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "oarlock-conformance: %v\n", err)
		os.Exit(2)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ws/control", suite.Control)
	mux.HandleFunc("/ws/session", suite.Session)
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	errCh := make(chan error, 1)
	go func() {
		if *certFile != "" {
			errCh <- srv.ListenAndServeTLS(*certFile, *keyFile)
			return
		}
		errCh <- srv.ListenAndServe()
	}()

	fmt.Printf("oarlock-conformance: waiting for device %q\n", *device)
	fmt.Printf("  control channel: %s/ws/control\n", base)
	fmt.Printf("  session URL:     %s/ws/session\n", base)
	if scheme == "ws" {
		// Said up front rather than only in the report, because an implementer who reads
		// "8 passed" and stops has not checked the thing v1 exists for.
		fmt.Println("  note: plain ws://, so the channel-binding cases will be skipped." +
			" Pass -cert and -key-file to check them.")
	}
	fmt.Println()

	// The suite blocks until it is done or something breaks the listener.
	done := make(chan agentconf.Report, 1)
	go func() { done <- suite.Run(context.Background()) }()

	var report agentconf.Report
	select {
	case report = <-done:
	case err := <-errCh:
		fmt.Fprintf(os.Stderr, "oarlock-conformance: serving: %v\n", err)
		os.Exit(2)
	}
	_ = srv.Close()

	fmt.Print(report)
	if !report.Passed() {
		os.Exit(1)
	}
}

// readPublicKey accepts an OpenSSH `ssh-ed25519 AAAA…` line or raw base64.
//
// Both, because an implementer's device key is usually already in one of those shapes and
// converting it by hand is a step at which people give up.
func readPublicKey(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	text := strings.TrimSpace(string(b))

	if strings.HasPrefix(text, "ssh-ed25519") {
		k, _, _, _, perr := xssh.ParseAuthorizedKey([]byte(text))
		if perr != nil {
			return nil, fmt.Errorf("parsing %s as an authorized_keys line: %w", path, perr)
		}
		ck, ok := k.(xssh.CryptoPublicKey)
		if !ok {
			return nil, fmt.Errorf("%s is not a key this suite can use", path)
		}
		pub, ok := ck.CryptoPublicKey().(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%s is not an Ed25519 key; a device key must be", path)
		}
		return pub, nil
	}

	raw, derr := base64.StdEncoding.DecodeString(text)
	if derr != nil {
		raw, derr = base64.RawURLEncoding.DecodeString(text)
	}
	if derr != nil {
		return nil, fmt.Errorf("%s is neither an ssh-ed25519 line nor base64", path)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%s decodes to %d bytes; an Ed25519 public key is %d",
			path, len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}
