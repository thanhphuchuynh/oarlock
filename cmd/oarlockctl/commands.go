package main

// The commands.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	xssh "golang.org/x/crypto/ssh"

	"github.com/oarlock/oarlock/internal/record"
)

func cmdSessionsList(ctx context.Context, g globals, args []string) error {
	fs := subflags("sessions list")
	device := fs.String("device", "", "only this device")
	principal := fs.String("principal", "", "only this principal")
	state := fs.String("state", "", "only this state (open, closed, …)")
	limit := fs.Int("limit", 0, "stop after this many; 0 means every page")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	c, g, err := g.dial()
	if err != nil {
		return err
	}

	q := url.Values{}
	for k, v := range map[string]string{"device": *device, "principal": *principal, "state": *state} {
		if v != "" {
			q.Set(k, v)
		}
	}
	rows, err := c.listSessions(ctx, q, *limit)
	if err != nil {
		return err
	}
	if g.json {
		return writeJSON(rows)
	}
	if len(rows) == 0 {
		fmt.Println("no sessions")
		return nil
	}
	t := newTable("SESSION", "DEVICE", "PROFILE", "PRINCIPAL", "STATE", "RECORDING", "REASON")
	for _, r := range rows {
		t.row(r.ID, r.DeviceID, r.Profile, r.Principal, r.State, r.RecordingState, r.CloseReason)
	}
	t.print()
	return nil
}

func cmdSessionsGet(ctx context.Context, g globals, args []string) error {
	if len(args) != 1 {
		return errors.New("sessions get needs exactly one session id")
	}
	c, g, err := g.dial()
	if err != nil {
		return err
	}
	var row sessionRow
	if err := c.do(ctx, http.MethodGet, "/api/v1/sessions/"+url.PathEscape(args[0]), nil, &row); err != nil {
		return err
	}
	if g.json {
		return writeJSON(row)
	}
	printPairs(
		"session", row.ID,
		"device", row.DeviceID,
		"profile", row.Profile,
		"principal", row.Principal,
		"state", row.State,
		"mode", row.Mode,
		"recording", row.RecordingState,
		"started", row.StartedAt,
		"attached", row.AttachedAt,
		"closed", row.ClosedAt,
		"close reason", row.CloseReason,
	)
	return nil
}

func cmdSessionsKill(ctx context.Context, g globals, args []string) error {
	fs := subflags("sessions kill")
	reason := fs.String("reason", "", "recorded against the session (free text)")
	id, rest := takeID(args)
	if err := fs.Parse(rest); err != nil {
		return errUsage
	}
	if id == "" {
		id = fs.Arg(0)
	}
	if id == "" || fs.NArg() > 1 {
		return errors.New("sessions kill needs exactly one session id")
	}

	c, _, err := g.dial()
	if err != nil {
		return err
	}
	path := "/api/v1/sessions/" + url.PathEscape(id)
	if *reason != "" {
		path += "?reason=" + url.QueryEscape(*reason)
	}
	if err := c.do(ctx, http.MethodDelete, path, nil, nil); err != nil {
		return err
	}
	// Says what happened, not what was requested. The operator is ending somebody else's
	// session and should see it confirmed.
	fmt.Printf("killed %s\n", id)
	return nil
}

func cmdDevicesList(ctx context.Context, g globals, args []string) error {
	if len(args) > 0 {
		return errors.New("devices list takes no arguments")
	}
	c, g, err := g.dial()
	if err != nil {
		return err
	}
	rows, err := c.listDevices(ctx)
	if err != nil {
		return err
	}
	if g.json {
		return writeJSON(rows)
	}
	if len(rows) == 0 {
		fmt.Println("no devices")
		return nil
	}
	t := newTable("DEVICE", "PLATFORM", "MODE", "CONNECTED", "STATE", "PASSTHROUGH")
	for _, d := range rows {
		state := "enabled"
		if d.Disabled {
			state = "disabled"
		}
		t.row(d.ID, d.Platform, d.ResolvedMode, yesNo(d.Connected), state, yesNo(d.AllowPassthrough))
	}
	t.print()
	return nil
}

func cmdDevicesGet(ctx context.Context, g globals, args []string) error {
	if len(args) != 1 {
		return errors.New("devices get needs exactly one device id")
	}
	c, g, err := g.dial()
	if err != nil {
		return err
	}
	var d deviceRow
	if err := c.do(ctx, http.MethodGet, "/api/v1/devices/"+url.PathEscape(args[0]), nil, &d); err != nil {
		return err
	}
	if g.json {
		return writeJSON(d)
	}
	printPairs(
		"device", d.ID,
		"platform", d.Platform,
		"mode", d.ResolvedMode,
		"connected", yesNo(d.Connected),
		"disabled", yesNo(d.Disabled),
		"passthrough", yesNo(d.AllowPassthrough),
		"profiles", strings.Join(d.Profiles, " "),
	)
	for k, v := range d.Tags {
		fmt.Printf("  tag %-14s %s\n", k, v)
	}
	return nil
}

func cmdAgentsList(ctx context.Context, g globals, args []string) error {
	if len(args) > 0 {
		return errors.New("agents list takes no arguments")
	}
	c, g, err := g.dial()
	if err != nil {
		return err
	}
	var list agentList
	if err := c.do(ctx, http.MethodGet, "/api/v1/agents", nil, &list); err != nil {
		return err
	}
	if g.json {
		return writeJSON(list.Agents)
	}
	if len(list.Agents) == 0 {
		fmt.Println("no agents are holding a control channel")
		return nil
	}
	t := newTable("DEVICE", "SINCE", "VERSION", "CAPS")
	for _, a := range list.Agents {
		t.row(a.DeviceID, a.Since, a.Version, strings.Join(a.Caps, " "))
	}
	t.print()
	return nil
}

func cmdRecordingsGet(ctx context.Context, g globals, args []string) error {
	fs := subflags("recordings get")
	out := fs.String("o", "", "write the asciicast here instead of stdout")
	id, rest := takeID(args)
	if err := fs.Parse(rest); err != nil {
		return errUsage
	}
	if id == "" {
		id = fs.Arg(0)
	}
	if id == "" {
		return errors.New("recordings get needs exactly one session id")
	}
	c, _, err := g.dial()
	if err != nil {
		return err
	}
	rec, err := fetchRecording(ctx, c, id)
	if err != nil {
		return err
	}
	// The gateway's own verdict, on stderr, labelled as the gateway's. It is worth
	// printing and it is not verification: see `recordings verify`.
	fmt.Fprintf(os.Stderr, "gateway's verdict: %s (%s)\n",
		rec.Verdict.Status, verdictWord(rec.Verdict.OK))
	if !rec.Verdict.OK && rec.Verdict.Detail != "" {
		fmt.Fprintf(os.Stderr, "  %s\n", rec.Verdict.Detail)
	}

	if *out == "" {
		_, err := os.Stdout.WriteString(rec.Cast)
		return err
	}
	if err := os.WriteFile(*out, []byte(rec.Cast), 0o600); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", *out)
	return nil
}

// cmdRecordingsVerify checks a recording against a key the operator holds.
//
// This is the command the signing and hash-chaining were for. Every other check available
// until now was the gateway's opinion of its own file — which is worth printing and is not
// evidence, because the party that might have altered a recording is the party being
// asked. Here the signature is checked locally against a public key that came from
// somewhere else, so a gateway that lies is caught rather than believed.
func cmdRecordingsVerify(ctx context.Context, g globals, args []string) error {
	fs := subflags("recordings verify")
	keyPath := fs.String("key", "", "the recorder's public key (ssh-ed25519 line or base64)")
	id, rest := takeID(args)
	if err := fs.Parse(rest); err != nil {
		return errUsage
	}
	if id == "" {
		id = fs.Arg(0)
	}
	if id == "" {
		return errors.New("recordings verify needs exactly one session id")
	}
	if *keyPath == "" {
		return errors.New("--key is required: verifying against a key the gateway " +
			"supplied would only prove the gateway agrees with itself")
	}
	pub, err := readRecordingKey(*keyPath)
	if err != nil {
		return err
	}
	c, g, err := g.dial()
	if err != nil {
		return err
	}
	rec, err := fetchRecording(ctx, c, id)
	if err != nil {
		return err
	}
	if len(rec.Manifest) == 0 {
		return errors.New("the gateway served no manifest, so this recording cannot be " +
			"verified independently. An older gateway does not send one")
	}
	m, err := record.DecodeManifest(rec.Manifest)
	if err != nil {
		return fmt.Errorf("the manifest did not decode: %w", err)
	}
	verdict, err := record.Verify(strings.NewReader(rec.Cast), m, pub)
	if err != nil {
		return fmt.Errorf("verifying: %w", err)
	}

	if g.json {
		return writeJSON(struct {
			Session string         `json:"session"`
			Local   record.Verdict `json:"local_verdict"`
			Gateway any            `json:"gateway_verdict"`
		}{id, verdict, rec.Verdict})
	}

	printPairs(
		"session", id,
		"verified locally", string(verdict.Status),
		"events", fmt.Sprintf("%d found, %d expected", verdict.EventsFound, verdict.EventsExpected),
		"gateway said", rec.Verdict.Status,
	)
	if verdict.Detail != "" {
		fmt.Printf("  %-16s %s\n", "detail", verdict.Detail)
	}
	// The interesting disagreement, called out rather than left to be spotted in two
	// lines of a table.
	if verdict.OK != rec.Verdict.OK {
		fmt.Printf("\nthe gateway and this check disagree. The local result is the one " +
			"that used your key.\n")
	}
	if !verdict.OK {
		return errors.New("the recording did not verify")
	}
	fmt.Println("\nthe recording verifies against the key you supplied")
	return nil
}

func fetchRecording(ctx context.Context, c *client, id string) (*recording, error) {
	var rec recording
	err := c.do(ctx, http.MethodGet, "/api/v1/recordings/"+url.PathEscape(id), nil, &rec)
	if err != nil {
		var p problem
		if errors.As(err, &p) && p.Status == http.StatusNotFound {
			return nil, errNoRecording
		}
		return nil, err
	}
	return &rec, nil
}

// readRecordingKey accepts an ssh-ed25519 line or raw base64, like the conformance suite.
func readRecordingKey(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	text := strings.TrimSpace(string(b))
	if strings.HasPrefix(text, "ssh-ed25519") {
		k, _, _, _, perr := xssh.ParseAuthorizedKey([]byte(text))
		if perr != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, perr)
		}
		ck, ok := k.(xssh.CryptoPublicKey)
		if !ok {
			return nil, fmt.Errorf("%s is not a usable key", path)
		}
		pub, ok := ck.CryptoPublicKey().(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%s is not Ed25519; a recording key must be", path)
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

func writeJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func verdictWord(ok bool) string {
	if ok {
		return "ok"
	}
	return "not ok"
}
