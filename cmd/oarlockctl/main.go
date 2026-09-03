// Command oarlockctl is the operator's CLI.
//
// FR40 exists because the alternative was a hand-made token and `curl`, and that is not a
// tool — it is a thing people get wrong at three in the morning. So this lists, inspects,
// kills and fetches, and it verifies a recording *without trusting the gateway that served
// it*.
//
//	oarlockctl sessions list --device treadmill-4821
//	oarlockctl sessions kill sess_abc --reason "wrong box"
//	oarlockctl recordings verify sess_abc --key recording.key.pub
//
// # Configuration
//
// The URL and token come from flags, then the environment (OARLOCK_URL, OARLOCK_TOKEN),
// then ~/.config/oarlock/config.yaml. A token on the command line is a token in the shell
// history and in `ps`, so the environment and the file are the ones to use and the flag is
// there for scripts that already hold one.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

const usage = `oarlockctl — the Oarlock operator CLI

usage: oarlockctl [--url URL] [--token TOKEN] [--json] <command>

commands:
  sessions list [--device D] [--principal P] [--state S] [--limit N]
  sessions get <id>
  sessions kill <id> [--reason R]
  devices list
  devices get <id>
  agents list
  recordings get <session-id> [-o FILE]
  recordings verify <session-id> --key FILE

configuration, in order of precedence:
  flags, then OARLOCK_URL / OARLOCK_TOKEN, then ~/.config/oarlock/config.yaml

`

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, errUsage) {
			fmt.Fprint(os.Stderr, usage)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "oarlockctl: %v\n", err)
		os.Exit(1)
	}
}

var errUsage = errors.New("usage")

func run(args []string) error {
	// Ctrl-C should stop a paging list promptly rather than after the next page.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	g, rest, err := parseGlobals(args)
	if err != nil {
		return err
	}
	if len(rest) == 0 {
		return errUsage
	}

	// Two words, because `sessions list` reads better than `list-sessions` and the
	// grouping is how somebody discovers what else is there.
	group := rest[0]
	var verb string
	if len(rest) > 1 {
		verb = rest[1]
	}
	tail := rest[min(2, len(rest)):]

	switch group + " " + verb {
	case "sessions list":
		return cmdSessionsList(ctx, g, tail)
	case "sessions get":
		return cmdSessionsGet(ctx, g, tail)
	case "sessions kill":
		return cmdSessionsKill(ctx, g, tail)
	case "devices list":
		return cmdDevicesList(ctx, g, tail)
	case "devices get":
		return cmdDevicesGet(ctx, g, tail)
	case "agents list":
		return cmdAgentsList(ctx, g, tail)
	case "recordings get":
		return cmdRecordingsGet(ctx, g, tail)
	case "recordings verify":
		return cmdRecordingsVerify(ctx, g, tail)
	case "help ", "help help":
		fmt.Print(usage)
		return nil
	}
	if verb == "" {
		return fmt.Errorf("%q needs a verb — try `oarlockctl %s list`", group, group)
	}
	return fmt.Errorf("unknown command %q", strings.TrimSpace(group+" "+verb))
}
