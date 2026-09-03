package main

// Where the URL and the token come from.

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// globals are the settings every command shares.
type globals struct {
	url   string
	token string
	json  bool
}

// fileConfig is ~/.config/oarlock/config.yaml.
//
// The same shape the gateway's own config uses for these two fields, so an operator who
// has read one has read the other.
type fileConfig struct {
	URL   string `yaml:"url"`
	Token string `yaml:"token"`
}

// parseGlobals pulls the shared flags off the front and returns the rest.
//
// Hand-rolled rather than a subcommand library, because the whole point of this binary is
// that it has no ceremony — and one loop is cheaper than a dependency for four flags.
func parseGlobals(args []string) (globals, []string, error) {
	var g globals
	var rest []string

	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() (string, bool) {
			if i+1 >= len(args) {
				return "", false
			}
			i++
			return args[i], true
		}
		switch {
		case a == "--json" || a == "-json":
			g.json = true
		case a == "--url" || a == "-url":
			v, ok := next()
			if !ok {
				return g, nil, errors.New("--url needs a value")
			}
			g.url = v
		case a == "--token" || a == "-token":
			v, ok := next()
			if !ok {
				return g, nil, errors.New("--token needs a value")
			}
			g.token = v
		case a == "-h" || a == "--help" || a == "help":
			return g, []string{"help"}, nil
		case strings.HasPrefix(a, "-"):
			// Not ours — a command's own flag. Everything from here is the command's.
			rest = append(rest, args[i:]...)
			return g, rest, nil
		default:
			rest = append(rest, args[i:]...)
			return g, rest, nil
		}
	}
	return g, rest, nil
}

// resolve fills in anything the flags did not, and fails with something actionable.
func (g globals) resolve() (globals, error) {
	if g.url == "" {
		g.url = os.Getenv("OARLOCK_URL")
	}
	if g.token == "" {
		g.token = os.Getenv("OARLOCK_TOKEN")
	}
	if g.url == "" || g.token == "" {
		fc, path, err := readFileConfig()
		if err != nil {
			return g, err
		}
		if g.url == "" {
			g.url = fc.URL
		}
		if g.token == "" {
			g.token = fc.Token
		}
		if g.url == "" {
			return g, fmt.Errorf("no gateway URL. Set --url, OARLOCK_URL, or `url:` in %s", path)
		}
	}
	if g.token == "" {
		// Not fatal: a gateway with no authenticator configured for the API exists in
		// development, and refusing here would mean this tool could not be used against
		// the thing it is easiest to try it against.
		return g, nil
	}
	return g, nil
}

func configPath() string {
	if p := os.Getenv("OARLOCK_CONFIG"); p != "" {
		return p
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return filepath.Join(".", "oarlock.yaml")
	}
	return filepath.Join(dir, "oarlock", "config.yaml")
}

func readFileConfig() (fileConfig, string, error) {
	path := configPath()
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return fileConfig{}, path, nil
	}
	if err != nil {
		return fileConfig{}, path, fmt.Errorf("reading %s: %w", path, err)
	}
	// A config file holding a bearer token that anybody on the machine can read is a
	// credential nobody is treating as one. Refused rather than warned, because a warning
	// on a tool people run all day is a warning nobody reads.
	if info, serr := os.Stat(path); serr == nil {
		if mode := info.Mode().Perm(); mode&0o077 != 0 {
			return fileConfig{}, path, fmt.Errorf(
				"%s is mode %04o and holds a token; run `chmod 600 %s`", path, mode, path)
		}
	}
	var fc fileConfig
	if err := yaml.Unmarshal(b, &fc); err != nil {
		return fileConfig{}, path, fmt.Errorf("parsing %s: %w", path, err)
	}
	return fc, path, nil
}

// dial resolves the configuration and returns a client.
func (g globals) dial() (*client, globals, error) {
	resolved, err := g.resolve()
	if err != nil {
		return nil, g, err
	}
	c, err := newClient(resolved.url, resolved.token)
	if err != nil {
		return nil, resolved, err
	}
	return c, resolved, nil
}

// takeID pulls a leading positional off the front so flags may follow it.
//
// Go's flag package stops parsing at the first non-flag argument, so
// `sessions kill sess_1 --reason X` would leave --reason unparsed — and that is the order
// everybody types. Taking the id first and parsing the rest accepts both orders without a
// dependency.
func takeID(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}

// subflags builds a FlagSet that prints to stderr and does not exit on error, so a bad
// flag produces one message from main rather than two from here.
func subflags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}
