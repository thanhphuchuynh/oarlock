// Package authorizedkeys authenticates operators from an authorized_keys file.
//
// It is the default because it needs no dependencies and everyone already has one.
// It is also the wrong choice past a handful of operators, and it says so at boot:
// revoking someone means editing a file on every replica, and a file edit is not a
// revocation mechanism you want to rely on when someone leaves in a hurry.
//
// The alternative is `sshca`, which now exists: trust one CA, accept short-lived
// certificates, and revocation becomes "stop issuing".
package authorizedkeys

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/oarlock/oarlock/pkg/plugin"
)

// ScaleWarningThreshold is when the boot warning gets louder. Past a handful of
// people, editing a file on every replica stops being a credible way to remove
// someone's access.
const ScaleWarningThreshold = 8

// Authenticator maps SSH public keys to principals.
type Authenticator struct {
	path string
	log  *slog.Logger

	mu      sync.RWMutex
	byKey   map[string]*plugin.Principal // marshalled authorized-key line -> principal
	entries int
}

var _ plugin.Authenticator = (*Authenticator)(nil)

// Open loads the file.
//
// Principals come from the key comment. `oarlock-principal=<id>` names one
// explicitly; otherwise the comment is used, which is conventionally an email and
// is what most people already have there. A key with no comment is refused rather
// than given a generated name: a recording attributed to "key #3" is a recording
// nobody can act on.
func Open(path string, log *slog.Logger) (*Authenticator, error) {
	if log == nil {
		log = slog.Default()
	}
	a := &Authenticator{path: path, log: log}
	if err := a.Reload(); err != nil {
		return nil, err
	}
	if a.entries > ScaleWarningThreshold {
		log.Warn("authorized_keys does not scale as an operator directory — "+
			"revoking access means editing this file on every replica; "+
			"consider the sshca or oidc authenticator",
			"path", path, "keys", a.entries)
	} else {
		log.Info("operator authentication: authorized_keys", "path", path, "keys", a.entries)
	}
	return a, nil
}

// Reload re-reads the file. Like the device registry, it is all-or-nothing: a
// half-applied key list would silently lock people out.
func (a *Authenticator) Reload() error {
	b, err := os.ReadFile(a.path)
	if err != nil {
		return fmt.Errorf("authorizedkeys: reading %s: %w", a.path, err)
	}

	byKey := make(map[string]*plugin.Principal)
	var problems []string
	rest := b
	line := 0
	for len(rest) > 0 {
		line++
		key, comment, _, next, perr := ssh.ParseAuthorizedKey(rest)
		if perr != nil {
			// ParseAuthorizedKey stops at the first thing it cannot read, so there
			// is no way to skip a bad line and carry on. Report where it gave up.
			if isBlankRemainder(rest) {
				break
			}
			problems = append(problems, fmt.Sprintf("line %d: %v", line, perr))
			break
		}
		rest = next

		id := principalFrom(comment)
		if id == "" {
			problems = append(problems, fmt.Sprintf(
				"line %d: key has no comment, so there is no principal to attribute "+
					"sessions to; add a comment or oarlock-principal=<id>", line))
			continue
		}
		fingerprint := string(key.Marshal())
		if _, dup := byKey[fingerprint]; dup {
			problems = append(problems, fmt.Sprintf("line %d: duplicate key", line))
			continue
		}
		byKey[fingerprint] = &plugin.Principal{ID: id, Email: emailFrom(id)}
	}
	if len(problems) > 0 {
		return fmt.Errorf("authorizedkeys: %s has %d problem(s):\n  %s",
			a.path, len(problems), strings.Join(problems, "\n  "))
	}

	a.mu.Lock()
	a.byKey, a.entries = byKey, len(byKey)
	a.mu.Unlock()
	return nil
}

func isBlankRemainder(b []byte) bool {
	return strings.TrimSpace(string(b)) == ""
}

func principalFrom(comment string) string {
	comment = strings.TrimSpace(comment)
	for _, field := range strings.Fields(comment) {
		if v, ok := strings.CutPrefix(field, "oarlock-principal="); ok {
			return strings.TrimSpace(v)
		}
	}
	return comment
}

func emailFrom(id string) string {
	if strings.Contains(id, "@") && !strings.Contains(id, " ") {
		return id
	}
	return ""
}

// AuthPublicKey looks the key up. The SSH user is the device id and is ignored
// here: the gateway checks it against the registry, and an operator's credentials
// address the whole fleet by design.
func (a *Authenticator) AuthPublicKey(_ context.Context, _ string, key ssh.PublicKey) (*plugin.Principal, error) {
	a.mu.RLock()
	p, ok := a.byKey[string(key.Marshal())]
	a.mu.RUnlock()
	if !ok {
		// No detail: an unauthenticated peer learns only that it failed.
		return nil, errors.New("authorizedkeys: no such key")
	}
	// Copied, so a handler cannot mutate the shared entry.
	out := *p
	return &out, nil
}

// AuthDelegated is not supported: a file of keys cannot verify an assertion about
// somebody else. Returning ErrUnsupported refuses every On-Behalf-Of call, which is
// the right answer rather than a weaker one.
func (a *Authenticator) AuthDelegated(context.Context, *plugin.Principal, string) (*plugin.Principal, error) {
	return nil, plugin.ErrUnsupported
}

// AuthHTTP is not supported either. An authorized_keys file authenticates an SSH
// public key; there is no honest way to turn an HTTP request into one of those, and
// inventing a mapping — a header naming a principal, say — would be an
// authentication bypass wearing a convenience's clothes.
func (a *Authenticator) AuthHTTP(context.Context, *http.Request) (*plugin.Principal, error) {
	return nil, plugin.ErrUnsupported
}

// Len is the number of keys loaded.
func (a *Authenticator) Len() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.entries
}
