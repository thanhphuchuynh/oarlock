package agent

// Path confinement for the `file` profile.
//
// The property under test is one sentence: **nothing outside the root can be read or
// written, whatever the path says.** Every case below is an attempt to break it, and the
// ones that matter most are the two that a string check cannot stop — a symlink inside the
// root pointing out of it, and the same symlink swapped in while the transfer is running.
//
// Confinement itself is os.Root's job. These tests are how we know it is actually wired to
// it, because the failure mode of "we meant to use the confined API" is invisible.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// bed is a root with a file in it, and a secret outside it that must never be reachable.
type bed struct {
	root   string
	secret string
	run    FileFunc
}

const secretText = "SECRET-OUTSIDE-THE-ROOT"

func newBed(t *testing.T, opts ...FileOption) *bed {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "root")
	if err := os.MkdirAll(filepath.Join(root, "logs"), 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(base, "secret.txt")
	if err := os.WriteFile(secret, []byte(secretText), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "logs", "app.log"), []byte("line one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run, err := File(root, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return &bed{root: root, secret: secret, run: run}
}

func (b *bed) read(t *testing.T, path string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := b.run(context.Background(),
		FileRequest{SessionID: "s1", Op: "read", Path: path}, &out, strings.NewReader(""))
	return out.String(), err
}

func (b *bed) write(t *testing.T, path, body string) error {
	t.Helper()
	return b.run(context.Background(),
		FileRequest{SessionID: "s1", Op: "write", Path: path,
			Size: int64(len(body))}, io.Discard, strings.NewReader(body))
}

func TestReadsAFileUnderTheRoot(t *testing.T) {
	b := newBed(t)
	got, err := b.read(t, "logs/app.log")
	if err != nil {
		t.Fatal(err)
	}
	if got != "line one\n" {
		t.Fatalf("read %q", got)
	}
}

// TestNothingOutsideTheRootIsReachable. Each of these has been a real vulnerability in
// something, and the last two cannot be stopped by looking at the string.
func TestNothingOutsideTheRootIsReachable(t *testing.T) {
	// A fresh bed per case. Sharing one let an earlier write replace a symlink, so a
	// later "read succeeded" was reading a perfectly ordinary file the test itself had
	// just created — a fixture bug that looked like a finding.
	fresh := func(t *testing.T) *bed {
		b := newBed(t, FileWritable())
		// A symlink inside the root pointing at the secret. The path looks innocent.
		if err := os.Symlink(b.secret, filepath.Join(b.root, "escape")); err != nil {
			t.Fatal(err)
		}
		// A symlink to the parent directory, so an innocent path traverses out.
		if err := os.Symlink("..", filepath.Join(b.root, "up")); err != nil {
			t.Fatal(err)
		}
		// A relative symlink that climbs out, which is the form os.Root has to reason
		// about rather than reject outright.
		if err := os.Symlink("../secret.txt", filepath.Join(b.root, "logs", "sneak")); err != nil {
			t.Fatal(err)
		}
		return b
	}

	for _, path := range []string{
		"../secret.txt",
		"../../secret.txt",
		"logs/../../secret.txt",
		"./../secret.txt",
		"logs/./../../secret.txt",
		"/etc/passwd",
		"//etc/passwd",
		"/tmp/secret.txt", // an absolute path, which must never be joined
		"..",
		"escape",        // symlink → the secret
		"up/secret.txt", // symlink → the parent
		"logs/sneak",    // relative symlink climbing out
		"logs/../escape",
	} {
		t.Run(path, func(t *testing.T) {
			b := fresh(t)
			// A read must never return anything from outside.
			got, err := b.read(t, path)
			if err == nil && strings.Contains(got, secretText) {
				t.Fatalf("the secret leaked through %q", path)
			}
			if strings.Contains(got, secretText) {
				t.Fatalf("the secret leaked through %q: %q", path, got)
			}

			// A write must never *modify* anything outside. Note that it may legitimately
			// succeed: a write goes to a temporary in the root and is renamed into place,
			// so writing to a name that happens to be an escaping symlink replaces the
			// link rather than following it out. That is the safe outcome and the same
			// thing an editor's atomic save does — the property is "nothing outside
			// changed", not "the call failed".
			_ = b.write(t, path, "overwritten")
			if after, rerr := os.ReadFile(b.secret); rerr == nil && string(after) != secretText {
				t.Fatalf("the secret was modified through %q", path)
			}
			if _, rerr := os.Stat(filepath.Join(b.root, "..", "overwritten")); rerr == nil {
				t.Fatalf("%q created a file outside the root", path)
			}
		})
	}
}

// TestASymlinkSwappedMidTransferCannotEscape is the time-of-check-to-time-of-use case.
//
// A path check followed by an open is two resolutions, and an attacker with write access
// to the root can change what the name means in between. There is no window here because
// the check and the open are the same syscall — but the way to be sure of that is to keep
// swapping while reads run.
func TestASymlinkSwappedMidTransferCannotEscape(t *testing.T) {
	b := newBed(t)
	target := filepath.Join(b.root, "swapme")
	inside := filepath.Join(b.root, "logs", "app.log")

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = os.Remove(target)
			_ = os.Symlink(inside, target)
			_ = os.Remove(target)
			_ = os.Symlink(b.secret, target)
		}
	}()
	defer func() { close(stop); <-done }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got, err := b.read(t, "swapme")
		if err == nil && strings.Contains(got, secretText) {
			t.Fatal("a symlink swapped mid-transfer reached outside the root")
		}
	}
}

// TestOnlyRegularFiles. A directory read would produce nonsense; /dev/zero would be an
// unbounded transfer; a fifo would block until something wrote to it.
func TestOnlyRegularFiles(t *testing.T) {
	b := newBed(t)
	if _, err := b.read(t, "logs"); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("reading a directory: %v", err)
	}
	if _, err := b.read(t, "."); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("reading the root itself: %v", err)
	}

	fifo := filepath.Join(b.root, "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("cannot create a fifo here: %v", err)
	}
	// Would block forever if it were opened for reading as a regular file.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- b.run(ctx, FileRequest{Op: "read", Path: "pipe"}, io.Discard, strings.NewReader(""))
	}()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("a fifo was read as a regular file")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reading a fifo blocked: it was opened rather than refused")
	}
}

func TestWritesAreOffByDefault(t *testing.T) {
	b := newBed(t) // no FileWritable
	if err := b.write(t, "logs/new.txt", "hello"); err == nil {
		t.Fatal("a read-only root accepted a write")
	}
	if _, err := os.Stat(filepath.Join(b.root, "logs", "new.txt")); err == nil {
		t.Fatal("the file was created anyway")
	}
}

func TestWriteIsAtomicAndCleansUpAfterItself(t *testing.T) {
	b := newBed(t, FileWritable())
	if err := b.write(t, "logs/new.txt", "hello"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(b.root, "logs", "new.txt"))
	if err != nil || string(got) != "hello" {
		t.Fatalf("file = %q, err %v", got, err)
	}
	// No partial left behind.
	entries, _ := os.ReadDir(filepath.Join(b.root, "logs"))
	for _, e := range entries {
		if strings.Contains(e.Name(), "oarlock-partial") {
			t.Fatalf("a partial file was left behind: %s", e.Name())
		}
	}
}

// TestAShortTransferIsNotCommitted. Publishing a truncated configuration file that looks
// whole is worse than failing.
func TestAShortTransferIsNotCommitted(t *testing.T) {
	b := newBed(t, FileWritable())
	existing := filepath.Join(b.root, "logs", "app.log")

	// Promise ten bytes, deliver four.
	err := b.run(context.Background(),
		FileRequest{Op: "write", Path: "logs/app.log", Size: 10},
		io.Discard, strings.NewReader("four"))
	if err == nil {
		t.Fatal("a short write was committed")
	}
	got, _ := os.ReadFile(existing)
	if string(got) != "line one\n" {
		t.Fatalf("the existing file was replaced by a truncated one: %q", got)
	}
	entries, _ := os.ReadDir(filepath.Join(b.root, "logs"))
	for _, e := range entries {
		if strings.Contains(e.Name(), "oarlock-partial") {
			t.Fatalf("a partial file survived a failed write: %s", e.Name())
		}
	}
}

func TestSizeLimits(t *testing.T) {
	b := newBed(t, FileWritable(), FileMaxBytes(8))
	if err := b.write(t, "logs/big.txt", "0123456789"); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("an oversized write: %v", err)
	}
	// And on read: a file already larger than the ceiling.
	if err := os.WriteFile(filepath.Join(b.root, "logs", "grown.log"),
		[]byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := b.read(t, "logs/grown.log"); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("an oversized read: %v", err)
	}
}

// TestModeIsMaskedToPermissionBits: setuid arriving over the wire is not a thing this
// profile grants, whatever a caller sends.
func TestModeIsMaskedToPermissionBits(t *testing.T) {
	b := newBed(t, FileWritable())
	err := b.run(context.Background(),
		FileRequest{Op: "write", Path: "logs/x.txt", Size: 2, Mode: 0o104755},
		io.Discard, strings.NewReader("hi"))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(b.root, "logs", "x.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSetuid != 0 {
		t.Fatalf("mode = %v; setuid survived", info.Mode())
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("perm = %v, want 0755", info.Mode().Perm())
	}
}

func TestMalformedPaths(t *testing.T) {
	b := newBed(t, FileWritable())
	for _, tc := range []struct{ name, path string }{
		{"empty", ""},
		{"a NUL byte", "logs/app\x00.log"},
		{"a backslash, which means two different things on two platforms", `logs\app.log`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := b.read(t, tc.path); err == nil {
				t.Fatalf("accepted %q", tc.path)
			}
		})
	}
}

func TestFileNeedsARoot(t *testing.T) {
	if _, err := File(""); err == nil {
		t.Fatal("a file profile with no root was accepted")
	}
	if _, err := File(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("a root that does not exist was accepted")
	}
}

// FuzzFilePathConfinement is NFR11's half for this profile.
//
// Not a crash hunt: the assertion is the security property. Whatever the input, the
// secret outside the root must never come back, and nothing outside the root may be
// created. A fuzzer is the right tool because the interesting inputs are the ones nobody
// thinks to write down.
func FuzzFilePathConfinement(f *testing.F) {
	base := f.TempDir()
	root := filepath.Join(base, "root")
	if err := os.MkdirAll(filepath.Join(root, "logs"), 0o755); err != nil {
		f.Fatal(err)
	}
	secret := filepath.Join(base, "secret.txt")
	if err := os.WriteFile(secret, []byte(secretText), 0o600); err != nil {
		f.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "logs", "app.log"), []byte("inside"), 0o600); err != nil {
		f.Fatal(err)
	}
	// Symlinks the fuzzer can stumble through, so escaping is actually possible if the
	// confinement is wrong.
	_ = os.Symlink(secret, filepath.Join(root, "escape"))
	_ = os.Symlink("..", filepath.Join(root, "up"))
	_ = os.Symlink("../secret.txt", filepath.Join(root, "logs", "sneak"))

	run, err := File(root, FileWritable())
	if err != nil {
		f.Fatal(err)
	}

	for _, seed := range []string{
		"logs/app.log", "../secret.txt", "escape", "up/secret.txt", "logs/sneak",
		"/etc/passwd", "..", ".", "", "logs/../../secret.txt", "logs//app.log",
		"./logs/app.log", "logs/./app.log", `logs\app.log`, "logs/app.log\x00",
		strings.Repeat("../", 40) + "secret.txt",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, p string) {
		var out bytes.Buffer
		_ = run(context.Background(),
			FileRequest{Op: "read", Path: p}, &out, strings.NewReader(""))
		if strings.Contains(out.String(), secretText) {
			t.Fatalf("path %q read outside the root", p)
		}

		_ = run(context.Background(),
			FileRequest{Op: "write", Path: p, Size: 5}, io.Discard, strings.NewReader("wrote"))
		// The secret must be untouched, and nothing new may appear beside it.
		if got, err := os.ReadFile(secret); err == nil && string(got) != secretText {
			t.Fatalf("path %q wrote outside the root", p)
		}
		entries, err := os.ReadDir(base)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.Name() != "root" && e.Name() != "secret.txt" {
				t.Fatalf("path %q created %s outside the root",
					p, fmt.Sprintf("%s/%s", base, e.Name()))
			}
		}
	})
}
