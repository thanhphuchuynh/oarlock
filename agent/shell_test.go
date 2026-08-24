package agent

// The shell opener, and specifically the identity a session runs as.
//
// This file exists because of one fact: the gateway decides *who may open* a shell, and
// the agent decides *what that shell can touch*. Nothing in the authorisation path
// constrains the second. So a mistake here hands every operator whatever the agent
// process is, which for an init service means root, for everybody, on a device in
// somebody's home.
//
// Actually changing uid needs root, which a test suite does not have. So these tests
// cover the parts that can be wrong without privilege: whether the credential is built
// at all, from which profile, and whether the failure to drop is legible.

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

func TestForkptyRunsAShellAndReportsItsExit(t *testing.T) {
	open := Forkpty([]string{"/bin/sh", "-c", "printf ready; exit 7"})
	p, err := open(context.Background(), ShellRequest{SessionID: "s1", Cols: 80, Rows: 24})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	buf := make([]byte, 64)
	n, _ := p.Read(buf)
	if !strings.Contains(string(buf[:n]), "ready") {
		t.Fatalf("shell output = %q", buf[:n])
	}
	if code, err := p.Wait(); err != nil || code != 7 {
		t.Fatalf("exit = %d, err = %v; want 7", code, err)
	}
}

func TestASessionGetsItsOwnProcessGroup(t *testing.T) {
	// The whole job has to be signallable, not just the shell: a Ctrl-C that reaches
	// the shell and not the pipeline it is running is not the Ctrl-C anybody means.
	open := Forkpty([]string{"/bin/sh", "-c", "printf $$; sleep 30"})
	p, err := open(context.Background(), ShellRequest{SessionID: "s1"})
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, _ := p.Read(buf)
	if n == 0 {
		t.Fatal("the shell printed nothing")
	}
	// Its pid is its own process-group leader, which is what Setsid bought.
	pid := p.(*ptyProcess).cmd.Process.Pid
	pgid, err := syscall.Getpgid(pid)
	if err != nil {
		t.Fatal(err)
	}
	if pgid != pid {
		t.Fatalf("pgid %d, want it to equal the pid %d", pgid, pid)
	}
	_ = p.Close()
}

// TestTheProfileReachesTheIdentityHook. The profile is the only thing that can select a
// privilege level, so it has to arrive. It travelled from the invitation through
// ShellRequest for exactly this.
func TestTheProfileReachesTheIdentityHook(t *testing.T) {
	var seen []string
	open := ForkptyWith([]string{"/bin/sh", "-c", "exit 0"}, ShellOptions{
		Identity: func(profile string) *Identity {
			seen = append(seen, profile)
			return nil // nil inherits the agent's own identity
		},
	})
	for _, profile := range []string{"shell", "exec"} {
		p, err := open(context.Background(), ShellRequest{SessionID: "s", Profile: profile})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = p.Wait()
		_ = p.Close()
	}
	if len(seen) != 2 || seen[0] != "shell" || seen[1] != "exec" {
		t.Fatalf("profiles seen by the identity hook = %v", seen)
	}
}

// TestANilIdentityDoesNotTouchTheCredential: inheriting the agent's identity must not
// go through setuid at all. An empty Credential{} would mean uid 0, which is the
// opposite of inheriting.
func TestANilIdentityDoesNotTouchTheCredential(t *testing.T) {
	open := ForkptyWith([]string{"/bin/sh", "-c", "exit 0"}, ShellOptions{
		Identity: func(string) *Identity { return nil },
	})
	p, err := open(context.Background(), ShellRequest{SessionID: "s"})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if cred := p.(*ptyProcess).cmd.SysProcAttr.Credential; cred != nil {
		t.Fatalf("a nil identity still set a credential: %+v", cred)
	}
	_, _ = p.Wait()
}

// TestAnIdentityBecomesACredential covers the mapping without needing to be root: the
// command is built, then the drop fails at exec because the test is unprivileged. Both
// halves matter — the credential must be right, and the refusal must say why.
func TestAnIdentityBecomesACredential(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: this test is about the unprivileged refusal")
	}
	// A uid that is not ours, so the kernel refuses. 1 is daemon on every Unix.
	want := &Identity{UID: 1, GID: 1, Groups: []uint32{2, 3}}
	open := ForkptyWith([]string{"/bin/sh", "-c", "exit 0"}, ShellOptions{
		Identity: func(string) *Identity { return want },
	})
	_, err := open(context.Background(), ShellRequest{SessionID: "s", Profile: "shell"})
	if err == nil {
		t.Fatal("an unprivileged agent dropped to another uid, which should be impossible")
	}
	// The message has to name the cause. "operation not permitted" on its own sends
	// somebody looking at the shell path or the pty, not at the agent's own privileges.
	for _, want := range []string{"uid 1", "privileged enough to drop"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
}

// TestAFailedStartLeaksNothing: the pty is opened before the child, so a refused drop
// must not leave the master behind. A device that leaks a pty per refused session runs
// out of them.
func TestAFailedStartLeaksNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: the drop would succeed")
	}
	before := countOpenPTYs(t)
	open := ForkptyWith([]string{"/bin/sh", "-c", "exit 0"}, ShellOptions{
		Identity: func(string) *Identity { return &Identity{UID: 1, GID: 1} },
	})
	for range 8 {
		if _, err := open(context.Background(), ShellRequest{SessionID: "s"}); err == nil {
			t.Fatal("expected the drop to be refused")
		}
	}
	if after := countOpenPTYs(t); after > before {
		t.Fatalf("open pty count went from %d to %d across eight refused sessions", before, after)
	}
}

func countOpenPTYs(t *testing.T) int {
	t.Helper()
	// Counting this process's own descriptors is portable enough for the two platforms
	// this agent is built for and does not need /proc.
	out, err := exec.Command("lsof", "-p", itoa(os.Getpid())).Output()
	if err != nil {
		t.Skip("lsof is unavailable; skipping the descriptor-leak check")
	}
	n := 0
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.Contains(line, "/dev/pt") || strings.Contains(line, "ptmx") {
			n++
		}
	}
	return n
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestABadTerminalSizeIsRefusedNotClamped guards a resize path that reaches an ioctl.
func TestABadTerminalSizeIsRefused(t *testing.T) {
	open := Forkpty([]string{"/bin/sh", "-c", "sleep 5"})
	p, err := open(context.Background(), ShellRequest{SessionID: "s"})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := p.Resize(0, 0); err == nil {
		t.Fatal("a 0x0 resize was accepted")
	}
}
