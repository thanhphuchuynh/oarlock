package agent

// The `exec` profile's allow-list, which is the whole security property.
//
// The failure mode this guards is not "a command was refused" but "a command was allowed
// that nobody intended". So most of these are attempts to get something past the list:
// a different program, extra arguments, a shell string, a case change, a path spelled
// another way.

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func run(t *testing.T, f ExecFunc, argv ...string) (ExecResult, string, string, error) {
	t.Helper()
	var out, errb bytes.Buffer
	res, err := f(context.Background(), ExecRequest{SessionID: "s1", Argv: argv}, &out, &errb)
	return res, out.String(), errb.String(), err
}

func TestAnAllowedCommandRuns(t *testing.T) {
	f := Exec([][]string{{"/bin/echo", "hello"}})
	res, out, _, err := run(t, f, "/bin/echo", "hello")
	if err != nil {
		t.Fatal(err)
	}
	if res.Code != 0 {
		t.Fatalf("exit = %d", res.Code)
	}
	if strings.TrimSpace(out) != "hello" {
		t.Fatalf("stdout = %q", out)
	}
}

// TestStdoutAndStderrStaySeparate. Merging them is what a terminal does and it is wrong
// here: a caller that has to grep an error out of the output it was collecting has been
// handed the shell problem back.
func TestStdoutAndStderrStaySeparate(t *testing.T) {
	argv := []string{"/bin/sh", "-c", "printf out; printf err >&2"}
	f := Exec([][]string{argv})
	_, out, errOut, err := run(t, f, argv...)
	if err != nil {
		t.Fatal(err)
	}
	if out != "out" {
		t.Fatalf("stdout = %q, want only the stdout half", out)
	}
	if errOut != "err" {
		t.Fatalf("stderr = %q, want only the stderr half", errOut)
	}
}

// TestANonZeroExitIsAnAnswerNotAnError: "grep found nothing" must not look like a broken
// gateway.
func TestANonZeroExitIsAnAnswerNotAnError(t *testing.T) {
	argv := []string{"/bin/sh", "-c", "exit 3"}
	res, _, _, err := run(t, Exec([][]string{argv}), argv...)
	if err != nil {
		t.Fatalf("a non-zero exit was reported as an error: %v", err)
	}
	if res.Code != 3 {
		t.Fatalf("exit = %d, want 3", res.Code)
	}
}

// TestTheAllowListIsExact is the core of the profile. Every case here is a way somebody
// might expect to get through, and each one is a refusal.
func TestTheAllowListIsExact(t *testing.T) {
	allowed := [][]string{
		{"/bin/echo", "hello"},
		{"/usr/bin/uptime"},
	}
	f := Exec(allowed)

	for _, tc := range []struct {
		name string
		argv []string
	}{
		{"a program that is not on the list", []string{"/bin/cat", "/etc/passwd"}},
		{"an allowed program with different arguments", []string{"/bin/echo", "goodbye"}},
		{"an allowed program with extra arguments", []string{"/bin/echo", "hello", "world"}},
		{"an allowed program with an argument removed", []string{"/bin/echo"}},
		{"an allowed argv in the wrong order", []string{"hello", "/bin/echo"}},
		{"the same binary by another path", []string{"/usr/bin/echo", "hello"}},
		{"a relative path to an allowed binary", []string{"echo", "hello"}},
		{"a path with a traversal that resolves to it", []string{"/bin/../bin/echo", "hello"}},
		{"a shell string rather than an argv", []string{"/bin/echo hello"}},
		{"a shell wrapping an allowed command", []string{"/bin/sh", "-c", "/bin/echo hello"}},
		{"different case", []string{"/bin/ECHO", "hello"}},
		{"a trailing empty argument", []string{"/bin/echo", "hello", ""}},
		{"nothing at all", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, out, _, err := run(t, f, tc.argv...)
			if err == nil {
				t.Fatalf("ALLOWED %q — it should not have run", tc.argv)
			}
			if out != "" {
				t.Fatalf("a refused command still produced output: %q", out)
			}
			if len(tc.argv) > 0 && !errors.Is(err, ErrNotAllowed) {
				t.Fatalf("err = %v, want ErrNotAllowed so the gateway can say which", err)
			}
		})
	}
}

// TestTheRefusalNamesTheCommand: the operator needs to know which one to get added, and
// the argv came from an authenticated, authorised caller — there is nothing in it they
// did not already send.
func TestTheRefusalNamesTheCommand(t *testing.T) {
	_, _, _, err := run(t, Exec([][]string{{"/usr/bin/uptime"}}), "/bin/cat", "/etc/shadow")
	if err == nil {
		t.Fatal("not refused")
	}
	if !strings.Contains(err.Error(), "/bin/cat /etc/shadow") {
		t.Fatalf("error %q does not name the command", err)
	}
}

// TestNoShellInterpretation. There is no `sh -c`, so the argv reaches execve as written:
// a semicolon is an argument, not a separator.
func TestNoShellInterpretation(t *testing.T) {
	argv := []string{"/bin/echo", "a;b|c$(d)`e`&f>g"}
	_, out, _, err := run(t, Exec([][]string{argv}), argv...)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out) != "a;b|c$(d)`e`&f>g" {
		t.Fatalf("stdout = %q; the shell metacharacters were interpreted somewhere", out)
	}
}

// TestAnEmptyEnvironmentByDefault: a command whose behaviour depends on how the agent
// happened to be started is a command that behaves differently on two identical devices.
func TestAnEmptyEnvironmentByDefault(t *testing.T) {
	t.Setenv("OARLOCK_LEAK_CHECK", "leaked")
	argv := []string{"/bin/sh", "-c", "echo [$OARLOCK_LEAK_CHECK]"}
	_, out, _, err := run(t, Exec([][]string{argv}), argv...)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "leaked") {
		t.Fatalf("the agent's environment reached the command: %q", out)
	}

	// And it is settable, for the cases that genuinely need one.
	_, out, _, err = run(t, Exec([][]string{argv}, ExecEnv([]string{"OARLOCK_LEAK_CHECK=set"})), argv...)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "set") {
		t.Fatalf("ExecEnv had no effect: %q", out)
	}
}

// TestATimeoutKillsTheWholeJob. Without a process group the timeout reaches the command
// and leaves its children running.
func TestATimeoutKillsTheWholeJob(t *testing.T) {
	// The parent exits immediately; the child outlives it unless the group is killed.
	marker := t.TempDir() + "/child-was-still-running"
	argv := []string{"/bin/sh", "-c",
		"( sleep 5; touch " + marker + " ) & sleep 5"}
	f := Exec([][]string{argv}, ExecTimeout(300*time.Millisecond))

	start := time.Now()
	_, _, _, err := run(t, f, argv...)
	if err == nil {
		t.Fatal("a command that outran its timeout was reported as succeeding")
	}
	if !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("err = %v, want it to say the command exceeded its timeout", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("the timeout took %s to fire", elapsed)
	}

	// Long enough for the orphan to have fired if it survived.
	time.Sleep(1500 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a child of the timed-out command was still running: the process group " +
			"was not killed, only the process")
	}
}

// TestNoStdin: an exec session is not interactive, and a command left waiting on a
// terminal nobody is attached to would hang until the timeout.
func TestNoStdin(t *testing.T) {
	argv := []string{"/bin/sh", "-c", "cat; echo done"}
	f := Exec([][]string{argv}, ExecTimeout(3*time.Second))
	start := time.Now()
	_, out, _, err := run(t, f, argv...)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "done") {
		t.Fatalf("stdout = %q; cat did not see end-of-file", out)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("the command waited for input that was never coming")
	}
}

func TestAnEmptyAllowListAllowsNothing(t *testing.T) {
	if _, _, _, err := run(t, Exec(nil), "/bin/echo", "hi"); err == nil {
		t.Fatal("an agent with no allow-list ran a command")
	}
}
