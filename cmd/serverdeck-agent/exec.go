package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Every command the agent spawns runs under a deadline.
//
// Without one, a single wedged child blocks its agent process forever. That
// matters more than it sounds: the app fans a refresh out into roughly twenty
// separate agent invocations, so a command that can hang — apt waiting on the
// dpkg lock held by unattended-upgrades is the common case — accumulates a new
// stuck process on every refresh, each holding its memory, until the box runs
// out. On a small instance that presents as a CPU/memory spike and an
// unresponsive server needing a hard reboot.
//
// The deadlines below are deliberately generous. They exist to bound the
// pathological case, not to police normal work.
const (
	// Read-only inspection: reading /proc, systemctl show, dpkg-query.
	quickTimeout = 30 * time.Second
	// Anything not otherwise classified.
	defaultTimeout = 2 * time.Minute
	// Package installs, image pulls, backups, certificate issuance.
	longTimeout = 20 * time.Minute
)

// ErrCommandTimedOut reports that a command was killed at its deadline.
var ErrCommandTimedOut = errors.New("command timed out")

// runWithTimeout runs a command and returns its combined output.
//
// On deadline the child is killed and whatever it managed to emit is returned
// alongside the error, so callers keep their existing diagnostics.
func runWithTimeout(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return output, fmt.Errorf("%w: %s did not finish within %s", ErrCommandTimedOut, name, timeout)
	}
	return output, err
}

// runOutputWithTimeout is the stdout-only counterpart to runWithTimeout.
func runOutputWithTimeout(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	output, err := exec.CommandContext(ctx, name, args...).Output()
	if ctx.Err() == context.DeadlineExceeded {
		return output, fmt.Errorf("%w: %s did not finish within %s", ErrCommandTimedOut, name, timeout)
	}
	return output, err
}

// run is the common case: combined output under the default deadline.
func run(name string, args ...string) ([]byte, error) {
	return runWithTimeout(defaultTimeout, name, args...)
}

// runQuick is for read-only inspection that should never be slow.
func runQuick(name string, args ...string) ([]byte, error) {
	return runWithTimeout(quickTimeout, name, args...)
}

// runLong is for genuinely slow work: installs, pulls, backups, certbot.
func runLong(name string, args ...string) ([]byte, error) {
	return runWithTimeout(longTimeout, name, args...)
}

// commandContext builds a deadline-bound *exec.Cmd for callers that need to set
// Env, Stdin, or streaming output themselves. The returned cancel must be
// deferred by the caller.
func commandContext(timeout time.Duration, name string, args ...string) (*exec.Cmd, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	return exec.CommandContext(ctx, name, args...), cancel
}

// aptLockArgs makes apt fail fast instead of blocking forever on the dpkg lock.
//
// Ubuntu ships unattended-upgrades enabled, which takes the lock on its own
// schedule. Without this, any apt call during that window waits indefinitely —
// the single largest source of stuck agent processes.
var aptLockArgs = []string{"-o", "DPkg::Lock::Timeout=30"}

// apt runs an apt/apt-get subcommand with the lock timeout applied.
func apt(timeout time.Duration, tool string, args ...string) ([]byte, error) {
	return runWithTimeout(timeout, tool, append(append([]string{}, aptLockArgs...), args...)...)
}

// mustRun runs a command under the default deadline and reports whether it
// succeeded, for callers that only care about success. Replaces bare
// exec.Command(...).Run(), which could block forever.
func mustRun(name string, args ...string) error {
	_, err := run(name, args...)
	return err
}

// runWithStdin runs a command with data supplied on standard input.
//
// This exists for secrets. Anything passed as a command-line argument is visible
// in /proc/<pid>/cmdline, which on a default Linux install is readable by every
// local user — including a web application running as www-data, which is exactly
// the account an attacker reaches first on a compromised site. A generated
// database password handed to `mysql --execute` is therefore readable by the
// thing most likely to be hostile.
//
// Standard input is not exposed that way, so credentials go through here.
func runWithStdin(timeout time.Duration, stdin string, name string, args ...string) ([]byte, error) {
	command, cancel := commandContext(timeout, name, args...)
	defer cancel()
	command.Stdin = strings.NewReader(stdin)
	output, err := command.CombinedOutput()
	if err != nil && strings.Contains(err.Error(), "context deadline exceeded") {
		return output, fmt.Errorf("%w: %s did not finish within %s", ErrCommandTimedOut, name, timeout)
	}
	return output, err
}
