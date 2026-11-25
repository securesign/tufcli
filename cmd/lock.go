/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"syscall"

	"github.com/securesign/tufcli/internal/lock"
	"github.com/spf13/cobra"
)

var lockRepoDir string

var lockCmd = &cobra.Command{
	Use:   "lock --repo <dir> -- <command> [args...]",
	Short: "Run a command while holding the repository lock",
	Long: `Run a command while holding the exclusive lock on a TUF repository directory.

The lock is the file <dir>/.tufcli.lock, the same one every tufcli write command
takes, so a script wrapped with this command never overlaps a tufcli writer (or
another wrapped script) on the same repository. It blocks until the lock is free
and prints a notice while it waits.

On Linux and macOS the command inherits the lock, so it stays held until the
command and anything it left running have exited, even if the wrapper is
killed. The command can itself run tufcli write commands on the same
repository: they recognise the inherited lock (TUFCLI_LOCK_HELD plus the
inherited file) and reuse it instead of waiting for it. On Windows the lock is
held until the command exits and a tufcli writer started inside it on the same
repository would wait for it, so do not nest there.

SIGTERM, and SIGINT unless the terminal already delivers Ctrl-C to the command,
are forwarded to it.

The exit code of the wrapped command is returned (128+N if it was killed by
signal N).`,
	Example: `  tufcli lock --repo /var/run/tuf -- sh -c 'cp new.root.json /var/run/tuf/root.json'`,
	Args:    cobra.MinimumNArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		l, err := lock.Acquire(lockRepoDir)
		if err != nil {
			return err
		}

		child := exec.Command(args[0], args[1:]...) //nolint:gosec // running the user's command is the purpose of this command
		child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
		releaseLock := shareLock(child, l)

		// Forward termination signals so the child can clean up. The lock is
		// freed when the child (and its descendants) are gone, or by the OS.
		sigs := make(chan os.Signal, 1)
		catch, forward := prepareSignals(child)
		signal.Notify(sigs, catch...)
		defer signal.Stop(sigs)

		if err := child.Start(); err != nil {
			_ = l.Release()
			return fmt.Errorf("failed to start %q: %w", args[0], err)
		}
		go func() {
			for s := range sigs {
				if slices.Contains(forward, s) {
					_ = child.Process.Signal(s)
				}
			}
		}()

		err = child.Wait()
		_ = releaseLock()
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitCode(exitErr))
		}
		return err
	},
}

// exitCode maps the child's status to a shell-style exit code.
func exitCode(e *exec.ExitError) int {
	if ws, ok := e.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return e.ExitCode()
}

func init() {
	// Stop flag parsing at the wrapped command so its own flags (ls -la) reach it, with or without "--".
	lockCmd.Flags().SetInterspersed(false)
	lockCmd.Flags().StringVar(&lockRepoDir, "repo", "", "Repository directory holding the lock file")
	lockCmd.MarkFlagRequired("repo")
}
