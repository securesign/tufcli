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

// Package lock provides the exclusive repository lock shared by every tufcli
// command that writes to a TUF repository directory.
package lock

import (
	"fmt"
	"os"
	"path/filepath"
)

// FileName is the lock file created inside the repository directory.
const FileName = ".tufcli.lock"

// HeldEnv names the environment variable "tufcli lock" sets for the command it
// runs. It holds the resolved path of the lock file that is already held, so a
// tufcli write command started by the wrapped script on the same repository
// does not wait for the wrapper (which would deadlock).
//
// The variable alone is not trusted: it only counts when this process also
// holds the open lock file the wrapper passed down (see adoptInherited), so a
// stale or hand-set value never skips locking. The handle is passed as the
// first extra file, which is always file descriptor InheritedFD. Not supported
// on Windows, where a writer inside the wrapper takes the lock normally and
// would wait for the wrapper.
const HeldEnv = "TUFCLI_LOCK_HELD"

// InheritedFD is the descriptor on which "tufcli lock" passes the lock file to
// the command it runs (first entry of exec.Cmd.ExtraFiles).
const InheritedFD = 3

// Lock is a held exclusive lock on a repository directory.
type Lock struct {
	f    *os.File
	path string
	// inherited is true when f is a handle passed down by a parent
	// "tufcli lock". The lock belongs to the parent: releasing must only close
	// our handle, because unlocking would free it for everyone sharing it.
	inherited bool
}

// Path returns the resolved path of the lock file.
func (l *Lock) Path() string { return l.path }

// File returns the open lock file. It is meant for handing the lock to a child
// process through exec.Cmd.ExtraFiles.
func (l *Lock) File() *os.File { return l.f }

// Acquire creates dir if needed and blocks until it holds the exclusive lock
// on <dir>/.tufcli.lock. The lock is advisory: it only excludes other tufcli
// writers (and scripts wrapped with "tufcli lock"). If another process holds
// it, a notice is printed to stderr before waiting. If this process was started by
// "tufcli lock" for this very repository (see HeldEnv), Acquire reuses the
// lock that wrapper holds instead of waiting for it. Call Release when done; the OS also releases the lock if the
// process dies.
func Acquire(dir string) (*Lock, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create repository directory: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve repository directory: %w", err)
	}
	if resolved, err = filepath.Abs(resolved); err != nil {
		return nil, fmt.Errorf("failed to resolve repository directory: %w", err)
	}
	path := filepath.Join(resolved, FileName)
	if os.Getenv(HeldEnv) == path {
		if f := adoptInherited(path); f != nil {
			return &Lock{f: f, path: path, inherited: true}, nil
		}
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644) //nolint:gosec // lock file inside the repository directory chosen by the caller
	if err != nil {
		return nil, fmt.Errorf("failed to open lock file %s: %w", path, err)
	}
	got, err := tryLockFile(f)
	if err == nil && !got {
		fmt.Fprintf(os.Stderr, "waiting for repository lock %s\n", path)
		err = lockFile(f)
	}
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("failed to lock %s: %w", path, err)
	}
	return &Lock{f: f, path: path}, nil
}

// Release unlocks and closes the lock file. The file itself is left in place
// on purpose: deleting it would let two writers lock different inodes.
func (l *Lock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	if l.inherited {
		return l.Close()
	}
	err := unlockFile(l.f)
	if cerr := l.f.Close(); err == nil {
		err = cerr
	}
	l.f = nil
	return err
}

// Close closes this process's handle without unlocking explicitly. If a child
// process was given the file (ExtraFiles), the lock stays held until the last
// holder closes it or exits, like flock(1) does.
func (l *Lock) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}
