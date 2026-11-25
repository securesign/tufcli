//go:build !windows

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

package lock

import (
	"os"
	"syscall"
)

func lockFile(f *os.File) error {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if err != syscall.EINTR {
			return err
		}
	}
}

// adoptInherited returns the lock file handle a parent "tufcli lock" passed on
// InheritedFD if, and only if, it really is the lock file at path. It marks the
// descriptor close-on-exec so it does not leak into unrelated children.
func adoptInherited(path string) *os.File {
	// Compare by stat before wrapping the descriptor: an *os.File would close
	// fd 3 on garbage collection, and fd 3 may be something unrelated.
	var held, want syscall.Stat_t
	if syscall.Fstat(InheritedFD, &held) != nil || syscall.Stat(path, &want) != nil {
		return nil
	}
	//nolint:unconvert // Dev/Ino have different integer types across platforms
	if uint64(held.Dev) != uint64(want.Dev) || uint64(held.Ino) != uint64(want.Ino) {
		return nil
	}
	syscall.CloseOnExec(InheritedFD)
	return os.NewFile(uintptr(InheritedFD), FileName)
}

func tryLockFile(f *os.File) (bool, error) {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		switch err {
		case nil:
			return true, nil
		case syscall.EINTR:
			continue
		case syscall.EWOULDBLOCK:
			return false, nil
		default:
			return false, err
		}
	}
}

func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
