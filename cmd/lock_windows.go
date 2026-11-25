//go:build windows

package cmd

import (
	"os"
	"os/exec"

	"github.com/securesign/tufcli/internal/lock"
)

// shareLock: Windows has no ExtraFiles, so the wrapper keeps the lock until the
// child exits and does not set lock.HeldEnv (a writer started inside the wrapper
// would wait for it).
func shareLock(_ *exec.Cmd, l *lock.Lock) func() error {
	return l.Release
}

func prepareSignals(_ *exec.Cmd) (catch, forward []os.Signal) {
	return []os.Signal{os.Interrupt}, []os.Signal{os.Interrupt}
}
