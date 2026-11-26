//go:build !windows

package cmd

import (
	"os"
	"os/exec"
	"syscall"

	"github.com/securesign/tufcli/internal/lock"
	"golang.org/x/sys/unix"
)

// shareLock gives the child its own handle on the lock file (fd 3) and tells it
// which lock that is (lock.HeldEnv). A flock belongs to the open file
// description, so the lock outlives the wrapper for as long as the child or any
// process it left running holds that description. When the wrapper itself runs
// under another wrapper, l.File() is the handle inherited from it and is passed
// on the same way. The returned func is what the wrapper calls once the child
// has exited; it only closes the wrapper's handle, it does not unlock.
func shareLock(child *exec.Cmd, l *lock.Lock) func() error {
	child.ExtraFiles = append(child.ExtraFiles, l.File())
	child.Env = append(os.Environ(), lock.HeldEnv+"="+l.Path())
	return l.Close
}

// prepareSignals decides how termination signals reach the child. It returns
// the signals the wrapper must catch and, of those, the ones it forwards.
//
// On an interactive terminal where the wrapper is in the foreground process
// group, Ctrl-C is delivered to the child by the terminal itself: the wrapper
// catches SIGINT (so it keeps waiting for the child and its exit code) but does
// not forward it, which would interrupt the child twice. Otherwise the child
// gets its own process group, so terminal signals reach it only through the
// wrapper, and SIGINT and SIGTERM are both forwarded exactly once.
func prepareSignals(child *exec.Cmd) (catch, forward []os.Signal) {
	if foregroundOnTerminal() {
		return []os.Signal{syscall.SIGINT, syscall.SIGTERM}, []os.Signal{syscall.SIGTERM}
	}
	child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	both := []os.Signal{syscall.SIGINT, syscall.SIGTERM}
	return both, both
}

func foregroundOnTerminal() bool {
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return false
	}
	defer tty.Close()
	pgrp, err := unix.IoctlGetInt(int(tty.Fd()), unix.TIOCGPGRP)
	return err == nil && pgrp == syscall.Getpgrp()
}
