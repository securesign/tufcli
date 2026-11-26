package lock

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestAcquireCreatesDirAndFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "repo")
	l, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, FileName)); err != nil {
		t.Fatalf("lock file missing: %v", err)
	}
	if err := l.Release(); err != nil {
		t.Fatal(err)
	}
	if err := l.Release(); err != nil {
		t.Fatalf("second release must be a no-op: %v", err)
	}
}

func TestConcurrentWritersSerialize(t *testing.T) {
	dir := t.TempDir()
	first, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}

	acquired := make(chan *Lock)
	go func() {
		l, err := Acquire(dir)
		if err != nil {
			t.Error(err)
		}
		acquired <- l
	}()

	select {
	case <-acquired:
		t.Fatal("second writer got the lock while the first still held it")
	case <-time.After(200 * time.Millisecond):
	}

	if err := first.Release(); err != nil {
		t.Fatal(err)
	}
	select {
	case l := <-acquired:
		_ = l.Release()
	case <-time.After(5 * time.Second):
		t.Fatal("second writer never got the lock after release")
	}
}

// A separate process holding the lock must block us too (flock is per open file
// description, so this is the cross-process case the Jobs rely on).
func TestLockHeldByOtherProcess(t *testing.T) {
	if os.Getenv("TUFCLI_LOCK_HELPER") != "" {
		l, err := Acquire(os.Getenv("TUFCLI_LOCK_DIR"))
		if err != nil {
			os.Exit(2)
		}
		os.Stdout.WriteString("held\n")
		time.Sleep(500 * time.Millisecond)
		_ = l.Release()
		return
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=TestLockHeldByOtherProcess")
	cmd.Env = append(os.Environ(), "TUFCLI_LOCK_HELPER=1", "TUFCLI_LOCK_DIR="+dir)
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := out.Read(buf); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	l, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 100*time.Millisecond {
		t.Fatal("acquired while the other process held the lock")
	}
	_ = l.Release()
	_ = cmd.Wait()
}

func TestReleaseOnFailurePath(t *testing.T) {
	dir := t.TempDir()
	run := func() (err error) {
		l, err := Acquire(dir)
		if err != nil {
			return err
		}
		defer func() { _ = l.Release() }()
		return os.ErrInvalid
	}
	_ = run()

	done := make(chan struct{})
	go func() {
		defer close(done)
		l, err := Acquire(dir)
		if err != nil {
			t.Error(err)
			return
		}
		_ = l.Release()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("lock was not released after a failed run")
	}
}

// helper process: reports how Acquire behaves given the environment/fds it was started with.
func TestInheritanceHelper(t *testing.T) {
	dir := os.Getenv("TUFCLI_LOCK_DIR")
	if dir == "" {
		t.Skip("helper process")
	}
	l, err := Acquire(dir)
	if err != nil {
		fmt.Println("error", err)
		return
	}
	if err := l.Release(); err != nil {
		fmt.Println("release-error", err)
		return
	}
	fmt.Println("acquired")
}

func runHelper(t *testing.T, dir, held string, extra *os.File) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestInheritanceHelper")
	cmd.Env = append(os.Environ(), "TUFCLI_LOCK_DIR="+dir, HeldEnv+"="+held)
	if extra != nil {
		cmd.ExtraFiles = []*os.File{extra}
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
		return out.String()
	case <-time.After(1500 * time.Millisecond):
		_ = cmd.Process.Kill()
		<-done
		return "blocked"
	}
}

func TestInheritedLockIsReused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("lock inheritance is not supported on Windows")
	}
	dir := t.TempDir()
	parent, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = parent.Release() }()

	out := runHelper(t, dir, parent.Path(), parent.File())
	if !strings.Contains(out, "acquired") {
		t.Fatalf("writer with the inherited lock should proceed, got %q", out)
	}
	// The child's release must not have freed the parent's lock.
	other, err := os.OpenFile(parent.Path(), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if got, err := tryLockFile(other); err != nil || got {
		t.Fatalf("parent lock must still be held after the child released (got=%v err=%v)", got, err)
	}
}

func TestHeldEnvWithoutInheritedHandleIsNotTrusted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("lock inheritance is not supported on Windows")
	}
	dir := t.TempDir()
	parent, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Matching env but no inherited handle: must wait for the real holder.
	if out := runHelper(t, dir, parent.Path(), nil); out != "blocked" {
		t.Fatalf("env alone must not skip the lock, got %q", out)
	}
	_ = parent.Release()
	// Lock free and stale env: must simply take the lock.
	if out := runHelper(t, dir, parent.Path(), nil); !strings.Contains(out, "acquired") {
		t.Fatalf("stale env with a free lock should acquire normally, got %q", out)
	}
}

func TestInheritedHandleOfAnotherFileIsNotTrusted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("lock inheritance is not supported on Windows")
	}
	dir := t.TempDir()
	parent, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = parent.Release() }()
	unrelated, err := os.CreateTemp(t.TempDir(), "x")
	if err != nil {
		t.Fatal(err)
	}
	defer unrelated.Close()
	if out := runHelper(t, dir, parent.Path(), unrelated); out != "blocked" {
		t.Fatalf("fd 3 pointing at another file must not count as the lock, got %q", out)
	}
}

func TestHeldEnvForOtherRepoDoesNotApply(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	parent, err := Acquire(a)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = parent.Release() }()

	t.Setenv(HeldEnv, parent.Path())
	l, err := Acquire(b)
	if err != nil {
		t.Fatal(err)
	}
	if l.inherited {
		t.Fatal("a lock for a different repository must be taken for real")
	}
	_ = l.Release()
}
