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

package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

// WriteFileAtomic writes data to a file atomically using a temp file + rename.
func WriteFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create parent directory: %w", err)
	}

	tmpFile, err := os.CreateTemp(filepath.Dir(path), TempFilePrefix+"*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to write to temp file: %w", err)
	}

	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to sync temp file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	if err := RenameReplace(tmpFile.Name(), path); err != nil {
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	if err := syncDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("failed to sync parent directory: %w", err)
	}

	return nil
}

// CopyFileAtomic copies src to dst atomically (temp file in dst's directory,
// then rename), streaming the content so large files are not held in memory.
// The result has mode perm. A crash leaves either no dst or the complete file,
// never a truncated one.
func CopyFileAtomic(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file %s: %w", src, err)
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return fmt.Errorf("failed to create parent directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), TempFilePrefix+"*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmp.Name())

	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to copy %s: %w", src, err)
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to set permissions: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}
	if err := RenameReplace(tmp.Name(), dst); err != nil {
		return fmt.Errorf("failed to rename temp file: %w", err)
	}
	if err := syncDir(filepath.Dir(dst)); err != nil {
		return fmt.Errorf("failed to sync parent directory: %w", err)
	}
	return nil
}

// renameAttempts and renameRetryDelay bound how long RenameReplace keeps
// retrying a rename that failed for a reason that may pass (see
// retryableRenameError).
const (
	renameAttempts   = 10
	renameRetryDelay = 20 * time.Millisecond
)

// RenameReplace renames oldpath to newpath, replacing newpath if it exists.
// On Windows a rename onto a file that a reader has open without
// FILE_SHARE_DELETE fails with a sharing violation or access denied until the
// reader closes it, so such failures are retried briefly with a growing delay.
// Elsewhere it is a plain os.Rename.
func RenameReplace(oldpath, newpath string) error {
	return renameWithRetry(os.Rename, oldpath, newpath, retryableRenameError, renameAttempts, renameRetryDelay)
}

func renameWithRetry(rename func(string, string) error, oldpath, newpath string, retryable func(error) bool, attempts int, delay time.Duration) error {
	var err error
	for i := 0; i < attempts; i++ {
		if err = rename(oldpath, newpath); err == nil || !retryable(err) {
			return err
		}
		time.Sleep(delay * time.Duration(i+1))
	}
	return err
}

// TempFilePrefix starts the name of every temp file WriteFileAtomic and
// CopyFileAtomic create. It is long and specific on purpose: the stale-file
// sweep removes anything with this prefix, so it must not match a name a user
// can publish as a target.
const TempFilePrefix = ".tufcli-tmp-"

// LegacyTempFilePrefix is what earlier versions used. Only ever sweep it at the
// top level of a directory: the files under a target's own directory are named
// by users and may start with it.
const LegacyTempFilePrefix = ".tmp-"

// isTempName reports whether name is a temp file name os.CreateTemp produces
// for prefix+"*": the prefix followed by its random decimal suffix.
func isTempName(name, prefix string) bool {
	rest, ok := strings.CutPrefix(name, prefix)
	if !ok || rest == "" {
		return false
	}
	for _, r := range rest {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// SweepStaleTemp removes leftover temp files older than olderThan from dir,
// descending into subdirectories when recursive is set. Only regular files whose
// name is exactly prefix plus os.CreateTemp's numeric suffix are candidates, and
// keep (when not nil) can protect paths that are in use, such as published
// targets that happen to be named like a temp file. A process killed mid-write
// leaves such a file behind; fresh ones are kept, so a write in progress is not
// disturbed. It reports how many files it removed; errors on individual entries
// are ignored (best effort).
func SweepStaleTemp(dir, prefix string, olderThan time.Duration, recursive bool, keep func(path string) bool) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	removed := 0
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		if entry.IsDir() {
			if recursive {
				removed += SweepStaleTemp(path, prefix, olderThan, recursive, keep)
			}
			continue
		}
		if !entry.Type().IsRegular() || !isTempName(entry.Name(), prefix) {
			continue
		}
		if keep != nil && keep(path) {
			continue
		}
		info, err := entry.Info()
		if err != nil || time.Since(info.ModTime()) < olderThan {
			continue
		}
		if os.Remove(path) == nil {
			removed++
		}
	}
	return removed
}

// WriteFile writes data to a file.
func WriteFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create parent directory: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// HashFile computes the SHA256 hash of a file.
func HashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("failed to hash file: %w", err)
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// FileExists checks if a file exists.
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ReadJSONFile reads a JSON file and unmarshals it into v.
func ReadJSONFile(path string, v interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("failed to parse %s: %w", path, err)
	}
	return nil
}

// IndentJSON re-formats compact JSON bytes with 2-space indentation.
func IndentJSON(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := json.Indent(&buf, data, "", "  "); err != nil {
		return nil, fmt.Errorf("failed to indent JSON: %w", err)
	}
	return buf.Bytes(), nil
}

// WriteJSONFile marshals v as indented JSON and writes it atomically.
func WriteJSONFile(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	return WriteFileAtomic(path, data)
}

// ValidatePathInDir checks that resolvedPath is inside baseDir.
// Both paths are resolved to absolute form before comparison. If baseDir
// exists on disk, symlinks in its path are resolved via EvalSymlinks so that
// a symlinked parent cannot bypass the containment check.
func ValidatePathInDir(baseDir, resolvedPath string) error {
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return fmt.Errorf("failed to resolve base directory: %w", err)
	}
	if evaluated, err := filepath.EvalSymlinks(absBase); err == nil {
		absBase = evaluated
	}
	absPath, err := filepath.Abs(resolvedPath)
	if err != nil {
		return fmt.Errorf("failed to resolve path: %w", err)
	}
	// Resolve symlinks in the existing prefix of the path. For new files the
	// full path won't exist yet, so resolve the parent directory instead.
	if evaluated, err := filepath.EvalSymlinks(absPath); err == nil {
		absPath = evaluated
	} else if dir := filepath.Dir(absPath); dir != absPath {
		if evaluatedDir, err := filepath.EvalSymlinks(dir); err == nil {
			absPath = filepath.Join(evaluatedDir, filepath.Base(absPath))
		}
	}
	if !strings.HasPrefix(absPath, absBase+string(filepath.Separator)) {
		return fmt.Errorf("path %q resolves outside directory %q", resolvedPath, baseDir)
	}
	return nil
}

// SafeWriter returns the given writer if it is non-nil, or os.Stderr as a
// fallback. It handles both untyped nil and typed-nil io.Writer values
// (a non-nil interface wrapping a nil pointer) which would panic on Write.
func SafeWriter(w io.Writer) io.Writer {
	if w == nil {
		return os.Stderr
	}
	v := reflect.ValueOf(w)
	if v.Kind() == reflect.Pointer && v.IsNil() {
		return os.Stderr
	}
	return w
}
