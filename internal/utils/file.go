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
)

// WriteFileAtomic writes data to a file atomically using a temp file + rename.
func WriteFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create parent directory: %w", err)
	}

	tmpFile, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
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

	if err := os.Rename(tmpFile.Name(), path); err != nil {
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	if err := syncDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("failed to sync parent directory: %w", err)
	}

	return nil
}

// syncDir fsyncs a directory to ensure its entries are persisted to stable storage.
func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	err = d.Sync()
	d.Close()
	return err
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
