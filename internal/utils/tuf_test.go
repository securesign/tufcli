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
	"os"
	"path/filepath"
	"testing"
)

func TestComputeMetaFileInfo(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")
	content := []byte(`{"signed":{"version":1}}`)
	os.WriteFile(path, content, 0644)

	meta, err := ComputeMetaFileInfo(path, 3, "sha256")
	if err != nil {
		t.Fatalf("ComputeMetaFileInfo failed: %v", err)
	}
	if meta.Version != 3 {
		t.Fatalf("expected version 3, got %d", meta.Version)
	}
	if meta.Length != int64(len(content)) {
		t.Fatalf("expected length %d, got %d", len(content), meta.Length)
	}
	sha256Hash, ok := meta.Hashes["sha256"]
	if !ok {
		t.Fatal("missing sha256 hash")
	}
	if len(sha256Hash) != 32 {
		t.Fatalf("expected 32-byte sha256, got %d bytes", len(sha256Hash))
	}
}

func TestComputeMetaFileInfo_SHA512(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")
	content := []byte(`{"signed":{"version":1}}`)
	os.WriteFile(path, content, 0644)

	meta, err := ComputeMetaFileInfo(path, 1, "sha512")
	if err != nil {
		t.Fatalf("ComputeMetaFileInfo with sha512 failed: %v", err)
	}
	sha512Hash, ok := meta.Hashes["sha512"]
	if !ok {
		t.Fatal("missing sha512 hash")
	}
	if len(sha512Hash) != 64 {
		t.Fatalf("expected 64-byte sha512, got %d bytes", len(sha512Hash))
	}
	if _, ok := meta.Hashes["sha256"]; ok {
		t.Fatal("sha256 hash should not be present when using sha512")
	}
}

func TestComputeMetaFileInfo_NotFound(t *testing.T) {
	_, err := ComputeMetaFileInfo("/nonexistent/path.json", 1, "sha256")
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}
