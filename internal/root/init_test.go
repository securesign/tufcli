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

package root

import (
	"os"
	"path/filepath"
	"testing"

	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"
)

func TestInit(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tufcli-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testPath := filepath.Join(tmpDir, "root.json")

	err = Init(InitOptions{
		Path:    testPath,
		Version: 0, // should default to 1
	})
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	if _, err := os.Stat(testPath); os.IsNotExist(err) {
		t.Fatal("root.json was not created")
	}

	md := &tufmeta.Metadata[tufmeta.RootType]{}
	if _, err := md.FromFile(testPath); err != nil {
		t.Fatalf("failed to parse root.json: %v", err)
	}

	if md.Signed.Type != tufmeta.ROOT {
		t.Errorf("expected _type %q, got %q", tufmeta.ROOT, md.Signed.Type)
	}

	if md.Signed.SpecVersion != tufmeta.SPECIFICATION_VERSION {
		t.Errorf("expected spec_version %q, got %q", tufmeta.SPECIFICATION_VERSION, md.Signed.SpecVersion)
	}

	if md.Signed.Version != 1 {
		t.Errorf("expected version 1, got %d", md.Signed.Version)
	}

	if !md.Signed.ConsistentSnapshot {
		t.Error("expected consistent_snapshot to be true")
	}

	for _, role := range []string{tufmeta.ROOT, tufmeta.SNAPSHOT, tufmeta.TARGETS, tufmeta.TIMESTAMP} {
		r, ok := md.Signed.Roles[role]
		if !ok {
			t.Errorf("role %s not found", role)
			continue
		}
		if r.Threshold != DefaultThreshold {
			t.Errorf("role %s: expected threshold %d, got %d", role, DefaultThreshold, r.Threshold)
		}
		if len(r.KeyIDs) != 0 {
			t.Errorf("role %s: expected empty keyids, got %d", role, len(r.KeyIDs))
		}
	}

	if len(md.Signed.Keys) != 0 {
		t.Errorf("expected empty keys, got %d", len(md.Signed.Keys))
	}

	if len(md.Signatures) != 0 {
		t.Errorf("expected empty signatures, got %d", len(md.Signatures))
	}
}

func TestInitCustomVersion(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tufcli-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testPath := filepath.Join(tmpDir, "root.json")

	const customVersion uint64 = 42
	err = Init(InitOptions{
		Path:    testPath,
		Version: customVersion,
	})
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	md := &tufmeta.Metadata[tufmeta.RootType]{}
	if _, err := md.FromFile(testPath); err != nil {
		t.Fatalf("failed to parse root.json: %v", err)
	}

	if md.Signed.Version != int64(customVersion) {
		t.Errorf("expected version %d, got %d", customVersion, md.Signed.Version)
	}
}
