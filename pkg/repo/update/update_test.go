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

package update

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/securesign/tufcli/pkg/repo/create"
	"github.com/securesign/tufcli/pkg/rootmeta"
)

func defaultExpires() time.Time {
	return time.Now().UTC().Truncate(time.Second).AddDate(1, 0, 0)
}

func setupTestRepo(t *testing.T) (dir, rootPath, keyPath, repoDir string) {
	t.Helper()
	dir = t.TempDir()
	rootPath = filepath.Join(dir, "root.json")
	keyPath = filepath.Join(dir, "key.pem")

	if err := rootmeta.Init(rootmeta.InitOptions{Path: rootPath}); err != nil {
		t.Fatalf("failed to init root: %v", err)
	}
	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		if err := rootmeta.SetThreshold(rootmeta.SetThresholdOptions{Path: rootPath, Role: role, Threshold: 1}); err != nil {
			t.Fatalf("failed to set threshold: %v", err)
		}
	}
	if _, err := rootmeta.GenRsaKey(rootmeta.GenRsaKeyOptions{
		Path: rootPath, KeyPath: keyPath, Bits: 2048,
		Roles: []string{"root", "targets", "snapshot", "timestamp"},
	}); err != nil {
		t.Fatalf("failed to gen key: %v", err)
	}
	if err := rootmeta.Sign(rootmeta.SignOptions{Path: rootPath, KeyPaths: []string{keyPath}}); err != nil {
		t.Fatalf("failed to sign root: %v", err)
	}

	repoDir = filepath.Join(dir, "repo")
	return
}

func createInitialRepo(t *testing.T, rootPath, keyPath, repoDir string) {
	t.Helper()
	inputDir := filepath.Join(t.TempDir(), "input")
	if err := os.MkdirAll(inputDir, 0755); err != nil {
		t.Fatalf("failed to create input dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(inputDir, "initial.txt"), []byte("initial"), 0600); err != nil {
		t.Fatalf("failed to write initial target: %v", err)
	}

	if err := create.Create(&create.Options{
		RootPath:         rootPath,
		KeyPaths:         []string{keyPath},
		OutDir:           repoDir,
		AddTargetsDir:    inputDir,
		TargetsExpires:   defaultExpires(),
		TargetsVersion:   1,
		SnapshotExpires:  defaultExpires(),
		SnapshotVersion:  1,
		TimestampExpires: defaultExpires(),
		TimestampVersion: 1,
	}); err != nil {
		t.Fatalf("failed to create initial repo: %v", err)
	}
}

func TestRun_Basic(t *testing.T) {
	_, rootPath, keyPath, repoDir := setupTestRepo(t)
	createInitialRepo(t, rootPath, keyPath, repoDir)

	inputDir := filepath.Join(t.TempDir(), "update-input")
	if err := os.MkdirAll(inputDir, 0755); err != nil {
		t.Fatalf("failed to create update input dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(inputDir, "new.txt"), []byte("new content"), 0600); err != nil {
		t.Fatalf("failed to write new target: %v", err)
	}

	err := Update(&Options{
		RootPath:      rootPath,
		KeyPaths:      []string{keyPath},
		OutDir:        repoDir,
		MetadataURL:   "file:///" + repoDir,
		AddTargetsDir: inputDir,
	})
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	tsMd := &tufmeta.Metadata[tufmeta.TimestampType]{}
	if _, err := tsMd.FromFile(filepath.Join(repoDir, "timestamp.json")); err != nil {
		t.Fatalf("failed to load timestamp.json: %v", err)
	}
	if tsMd.Signed.Version != 2 {
		t.Fatalf("expected timestamp version 2, got %d", tsMd.Signed.Version)
	}

	targetsMd := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := targetsMd.FromFile(filepath.Join(repoDir, "2.targets.json")); err != nil {
		t.Fatalf("failed to load 2.targets.json: %v", err)
	}
	if _, ok := targetsMd.Signed.Targets["new.txt"]; !ok {
		t.Fatal("new.txt not found in updated targets")
	}
	if _, ok := targetsMd.Signed.Targets["initial.txt"]; !ok {
		t.Fatal("initial.txt should still be in updated targets")
	}
}
