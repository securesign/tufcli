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

package create

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/securesign/tufcli/pkg/rootmeta"
)

func setupTestRepo(t *testing.T) (dir, rootPath, keyPath, outDir string) {
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

	outDir = filepath.Join(dir, "repo")
	return
}

func defaultExpires() time.Time {
	return time.Now().UTC().Truncate(time.Second).AddDate(1, 0, 0)
}

func TestRun_Basic(t *testing.T) {
	_, rootPath, keyPath, outDir := setupTestRepo(t)

	inputDir := filepath.Join(t.TempDir(), "input")
	if err := os.MkdirAll(inputDir, 0755); err != nil {
		t.Fatalf("failed to create input dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(inputDir, "artifact.txt"), []byte("test data"), 0600); err != nil {
		t.Fatalf("failed to write target file: %v", err)
	}

	err := Create(&Options{
		RootPath:         rootPath,
		KeyPaths:         []string{keyPath},
		OutDir:           outDir,
		AddTargetsDir:    inputDir,
		TargetsExpires:   defaultExpires(),
		TargetsVersion:   1,
		SnapshotExpires:  defaultExpires(),
		SnapshotVersion:  1,
		TimestampExpires: defaultExpires(),
		TimestampVersion: 1,
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	for _, name := range []string{"root.json", "1.root.json", "1.targets.json", "1.snapshot.json", "timestamp.json"} {
		path := filepath.Join(outDir, name)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s to exist", name)
		}
	}

	md := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := md.FromFile(filepath.Join(outDir, "1.targets.json")); err != nil {
		t.Fatalf("failed to load targets.json: %v", err)
	}
	if _, ok := md.Signed.Targets["artifact.txt"]; !ok {
		t.Fatal("artifact.txt not found in targets metadata")
	}
}
