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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/securesign/tufcli/internal/root"
	"github.com/securesign/tufcli/internal/utils"
)

func generateTestKey(t *testing.T, dir string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	privBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}
	path := filepath.Join(dir, "key.pem")
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}
	return path
}

func setupTestRepo(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()

	generateTestKey(t, dir)

	rootPath := filepath.Join(dir, "root.json")
	err := root.Init(root.InitOptions{
		Path:    rootPath,
		Version: 1,
	})
	if err != nil {
		t.Fatalf("failed to init root.json: %v", err)
	}

	md := &tufmeta.Metadata[tufmeta.RootType]{}
	if _, err := md.FromFile(rootPath); err != nil {
		t.Fatalf("failed to load root.json: %v", err)
	}
	for role := range md.Signed.Roles {
		md.Signed.Roles[role].Threshold = 1
	}
	md.ClearSignatures()
	data, err := md.ToBytes(true)
	if err != nil {
		t.Fatalf("failed to serialize root.json: %v", err)
	}
	if err := utils.WriteFileAtomic(rootPath, data); err != nil {
		t.Fatalf("failed to write root.json: %v", err)
	}

	outDir := filepath.Join(dir, "repo")

	return dir, rootPath, outDir
}

func defaultExpires() time.Time {
	return time.Now().UTC().Truncate(time.Second).AddDate(1, 0, 0)
}

// --- Validation tests ---

func TestValidateAndSetDefaults_MissingRoot(t *testing.T) {
	opts := &Options{
		RootPath:      "/nonexistent/root.json",
		AddTargetsDir: t.TempDir(),
		TargetsVersion:   1,
		SnapshotVersion:  1,
		TimestampVersion: 1,
		TargetsExpires:   defaultExpires(),
		SnapshotExpires:  defaultExpires(),
		TimestampExpires: defaultExpires(),
	}
	if err := opts.ValidateAndSetDefaults(); err == nil {
		t.Fatal("expected error for missing root.json")
	}
}

func TestValidateAndSetDefaults_MissingAddTargetsDir(t *testing.T) {
	dir, rootPath, _ := setupTestRepo(t)
	_ = dir
	opts := &Options{
		RootPath:      rootPath,
		AddTargetsDir: "/nonexistent/targets",
		TargetsVersion:   1,
		SnapshotVersion:  1,
		TimestampVersion: 1,
		TargetsExpires:   defaultExpires(),
		SnapshotExpires:  defaultExpires(),
		TimestampExpires: defaultExpires(),
	}
	if err := opts.ValidateAndSetDefaults(); err == nil {
		t.Fatal("expected error for missing add-targets directory")
	}
}

func TestValidateAndSetDefaults_ZeroVersion(t *testing.T) {
	dir, rootPath, _ := setupTestRepo(t)
	_ = dir
	opts := &Options{
		RootPath:      rootPath,
		AddTargetsDir: t.TempDir(),
		TargetsVersion:   0,
		SnapshotVersion:  1,
		TimestampVersion: 1,
		TargetsExpires:   defaultExpires(),
		SnapshotExpires:  defaultExpires(),
		TimestampExpires: defaultExpires(),
	}
	if err := opts.ValidateAndSetDefaults(); err == nil {
		t.Fatal("expected error for zero targets version")
	}
}

func TestValidateAndSetDefaults_InvalidTargetPathExists(t *testing.T) {
	dir, rootPath, _ := setupTestRepo(t)
	_ = dir
	opts := &Options{
		RootPath:         rootPath,
		AddTargetsDir:    t.TempDir(),
		TargetsVersion:   1,
		SnapshotVersion:  1,
		TimestampVersion: 1,
		TargetsExpires:   defaultExpires(),
		SnapshotExpires:  defaultExpires(),
		TimestampExpires: defaultExpires(),
		TargetPathExists: "invalid",
	}
	if err := opts.ValidateAndSetDefaults(); err == nil {
		t.Fatal("expected error for invalid target-path-exists")
	}
}

func TestValidateAndSetDefaults_DefaultTargetPathExists(t *testing.T) {
	dir, rootPath, _ := setupTestRepo(t)
	_ = dir
	opts := &Options{
		RootPath:         rootPath,
		AddTargetsDir:    t.TempDir(),
		TargetsVersion:   1,
		SnapshotVersion:  1,
		TimestampVersion: 1,
		TargetsExpires:   defaultExpires(),
		SnapshotExpires:  defaultExpires(),
		TimestampExpires: defaultExpires(),
	}
	if err := opts.ValidateAndSetDefaults(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.TargetPathExists != "skip" {
		t.Fatalf("expected default target-path-exists 'skip', got %q", opts.TargetPathExists)
	}
}

// --- Run tests ---

func TestRun_EmptyTargetsDir(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	inputDir := filepath.Join(dir, "input")
	os.MkdirAll(inputDir, 0755)

	opts := &Options{
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
	}

	if err := Run(opts); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	for _, name := range []string{"root.json", "1.root.json", "1.targets.json", "1.snapshot.json", "timestamp.json"} {
		path := filepath.Join(outDir, name)
		if !utils.FileExists(path) {
			t.Fatalf("expected %s to exist", name)
		}
	}
}

func TestRun_WithTargets(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	inputDir := filepath.Join(dir, "input")
	os.MkdirAll(inputDir, 0755)

	os.WriteFile(filepath.Join(inputDir, "file1.txt"), []byte("hello"), 0600)
	os.WriteFile(filepath.Join(inputDir, "file2.txt"), []byte("world"), 0600)

	opts := &Options{
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
	}

	if err := Run(opts); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	targetsPath := filepath.Join(outDir, "1.targets.json")
	md := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := md.FromFile(targetsPath); err != nil {
		t.Fatalf("failed to load targets.json: %v", err)
	}

	if _, ok := md.Signed.Targets["file1.txt"]; !ok {
		t.Fatal("file1.txt not found in targets metadata")
	}
	if _, ok := md.Signed.Targets["file2.txt"]; !ok {
		t.Fatal("file2.txt not found in targets metadata")
	}

	targetsDir := filepath.Join(outDir, "targets")
	entries, _ := os.ReadDir(targetsDir)
	if len(entries) < 2 {
		t.Fatalf("expected at least 2 files in targets dir, got %d", len(entries))
	}
}

func TestRun_VersionsAndExpirations(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	inputDir := filepath.Join(dir, "input")
	os.MkdirAll(inputDir, 0755)

	targetsExp := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	snapshotExp := time.Date(2027, 7, 1, 0, 0, 0, 0, time.UTC)
	timestampExp := time.Date(2027, 8, 1, 0, 0, 0, 0, time.UTC)

	opts := &Options{
		RootPath:         rootPath,
		KeyPaths:         []string{keyPath},
		OutDir:           outDir,
		AddTargetsDir:    inputDir,
		TargetsExpires:   targetsExp,
		TargetsVersion:   3,
		SnapshotExpires:  snapshotExp,
		SnapshotVersion:  5,
		TimestampExpires: timestampExp,
		TimestampVersion: 7,
	}

	if err := Run(opts); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// Check targets
	targetsMd := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := targetsMd.FromFile(filepath.Join(outDir, "3.targets.json")); err != nil {
		t.Fatalf("failed to load 3.targets.json: %v", err)
	}
	if targetsMd.Signed.Version != 3 {
		t.Fatalf("expected targets version 3, got %d", targetsMd.Signed.Version)
	}
	if !targetsMd.Signed.Expires.Truncate(time.Second).Equal(targetsExp) {
		t.Fatalf("targets expires mismatch: got %v, want %v", targetsMd.Signed.Expires, targetsExp)
	}

	// Check snapshot
	snapshotMd := &tufmeta.Metadata[tufmeta.SnapshotType]{}
	if _, err := snapshotMd.FromFile(filepath.Join(outDir, "5.snapshot.json")); err != nil {
		t.Fatalf("failed to load 5.snapshot.json: %v", err)
	}
	if snapshotMd.Signed.Version != 5 {
		t.Fatalf("expected snapshot version 5, got %d", snapshotMd.Signed.Version)
	}
	if !snapshotMd.Signed.Expires.Truncate(time.Second).Equal(snapshotExp) {
		t.Fatalf("snapshot expires mismatch: got %v, want %v", snapshotMd.Signed.Expires, snapshotExp)
	}

	// Check timestamp
	timestampMd := &tufmeta.Metadata[tufmeta.TimestampType]{}
	if _, err := timestampMd.FromFile(filepath.Join(outDir, "timestamp.json")); err != nil {
		t.Fatalf("failed to load timestamp.json: %v", err)
	}
	if timestampMd.Signed.Version != 7 {
		t.Fatalf("expected timestamp version 7, got %d", timestampMd.Signed.Version)
	}
	if !timestampMd.Signed.Expires.Truncate(time.Second).Equal(timestampExp) {
		t.Fatalf("timestamp expires mismatch: got %v, want %v", timestampMd.Signed.Expires, timestampExp)
	}
}

func TestRun_TargetPathExists_Fail(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	inputDir := filepath.Join(dir, "input")
	os.MkdirAll(inputDir, 0755)
	os.WriteFile(filepath.Join(inputDir, "file.txt"), []byte("data"), 0600)

	opts := &Options{
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
	}

	if err := Run(opts); err != nil {
		t.Fatalf("first Run failed: %v", err)
	}

	opts.TargetPathExists = "fail"
	if err := Run(opts); err == nil {
		t.Fatal("expected error on second run with target-path-exists=fail")
	}
}

func TestRun_TargetPathExists_Skip(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	inputDir := filepath.Join(dir, "input")
	os.MkdirAll(inputDir, 0755)
	os.WriteFile(filepath.Join(inputDir, "file.txt"), []byte("original"), 0600)

	opts := &Options{
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
		TargetPathExists: "skip",
	}

	if err := Run(opts); err != nil {
		t.Fatalf("first Run failed: %v", err)
	}

	// Change file content and run again
	os.WriteFile(filepath.Join(inputDir, "file.txt"), []byte("modified"), 0600)
	if err := Run(opts); err != nil {
		t.Fatalf("second Run with skip failed: %v", err)
	}
}
