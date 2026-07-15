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
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("failed to create key dir: %v", err)
	}
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

	keyPath := generateTestKey(t, dir)

	rootPath := filepath.Join(dir, "root.json")
	err := root.Init(root.InitOptions{
		Path:    rootPath,
		Version: 1,
	})
	if err != nil {
		t.Fatalf("failed to init root.json: %v", err)
	}

	// Add the generated key to all roles
	keyIDs, err := root.AddKey(root.AddKeyOptions{
		Path:     rootPath,
		KeyPaths: []string{keyPath},
		Roles:    []string{"root", "targets", "snapshot", "timestamp"},
	})
	if err != nil {
		t.Fatalf("failed to add key to roles: %v", err)
	}
	if len(keyIDs) == 0 {
		t.Fatalf("no key IDs returned")
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
		RootPath:         "/nonexistent/root.json",
		AddTargetsDir:    t.TempDir(),
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
		RootPath:         rootPath,
		AddTargetsDir:    "/nonexistent/targets",
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

func TestValidateAndSetDefaults_AddTargetsIsFile(t *testing.T) {
	_, rootPath, _ := setupTestRepo(t)
	f := filepath.Join(t.TempDir(), "notadir.txt")
	os.WriteFile(f, []byte("data"), 0600)

	opts := &Options{
		RootPath:         rootPath,
		AddTargetsDir:    f,
		TargetsVersion:   1,
		SnapshotVersion:  1,
		TimestampVersion: 1,
		TargetsExpires:   defaultExpires(),
		SnapshotExpires:  defaultExpires(),
		TimestampExpires: defaultExpires(),
	}
	if err := opts.ValidateAndSetDefaults(); err == nil {
		t.Fatal("expected error when add-targets path is a file")
	}
}

func TestValidateAndSetDefaults_ZeroVersion(t *testing.T) {
	dir, rootPath, _ := setupTestRepo(t)
	_ = dir
	opts := &Options{
		RootPath:         rootPath,
		AddTargetsDir:    t.TempDir(),
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

func TestValidateAndSetDefaults_NegativeVersion(t *testing.T) {
	_, rootPath, _ := setupTestRepo(t)
	opts := &Options{
		RootPath:         rootPath,
		AddTargetsDir:    t.TempDir(),
		TargetsVersion:   -1,
		SnapshotVersion:  1,
		TimestampVersion: 1,
		TargetsExpires:   defaultExpires(),
		SnapshotExpires:  defaultExpires(),
		TimestampExpires: defaultExpires(),
	}
	if err := opts.ValidateAndSetDefaults(); err == nil {
		t.Fatal("expected error for negative targets version")
	}
}

func TestValidateAndSetDefaults_ZeroSnapshotVersion(t *testing.T) {
	_, rootPath, _ := setupTestRepo(t)
	opts := &Options{
		RootPath:         rootPath,
		AddTargetsDir:    t.TempDir(),
		TargetsVersion:   1,
		SnapshotVersion:  0,
		TimestampVersion: 1,
		TargetsExpires:   defaultExpires(),
		SnapshotExpires:  defaultExpires(),
		TimestampExpires: defaultExpires(),
	}
	if err := opts.ValidateAndSetDefaults(); err == nil {
		t.Fatal("expected error for zero snapshot version")
	}
}

func TestValidateAndSetDefaults_ZeroTimestampVersion(t *testing.T) {
	_, rootPath, _ := setupTestRepo(t)
	opts := &Options{
		RootPath:         rootPath,
		AddTargetsDir:    t.TempDir(),
		TargetsVersion:   1,
		SnapshotVersion:  1,
		TimestampVersion: 0,
		TargetsExpires:   defaultExpires(),
		SnapshotExpires:  defaultExpires(),
		TimestampExpires: defaultExpires(),
	}
	if err := opts.ValidateAndSetDefaults(); err == nil {
		t.Fatal("expected error for zero timestamp version")
	}
}

func TestValidateAndSetDefaults_MissingExpires(t *testing.T) {
	_, rootPath, _ := setupTestRepo(t)
	tests := []struct {
		name string
		opts Options
	}{
		{
			name: "missing targets expires",
			opts: Options{
				RootPath:         rootPath,
				AddTargetsDir:    t.TempDir(),
				TargetsVersion:   1,
				SnapshotVersion:  1,
				TimestampVersion: 1,
				SnapshotExpires:  defaultExpires(),
				TimestampExpires: defaultExpires(),
			},
		},
		{
			name: "missing snapshot expires",
			opts: Options{
				RootPath:         rootPath,
				AddTargetsDir:    t.TempDir(),
				TargetsVersion:   1,
				SnapshotVersion:  1,
				TimestampVersion: 1,
				TargetsExpires:   defaultExpires(),
				TimestampExpires: defaultExpires(),
			},
		},
		{
			name: "missing timestamp expires",
			opts: Options{
				RootPath:         rootPath,
				AddTargetsDir:    t.TempDir(),
				TargetsVersion:   1,
				SnapshotVersion:  1,
				TimestampVersion: 1,
				TargetsExpires:   defaultExpires(),
				SnapshotExpires:  defaultExpires(),
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.opts.ValidateAndSetDefaults(); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
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

func TestValidateAndSetDefaults_ValidTargetPathExists(t *testing.T) {
	_, rootPath, _ := setupTestRepo(t)
	for _, val := range []string{"skip", "replace", "fail"} {
		t.Run(val, func(t *testing.T) {
			opts := &Options{
				RootPath:         rootPath,
				AddTargetsDir:    t.TempDir(),
				TargetsVersion:   1,
				SnapshotVersion:  1,
				TimestampVersion: 1,
				TargetsExpires:   defaultExpires(),
				SnapshotExpires:  defaultExpires(),
				TimestampExpires: defaultExpires(),
				TargetPathExists: val,
			}
			if err := opts.ValidateAndSetDefaults(); err != nil {
				t.Fatalf("unexpected error for target-path-exists=%s: %v", val, err)
			}
		})
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

func TestRun_TargetPathExists_Replace(t *testing.T) {
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
		TargetPathExists: "replace",
	}

	if err := Run(opts); err != nil {
		t.Fatalf("first Run failed: %v", err)
	}

	os.WriteFile(filepath.Join(inputDir, "file.txt"), []byte("replaced"), 0600)
	if err := Run(opts); err != nil {
		t.Fatalf("second Run with replace failed: %v", err)
	}

	md := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := md.FromFile(filepath.Join(outDir, "1.targets.json")); err != nil {
		t.Fatalf("failed to load targets: %v", err)
	}
	tf, ok := md.Signed.Targets["file.txt"]
	if !ok {
		t.Fatal("file.txt not in targets after replace")
	}
	if tf.Length != int64(len("replaced")) {
		t.Fatalf("expected length %d after replace, got %d", len("replaced"), tf.Length)
	}
}

func TestRun_NestedSubdirectories(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	inputDir := filepath.Join(dir, "input")
	os.MkdirAll(filepath.Join(inputDir, "sub", "deep"), 0755)
	os.WriteFile(filepath.Join(inputDir, "top.txt"), []byte("top"), 0600)
	os.WriteFile(filepath.Join(inputDir, "sub", "mid.txt"), []byte("mid"), 0600)
	os.WriteFile(filepath.Join(inputDir, "sub", "deep", "bottom.txt"), []byte("bottom"), 0600)

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

	md := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := md.FromFile(filepath.Join(outDir, "1.targets.json")); err != nil {
		t.Fatalf("failed to load targets: %v", err)
	}

	expected := []string{"top.txt", filepath.Join("sub", "mid.txt"), filepath.Join("sub", "deep", "bottom.txt")}
	for _, name := range expected {
		if _, ok := md.Signed.Targets[name]; !ok {
			t.Fatalf("expected target %q not found in metadata", name)
		}
	}
	if len(md.Signed.Targets) != 3 {
		t.Fatalf("expected 3 targets, got %d", len(md.Signed.Targets))
	}
}

func TestRun_SymlinkWithoutFollow(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	inputDir := filepath.Join(dir, "input")
	os.MkdirAll(inputDir, 0755)

	realFile := filepath.Join(dir, "real.txt")
	os.WriteFile(realFile, []byte("real content"), 0600)
	os.Symlink(realFile, filepath.Join(inputDir, "link.txt"))

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
		Follow:           false,
	}

	if err := Run(opts); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	md := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := md.FromFile(filepath.Join(outDir, "1.targets.json")); err != nil {
		t.Fatalf("failed to load targets: %v", err)
	}

	if len(md.Signed.Targets) != 0 {
		t.Fatalf("expected 0 targets (symlink skipped), got %d", len(md.Signed.Targets))
	}
}

func TestRun_SymlinkWithFollow(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	inputDir := filepath.Join(dir, "input")
	os.MkdirAll(inputDir, 0755)

	realFile := filepath.Join(dir, "real.txt")
	os.WriteFile(realFile, []byte("real content"), 0600)
	os.Symlink(realFile, filepath.Join(inputDir, "link.txt"))

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
		Follow:           true,
	}

	if err := Run(opts); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	md := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := md.FromFile(filepath.Join(outDir, "1.targets.json")); err != nil {
		t.Fatalf("failed to load targets: %v", err)
	}

	if _, ok := md.Signed.Targets["link.txt"]; !ok {
		t.Fatal("expected link.txt in targets when follow=true")
	}
}

func TestRun_TargetHashIntegrity(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	inputDir := filepath.Join(dir, "input")
	os.MkdirAll(inputDir, 0755)

	content := []byte("verify hash integrity")
	os.WriteFile(filepath.Join(inputDir, "check.txt"), content, 0600)

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

	md := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := md.FromFile(filepath.Join(outDir, "1.targets.json")); err != nil {
		t.Fatalf("failed to load targets: %v", err)
	}

	tf, ok := md.Signed.Targets["check.txt"]
	if !ok {
		t.Fatal("check.txt not in targets")
	}
	if tf.Length != int64(len(content)) {
		t.Fatalf("length mismatch: got %d, want %d", tf.Length, len(content))
	}
	sha256Hash, ok := tf.Hashes["sha256"]
	if !ok {
		t.Fatal("sha256 hash missing from target metadata")
	}

	hashPrefixed := filepath.Join(outDir, "targets", sha256Hash.String()+".check.txt")
	data, err := os.ReadFile(hashPrefixed)
	if err != nil {
		t.Fatalf("hash-prefixed target file not found: %v", err)
	}
	if string(data) != string(content) {
		t.Fatalf("target file content mismatch")
	}
}

func TestRun_OutputDirCreatedAutomatically(t *testing.T) {
	dir, rootPath, _ := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	inputDir := filepath.Join(dir, "input")
	os.MkdirAll(inputDir, 0755)

	outDir := filepath.Join(dir, "new", "nested", "repo")

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

	fi, err := os.Stat(outDir)
	if err != nil {
		t.Fatalf("output directory not created: %v", err)
	}
	if !fi.IsDir() {
		t.Fatal("output path is not a directory")
	}
}

func TestRun_MultipleKeys(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	key1 := filepath.Join(dir, "key.pem")
	inputDir := filepath.Join(dir, "input")
	os.MkdirAll(inputDir, 0755)

	key2 := generateTestKey(t, filepath.Join(dir, "key2"))

	// Add the second key to all roles in root.json
	_, err := root.AddKey(root.AddKeyOptions{
		Path:     rootPath,
		KeyPaths: []string{key2},
		Roles:    []string{"targets", "snapshot", "timestamp"},
	})
	if err != nil {
		t.Fatalf("failed to add second key to roles: %v", err)
	}

	opts := &Options{
		RootPath:         rootPath,
		KeyPaths:         []string{key1, key2},
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

	// Now that both keys are authorized for targets role, should have 2 signatures
	md := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := md.FromFile(filepath.Join(outDir, "1.targets.json")); err != nil {
		t.Fatalf("failed to load targets: %v", err)
	}
	if len(md.Signatures) != 2 {
		t.Fatalf("expected 2 signatures (both keys authorized for targets), got %d", len(md.Signatures))
	}
}

func TestRun_MetadataChainConsistency(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	inputDir := filepath.Join(dir, "input")
	os.MkdirAll(inputDir, 0755)
	os.WriteFile(filepath.Join(inputDir, "data.bin"), []byte("binary data"), 0600)

	opts := &Options{
		RootPath:         rootPath,
		KeyPaths:         []string{keyPath},
		OutDir:           outDir,
		AddTargetsDir:    inputDir,
		TargetsExpires:   defaultExpires(),
		TargetsVersion:   2,
		SnapshotExpires:  defaultExpires(),
		SnapshotVersion:  3,
		TimestampExpires: defaultExpires(),
		TimestampVersion: 4,
	}

	if err := Run(opts); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	snapMd := &tufmeta.Metadata[tufmeta.SnapshotType]{}
	if _, err := snapMd.FromFile(filepath.Join(outDir, "3.snapshot.json")); err != nil {
		t.Fatalf("failed to load snapshot: %v", err)
	}
	targetsMeta, ok := snapMd.Signed.Meta["targets.json"]
	if !ok {
		t.Fatal("snapshot does not reference targets.json")
	}
	if targetsMeta.Version != 2 {
		t.Fatalf("snapshot references targets version %d, want 2", targetsMeta.Version)
	}

	tsMd := &tufmeta.Metadata[tufmeta.TimestampType]{}
	if _, err := tsMd.FromFile(filepath.Join(outDir, "timestamp.json")); err != nil {
		t.Fatalf("failed to load timestamp: %v", err)
	}
	snapMeta, ok := tsMd.Signed.Meta["snapshot.json"]
	if !ok {
		t.Fatal("timestamp does not reference snapshot.json")
	}
	if snapMeta.Version != 3 {
		t.Fatalf("timestamp references snapshot version %d, want 3", snapMeta.Version)
	}
}

func TestRun_RootJsonCopied(t *testing.T) {
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

	srcData, _ := os.ReadFile(rootPath)
	outRoot, err := os.ReadFile(filepath.Join(outDir, "root.json"))
	if err != nil {
		t.Fatalf("root.json not found in output: %v", err)
	}
	if string(srcData) != string(outRoot) {
		t.Fatal("root.json in output does not match source root.json")
	}

	versionedRoot, err := os.ReadFile(filepath.Join(outDir, "1.root.json"))
	if err != nil {
		t.Fatalf("1.root.json not found in output: %v", err)
	}
	if string(srcData) != string(versionedRoot) {
		t.Fatal("1.root.json in output does not match source root.json")
	}
}
