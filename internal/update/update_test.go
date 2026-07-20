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

	"github.com/securesign/tufcli/internal/create"
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

func defaultExpires() time.Time {
	return time.Now().UTC().Truncate(time.Second).AddDate(1, 0, 0)
}

func setupTestRepo(t *testing.T) (dir, rootPath, keyPath, repoDir string) {
	t.Helper()
	dir = t.TempDir()

	keyPath = generateTestKey(t, dir)

	rootPath = filepath.Join(dir, "root.json")
	err := root.Init(root.InitOptions{
		Path:    rootPath,
		Version: 1,
	})
	if err != nil {
		t.Fatalf("failed to init root.json: %v", err)
	}

	_, err = root.AddKey(root.AddKeyOptions{
		Path:     rootPath,
		KeyPaths: []string{keyPath},
		Roles:    []string{"root", "targets", "snapshot", "timestamp"},
	})
	if err != nil {
		t.Fatalf("failed to add key to roles: %v", err)
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

	repoDir = filepath.Join(dir, "repo")
	return
}

func createInitialRepo(t *testing.T, rootPath, keyPath, repoDir string) {
	t.Helper()
	inputDir := filepath.Join(t.TempDir(), "input")
	os.MkdirAll(inputDir, 0755)
	os.WriteFile(filepath.Join(inputDir, "1.txt"), []byte("1"), 0600)
	os.WriteFile(filepath.Join(inputDir, "2.txt"), []byte("2"), 0600)

	err := create.Run(&create.Options{
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
	})
	if err != nil {
		t.Fatalf("failed to create initial repo: %v", err)
	}
}

func metadataURL(repoDir string) string {
	return "file:///" + repoDir
}

// --- Validation tests ---

func TestValidateAndSetDefaults_MissingMetadataURL(t *testing.T) {
	opts := &Options{}
	if err := opts.ValidateAndSetDefaults(); err == nil {
		t.Fatal("expected error for missing metadata-url")
	}
}

func TestValidateAndSetDefaults_InvalidMetadataURLScheme(t *testing.T) {
	opts := &Options{MetadataURL: "ftp://example.com/repo"}
	if err := opts.ValidateAndSetDefaults(); err == nil {
		t.Fatal("expected error for invalid metadata-url scheme")
	}
}

func TestValidateAndSetDefaults_ForceVersionRequired(t *testing.T) {
	v := int64(5)
	opts := &Options{
		MetadataURL:    "file:///tmp/repo",
		TargetsVersion: &v,
	}
	if err := opts.ValidateAndSetDefaults(); err == nil {
		t.Fatal("expected error when version set without force-version")
	}
}

func TestValidateAndSetDefaults_ForceVersionAllowed(t *testing.T) {
	v := int64(5)
	opts := &Options{
		MetadataURL:    "file:///tmp/repo",
		TargetsVersion: &v,
		ForceVersion:   true,
	}
	if err := opts.ValidateAndSetDefaults(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateAndSetDefaults_InvalidAddTargetsDir(t *testing.T) {
	opts := &Options{
		MetadataURL:   "file:///tmp/repo",
		AddTargetsDir: "/nonexistent/path",
	}
	if err := opts.ValidateAndSetDefaults(); err == nil {
		t.Fatal("expected error for missing add-targets directory")
	}
}

func TestValidateAndSetDefaults_InvalidTargetPathExists(t *testing.T) {
	opts := &Options{
		MetadataURL:      "file:///tmp/repo",
		TargetPathExists: "invalid",
	}
	if err := opts.ValidateAndSetDefaults(); err == nil {
		t.Fatal("expected error for invalid target-path-exists")
	}
}

func TestValidateAndSetDefaults_IncomingMetadataWithoutRole(t *testing.T) {
	opts := &Options{
		MetadataURL:      "file:///tmp/repo",
		IncomingMetadata: "/some/path",
	}
	if err := opts.ValidateAndSetDefaults(); err == nil {
		t.Fatal("expected error for incoming-metadata without role")
	}
}

func TestValidateAndSetDefaults_RoleWithoutIncomingMetadata(t *testing.T) {
	opts := &Options{
		MetadataURL:   "file:///tmp/repo",
		DelegatedRole: "delegatee",
	}
	if err := opts.ValidateAndSetDefaults(); err == nil {
		t.Fatal("expected error for role without incoming-metadata")
	}
}

func TestValidateAndSetDefaults_DefaultTargetPathExists(t *testing.T) {
	opts := &Options{
		MetadataURL: "file:///tmp/repo",
	}
	if err := opts.ValidateAndSetDefaults(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.TargetPathExists != "skip" {
		t.Fatalf("expected default target-path-exists 'skip', got %q", opts.TargetPathExists)
	}
}

// --- Run tests ---

func TestRun_AutoBumpVersions(t *testing.T) {
	_, rootPath, keyPath, repoDir := setupTestRepo(t)
	createInitialRepo(t, rootPath, keyPath, repoDir)

	inputDir := filepath.Join(t.TempDir(), "input")
	os.MkdirAll(inputDir, 0755)
	os.WriteFile(filepath.Join(inputDir, "1.txt"), []byte("1.1"), 0600)

	err := Run(&Options{
		RootPath:      rootPath,
		KeyPaths:      []string{keyPath},
		OutDir:        repoDir,
		MetadataURL:   metadataURL(repoDir),
		AddTargetsDir: inputDir,
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// Targets version should be bumped to 2 (was 1, add-targets triggers bump)
	targetsMd := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := targetsMd.FromFile(filepath.Join(repoDir, "2.targets.json")); err != nil {
		t.Fatalf("failed to load 2.targets.json: %v", err)
	}
	if targetsMd.Signed.Version != 2 {
		t.Fatalf("expected targets version 2, got %d", targetsMd.Signed.Version)
	}

	// Snapshot version should be bumped to 2
	snapMd := &tufmeta.Metadata[tufmeta.SnapshotType]{}
	if _, err := snapMd.FromFile(filepath.Join(repoDir, "2.snapshot.json")); err != nil {
		t.Fatalf("failed to load 2.snapshot.json: %v", err)
	}
	if snapMd.Signed.Version != 2 {
		t.Fatalf("expected snapshot version 2, got %d", snapMd.Signed.Version)
	}

	// Timestamp version should be bumped to 2
	tsMd := &tufmeta.Metadata[tufmeta.TimestampType]{}
	if _, err := tsMd.FromFile(filepath.Join(repoDir, "timestamp.json")); err != nil {
		t.Fatalf("failed to load timestamp.json: %v", err)
	}
	if tsMd.Signed.Version != 2 {
		t.Fatalf("expected timestamp version 2, got %d", tsMd.Signed.Version)
	}
}

func TestRun_NoTargetChanges_OnlySnapshotTimestampBump(t *testing.T) {
	_, rootPath, keyPath, repoDir := setupTestRepo(t)
	createInitialRepo(t, rootPath, keyPath, repoDir)

	err := Run(&Options{
		RootPath:    rootPath,
		KeyPaths:    []string{keyPath},
		OutDir:      repoDir,
		MetadataURL: metadataURL(repoDir),
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// Targets version should remain 1 (no target modifications)
	targetsMd := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := targetsMd.FromFile(filepath.Join(repoDir, "1.targets.json")); err != nil {
		t.Fatalf("failed to load 1.targets.json: %v", err)
	}
	if targetsMd.Signed.Version != 1 {
		t.Fatalf("expected targets version 1 (unchanged), got %d", targetsMd.Signed.Version)
	}

	// Snapshot and timestamp should be bumped
	snapMd := &tufmeta.Metadata[tufmeta.SnapshotType]{}
	if _, err := snapMd.FromFile(filepath.Join(repoDir, "2.snapshot.json")); err != nil {
		t.Fatalf("failed to load 2.snapshot.json: %v", err)
	}
	if snapMd.Signed.Version != 2 {
		t.Fatalf("expected snapshot version 2, got %d", snapMd.Signed.Version)
	}

	tsMd := &tufmeta.Metadata[tufmeta.TimestampType]{}
	if _, err := tsMd.FromFile(filepath.Join(repoDir, "timestamp.json")); err != nil {
		t.Fatalf("failed to load timestamp.json: %v", err)
	}
	if tsMd.Signed.Version != 2 {
		t.Fatalf("expected timestamp version 2, got %d", tsMd.Signed.Version)
	}
}

func TestRun_TargetsExpiresTriggersBump(t *testing.T) {
	_, rootPath, keyPath, repoDir := setupTestRepo(t)
	createInitialRepo(t, rootPath, keyPath, repoDir)

	newExpires := time.Now().UTC().Truncate(time.Second).AddDate(2, 0, 0)
	err := Run(&Options{
		RootPath:       rootPath,
		KeyPaths:       []string{keyPath},
		OutDir:         repoDir,
		MetadataURL:    metadataURL(repoDir),
		TargetsExpires: &newExpires,
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// Setting targets-expires should trigger targets version bump
	targetsMd := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := targetsMd.FromFile(filepath.Join(repoDir, "2.targets.json")); err != nil {
		t.Fatalf("failed to load 2.targets.json: %v", err)
	}
	if targetsMd.Signed.Version != 2 {
		t.Fatalf("expected targets version 2, got %d", targetsMd.Signed.Version)
	}
	if !targetsMd.Signed.Expires.Truncate(time.Second).Equal(newExpires) {
		t.Fatalf("targets expires mismatch: got %v, want %v", targetsMd.Signed.Expires, newExpires)
	}
}

func TestRun_UpdateExpires(t *testing.T) {
	_, rootPath, keyPath, repoDir := setupTestRepo(t)
	createInitialRepo(t, rootPath, keyPath, repoDir)

	inputDir := filepath.Join(t.TempDir(), "input")
	os.MkdirAll(inputDir, 0755)
	os.WriteFile(filepath.Join(inputDir, "new.txt"), []byte("new"), 0600)

	targetsExp := time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)
	snapshotExp := time.Date(2028, 2, 1, 0, 0, 0, 0, time.UTC)
	timestampExp := time.Date(2028, 3, 1, 0, 0, 0, 0, time.UTC)

	err := Run(&Options{
		RootPath:         rootPath,
		KeyPaths:         []string{keyPath},
		OutDir:           repoDir,
		MetadataURL:      metadataURL(repoDir),
		AddTargetsDir:    inputDir,
		TargetsExpires:   &targetsExp,
		SnapshotExpires:  &snapshotExp,
		TimestampExpires: &timestampExp,
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	targetsMd := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := targetsMd.FromFile(filepath.Join(repoDir, "2.targets.json")); err != nil {
		t.Fatalf("failed to load targets: %v", err)
	}
	if !targetsMd.Signed.Expires.Truncate(time.Second).Equal(targetsExp) {
		t.Fatalf("targets expires mismatch")
	}

	snapMd := &tufmeta.Metadata[tufmeta.SnapshotType]{}
	if _, err := snapMd.FromFile(filepath.Join(repoDir, "2.snapshot.json")); err != nil {
		t.Fatalf("failed to load snapshot: %v", err)
	}
	if !snapMd.Signed.Expires.Truncate(time.Second).Equal(snapshotExp) {
		t.Fatalf("snapshot expires mismatch")
	}

	tsMd := &tufmeta.Metadata[tufmeta.TimestampType]{}
	if _, err := tsMd.FromFile(filepath.Join(repoDir, "timestamp.json")); err != nil {
		t.Fatalf("failed to load timestamp: %v", err)
	}
	if !tsMd.Signed.Expires.Truncate(time.Second).Equal(timestampExp) {
		t.Fatalf("timestamp expires mismatch")
	}
}

func TestRun_ForceVersion(t *testing.T) {
	_, rootPath, keyPath, repoDir := setupTestRepo(t)
	createInitialRepo(t, rootPath, keyPath, repoDir)

	inputDir := filepath.Join(t.TempDir(), "input")
	os.MkdirAll(inputDir, 0755)
	os.WriteFile(filepath.Join(inputDir, "new.txt"), []byte("new"), 0600)

	tv := int64(10)
	sv := int64(20)
	tsv := int64(30)

	err := Run(&Options{
		RootPath:         rootPath,
		KeyPaths:         []string{keyPath},
		OutDir:           repoDir,
		MetadataURL:      metadataURL(repoDir),
		AddTargetsDir:    inputDir,
		ForceVersion:     true,
		TargetsVersion:   &tv,
		SnapshotVersion:  &sv,
		TimestampVersion: &tsv,
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	targetsMd := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := targetsMd.FromFile(filepath.Join(repoDir, "10.targets.json")); err != nil {
		t.Fatalf("failed to load 10.targets.json: %v", err)
	}
	if targetsMd.Signed.Version != 10 {
		t.Fatalf("expected targets version 10, got %d", targetsMd.Signed.Version)
	}

	snapMd := &tufmeta.Metadata[tufmeta.SnapshotType]{}
	if _, err := snapMd.FromFile(filepath.Join(repoDir, "20.snapshot.json")); err != nil {
		t.Fatalf("failed to load 20.snapshot.json: %v", err)
	}
	if snapMd.Signed.Version != 20 {
		t.Fatalf("expected snapshot version 20, got %d", snapMd.Signed.Version)
	}

	tsMd := &tufmeta.Metadata[tufmeta.TimestampType]{}
	if _, err := tsMd.FromFile(filepath.Join(repoDir, "timestamp.json")); err != nil {
		t.Fatalf("failed to load timestamp.json: %v", err)
	}
	if tsMd.Signed.Version != 30 {
		t.Fatalf("expected timestamp version 30, got %d", tsMd.Signed.Version)
	}
}

func TestRun_AddNewTargets(t *testing.T) {
	_, rootPath, keyPath, repoDir := setupTestRepo(t)
	createInitialRepo(t, rootPath, keyPath, repoDir)

	inputDir := filepath.Join(t.TempDir(), "input")
	os.MkdirAll(inputDir, 0755)
	os.WriteFile(filepath.Join(inputDir, "3.txt"), []byte("3"), 0600)

	err := Run(&Options{
		RootPath:      rootPath,
		KeyPaths:      []string{keyPath},
		OutDir:        repoDir,
		MetadataURL:   metadataURL(repoDir),
		AddTargetsDir: inputDir,
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	targetsMd := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := targetsMd.FromFile(filepath.Join(repoDir, "2.targets.json")); err != nil {
		t.Fatalf("failed to load targets: %v", err)
	}

	// Should contain old targets plus new one
	if _, ok := targetsMd.Signed.Targets["1.txt"]; !ok {
		t.Fatal("1.txt not found in updated targets")
	}
	if _, ok := targetsMd.Signed.Targets["2.txt"]; !ok {
		t.Fatal("2.txt not found in updated targets")
	}
	if _, ok := targetsMd.Signed.Targets["3.txt"]; !ok {
		t.Fatal("3.txt not found in updated targets")
	}
}

func TestRun_UpdateExistingTarget(t *testing.T) {
	_, rootPath, keyPath, repoDir := setupTestRepo(t)
	createInitialRepo(t, rootPath, keyPath, repoDir)

	inputDir := filepath.Join(t.TempDir(), "input")
	os.MkdirAll(inputDir, 0755)
	os.WriteFile(filepath.Join(inputDir, "1.txt"), []byte("updated content"), 0600)

	err := Run(&Options{
		RootPath:         rootPath,
		KeyPaths:         []string{keyPath},
		OutDir:           repoDir,
		MetadataURL:      metadataURL(repoDir),
		AddTargetsDir:    inputDir,
		TargetPathExists: "replace",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	targetsMd := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := targetsMd.FromFile(filepath.Join(repoDir, "2.targets.json")); err != nil {
		t.Fatalf("failed to load targets: %v", err)
	}

	tf, ok := targetsMd.Signed.Targets["1.txt"]
	if !ok {
		t.Fatal("1.txt not found in updated targets")
	}
	if tf.Length != int64(len("updated content")) {
		t.Fatalf("expected updated length %d, got %d", len("updated content"), tf.Length)
	}
}

func TestRun_MetadataChainConsistency(t *testing.T) {
	_, rootPath, keyPath, repoDir := setupTestRepo(t)
	createInitialRepo(t, rootPath, keyPath, repoDir)

	inputDir := filepath.Join(t.TempDir(), "input")
	os.MkdirAll(inputDir, 0755)
	os.WriteFile(filepath.Join(inputDir, "new.txt"), []byte("new"), 0600)

	err := Run(&Options{
		RootPath:      rootPath,
		KeyPaths:      []string{keyPath},
		OutDir:        repoDir,
		MetadataURL:   metadataURL(repoDir),
		AddTargetsDir: inputDir,
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	snapMd := &tufmeta.Metadata[tufmeta.SnapshotType]{}
	if _, err := snapMd.FromFile(filepath.Join(repoDir, "2.snapshot.json")); err != nil {
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
	if _, err := tsMd.FromFile(filepath.Join(repoDir, "timestamp.json")); err != nil {
		t.Fatalf("failed to load timestamp: %v", err)
	}
	snapMeta, ok := tsMd.Signed.Meta["snapshot.json"]
	if !ok {
		t.Fatal("timestamp does not reference snapshot.json")
	}
	if snapMeta.Version != 2 {
		t.Fatalf("timestamp references snapshot version %d, want 2", snapMeta.Version)
	}
}

func TestRun_MultipleUpdatesInSequence(t *testing.T) {
	_, rootPath, keyPath, repoDir := setupTestRepo(t)
	createInitialRepo(t, rootPath, keyPath, repoDir)

	for i := 0; i < 3; i++ {
		inputDir := filepath.Join(t.TempDir(), "input")
		os.MkdirAll(inputDir, 0755)
		os.WriteFile(filepath.Join(inputDir, "new.txt"), []byte("data"), 0600)

		err := Run(&Options{
			RootPath:      rootPath,
			KeyPaths:      []string{keyPath},
			OutDir:        repoDir,
			MetadataURL:   metadataURL(repoDir),
			AddTargetsDir: inputDir,
		})
		if err != nil {
			t.Fatalf("Run iteration %d failed: %v", i, err)
		}
	}

	// After 3 updates, versions should be 4 (1 initial + 3 bumps)
	tsMd := &tufmeta.Metadata[tufmeta.TimestampType]{}
	if _, err := tsMd.FromFile(filepath.Join(repoDir, "timestamp.json")); err != nil {
		t.Fatalf("failed to load timestamp.json: %v", err)
	}
	if tsMd.Signed.Version != 4 {
		t.Fatalf("expected timestamp version 4, got %d", tsMd.Signed.Version)
	}
}

func TestRun_PreservesExpiresWhenNotSet(t *testing.T) {
	_, rootPath, keyPath, repoDir := setupTestRepo(t)
	createInitialRepo(t, rootPath, keyPath, repoDir)

	// Read original expires
	origTargets := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := origTargets.FromFile(filepath.Join(repoDir, "1.targets.json")); err != nil {
		t.Fatalf("failed to load original targets: %v", err)
	}
	origExpires := origTargets.Signed.Expires

	inputDir := filepath.Join(t.TempDir(), "input")
	os.MkdirAll(inputDir, 0755)
	os.WriteFile(filepath.Join(inputDir, "new.txt"), []byte("new"), 0600)

	// Update without setting targets-expires
	err := Run(&Options{
		RootPath:      rootPath,
		KeyPaths:      []string{keyPath},
		OutDir:        repoDir,
		MetadataURL:   metadataURL(repoDir),
		AddTargetsDir: inputDir,
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	updatedTargets := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := updatedTargets.FromFile(filepath.Join(repoDir, "2.targets.json")); err != nil {
		t.Fatalf("failed to load updated targets: %v", err)
	}

	if !updatedTargets.Signed.Expires.Truncate(time.Second).Equal(origExpires.Truncate(time.Second)) {
		t.Fatalf("targets expires changed when not set: got %v, want %v",
			updatedTargets.Signed.Expires, origExpires)
	}
}
