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

package transfer

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"
)

type testKeys struct {
	pub    ed25519.PublicKey
	priv   ed25519.PrivateKey
	signer signature.Signer
	key    *tufmeta.Key
	keyID  string
}

func generateTestKeys(t *testing.T) *testKeys {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	signer, err := signature.LoadED25519Signer(priv)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	key, err := tufmeta.KeyFromPublicKey(pub)
	if err != nil {
		t.Fatalf("failed to create TUF key: %v", err)
	}
	keyID, err := key.ID()
	if err != nil {
		t.Fatalf("failed to get key ID: %v", err)
	}
	return &testKeys{pub: pub, priv: priv, signer: signer, key: key, keyID: keyID}
}

func writeKeyFile(t *testing.T, dir string, priv ed25519.PrivateKey) string {
	t.Helper()
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyPath, pemBlock, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}
	return keyPath
}

func buildTestRepo(t *testing.T, dir string, keys *testKeys, expires time.Time) {
	t.Helper()

	targetsDir := filepath.Join(dir, "targets")
	if err := os.MkdirAll(targetsDir, 0755); err != nil {
		t.Fatal(err)
	}
	targetContent := []byte("hello world\n")
	targetHash := sha256.Sum256(targetContent)
	targetHashHex := hex.EncodeToString(targetHash[:])
	hashPrefixedName := targetHashHex + ".test-artifact.txt"
	if err := os.WriteFile(filepath.Join(targetsDir, hashPrefixedName), targetContent, 0600); err != nil {
		t.Fatal(err)
	}

	root := tufmeta.Root(expires)
	root.Signed.ConsistentSnapshot = true
	root.Signed.Version = 1
	root.Signed.Keys[keys.keyID] = keys.key
	for _, role := range []string{"root", "snapshot", "targets", "timestamp"} {
		root.Signed.Roles[role] = &tufmeta.Role{
			KeyIDs:    []string{keys.keyID},
			Threshold: 1,
		}
	}
	if _, err := root.Sign(keys.signer); err != nil {
		t.Fatal(err)
	}

	targets := tufmeta.Targets(expires)
	targets.Signed.Version = 1
	tf := &tufmeta.TargetFiles{
		Length: int64(len(targetContent)),
		Hashes: tufmeta.Hashes{"sha256": targetHash[:]},
		Path:   "test-artifact.txt",
	}
	targets.Signed.Targets["test-artifact.txt"] = tf
	if _, err := targets.Sign(keys.signer); err != nil {
		t.Fatal(err)
	}
	targetsBytes, err := targets.ToBytes(true)
	if err != nil {
		t.Fatal(err)
	}

	targetsFileHash := sha256.Sum256(targetsBytes)
	snapshot := tufmeta.Snapshot(expires)
	snapshot.Signed.Version = 1
	snapshot.Signed.Meta["targets.json"] = &tufmeta.MetaFiles{
		Version: 1,
		Length:  int64(len(targetsBytes)),
		Hashes:  tufmeta.Hashes{"sha256": targetsFileHash[:]},
	}
	if _, err := snapshot.Sign(keys.signer); err != nil {
		t.Fatal(err)
	}
	snapshotBytes, err := snapshot.ToBytes(true)
	if err != nil {
		t.Fatal(err)
	}

	snapshotFileHash := sha256.Sum256(snapshotBytes)
	timestamp := tufmeta.Timestamp(expires)
	timestamp.Signed.Version = 1
	timestamp.Signed.Meta["snapshot.json"] = &tufmeta.MetaFiles{
		Version: 1,
		Length:  int64(len(snapshotBytes)),
		Hashes:  tufmeta.Hashes{"sha256": snapshotFileHash[:]},
	}
	if _, err := timestamp.Sign(keys.signer); err != nil {
		t.Fatal(err)
	}
	timestampBytes, err := timestamp.ToBytes(true)
	if err != nil {
		t.Fatal(err)
	}

	rootBytes, err := root.ToBytes(true)
	if err != nil {
		t.Fatal(err)
	}

	files := map[string][]byte{
		"root.json":       rootBytes,
		"1.root.json":     rootBytes,
		"timestamp.json":  timestampBytes,
		"1.snapshot.json": snapshotBytes,
		"1.targets.json":  targetsBytes,
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatalf("failed to write %s: %v", name, err)
		}
	}
}

func writeRootJSON(t *testing.T, dir string, keys *testKeys, expires time.Time) string {
	t.Helper()
	root := tufmeta.Root(expires)
	root.Signed.ConsistentSnapshot = true
	root.Signed.Version = 1
	root.Signed.Keys[keys.keyID] = keys.key
	for _, role := range []string{"root", "snapshot", "targets", "timestamp"} {
		root.Signed.Roles[role] = &tufmeta.Role{
			KeyIDs:    []string{keys.keyID},
			Threshold: 1,
		}
	}
	if _, err := root.Sign(keys.signer); err != nil {
		t.Fatal(err)
	}
	rootBytes, err := root.ToBytes(true)
	if err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(dir, "root.json")
	if err := os.WriteFile(rootPath, rootBytes, 0600); err != nil {
		t.Fatal(err)
	}
	return rootPath
}

func TestValidateAndSetDefaults_MissingCurrentRoot(t *testing.T) {
	opts := &Options{
		CurrentRoot:      "/nonexistent/root.json",
		NewRoot:          "/nonexistent/new-root.json",
		TargetsVersion:   1,
		SnapshotVersion:  1,
		TimestampVersion: 1,
		TargetsExpires:   time.Now().Add(24 * time.Hour),
		SnapshotExpires:  time.Now().Add(24 * time.Hour),
		TimestampExpires: time.Now().Add(24 * time.Hour),
	}
	err := opts.ValidateAndSetDefaults()
	if err == nil {
		t.Fatal("expected error for missing current root")
	}
	if err.Error() != "current root.json not found at /nonexistent/root.json" {
		t.Fatalf("unexpected error: %s", err)
	}
}

func TestValidateAndSetDefaults_InvalidVersions(t *testing.T) {
	tmpDir := t.TempDir()
	currentRoot := filepath.Join(tmpDir, "current-root.json")
	newRoot := filepath.Join(tmpDir, "new-root.json")
	os.WriteFile(currentRoot, []byte("{}"), 0600)
	os.WriteFile(newRoot, []byte("{}"), 0600)

	tests := []struct {
		name    string
		targets int64
		snap    int64
		ts      int64
		wantErr string
	}{
		{"zero targets", 0, 1, 1, "targets-version must be > 0"},
		{"negative snapshot", 1, -1, 1, "snapshot-version must be > 0"},
		{"zero timestamp", 1, 1, 0, "timestamp-version must be > 0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := &Options{
				CurrentRoot:      currentRoot,
				NewRoot:          newRoot,
				TargetsVersion:   tc.targets,
				SnapshotVersion:  tc.snap,
				TimestampVersion: tc.ts,
				TargetsExpires:   time.Now().Add(24 * time.Hour),
				SnapshotExpires:  time.Now().Add(24 * time.Hour),
				TimestampExpires: time.Now().Add(24 * time.Hour),
			}
			err := opts.ValidateAndSetDefaults()
			if err == nil {
				t.Fatal("expected error")
			}
			if err.Error() != tc.wantErr {
				t.Fatalf("expected %q, got %q", tc.wantErr, err.Error())
			}
		})
	}
}

func TestValidateAndSetDefaults_MissingExpires(t *testing.T) {
	tmpDir := t.TempDir()
	currentRoot := filepath.Join(tmpDir, "current-root.json")
	newRoot := filepath.Join(tmpDir, "new-root.json")
	os.WriteFile(currentRoot, []byte("{}"), 0600)
	os.WriteFile(newRoot, []byte("{}"), 0600)

	opts := &Options{
		CurrentRoot:      currentRoot,
		NewRoot:          newRoot,
		TargetsVersion:   1,
		SnapshotVersion:  1,
		TimestampVersion: 1,
	}
	err := opts.ValidateAndSetDefaults()
	if err == nil {
		t.Fatal("expected error for missing expires")
	}
	if err.Error() != "targets-expires is required" {
		t.Fatalf("unexpected error: %s", err)
	}
}

func TestRun_FullTransfer(t *testing.T) {
	oldKeys := generateTestKeys(t)
	newKeys := generateTestKeys(t)

	repoDir := t.TempDir()
	buildTestRepo(t, repoDir, oldKeys, time.Now().AddDate(1, 0, 0))

	srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
	defer srv.Close()

	newRootDir := t.TempDir()
	newRootPath := writeRootJSON(t, newRootDir, newKeys, time.Now().AddDate(1, 0, 0))
	keyPath := writeKeyFile(t, newRootDir, newKeys.priv)

	outDir := filepath.Join(t.TempDir(), "transfer-out")
	expires := time.Now().UTC().Truncate(time.Second).AddDate(0, 6, 0)

	opts := &Options{
		CurrentRoot:      filepath.Join(repoDir, "root.json"),
		NewRoot:          newRootPath,
		KeyPaths:         []string{keyPath},
		MetadataURL:      srv.URL,
		TargetsURL:       srv.URL + "/targets",
		OutDir:           outDir,
		TargetsExpires:   expires,
		TargetsVersion:   1,
		SnapshotExpires:  expires,
		SnapshotVersion:  1,
		TimestampExpires: expires,
		TimestampVersion: 1,
	}

	if err := Run(opts); err != nil {
		t.Fatalf("transfer failed: %v", err)
	}

	// Verify output files exist
	for _, name := range []string{"root.json", "1.root.json", "1.targets.json", "1.snapshot.json", "timestamp.json"} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Fatalf("expected output file %s: %v", name, err)
		}
	}

	// Verify new root was written
	newRootMd := &tufmeta.Metadata[tufmeta.RootType]{}
	if _, err := newRootMd.FromFile(filepath.Join(outDir, "root.json")); err != nil {
		t.Fatalf("failed to parse output root.json: %v", err)
	}
	if newRootMd.Signed.Version != 1 {
		t.Fatalf("expected root version 1, got %d", newRootMd.Signed.Version)
	}

	// Verify targets contain the transferred entries
	targetsMd := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := targetsMd.FromFile(filepath.Join(outDir, "1.targets.json")); err != nil {
		t.Fatalf("failed to parse output targets.json: %v", err)
	}
	if _, ok := targetsMd.Signed.Targets["test-artifact.txt"]; !ok {
		t.Fatal("expected target entry test-artifact.txt to be transferred")
	}
	if targetsMd.Signed.Version != 1 {
		t.Fatalf("expected targets version 1, got %d", targetsMd.Signed.Version)
	}
}

func TestRun_TargetEntriesPreserved(t *testing.T) {
	oldKeys := generateTestKeys(t)
	newKeys := generateTestKeys(t)

	repoDir := t.TempDir()
	buildTestRepo(t, repoDir, oldKeys, time.Now().AddDate(1, 0, 0))

	srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
	defer srv.Close()

	newRootDir := t.TempDir()
	newRootPath := writeRootJSON(t, newRootDir, newKeys, time.Now().AddDate(1, 0, 0))
	keyPath := writeKeyFile(t, newRootDir, newKeys.priv)

	outDir := filepath.Join(t.TempDir(), "transfer-out")
	expires := time.Now().UTC().Truncate(time.Second).AddDate(0, 6, 0)

	opts := &Options{
		CurrentRoot:      filepath.Join(repoDir, "root.json"),
		NewRoot:          newRootPath,
		KeyPaths:         []string{keyPath},
		MetadataURL:      srv.URL,
		TargetsURL:       srv.URL + "/targets",
		OutDir:           outDir,
		TargetsExpires:   expires,
		TargetsVersion:   2,
		SnapshotExpires:  expires,
		SnapshotVersion:  3,
		TimestampExpires: expires,
		TimestampVersion: 4,
	}

	if err := Run(opts); err != nil {
		t.Fatalf("transfer failed: %v", err)
	}

	// Verify target entry has correct hash/length from original repo
	targetsMd := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := targetsMd.FromFile(filepath.Join(outDir, "2.targets.json")); err != nil {
		t.Fatalf("failed to parse output targets.json: %v", err)
	}

	tf, ok := targetsMd.Signed.Targets["test-artifact.txt"]
	if !ok {
		t.Fatal("target entry not found")
	}
	if tf.Length != int64(len("hello world\n")) {
		t.Fatalf("expected length %d, got %d", len("hello world\n"), tf.Length)
	}
	expectedHash := sha256.Sum256([]byte("hello world\n"))
	if hex.EncodeToString(tf.Hashes["sha256"]) != hex.EncodeToString(expectedHash[:]) {
		t.Fatal("target hash mismatch")
	}

	// Verify versions
	if targetsMd.Signed.Version != 2 {
		t.Fatalf("expected targets version 2, got %d", targetsMd.Signed.Version)
	}

	snapshotMd := &tufmeta.Metadata[tufmeta.SnapshotType]{}
	if _, err := snapshotMd.FromFile(filepath.Join(outDir, "3.snapshot.json")); err != nil {
		t.Fatalf("failed to parse output snapshot.json: %v", err)
	}
	if snapshotMd.Signed.Version != 3 {
		t.Fatalf("expected snapshot version 3, got %d", snapshotMd.Signed.Version)
	}

	timestampMd := &tufmeta.Metadata[tufmeta.TimestampType]{}
	if _, err := timestampMd.FromFile(filepath.Join(outDir, "timestamp.json")); err != nil {
		t.Fatalf("failed to parse output timestamp.json: %v", err)
	}
	if timestampMd.Signed.Version != 4 {
		t.Fatalf("expected timestamp version 4, got %d", timestampMd.Signed.Version)
	}
}

func TestRun_FileURL(t *testing.T) {
	oldKeys := generateTestKeys(t)
	newKeys := generateTestKeys(t)

	repoDir := t.TempDir()
	buildTestRepo(t, repoDir, oldKeys, time.Now().AddDate(1, 0, 0))

	newRootDir := t.TempDir()
	newRootPath := writeRootJSON(t, newRootDir, newKeys, time.Now().AddDate(1, 0, 0))
	keyPath := writeKeyFile(t, newRootDir, newKeys.priv)

	outDir := filepath.Join(t.TempDir(), "transfer-out")
	expires := time.Now().UTC().Truncate(time.Second).AddDate(0, 6, 0)

	opts := &Options{
		CurrentRoot:      filepath.Join(repoDir, "root.json"),
		NewRoot:          newRootPath,
		KeyPaths:         []string{keyPath},
		MetadataURL:      "file://" + repoDir,
		TargetsURL:       "file://" + repoDir + "/targets",
		OutDir:           outDir,
		TargetsExpires:   expires,
		TargetsVersion:   1,
		SnapshotExpires:  expires,
		SnapshotVersion:  1,
		TimestampExpires: expires,
		TimestampVersion: 1,
	}

	if err := Run(opts); err != nil {
		t.Fatalf("transfer with file:// URL failed: %v", err)
	}

	targetsMd := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := targetsMd.FromFile(filepath.Join(outDir, "1.targets.json")); err != nil {
		t.Fatalf("failed to parse targets.json: %v", err)
	}
	if _, ok := targetsMd.Signed.Targets["test-artifact.txt"]; !ok {
		t.Fatal("target entry not transferred")
	}
}

func TestRun_AllowExpiredRepo(t *testing.T) {
	oldKeys := generateTestKeys(t)
	newKeys := generateTestKeys(t)

	repoDir := t.TempDir()
	buildTestRepo(t, repoDir, oldKeys, time.Now().AddDate(0, 0, -1))

	srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
	defer srv.Close()

	newRootDir := t.TempDir()
	newRootPath := writeRootJSON(t, newRootDir, newKeys, time.Now().AddDate(1, 0, 0))
	keyPath := writeKeyFile(t, newRootDir, newKeys.priv)

	expires := time.Now().UTC().Truncate(time.Second).AddDate(0, 6, 0)

	// Should fail without --allow-expired-repo
	outDir1 := filepath.Join(t.TempDir(), "no-expired")
	opts := &Options{
		CurrentRoot:      filepath.Join(repoDir, "root.json"),
		NewRoot:          newRootPath,
		KeyPaths:         []string{keyPath},
		MetadataURL:      srv.URL,
		TargetsURL:       srv.URL + "/targets",
		OutDir:           outDir1,
		TargetsExpires:   expires,
		TargetsVersion:   1,
		SnapshotExpires:  expires,
		SnapshotVersion:  1,
		TimestampExpires: expires,
		TimestampVersion: 1,
	}
	if err := Run(opts); err == nil {
		t.Fatal("expected error for expired repo without --allow-expired-repo")
	}

	// Should succeed with --allow-expired-repo
	outDir2 := filepath.Join(t.TempDir(), "with-expired")
	opts.OutDir = outDir2
	opts.AllowExpiredRepo = true
	if err := Run(opts); err != nil {
		t.Fatalf("transfer with --allow-expired-repo failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(outDir2, "1.targets.json")); err != nil {
		t.Fatalf("targets.json not written: %v", err)
	}
}

func TestRun_WrongKey(t *testing.T) {
	oldKeys := generateTestKeys(t)
	newKeys := generateTestKeys(t)
	wrongKeys := generateTestKeys(t)

	repoDir := t.TempDir()
	buildTestRepo(t, repoDir, oldKeys, time.Now().AddDate(1, 0, 0))

	srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
	defer srv.Close()

	newRootDir := t.TempDir()
	newRootPath := writeRootJSON(t, newRootDir, newKeys, time.Now().AddDate(1, 0, 0))
	wrongKeyPath := writeKeyFile(t, t.TempDir(), wrongKeys.priv)

	outDir := filepath.Join(t.TempDir(), "transfer-out")
	expires := time.Now().UTC().Truncate(time.Second).AddDate(0, 6, 0)

	opts := &Options{
		CurrentRoot:      filepath.Join(repoDir, "root.json"),
		NewRoot:          newRootPath,
		KeyPaths:         []string{wrongKeyPath},
		MetadataURL:      srv.URL,
		TargetsURL:       srv.URL + "/targets",
		OutDir:           outDir,
		TargetsExpires:   expires,
		TargetsVersion:   1,
		SnapshotExpires:  expires,
		SnapshotVersion:  1,
		TimestampExpires: expires,
		TimestampVersion: 1,
	}

	err := Run(opts)
	if err == nil {
		t.Fatal("expected error when key doesn't match new root")
	}

	expected := fmt.Sprintf("none of the provided keys match role targets in new root.json (expected key IDs: [%s])", newKeys.keyID)
	if err.Error() != fmt.Sprintf("failed to find signers for targets role: %s", expected) {
		t.Fatalf("unexpected error: %s", err)
	}
}

func TestRun_NoTargetsInOldRepo(t *testing.T) {
	oldKeys := generateTestKeys(t)
	newKeys := generateTestKeys(t)

	repoDir := t.TempDir()

	// Build a repo without any target entries
	expires := time.Now().AddDate(1, 0, 0)
	root := tufmeta.Root(expires)
	root.Signed.ConsistentSnapshot = true
	root.Signed.Version = 1
	root.Signed.Keys[oldKeys.keyID] = oldKeys.key
	for _, role := range []string{"root", "snapshot", "targets", "timestamp"} {
		root.Signed.Roles[role] = &tufmeta.Role{
			KeyIDs:    []string{oldKeys.keyID},
			Threshold: 1,
		}
	}
	root.Sign(oldKeys.signer)

	targets := tufmeta.Targets(expires)
	targets.Signed.Version = 1
	targets.Sign(oldKeys.signer)
	targetsBytes, _ := targets.ToBytes(true)

	targetsFileHash := sha256.Sum256(targetsBytes)
	snapshot := tufmeta.Snapshot(expires)
	snapshot.Signed.Version = 1
	snapshot.Signed.Meta["targets.json"] = &tufmeta.MetaFiles{
		Version: 1,
		Length:  int64(len(targetsBytes)),
		Hashes:  tufmeta.Hashes{"sha256": targetsFileHash[:]},
	}
	snapshot.Sign(oldKeys.signer)
	snapshotBytes, _ := snapshot.ToBytes(true)

	snapshotFileHash := sha256.Sum256(snapshotBytes)
	timestamp := tufmeta.Timestamp(expires)
	timestamp.Signed.Version = 1
	timestamp.Signed.Meta["snapshot.json"] = &tufmeta.MetaFiles{
		Version: 1,
		Length:  int64(len(snapshotBytes)),
		Hashes:  tufmeta.Hashes{"sha256": snapshotFileHash[:]},
	}
	timestamp.Sign(oldKeys.signer)
	timestampBytes, _ := timestamp.ToBytes(true)

	rootBytes, _ := root.ToBytes(true)
	files := map[string][]byte{
		"root.json":       rootBytes,
		"1.root.json":     rootBytes,
		"timestamp.json":  timestampBytes,
		"1.snapshot.json": snapshotBytes,
		"1.targets.json":  targetsBytes,
	}
	for name, data := range files {
		os.WriteFile(filepath.Join(repoDir, name), data, 0600)
	}

	srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
	defer srv.Close()

	newRootDir := t.TempDir()
	newRootPath := writeRootJSON(t, newRootDir, newKeys, time.Now().AddDate(1, 0, 0))
	keyPath := writeKeyFile(t, newRootDir, newKeys.priv)

	outDir := filepath.Join(t.TempDir(), "transfer-out")
	expiresOpt := time.Now().UTC().Truncate(time.Second).AddDate(0, 6, 0)

	opts := &Options{
		CurrentRoot:      filepath.Join(repoDir, "root.json"),
		NewRoot:          newRootPath,
		KeyPaths:         []string{keyPath},
		MetadataURL:      srv.URL,
		TargetsURL:       srv.URL + "/targets",
		OutDir:           outDir,
		TargetsExpires:   expiresOpt,
		TargetsVersion:   1,
		SnapshotExpires:  expiresOpt,
		SnapshotVersion:  1,
		TimestampExpires: expiresOpt,
		TimestampVersion: 1,
	}

	if err := Run(opts); err != nil {
		t.Fatalf("transfer with empty targets should succeed: %v", err)
	}

	targetsMd := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := targetsMd.FromFile(filepath.Join(outDir, "1.targets.json")); err != nil {
		t.Fatalf("failed to parse targets.json: %v", err)
	}
	if len(targetsMd.Signed.Targets) != 0 {
		t.Fatalf("expected 0 targets, got %d", len(targetsMd.Signed.Targets))
	}
}

func TestRun_ExpirationSet(t *testing.T) {
	oldKeys := generateTestKeys(t)
	newKeys := generateTestKeys(t)

	repoDir := t.TempDir()
	buildTestRepo(t, repoDir, oldKeys, time.Now().AddDate(1, 0, 0))

	srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
	defer srv.Close()

	newRootDir := t.TempDir()
	newRootPath := writeRootJSON(t, newRootDir, newKeys, time.Now().AddDate(1, 0, 0))
	keyPath := writeKeyFile(t, newRootDir, newKeys.priv)

	outDir := filepath.Join(t.TempDir(), "transfer-out")

	targetsExpires := time.Now().UTC().Truncate(time.Second).AddDate(0, 3, 0)
	snapshotExpires := time.Now().UTC().Truncate(time.Second).AddDate(0, 2, 0)
	timestampExpires := time.Now().UTC().Truncate(time.Second).AddDate(0, 0, 7)

	opts := &Options{
		CurrentRoot:      filepath.Join(repoDir, "root.json"),
		NewRoot:          newRootPath,
		KeyPaths:         []string{keyPath},
		MetadataURL:      srv.URL,
		TargetsURL:       srv.URL + "/targets",
		OutDir:           outDir,
		TargetsExpires:   targetsExpires,
		TargetsVersion:   1,
		SnapshotExpires:  snapshotExpires,
		SnapshotVersion:  1,
		TimestampExpires: timestampExpires,
		TimestampVersion: 1,
	}

	if err := Run(opts); err != nil {
		t.Fatalf("transfer failed: %v", err)
	}

	targetsMd := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := targetsMd.FromFile(filepath.Join(outDir, "1.targets.json")); err != nil {
		t.Fatal(err)
	}
	if !targetsMd.Signed.Expires.Equal(targetsExpires) {
		t.Fatalf("targets expires: expected %v, got %v", targetsExpires, targetsMd.Signed.Expires)
	}

	snapshotMd := &tufmeta.Metadata[tufmeta.SnapshotType]{}
	if _, err := snapshotMd.FromFile(filepath.Join(outDir, "1.snapshot.json")); err != nil {
		t.Fatal(err)
	}
	if !snapshotMd.Signed.Expires.Equal(snapshotExpires) {
		t.Fatalf("snapshot expires: expected %v, got %v", snapshotExpires, snapshotMd.Signed.Expires)
	}

	timestampMd := &tufmeta.Metadata[tufmeta.TimestampType]{}
	if _, err := timestampMd.FromFile(filepath.Join(outDir, "timestamp.json")); err != nil {
		t.Fatal(err)
	}
	if !timestampMd.Signed.Expires.Equal(timestampExpires) {
		t.Fatalf("timestamp expires: expected %v, got %v", timestampExpires, timestampMd.Signed.Expires)
	}
}
