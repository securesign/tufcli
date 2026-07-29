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

package tufclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

func TestValidateTargetPath_Valid(t *testing.T) {
	dir := t.TempDir()
	targetPath := filepath.Join(dir, "subdir", "target.txt")

	err := ValidateTargetPath(dir, targetPath)
	if err != nil {
		t.Fatalf("unexpected error for valid path: %v", err)
	}
}

func TestValidateTargetPath_ValidNested(t *testing.T) {
	dir := t.TempDir()
	targetPath := filepath.Join(dir, "a", "b", "c", "target.txt")

	err := ValidateTargetPath(dir, targetPath)
	if err != nil {
		t.Fatalf("unexpected error for nested valid path: %v", err)
	}
}

func TestValidateTargetPath_DirectChild(t *testing.T) {
	dir := t.TempDir()
	targetPath := filepath.Join(dir, "target.txt")

	err := ValidateTargetPath(dir, targetPath)
	if err != nil {
		t.Fatalf("unexpected error for direct child: %v", err)
	}
}

func TestValidateTargetPath_Traversal(t *testing.T) {
	dir := t.TempDir()
	targetPath := filepath.Join(dir, "..", "escaped.txt")

	err := ValidateTargetPath(dir, targetPath)
	if err == nil {
		t.Fatal("expected error for path traversal")
	}
	if !strings.Contains(err.Error(), "escapes output directory") {
		t.Fatalf("error should mention escaping, got: %v", err)
	}
}

func TestValidateTargetPath_TraversalDeep(t *testing.T) {
	dir := t.TempDir()
	targetPath := filepath.Join(dir, "a", "..", "..", "escaped.txt")

	err := ValidateTargetPath(dir, targetPath)
	if err == nil {
		t.Fatal("expected error for deep path traversal")
	}
}

func TestValidateTargetPath_SameDir(t *testing.T) {
	dir := t.TempDir()
	// Passing outDir itself as the target path should fail (rel would be ".")
	err := ValidateTargetPath(dir, dir)
	if err == nil {
		t.Fatal("expected error when target path equals output directory")
	}
}

func TestValidateTargetPath_ParentDir(t *testing.T) {
	dir := t.TempDir()
	parentDir := filepath.Dir(dir)

	err := ValidateTargetPath(dir, parentDir)
	if err == nil {
		t.Fatal("expected error when target is parent of output directory")
	}
}

func buildTestRepo(dir string) error {
	expires := time.Now().UTC().Truncate(time.Second).AddDate(1, 0, 0)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	key, err := tufmeta.KeyFromPublicKey(pub)
	if err != nil {
		return err
	}
	keyID, _ := key.ID()
	signer, _ := signature.LoadED25519Signer(priv)

	targetsDir := filepath.Join(dir, "targets")
	os.MkdirAll(targetsDir, 0755)
	targetContent := []byte("test content")
	targetHash := sha256.Sum256(targetContent)
	hashHex := hex.EncodeToString(targetHash[:])
	os.WriteFile(filepath.Join(targetsDir, hashHex+".artifact.txt"), targetContent, 0600)

	root := tufmeta.Root(expires)
	root.Signed.ConsistentSnapshot = true
	root.Signed.Version = 1
	root.Signed.Keys[keyID] = key
	for _, role := range []string{"root", "snapshot", "targets", "timestamp"} {
		root.Signed.Roles[role] = &tufmeta.Role{KeyIDs: []string{keyID}, Threshold: 1}
	}
	root.Sign(signer)

	targets := tufmeta.Targets(expires)
	targets.Signed.Version = 1
	targets.Signed.Targets["artifact.txt"] = &tufmeta.TargetFiles{
		Length: int64(len(targetContent)),
		Hashes: tufmeta.Hashes{"sha256": targetHash[:]},
		Path:   "artifact.txt",
	}
	targets.Sign(signer)
	targetsBytes, _ := targets.ToBytes(true)

	targetsFileHash := sha256.Sum256(targetsBytes)
	snapshot := tufmeta.Snapshot(expires)
	snapshot.Signed.Version = 1
	snapshot.Signed.Meta["targets.json"] = &tufmeta.MetaFiles{
		Version: 1, Length: int64(len(targetsBytes)), Hashes: tufmeta.Hashes{"sha256": targetsFileHash[:]},
	}
	snapshot.Sign(signer)
	snapshotBytes, _ := snapshot.ToBytes(true)

	snapshotFileHash := sha256.Sum256(snapshotBytes)
	timestamp := tufmeta.Timestamp(expires)
	timestamp.Signed.Version = 1
	timestamp.Signed.Meta["snapshot.json"] = &tufmeta.MetaFiles{
		Version: 1, Length: int64(len(snapshotBytes)), Hashes: tufmeta.Hashes{"sha256": snapshotFileHash[:]},
	}
	timestamp.Sign(signer)
	timestampBytes, _ := timestamp.ToBytes(true)
	rootBytes, _ := root.ToBytes(true)

	for name, data := range map[string][]byte{
		"root.json": rootBytes, "1.root.json": rootBytes,
		"timestamp.json": timestampBytes, "1.snapshot.json": snapshotBytes, "1.targets.json": targetsBytes,
	} {
		os.WriteFile(filepath.Join(dir, name), data, 0600)
	}
	return nil
}

func setupUpdater(t *testing.T) (*updater.Updater, *httptest.Server) {
	t.Helper()
	repoDir := t.TempDir()
	if err := buildTestRepo(repoDir); err != nil {
		t.Fatalf("failed to build test repo: %v", err)
	}
	srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))

	rootBytes, _ := os.ReadFile(filepath.Join(repoDir, "root.json"))
	metaDir := t.TempDir()

	cfg, err := config.New(srv.URL, rootBytes)
	if err != nil {
		t.Fatalf("failed to create config: %v", err)
	}
	cfg.LocalMetadataDir = metaDir
	cfg.LocalTargetsDir = filepath.Join(metaDir, "targets")
	cfg.Fetcher = NewLocalFetcher(cfg.Fetcher)

	up, err := updater.New(cfg)
	if err != nil {
		t.Fatalf("failed to create updater: %v", err)
	}
	if err := up.Refresh(); err != nil {
		t.Fatalf("failed to refresh: %v", err)
	}
	return up, srv
}

func TestResolveTargets_AllTargets(t *testing.T) {
	up, srv := setupUpdater(t)
	defer srv.Close()

	targets, err := ResolveTargets(up, nil)
	if err != nil {
		t.Fatalf("ResolveTargets(nil) failed: %v", err)
	}
	if len(targets) == 0 {
		t.Fatal("expected at least one target")
	}
	if _, ok := targets["artifact.txt"]; !ok {
		t.Fatal("expected artifact.txt in targets")
	}
}

func TestResolveTargets_SpecificTarget(t *testing.T) {
	up, srv := setupUpdater(t)
	defer srv.Close()

	targets, err := ResolveTargets(up, []string{"artifact.txt"})
	if err != nil {
		t.Fatalf("ResolveTargets(artifact.txt) failed: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}
}

func TestResolveTargets_NotFound(t *testing.T) {
	up, srv := setupUpdater(t)
	defer srv.Close()

	_, err := ResolveTargets(up, []string{"nonexistent.txt"})
	if err == nil {
		t.Fatal("expected error for nonexistent target")
	}
}
