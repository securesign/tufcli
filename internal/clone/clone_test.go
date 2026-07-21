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

package clone

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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

func buildTestRepo(dir string) error {
	return buildTestRepoWithExpiry(dir, time.Now().UTC().Truncate(time.Second).AddDate(1, 0, 0))
}

func buildTestRepoExpired(dir string) error {
	return buildTestRepoWithExpiry(dir, time.Now().UTC().Truncate(time.Second).AddDate(0, 0, -1))
}

func buildTestRepoWithExpiry(dir string, expires time.Time) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	key, err := tufmeta.KeyFromPublicKey(pub)
	if err != nil {
		return fmt.Errorf("failed to create TUF key: %w", err)
	}
	keyID, err := key.ID()
	if err != nil {
		return fmt.Errorf("failed to get key ID: %w", err)
	}

	signer, err := signature.LoadED25519Signer(priv)
	if err != nil {
		return fmt.Errorf("failed to create signer: %w", err)
	}

	targetsDir := filepath.Join(dir, "targets")
	if err := os.MkdirAll(targetsDir, 0755); err != nil {
		return err
	}
	targetContent := []byte("hello world\n")
	targetHash := sha256.Sum256(targetContent)
	targetHashHex := hex.EncodeToString(targetHash[:])
	hashPrefixedName := targetHashHex + ".test-artifact.txt"
	if err := os.WriteFile(filepath.Join(targetsDir, hashPrefixedName), targetContent, 0600); err != nil {
		return err
	}

	root := tufmeta.Root(expires)
	root.Signed.ConsistentSnapshot = true
	root.Signed.Version = 1
	root.Signed.Keys[keyID] = key
	for _, role := range []string{"root", "snapshot", "targets", "timestamp"} {
		root.Signed.Roles[role] = &tufmeta.Role{
			KeyIDs:    []string{keyID},
			Threshold: 1,
		}
	}
	if _, err := root.Sign(signer); err != nil {
		return fmt.Errorf("failed to sign root: %w", err)
	}

	targets := tufmeta.Targets(expires)
	targets.Signed.Version = 1
	tf := &tufmeta.TargetFiles{
		Length: int64(len(targetContent)),
		Hashes: tufmeta.Hashes{"sha256": targetHash[:]},
		Path:   "test-artifact.txt",
	}
	targets.Signed.Targets["test-artifact.txt"] = tf
	if _, err := targets.Sign(signer); err != nil {
		return fmt.Errorf("failed to sign targets: %w", err)
	}
	targetsBytes, err := targets.ToBytes(true)
	if err != nil {
		return fmt.Errorf("failed to serialize targets: %w", err)
	}

	targetsFileHash := sha256.Sum256(targetsBytes)
	snapshot := tufmeta.Snapshot(expires)
	snapshot.Signed.Version = 1
	snapshot.Signed.Meta["targets.json"] = &tufmeta.MetaFiles{
		Version: 1,
		Length:  int64(len(targetsBytes)),
		Hashes:  tufmeta.Hashes{"sha256": targetsFileHash[:]},
	}
	if _, err := snapshot.Sign(signer); err != nil {
		return fmt.Errorf("failed to sign snapshot: %w", err)
	}
	snapshotBytes, err := snapshot.ToBytes(true)
	if err != nil {
		return fmt.Errorf("failed to serialize snapshot: %w", err)
	}

	snapshotFileHash := sha256.Sum256(snapshotBytes)
	timestamp := tufmeta.Timestamp(expires)
	timestamp.Signed.Version = 1
	timestamp.Signed.Meta["snapshot.json"] = &tufmeta.MetaFiles{
		Version: 1,
		Length:  int64(len(snapshotBytes)),
		Hashes:  tufmeta.Hashes{"sha256": snapshotFileHash[:]},
	}
	if _, err := timestamp.Sign(signer); err != nil {
		return fmt.Errorf("failed to sign timestamp: %w", err)
	}
	timestampBytes, err := timestamp.ToBytes(true)
	if err != nil {
		return fmt.Errorf("failed to serialize timestamp: %w", err)
	}

	rootBytes, err := root.ToBytes(true)
	if err != nil {
		return fmt.Errorf("failed to serialize root: %w", err)
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
			return fmt.Errorf("failed to write %s: %w", name, err)
		}
	}

	return nil
}

func TestRun_FullClone(t *testing.T) {
	repoDir := t.TempDir()
	if err := buildTestRepo(repoDir); err != nil {
		t.Fatalf("failed to build test repo: %v", err)
	}

	srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
	defer srv.Close()

	metadataDir := filepath.Join(t.TempDir(), "metadata")
	targetsDir := filepath.Join(t.TempDir(), "targets")

	opts := &Options{
		Root:        filepath.Join(repoDir, "root.json"),
		MetadataURL: srv.URL,
		TargetsURL:  srv.URL + "/targets",
		MetadataDir: metadataDir,
		TargetsDir:  targetsDir,
	}
	if err := Run(opts); err != nil {
		t.Fatalf("clone failed: %v", err)
	}

	// Check metadata files
	for _, name := range []string{"root.json", "1.root.json", "timestamp.json", "1.snapshot.json", "1.targets.json"} {
		if _, err := os.Stat(filepath.Join(metadataDir, name)); err != nil {
			t.Fatalf("expected metadata file %s: %v", name, err)
		}
	}

	// Check target file
	data, err := os.ReadFile(filepath.Join(targetsDir, "test-artifact.txt"))
	if err != nil {
		t.Fatalf("target file not found: %v", err)
	}
	if string(data) != "hello world\n" {
		t.Fatalf("unexpected target content: %q", string(data))
	}
}

func TestRun_MetadataOnly(t *testing.T) {
	repoDir := t.TempDir()
	if err := buildTestRepo(repoDir); err != nil {
		t.Fatalf("failed to build test repo: %v", err)
	}

	srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
	defer srv.Close()

	metadataDir := filepath.Join(t.TempDir(), "metadata")

	opts := &Options{
		Root:         filepath.Join(repoDir, "root.json"),
		MetadataURL:  srv.URL,
		MetadataDir:  metadataDir,
		MetadataOnly: true,
	}
	if err := Run(opts); err != nil {
		t.Fatalf("clone metadata-only failed: %v", err)
	}

	for _, name := range []string{"root.json", "1.root.json", "timestamp.json", "1.snapshot.json", "1.targets.json"} {
		if _, err := os.Stat(filepath.Join(metadataDir, name)); err != nil {
			t.Fatalf("expected metadata file %s: %v", name, err)
		}
	}
}

func TestRun_SpecificTargets(t *testing.T) {
	repoDir := t.TempDir()
	if err := buildTestRepo(repoDir); err != nil {
		t.Fatalf("failed to build test repo: %v", err)
	}

	srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
	defer srv.Close()

	metadataDir := filepath.Join(t.TempDir(), "metadata")
	targetsDir := filepath.Join(t.TempDir(), "targets")

	opts := &Options{
		Root:        filepath.Join(repoDir, "root.json"),
		MetadataURL: srv.URL,
		TargetsURL:  srv.URL + "/targets",
		MetadataDir: metadataDir,
		TargetsDir:  targetsDir,
		TargetNames: []string{"test-artifact.txt"},
	}
	if err := Run(opts); err != nil {
		t.Fatalf("clone with specific targets failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(targetsDir, "test-artifact.txt")); err != nil {
		t.Fatalf("specific target not downloaded: %v", err)
	}
}

func TestRun_TargetNotFound(t *testing.T) {
	repoDir := t.TempDir()
	if err := buildTestRepo(repoDir); err != nil {
		t.Fatalf("failed to build test repo: %v", err)
	}

	srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
	defer srv.Close()

	metadataDir := filepath.Join(t.TempDir(), "metadata")
	targetsDir := filepath.Join(t.TempDir(), "targets")

	opts := &Options{
		Root:        filepath.Join(repoDir, "root.json"),
		MetadataURL: srv.URL,
		TargetsURL:  srv.URL + "/targets",
		MetadataDir: metadataDir,
		TargetsDir:  targetsDir,
		TargetNames: []string{"nonexistent.txt"},
	}
	if err := Run(opts); err == nil {
		t.Fatal("expected error for nonexistent target")
	}
}

func TestRun_NoRoot(t *testing.T) {
	opts := &Options{
		MetadataURL: "http://example.com",
		MetadataDir: t.TempDir(),
	}
	err := Run(opts)
	if err == nil {
		t.Fatal("expected error when no root provided")
	}
	if err.Error() != "no root.json available; provide --root or use --allow-root-download" {
		t.Fatalf("unexpected error: %s", err)
	}
}

func TestRun_AllowRootDownload(t *testing.T) {
	repoDir := t.TempDir()
	if err := buildTestRepo(repoDir); err != nil {
		t.Fatalf("failed to build test repo: %v", err)
	}

	srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
	defer srv.Close()

	metadataDir := filepath.Join(t.TempDir(), "metadata")
	targetsDir := filepath.Join(t.TempDir(), "targets")

	opts := &Options{
		MetadataURL:       srv.URL,
		TargetsURL:        srv.URL + "/targets",
		MetadataDir:       metadataDir,
		TargetsDir:        targetsDir,
		RootVersion:       1,
		AllowRootDownload: true,
	}
	if err := Run(opts); err != nil {
		t.Fatalf("clone with root download failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(targetsDir, "test-artifact.txt")); err != nil {
		t.Fatalf("target not downloaded: %v", err)
	}
}

func TestRun_AllowExpiredRepo(t *testing.T) {
	repoDir := t.TempDir()
	if err := buildTestRepoExpired(repoDir); err != nil {
		t.Fatalf("failed to build expired test repo: %v", err)
	}

	srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
	defer srv.Close()

	rootPath := filepath.Join(repoDir, "root.json")

	// Should fail without --allow-expired-repo
	metadataDir := filepath.Join(t.TempDir(), "no-expired")
	opts := &Options{
		Root:         rootPath,
		MetadataURL:  srv.URL,
		TargetsURL:   srv.URL + "/targets",
		MetadataDir:  metadataDir,
		TargetsDir:   filepath.Join(t.TempDir(), "targets1"),
		MetadataOnly: true,
	}
	if err := Run(opts); err == nil {
		t.Fatal("expected error for expired repo without --allow-expired-repo")
	}

	// Should succeed with --allow-expired-repo
	metadataDir = filepath.Join(t.TempDir(), "with-expired")
	opts = &Options{
		Root:             rootPath,
		MetadataURL:      srv.URL,
		MetadataDir:      metadataDir,
		MetadataOnly:     true,
		AllowExpiredRepo: true,
	}
	if err := Run(opts); err != nil {
		t.Fatalf("clone with --allow-expired-repo failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(metadataDir, "root.json")); err != nil {
		t.Fatalf("metadata not cloned: %v", err)
	}
}

func TestRun_FileURL(t *testing.T) {
	repoDir := t.TempDir()
	if err := buildTestRepo(repoDir); err != nil {
		t.Fatalf("failed to build test repo: %v", err)
	}

	metadataDir := filepath.Join(t.TempDir(), "metadata")
	targetsDir := filepath.Join(t.TempDir(), "targets")

	opts := &Options{
		Root:        filepath.Join(repoDir, "root.json"),
		MetadataURL: "file://" + repoDir,
		TargetsURL:  "file://" + repoDir + "/targets",
		MetadataDir: metadataDir,
		TargetsDir:  targetsDir,
	}
	if err := Run(opts); err != nil {
		t.Fatalf("clone with file:// URL failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(targetsDir, "test-artifact.txt"))
	if err != nil {
		t.Fatalf("target file not found: %v", err)
	}
	if string(data) != "hello world\n" {
		t.Fatalf("unexpected target content: %q", string(data))
	}
}

func TestRun_MetadataVersionedFiles(t *testing.T) {
	repoDir := t.TempDir()
	if err := buildTestRepo(repoDir); err != nil {
		t.Fatalf("failed to build test repo: %v", err)
	}

	srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
	defer srv.Close()

	metadataDir := filepath.Join(t.TempDir(), "metadata")

	opts := &Options{
		Root:         filepath.Join(repoDir, "root.json"),
		MetadataURL:  srv.URL,
		MetadataDir:  metadataDir,
		MetadataOnly: true,
	}
	if err := Run(opts); err != nil {
		t.Fatalf("clone failed: %v", err)
	}

	// Verify root.json is parseable and has correct version
	rootMd := &tufmeta.Metadata[tufmeta.RootType]{}
	if _, err := rootMd.FromFile(filepath.Join(metadataDir, "root.json")); err != nil {
		t.Fatalf("failed to parse cloned root.json: %v", err)
	}
	if rootMd.Signed.Version != 1 {
		t.Fatalf("expected root version 1, got %d", rootMd.Signed.Version)
	}

	// Verify versioned root is also parseable
	versionedRootMd := &tufmeta.Metadata[tufmeta.RootType]{}
	if _, err := versionedRootMd.FromFile(filepath.Join(metadataDir, "1.root.json")); err != nil {
		t.Fatalf("failed to parse 1.root.json: %v", err)
	}
	if versionedRootMd.Signed.Version != 1 {
		t.Fatalf("expected versioned root version 1, got %d", versionedRootMd.Signed.Version)
	}

	// Verify versioned targets is parseable and has correct version
	targetsMd := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := targetsMd.FromFile(filepath.Join(metadataDir, "1.targets.json")); err != nil {
		t.Fatalf("failed to parse cloned targets.json: %v", err)
	}
	if targetsMd.Signed.Version != 1 {
		t.Fatalf("expected targets version 1, got %d", targetsMd.Signed.Version)
	}
}

func TestValidateTargetPath(t *testing.T) {
	outDir := "/tmp/test-outdir"

	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{"normal", "/tmp/test-outdir/file.txt", false},
		{"nested", "/tmp/test-outdir/sub/file.txt", false},
		{"traversal", "/tmp/test-outdir/../etc/passwd", true},
		{"absolute escape", "/etc/passwd", true},
		{"equals outdir", "/tmp/test-outdir", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTargetPath(outDir, tc.target)
			if tc.wantErr && err == nil {
				t.Error("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
