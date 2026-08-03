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

package editor

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

func setupTestRoot(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	rootPath := filepath.Join(dir, "root.json")

	if err := root.Init(root.InitOptions{Path: rootPath, Version: 1}); err != nil {
		t.Fatalf("failed to init root: %v", err)
	}
	if _, err := root.AddKey(root.AddKeyOptions{
		Path: rootPath, KeyPaths: []string{keyPath},
		Roles: []string{"root", "targets", "snapshot", "timestamp"},
	}); err != nil {
		t.Fatalf("failed to add key: %v", err)
	}

	md := &tufmeta.Metadata[tufmeta.RootType]{}
	if _, err := md.FromFile(rootPath); err != nil {
		t.Fatalf("failed to load root: %v", err)
	}
	for role := range md.Signed.Roles {
		md.Signed.Roles[role].Threshold = 1
	}
	md.ClearSignatures()
	data, err := md.ToBytes(true)
	if err != nil {
		t.Fatalf("failed to serialize root: %v", err)
	}
	if err := utils.WriteFileAtomic(rootPath, data); err != nil {
		t.Fatalf("failed to write root: %v", err)
	}

	return rootPath, keyPath
}

func TestLoadRepository_NoRoot(t *testing.T) {
	_, err := LoadRepository(LoadOptions{RootPath: "/nonexistent/root.json", OutDir: t.TempDir()})
	if err == nil {
		t.Fatal("expected error for missing root.json")
	}
}

func TestLoadRepository_EmptyRepo(t *testing.T) {
	rootPath, _ := setupTestRoot(t)
	outDir := t.TempDir()

	ed, err := LoadRepository(LoadOptions{RootPath: rootPath, OutDir: outDir})
	if err != nil {
		t.Fatalf("LoadRepository failed: %v", err)
	}
	if ed == nil {
		t.Fatal("expected non-nil editor")
	}
	if ed.OutDir() != outDir {
		t.Fatalf("OutDir mismatch: got %s, want %s", ed.OutDir(), outDir)
	}
}

func TestEditor_AddRemoveTarget(t *testing.T) {
	rootPath, _ := setupTestRoot(t)
	ed, _ := LoadRepository(LoadOptions{RootPath: rootPath, OutDir: t.TempDir()})

	tf := tufmeta.TargetFile()
	ed.AddTarget("test.txt", tf)

	targets := ed.Targets()
	if _, ok := targets.Signed.Targets["test.txt"]; !ok {
		t.Fatal("target not added")
	}

	if err := ed.RemoveTarget("test.txt"); err != nil {
		t.Fatalf("RemoveTarget failed: %v", err)
	}
	if _, ok := targets.Signed.Targets["test.txt"]; ok {
		t.Fatal("target not removed")
	}
}

func TestEditor_RemoveTarget_NotFound(t *testing.T) {
	rootPath, _ := setupTestRoot(t)
	ed, _ := LoadRepository(LoadOptions{RootPath: rootPath, OutDir: t.TempDir()})

	err := ed.RemoveTarget("nonexistent.txt")
	if err == nil {
		t.Fatal("expected error for non-existent target")
	}
}

func TestEditor_VersionBumps(t *testing.T) {
	rootPath, _ := setupTestRoot(t)
	ed, _ := LoadRepository(LoadOptions{RootPath: rootPath, OutDir: t.TempDir()})

	targets := ed.Targets()
	origVersion := targets.Signed.Version

	ed.BumpTargetsVersion()
	if targets.Signed.Version != origVersion+1 {
		t.Fatalf("targets version not bumped")
	}

	ed.BumpSnapshotVersion()
	ed.BumpTimestampVersion()
}

func TestEditor_SetVersionsAndExpires(t *testing.T) {
	rootPath, _ := setupTestRoot(t)
	ed, _ := LoadRepository(LoadOptions{RootPath: rootPath, OutDir: t.TempDir()})

	ed.SetTargetsVersion(10)
	ed.SetSnapshotVersion(20)
	ed.SetTimestampVersion(30)

	future := time.Now().AddDate(1, 0, 0)
	ed.SetTargetsExpires(future)
	ed.SetSnapshotExpires(future)
	ed.SetTimestampExpires(future)
}

func TestEditor_CheckExpiration_NotExpired(t *testing.T) {
	rootPath, _ := setupTestRoot(t)
	ed, _ := LoadRepository(LoadOptions{RootPath: rootPath, OutDir: t.TempDir()})

	future := time.Now().AddDate(1, 0, 0)
	ed.SetTargetsExpires(future)
	ed.SetSnapshotExpires(future)
	ed.SetTimestampExpires(future)

	if err := ed.CheckExpiration(false); err != nil {
		t.Fatalf("should not be expired: %v", err)
	}
}

func TestEditor_CheckExpiration_Expired(t *testing.T) {
	rootPath, _ := setupTestRoot(t)
	ed, _ := LoadRepository(LoadOptions{RootPath: rootPath, OutDir: t.TempDir()})

	past := time.Now().AddDate(-1, 0, 0)
	ed.SetTargetsExpires(past)

	err := ed.CheckExpiration(false)
	if err == nil {
		t.Fatal("expected error for expired metadata")
	}
}

func TestEditor_CheckExpiration_AllowExpired(t *testing.T) {
	rootPath, _ := setupTestRoot(t)
	ed, _ := LoadRepository(LoadOptions{RootPath: rootPath, OutDir: t.TempDir()})

	past := time.Now().AddDate(-1, 0, 0)
	ed.SetTargetsExpires(past)

	if err := ed.CheckExpiration(true); err != nil {
		t.Fatalf("should allow expired: %v", err)
	}
}

func TestEditor_CheckExpiration_OutputWriter(t *testing.T) {
	var buf bytes.Buffer
	rootPath, _ := setupTestRoot(t)
	ed, err := LoadRepository(LoadOptions{RootPath: rootPath, OutDir: t.TempDir(), Output: &buf})
	if err != nil {
		t.Fatalf("LoadRepository failed: %v", err)
	}

	past := time.Now().AddDate(-1, 0, 0)
	ed.SetTargetsExpires(past)

	if err := ed.CheckExpiration(true); err != nil {
		t.Fatalf("CheckExpiration failed: %v", err)
	}

	if !strings.Contains(buf.String(), "WARNING") {
		t.Fatalf("expected WARNING in output, got: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "AllowExpiredRepo") {
		t.Fatalf("expected AllowExpiredRepo in output, got: %q", buf.String())
	}
}

func TestEditor_CheckExpiration_OutputDiscard(t *testing.T) {
	rootPath, _ := setupTestRoot(t)
	ed, err := LoadRepository(LoadOptions{RootPath: rootPath, OutDir: t.TempDir(), Output: io.Discard})
	if err != nil {
		t.Fatalf("LoadRepository failed: %v", err)
	}

	past := time.Now().AddDate(-1, 0, 0)
	ed.SetTargetsExpires(past)

	if err := ed.CheckExpiration(true); err != nil {
		t.Fatalf("should allow expired: %v", err)
	}
}

func TestEditor_CopyTargetToRepo(t *testing.T) {
	rootPath, _ := setupTestRoot(t)
	outDir := t.TempDir()
	ed, _ := LoadRepository(LoadOptions{RootPath: rootPath, OutDir: outDir})

	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "artifact.txt")
	os.WriteFile(srcPath, []byte("artifact content"), 0644)

	tf, err := BuildTargetFiles(srcPath, "sha256")
	if err != nil {
		t.Fatalf("BuildTargetFiles failed: %v", err)
	}
	ed.AddTarget("artifact.txt", tf)

	if err := ed.CopyTargetToRepo(srcPath, "artifact.txt"); err != nil {
		t.Fatalf("CopyTargetToRepo failed: %v", err)
	}

	targetsDir := filepath.Join(outDir, "targets")
	entries, _ := os.ReadDir(targetsDir)
	if len(entries) == 0 {
		t.Fatal("no files in targets dir after copy")
	}
}

func TestEditor_CopyTargetToRepo_HashAlgoPrefix(t *testing.T) {
	rootPath, _ := setupTestRoot(t)

	content := []byte("hash algo test content")

	for _, algo := range []string{"sha256", "sha512"} {
		t.Run(algo, func(t *testing.T) {
			outDir := t.TempDir()
			ed, _ := LoadRepository(LoadOptions{RootPath: rootPath, OutDir: outDir})

			srcDir := t.TempDir()
			srcPath := filepath.Join(srcDir, "target.bin")
			os.WriteFile(srcPath, content, 0644)

			tf, err := BuildTargetFiles(srcPath, algo)
			if err != nil {
				t.Fatalf("BuildTargetFiles(%s) failed: %v", algo, err)
			}
			ed.AddTarget("target.bin", tf)

			if err := ed.CopyTargetToRepo(srcPath, "target.bin"); err != nil {
				t.Fatalf("CopyTargetToRepo failed: %v", err)
			}

			hashStr, err := utils.PreferredHash(tf.Hashes)
			if err != nil {
				t.Fatalf("PreferredHash failed: %v", err)
			}

			expectedName := hashStr + ".target.bin"
			expectedPath := filepath.Join(outDir, "targets", expectedName)
			if !utils.FileExists(expectedPath) {
				entries, _ := os.ReadDir(filepath.Join(outDir, "targets"))
				var names []string
				for _, e := range entries {
					names = append(names, e.Name())
				}
				t.Fatalf("expected %s-prefixed file %s, got: %v", algo, expectedName, names)
			}
		})
	}
}

func TestEditor_CopyTargetToRepo_SymlinkNoFollow(t *testing.T) {
	rootPath, _ := setupTestRoot(t)
	outDir := t.TempDir()
	ed, _ := LoadRepository(LoadOptions{RootPath: rootPath, OutDir: outDir, Follow: false})

	srcDir := t.TempDir()
	realFile := filepath.Join(srcDir, "real.txt")
	os.WriteFile(realFile, []byte("real"), 0644)
	linkFile := filepath.Join(srcDir, "link.txt")
	os.Symlink(realFile, linkFile)

	err := ed.CopyTargetToRepo(linkFile, "link.txt")
	if err == nil {
		t.Fatal("expected error for symlink without --follow")
	}
}

func TestEditor_SignAndWrite(t *testing.T) {
	rootPath, keyPath := setupTestRoot(t)
	outDir := t.TempDir()
	ed, _ := LoadRepository(LoadOptions{RootPath: rootPath, OutDir: outDir})

	future := time.Now().AddDate(1, 0, 0)
	ed.SetTargetsExpires(future)
	ed.SetSnapshotExpires(future)
	ed.SetTimestampExpires(future)

	err := ed.SignAndWrite(SignAndWriteOptions{KeyPaths: []string{keyPath}, OutDir: outDir})
	if err != nil {
		t.Fatalf("SignAndWrite failed: %v", err)
	}

	if !utils.FileExists(filepath.Join(outDir, "timestamp.json")) {
		t.Fatal("timestamp.json not written")
	}
	if !utils.FileExists(filepath.Join(outDir, "root.json")) {
		t.Fatal("root.json not written")
	}
}

func TestBuildTargetFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target.txt")
	os.WriteFile(path, []byte("target content"), 0644)

	tf, err := BuildTargetFiles(path, "sha256")
	if err != nil {
		t.Fatalf("BuildTargetFiles failed: %v", err)
	}
	if tf.Length != 14 {
		t.Fatalf("expected length 14, got %d", tf.Length)
	}
}

func TestSetTargetCustom(t *testing.T) {
	tf := tufmeta.TargetFile()
	custom := map[string]interface{}{"key": "value"}
	if err := SetTargetCustom(tf, custom); err != nil {
		t.Fatalf("SetTargetCustom failed: %v", err)
	}
	if tf.Custom == nil {
		t.Fatal("custom metadata not set")
	}
	var parsed map[string]interface{}
	json.Unmarshal(*tf.Custom, &parsed)
	if parsed["key"] != "value" {
		t.Fatal("custom metadata mismatch")
	}
}

func TestFindLatestVersionedFile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "1.targets.json"), []byte("v1"), 0644)
	os.WriteFile(filepath.Join(dir, "3.targets.json"), []byte("v3"), 0644)
	os.WriteFile(filepath.Join(dir, "2.targets.json"), []byte("v2"), 0644)

	path, version, err := FindLatestVersionedFile(dir, "targets.json")
	if err != nil {
		t.Fatalf("FindLatestVersionedFile failed: %v", err)
	}
	if version != 3 {
		t.Fatalf("expected version 3, got %d", version)
	}
	if filepath.Base(path) != "3.targets.json" {
		t.Fatalf("expected 3.targets.json, got %s", filepath.Base(path))
	}
}

func TestFindLatestVersionedFile_NotFound(t *testing.T) {
	dir := t.TempDir()
	_, _, err := FindLatestVersionedFile(dir, "targets.json")
	if err == nil {
		t.Fatal("expected error for no versioned files")
	}
}

func TestFetchMetadataFromURL(t *testing.T) {
	// Build a minimal TUF repo for the HTTP server
	dir := t.TempDir()
	expires := time.Now().AddDate(1, 0, 0)

	targets := tufmeta.Targets(expires)
	targets.Signed.Version = 1
	targetsBytes, _ := targets.ToBytes(true)

	snapshot := tufmeta.Snapshot(expires)
	snapshot.Signed.Version = 1
	snapshot.Signed.Meta["targets.json"] = &tufmeta.MetaFiles{Version: 1, Length: int64(len(targetsBytes))}
	snapshotBytes, _ := snapshot.ToBytes(true)

	timestamp := tufmeta.Timestamp(expires)
	timestamp.Signed.Version = 1
	timestamp.Signed.Meta["snapshot.json"] = &tufmeta.MetaFiles{Version: 1, Length: int64(len(snapshotBytes))}
	timestampBytes, _ := timestamp.ToBytes(true)

	os.WriteFile(filepath.Join(dir, "timestamp.json"), timestampBytes, 0644)
	os.WriteFile(filepath.Join(dir, "1.snapshot.json"), snapshotBytes, 0644)
	os.WriteFile(filepath.Join(dir, "1.targets.json"), targetsBytes, 0644)

	srv := httptest.NewServer(http.FileServer(http.Dir(dir)))
	defer srv.Close()

	outDir := t.TempDir()
	if err := fetchMetadataFromURL(srv.URL, outDir); err != nil {
		t.Fatalf("fetchMetadataFromURL failed: %v", err)
	}

	if !utils.FileExists(filepath.Join(outDir, "timestamp.json")) {
		t.Fatal("timestamp.json not fetched")
	}
}

func TestLoadRepository_WithMetadataURL(t *testing.T) {
	rootPath, keyPath := setupTestRoot(t)
	outDir := t.TempDir()

	// Create a repo first
	ed, _ := LoadRepository(LoadOptions{RootPath: rootPath, OutDir: outDir})
	future := time.Now().AddDate(1, 0, 0)
	ed.SetTargetsExpires(future)
	ed.SetSnapshotExpires(future)
	ed.SetTimestampExpires(future)
	ed.SignAndWrite(SignAndWriteOptions{KeyPaths: []string{keyPath}, OutDir: outDir})

	// Serve it via HTTP
	srv := httptest.NewServer(http.FileServer(http.Dir(outDir)))
	defer srv.Close()

	// Load via metadata URL
	outDir2 := t.TempDir()
	ed2, err := LoadRepository(LoadOptions{
		RootPath:    rootPath,
		OutDir:      outDir2,
		MetadataURL: srv.URL,
	})
	if err != nil {
		t.Fatalf("LoadRepository with MetadataURL failed: %v", err)
	}
	if ed2 == nil {
		t.Fatal("expected non-nil editor")
	}
}
