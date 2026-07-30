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

package download

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"
)

func buildTestRepo(t *testing.T, dir string) {
	t.Helper()
	expires := time.Now().UTC().Truncate(time.Second).AddDate(1, 0, 0)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	key, err := tufmeta.KeyFromPublicKey(pub)
	if err != nil {
		t.Fatalf("failed to create TUF key: %v", err)
	}
	keyID, err := key.ID()
	if err != nil {
		t.Fatalf("failed to get key ID: %v", err)
	}
	signer, err := signature.LoadED25519Signer(priv)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	targetsDir := filepath.Join(dir, "targets")
	if err := os.MkdirAll(targetsDir, 0755); err != nil {
		t.Fatalf("failed to create targets dir: %v", err)
	}
	targetContent := []byte("download test content\n")
	targetHash := sha256.Sum256(targetContent)
	targetHashHex := hex.EncodeToString(targetHash[:])
	hashPrefixedName := targetHashHex + ".artifact.txt"
	if err := os.WriteFile(filepath.Join(targetsDir, hashPrefixedName), targetContent, 0600); err != nil {
		t.Fatalf("failed to write target: %v", err)
	}

	root := tufmeta.Root(expires)
	root.Signed.ConsistentSnapshot = true
	root.Signed.Version = 1
	root.Signed.Keys[keyID] = key
	for _, role := range []string{"root", "snapshot", "targets", "timestamp"} {
		root.Signed.Roles[role] = &tufmeta.Role{KeyIDs: []string{keyID}, Threshold: 1}
	}
	if _, err := root.Sign(signer); err != nil {
		t.Fatalf("failed to sign root: %v", err)
	}

	targets := tufmeta.Targets(expires)
	targets.Signed.Version = 1
	targets.Signed.Targets["artifact.txt"] = &tufmeta.TargetFiles{
		Length: int64(len(targetContent)),
		Hashes: tufmeta.Hashes{"sha256": targetHash[:]},
		Path:   "artifact.txt",
	}
	if _, err := targets.Sign(signer); err != nil {
		t.Fatalf("failed to sign targets: %v", err)
	}
	targetsBytes, err := targets.ToBytes(true)
	if err != nil {
		t.Fatalf("failed to serialize targets: %v", err)
	}

	targetsFileHash := sha256.Sum256(targetsBytes)
	snapshot := tufmeta.Snapshot(expires)
	snapshot.Signed.Version = 1
	snapshot.Signed.Meta["targets.json"] = &tufmeta.MetaFiles{
		Version: 1, Length: int64(len(targetsBytes)), Hashes: tufmeta.Hashes{"sha256": targetsFileHash[:]},
	}
	if _, err := snapshot.Sign(signer); err != nil {
		t.Fatalf("failed to sign snapshot: %v", err)
	}
	snapshotBytes, err := snapshot.ToBytes(true)
	if err != nil {
		t.Fatalf("failed to serialize snapshot: %v", err)
	}

	snapshotFileHash := sha256.Sum256(snapshotBytes)
	timestamp := tufmeta.Timestamp(expires)
	timestamp.Signed.Version = 1
	timestamp.Signed.Meta["snapshot.json"] = &tufmeta.MetaFiles{
		Version: 1, Length: int64(len(snapshotBytes)), Hashes: tufmeta.Hashes{"sha256": snapshotFileHash[:]},
	}
	if _, err := timestamp.Sign(signer); err != nil {
		t.Fatalf("failed to sign timestamp: %v", err)
	}
	timestampBytes, err := timestamp.ToBytes(true)
	if err != nil {
		t.Fatalf("failed to serialize timestamp: %v", err)
	}

	rootBytes, err := root.ToBytes(true)
	if err != nil {
		t.Fatalf("failed to serialize root: %v", err)
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

func TestRun_Basic(t *testing.T) {
	repoDir := t.TempDir()
	buildTestRepo(t, repoDir)

	srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
	defer srv.Close()

	outDir := filepath.Join(t.TempDir(), "output")

	err := Download(&Options{
		Root:        filepath.Join(repoDir, "root.json"),
		MetadataURL: srv.URL,
		TargetsURL:  srv.URL + "/targets",
		OutDir:      outDir,
	})
	if err != nil {
		t.Fatalf("download failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(outDir, "artifact.txt"))
	if err != nil {
		t.Fatalf("target file not found: %v", err)
	}
	if string(data) != "download test content\n" {
		t.Fatalf("unexpected target content: %q", string(data))
	}
}
