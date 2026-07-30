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

func buildTestRepo(t *testing.T, dir string, keys *testKeys) {
	t.Helper()
	expires := time.Now().UTC().Truncate(time.Second).AddDate(1, 0, 0)

	targetsDir := filepath.Join(dir, "targets")
	if err := os.MkdirAll(targetsDir, 0755); err != nil {
		t.Fatalf("failed to create targets dir: %v", err)
	}
	targetContent := []byte("transfer test content\n")
	targetHash := sha256.Sum256(targetContent)
	targetHashHex := hex.EncodeToString(targetHash[:])
	hashPrefixedName := targetHashHex + ".artifact.txt"
	if err := os.WriteFile(filepath.Join(targetsDir, hashPrefixedName), targetContent, 0600); err != nil {
		t.Fatalf("failed to write target: %v", err)
	}

	root := tufmeta.Root(expires)
	root.Signed.ConsistentSnapshot = true
	root.Signed.Version = 1
	root.Signed.Keys[keys.keyID] = keys.key
	for _, role := range []string{"root", "snapshot", "targets", "timestamp"} {
		root.Signed.Roles[role] = &tufmeta.Role{KeyIDs: []string{keys.keyID}, Threshold: 1}
	}
	if _, err := root.Sign(keys.signer); err != nil {
		t.Fatalf("failed to sign root: %v", err)
	}

	targets := tufmeta.Targets(expires)
	targets.Signed.Version = 1
	targets.Signed.Targets["artifact.txt"] = &tufmeta.TargetFiles{
		Length: int64(len(targetContent)),
		Hashes: tufmeta.Hashes{"sha256": targetHash[:]},
		Path:   "artifact.txt",
	}
	if _, err := targets.Sign(keys.signer); err != nil {
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
	if _, err := snapshot.Sign(keys.signer); err != nil {
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
	if _, err := timestamp.Sign(keys.signer); err != nil {
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

func writeRootJSON(t *testing.T, dir string, keys *testKeys) string {
	t.Helper()
	expires := time.Now().UTC().Truncate(time.Second).AddDate(1, 0, 0)
	root := tufmeta.Root(expires)
	root.Signed.ConsistentSnapshot = true
	root.Signed.Version = 1
	root.Signed.Keys[keys.keyID] = keys.key
	for _, role := range []string{"root", "snapshot", "targets", "timestamp"} {
		root.Signed.Roles[role] = &tufmeta.Role{KeyIDs: []string{keys.keyID}, Threshold: 1}
	}
	if _, err := root.Sign(keys.signer); err != nil {
		t.Fatalf("failed to sign root: %v", err)
	}
	rootBytes, err := root.ToBytes(true)
	if err != nil {
		t.Fatalf("failed to serialize root: %v", err)
	}
	rootPath := filepath.Join(dir, "root.json")
	if err := os.WriteFile(rootPath, rootBytes, 0600); err != nil {
		t.Fatalf("failed to write root.json: %v", err)
	}
	return rootPath
}

func TestRun_Basic(t *testing.T) {
	oldKeys := generateTestKeys(t)
	newKeys := generateTestKeys(t)

	repoDir := t.TempDir()
	buildTestRepo(t, repoDir, oldKeys)

	srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
	defer srv.Close()

	newRootDir := t.TempDir()
	newRootPath := writeRootJSON(t, newRootDir, newKeys)
	keyPath := writeKeyFile(t, newRootDir, newKeys.priv)

	outDir := filepath.Join(t.TempDir(), "transfer-out")
	expires := time.Now().UTC().Truncate(time.Second).AddDate(0, 6, 0)

	err := Transfer(&Options{
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
	})
	if err != nil {
		t.Fatalf("transfer failed: %v", err)
	}

	for _, name := range []string{"root.json", "1.root.json", "1.targets.json", "1.snapshot.json", "timestamp.json"} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Fatalf("expected output file %s: %v", name, err)
		}
	}

	targetsMd := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := targetsMd.FromFile(filepath.Join(outDir, "1.targets.json")); err != nil {
		t.Fatalf("failed to parse targets.json: %v", err)
	}
	if _, ok := targetsMd.Signed.Targets["artifact.txt"]; !ok {
		t.Fatal("artifact.txt not transferred to new repo")
	}
}
