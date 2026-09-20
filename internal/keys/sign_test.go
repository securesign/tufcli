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

package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"
)

func writeTestKey(t *testing.T, dir string) string {
	t.Helper()
	os.MkdirAll(dir, 0755)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privBytes, _ := x509.MarshalECPrivateKey(key)
	path := filepath.Join(dir, "key.pem")
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}
	os.WriteFile(path, pem.EncodeToMemory(block), 0600)
	return path
}

func TestLoadSignerSet(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeTestKey(t, dir)

	ss, err := LoadSignerSet([]string{keyPath}, nil)
	if err != nil {
		t.Fatalf("LoadSignerSet failed: %v", err)
	}
	if len(ss.entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(ss.entries))
	}
	if ss.entries[0].keyID == "" {
		t.Fatal("keyID should not be empty")
	}
}

func TestLoadSignerSet_InvalidPath(t *testing.T) {
	_, err := LoadSignerSet([]string{"/nonexistent/key.pem"}, nil)
	if err == nil {
		t.Fatal("expected error for non-existent key")
	}
}

func TestLoadSignerSet_MultipleKeys(t *testing.T) {
	dir := t.TempDir()
	key1 := writeTestKey(t, filepath.Join(dir, "k1"))
	key2 := writeTestKey(t, filepath.Join(dir, "k2"))

	ss, err := LoadSignerSet([]string{key1, key2}, nil)
	if err != nil {
		t.Fatalf("LoadSignerSet failed: %v", err)
	}
	if len(ss.entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(ss.entries))
	}
}

func TestSignForRole(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeTestKey(t, dir)

	ss, _ := LoadSignerSet([]string{keyPath}, nil)
	keyID := ss.entries[0].keyID

	expires := time.Now().AddDate(1, 0, 0)
	md := tufmeta.Targets(expires)

	err := SignForRole(ss, md, "targets", []string{keyID}, 1)
	if err != nil {
		t.Fatalf("SignForRole failed: %v", err)
	}
	if len(md.Signatures) == 0 {
		t.Fatal("expected at least one signature")
	}
	if md.Signatures[0].KeyID != keyID {
		t.Fatalf("signature keyID mismatch: got %s, want %s", md.Signatures[0].KeyID, keyID)
	}
}

func TestSignForRole_NoAuthorizedKeys(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeTestKey(t, dir)
	ss, _ := LoadSignerSet([]string{keyPath}, nil)

	md := tufmeta.Targets(time.Now().AddDate(1, 0, 0))
	err := SignForRole(ss, md, "targets", []string{}, 1)
	if err == nil {
		t.Fatal("expected error for no authorized keys")
	}
}

func TestSignForRole_NoMatchingKeys(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeTestKey(t, dir)
	ss, _ := LoadSignerSet([]string{keyPath}, nil)

	md := tufmeta.Targets(time.Now().AddDate(1, 0, 0))
	err := SignForRole(ss, md, "targets", []string{"wrong-key-id"}, 1)
	if err == nil {
		t.Fatal("expected error for no matching keys")
	}
}

func TestSignForRole_Snapshot(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeTestKey(t, dir)
	ss, _ := LoadSignerSet([]string{keyPath}, nil)
	keyID := ss.entries[0].keyID

	md := tufmeta.Snapshot(time.Now().AddDate(1, 0, 0))
	err := SignForRole(ss, md, "snapshot", []string{keyID}, 1)
	if err != nil {
		t.Fatalf("SignForRole snapshot failed: %v", err)
	}
	if len(md.Signatures) == 0 {
		t.Fatal("expected signature on snapshot")
	}
}

func TestSignForRole_Timestamp(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeTestKey(t, dir)
	ss, _ := LoadSignerSet([]string{keyPath}, nil)
	keyID := ss.entries[0].keyID

	md := tufmeta.Timestamp(time.Now().AddDate(1, 0, 0))
	err := SignForRole(ss, md, "timestamp", []string{keyID}, 1)
	if err != nil {
		t.Fatalf("SignForRole timestamp failed: %v", err)
	}
	if len(md.Signatures) == 0 {
		t.Fatal("expected signature on timestamp")
	}
}

func TestSignForRole_BelowThreshold(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeTestKey(t, dir)
	ss, _ := LoadSignerSet([]string{keyPath}, nil)
	keyID := ss.entries[0].keyID

	md := tufmeta.Targets(time.Now().AddDate(1, 0, 0))
	err := SignForRole(ss, md, "targets", []string{keyID}, 2)
	if err == nil {
		t.Fatal("expected error when below threshold")
	}
	if !strings.Contains(err.Error(), "not enough signing keys") {
		t.Fatalf("expected threshold error, got: %v", err)
	}
}

func TestSignForRole_DuplicateKeyDoesNotInflateCount(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeTestKey(t, dir)
	// Load the same key twice to simulate duplicate entries
	ss, _ := LoadSignerSet([]string{keyPath, keyPath}, nil)
	if len(ss.entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(ss.entries))
	}
	keyID := ss.entries[0].keyID

	md := tufmeta.Targets(time.Now().AddDate(1, 0, 0))
	// Threshold of 2 should fail because there's only 1 distinct key
	err := SignForRole(ss, md, "targets", []string{keyID}, 2)
	if err == nil {
		t.Fatal("expected error: duplicate key should not satisfy threshold=2")
	}
	if !strings.Contains(err.Error(), "not enough signing keys") {
		t.Fatalf("expected threshold error, got: %v", err)
	}
}
