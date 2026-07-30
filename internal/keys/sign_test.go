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

	ss, err := LoadSignerSet([]string{keyPath})
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
	_, err := LoadSignerSet([]string{"/nonexistent/key.pem"})
	if err == nil {
		t.Fatal("expected error for non-existent key")
	}
}

func TestLoadSignerSet_MultipleKeys(t *testing.T) {
	dir := t.TempDir()
	key1 := writeTestKey(t, filepath.Join(dir, "k1"))
	key2 := writeTestKey(t, filepath.Join(dir, "k2"))

	ss, err := LoadSignerSet([]string{key1, key2})
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

	ss, _ := LoadSignerSet([]string{keyPath})
	keyID := ss.entries[0].keyID

	expires := time.Now().AddDate(1, 0, 0)
	md := tufmeta.Targets(expires)

	err := SignForRole(ss, md, "targets", []string{keyID})
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
	ss, _ := LoadSignerSet([]string{keyPath})

	md := tufmeta.Targets(time.Now().AddDate(1, 0, 0))
	err := SignForRole(ss, md, "targets", []string{})
	if err == nil {
		t.Fatal("expected error for no authorized keys")
	}
}

func TestSignForRole_NoMatchingKeys(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeTestKey(t, dir)
	ss, _ := LoadSignerSet([]string{keyPath})

	md := tufmeta.Targets(time.Now().AddDate(1, 0, 0))
	err := SignForRole(ss, md, "targets", []string{"wrong-key-id"})
	if err == nil {
		t.Fatal("expected error for no matching keys")
	}
}

func TestSignForRole_Snapshot(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeTestKey(t, dir)
	ss, _ := LoadSignerSet([]string{keyPath})
	keyID := ss.entries[0].keyID

	md := tufmeta.Snapshot(time.Now().AddDate(1, 0, 0))
	err := SignForRole(ss, md, "snapshot", []string{keyID})
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
	ss, _ := LoadSignerSet([]string{keyPath})
	keyID := ss.entries[0].keyID

	md := tufmeta.Timestamp(time.Now().AddDate(1, 0, 0))
	err := SignForRole(ss, md, "timestamp", []string{keyID})
	if err != nil {
		t.Fatalf("SignForRole timestamp failed: %v", err)
	}
	if len(md.Signatures) == 0 {
		t.Fatal("expected signature on timestamp")
	}
}
