package root

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

func initRoot(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "root.json")
	if err := Init(InitOptions{Path: path, Version: 1}); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	return path
}

func readRoot(t *testing.T, path string) *tufmeta.Metadata[tufmeta.RootType] {
	t.Helper()
	md := &tufmeta.Metadata[tufmeta.RootType]{}
	if _, err := md.FromFile(path); err != nil {
		t.Fatalf("failed to parse root.json: %v", err)
	}
	return md
}

func generateECKeyFile(t *testing.T, dir, name string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}
	path := filepath.Join(dir, name)
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}
	return path
}

func TestExpire(t *testing.T) {
	dir := t.TempDir()
	path := initRoot(t, dir)

	future := time.Now().Add(365 * 24 * time.Hour)
	err := Expire(ExpireOptions{Path: path, Expires: future})
	if err != nil {
		t.Fatalf("Expire failed: %v", err)
	}

	md := readRoot(t, path)
	diff := md.Signed.Expires.Sub(future.UTC().Truncate(time.Second))
	if diff < 0 {
		diff = -diff
	}
	if diff > time.Second {
		t.Fatalf("expiration not set correctly: got %v, want ~%v", md.Signed.Expires, future)
	}

	if len(md.Signatures) != 0 {
		t.Fatalf("expected signatures cleared, got %d", len(md.Signatures))
	}
}

func TestExpire_InvalidPath(t *testing.T) {
	err := Expire(ExpireOptions{Path: "/nonexistent/root.json", Expires: time.Now()})
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func TestSetThreshold(t *testing.T) {
	dir := t.TempDir()
	path := initRoot(t, dir)

	err := SetThreshold(SetThresholdOptions{Path: path, Role: tufmeta.ROOT, Threshold: 3})
	if err != nil {
		t.Fatalf("SetThreshold failed: %v", err)
	}

	md := readRoot(t, path)
	if md.Signed.Roles[tufmeta.ROOT].Threshold != 3 {
		t.Fatalf("expected threshold 3, got %d", md.Signed.Roles[tufmeta.ROOT].Threshold)
	}
}

func TestSetThreshold_Zero(t *testing.T) {
	dir := t.TempDir()
	path := initRoot(t, dir)

	err := SetThreshold(SetThresholdOptions{Path: path, Role: tufmeta.ROOT, Threshold: 0})
	if err == nil {
		t.Fatal("expected error for threshold 0")
	}
}

func TestSetThreshold_InvalidRole(t *testing.T) {
	dir := t.TempDir()
	path := initRoot(t, dir)

	err := SetThreshold(SetThresholdOptions{Path: path, Role: "nonexistent", Threshold: 1})
	if err == nil {
		t.Fatal("expected error for nonexistent role")
	}
}

func TestSetThreshold_InvalidPath(t *testing.T) {
	err := SetThreshold(SetThresholdOptions{Path: "/nonexistent", Role: tufmeta.ROOT, Threshold: 1})
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func TestBumpVersion(t *testing.T) {
	dir := t.TempDir()
	path := initRoot(t, dir)

	md := readRoot(t, path)
	original := md.Signed.Version

	err := BumpVersion(BumpVersionOptions{Path: path})
	if err != nil {
		t.Fatalf("BumpVersion failed: %v", err)
	}

	md = readRoot(t, path)
	if md.Signed.Version != original+1 {
		t.Fatalf("expected version %d, got %d", original+1, md.Signed.Version)
	}
}

func TestBumpVersion_InvalidPath(t *testing.T) {
	err := BumpVersion(BumpVersionOptions{Path: "/nonexistent"})
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func TestSetVersion(t *testing.T) {
	dir := t.TempDir()
	path := initRoot(t, dir)

	err := SetVersion(SetVersionOptions{Path: path, Version: 42})
	if err != nil {
		t.Fatalf("SetVersion failed: %v", err)
	}

	md := readRoot(t, path)
	if md.Signed.Version != 42 {
		t.Fatalf("expected version 42, got %d", md.Signed.Version)
	}
}

func TestSetVersion_Zero(t *testing.T) {
	dir := t.TempDir()
	path := initRoot(t, dir)

	err := SetVersion(SetVersionOptions{Path: path, Version: 0})
	if err == nil {
		t.Fatal("expected error for version 0")
	}
}

func TestSetVersion_InvalidPath(t *testing.T) {
	err := SetVersion(SetVersionOptions{Path: "/nonexistent", Version: 1})
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func TestAddKey(t *testing.T) {
	dir := t.TempDir()
	path := initRoot(t, dir)
	keyPath := generateECKeyFile(t, dir, "key.pem")

	ids, err := AddKey(AddKeyOptions{
		Path:     path,
		KeyPaths: []string{keyPath},
		Roles:    []string{tufmeta.ROOT, tufmeta.TARGETS},
	})
	if err != nil {
		t.Fatalf("AddKey failed: %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("expected 1 key ID, got %d", len(ids))
	}

	md := readRoot(t, path)
	if len(md.Signed.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(md.Signed.Keys))
	}
	if len(md.Signed.Roles[tufmeta.ROOT].KeyIDs) != 1 {
		t.Fatalf("expected 1 key in root role, got %d", len(md.Signed.Roles[tufmeta.ROOT].KeyIDs))
	}
	if len(md.Signed.Roles[tufmeta.TARGETS].KeyIDs) != 1 {
		t.Fatalf("expected 1 key in targets role, got %d", len(md.Signed.Roles[tufmeta.TARGETS].KeyIDs))
	}
	if len(md.Signed.Roles[tufmeta.SNAPSHOT].KeyIDs) != 0 {
		t.Fatalf("expected 0 keys in snapshot role, got %d", len(md.Signed.Roles[tufmeta.SNAPSHOT].KeyIDs))
	}
}

func TestAddKey_MultipleKeys(t *testing.T) {
	dir := t.TempDir()
	path := initRoot(t, dir)
	key1 := generateECKeyFile(t, dir, "key1.pem")
	key2 := generateECKeyFile(t, dir, "key2.pem")

	ids, err := AddKey(AddKeyOptions{
		Path:     path,
		KeyPaths: []string{key1, key2},
		Roles:    []string{tufmeta.ROOT},
	})
	if err != nil {
		t.Fatalf("AddKey failed: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("expected 2 key IDs, got %d", len(ids))
	}

	md := readRoot(t, path)
	if len(md.Signed.Keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(md.Signed.Keys))
	}
}

func TestAddKey_InvalidKeyPath(t *testing.T) {
	dir := t.TempDir()
	path := initRoot(t, dir)

	_, err := AddKey(AddKeyOptions{
		Path:     path,
		KeyPaths: []string{"/nonexistent/key.pem"},
		Roles:    []string{tufmeta.ROOT},
	})
	if err == nil {
		t.Fatal("expected error for nonexistent key")
	}
}

func TestAddKey_InvalidRootPath(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateECKeyFile(t, dir, "key.pem")

	_, err := AddKey(AddKeyOptions{
		Path:     "/nonexistent/root.json",
		KeyPaths: []string{keyPath},
		Roles:    []string{tufmeta.ROOT},
	})
	if err == nil {
		t.Fatal("expected error for nonexistent root.json")
	}
}

func TestRemoveKey(t *testing.T) {
	dir := t.TempDir()
	path := initRoot(t, dir)
	keyPath := generateECKeyFile(t, dir, "key.pem")

	ids, _ := AddKey(AddKeyOptions{
		Path:     path,
		KeyPaths: []string{keyPath},
		Roles:    []string{tufmeta.ROOT, tufmeta.TARGETS, tufmeta.SNAPSHOT, tufmeta.TIMESTAMP},
	})

	role := tufmeta.SNAPSHOT
	err := RemoveKey(RemoveKeyOptions{Path: path, KeyID: ids[0], Role: &role})
	if err != nil {
		t.Fatalf("RemoveKey failed: %v", err)
	}

	md := readRoot(t, path)
	if len(md.Signed.Roles[tufmeta.SNAPSHOT].KeyIDs) != 0 {
		t.Fatal("key should be removed from snapshot role")
	}
	if len(md.Signed.Roles[tufmeta.ROOT].KeyIDs) != 1 {
		t.Fatal("key should still be in root role")
	}
	if len(md.Signed.Keys) != 1 {
		t.Fatal("key should still be in keys map (referenced by other roles)")
	}
}

func TestRemoveKey_AllRoles(t *testing.T) {
	dir := t.TempDir()
	path := initRoot(t, dir)
	keyPath := generateECKeyFile(t, dir, "key.pem")

	ids, _ := AddKey(AddKeyOptions{
		Path:     path,
		KeyPaths: []string{keyPath},
		Roles:    []string{tufmeta.ROOT, tufmeta.TARGETS, tufmeta.SNAPSHOT, tufmeta.TIMESTAMP},
	})

	err := RemoveKey(RemoveKeyOptions{Path: path, KeyID: ids[0], Role: nil})
	if err != nil {
		t.Fatalf("RemoveKey all roles failed: %v", err)
	}

	md := readRoot(t, path)
	for _, role := range []string{tufmeta.ROOT, tufmeta.TARGETS, tufmeta.SNAPSHOT, tufmeta.TIMESTAMP} {
		if len(md.Signed.Roles[role].KeyIDs) != 0 {
			t.Fatalf("key should be removed from %s role", role)
		}
	}
	if len(md.Signed.Keys) != 0 {
		t.Fatalf("key should be removed from keys map, got %d", len(md.Signed.Keys))
	}
}

func TestRemoveKey_NonexistentKey(t *testing.T) {
	dir := t.TempDir()
	path := initRoot(t, dir)

	role := tufmeta.ROOT
	err := RemoveKey(RemoveKeyOptions{Path: path, KeyID: "nonexistent-key-id", Role: &role})
	if err != nil {
		t.Fatalf("RemoveKey for nonexistent key should not error (silently ignore): %v", err)
	}
}

func TestRemoveKey_InvalidPath(t *testing.T) {
	err := RemoveKey(RemoveKeyOptions{Path: "/nonexistent", KeyID: "abc"})
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func TestGenRsaKey(t *testing.T) {
	dir := t.TempDir()
	path := initRoot(t, dir)
	keyPath := filepath.Join(dir, "rsa-key")

	keyID, err := GenRsaKey(GenRsaKeyOptions{
		Path:     path,
		KeyPath:  keyPath,
		Bits:     2048,
		Exponent: 65537,
		Roles:    []string{tufmeta.ROOT},
	})
	if err != nil {
		t.Fatalf("GenRsaKey failed: %v", err)
	}
	if keyID == "" {
		t.Fatal("expected non-empty key ID")
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Fatal("private key file was not created")
	}

	md := readRoot(t, path)
	if len(md.Signed.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(md.Signed.Keys))
	}
	if _, ok := md.Signed.Keys[keyID]; !ok {
		t.Fatal("generated key ID not found in root.json")
	}
}

func TestGenRsaKey_InvalidPath(t *testing.T) {
	dir := t.TempDir()
	_, err := GenRsaKey(GenRsaKeyOptions{
		Path:     "/nonexistent/root.json",
		KeyPath:  filepath.Join(dir, "key"),
		Bits:     2048,
		Exponent: 65537,
		Roles:    []string{tufmeta.ROOT},
	})
	if err == nil {
		t.Fatal("expected error for nonexistent root.json")
	}
}

func TestLoadAndSaveRoot_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	path := initRoot(t, dir)

	md, err := loadRoot(path)
	if err != nil {
		t.Fatalf("loadRoot failed: %v", err)
	}

	md.Signed.Version = 99
	if err := saveRoot(path, md); err != nil {
		t.Fatalf("saveRoot failed: %v", err)
	}

	md2, err := loadRoot(path)
	if err != nil {
		t.Fatalf("loadRoot after save failed: %v", err)
	}
	if md2.Signed.Version != 99 {
		t.Fatalf("expected version 99, got %d", md2.Signed.Version)
	}
}

func TestLoadRoot_InvalidPath(t *testing.T) {
	_, err := loadRoot("/nonexistent/root.json")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestSetVersion_ClearsSignatures(t *testing.T) {
	dir := t.TempDir()
	path := initRoot(t, dir)

	SetVersion(SetVersionOptions{Path: path, Version: 5})
	md := readRoot(t, path)
	if len(md.Signatures) != 0 {
		t.Fatal("expected signatures cleared after SetVersion")
	}
}

func TestBumpVersion_ClearsSignatures(t *testing.T) {
	dir := t.TempDir()
	path := initRoot(t, dir)

	BumpVersion(BumpVersionOptions{Path: path})
	md := readRoot(t, path)
	if len(md.Signatures) != 0 {
		t.Fatal("expected signatures cleared after BumpVersion")
	}
}
