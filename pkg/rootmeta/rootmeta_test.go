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

package rootmeta

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

func TestInit_Basic(t *testing.T) {
	dir := t.TempDir()
	rootPath := filepath.Join(dir, "root.json")

	if err := Init(InitOptions{Path: rootPath, Version: 1}); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	md := &tufmeta.Metadata[tufmeta.RootType]{}
	if _, err := md.FromFile(rootPath); err != nil {
		t.Fatalf("failed to parse root.json: %v", err)
	}
	if md.Signed.Version != 1 {
		t.Fatalf("expected version 1, got %d", md.Signed.Version)
	}
	if md.Signed.Roles["root"].Threshold != DefaultThreshold {
		t.Fatalf("expected default threshold %d, got %d", DefaultThreshold, md.Signed.Roles["root"].Threshold)
	}
}

func TestExpire(t *testing.T) {
	dir := t.TempDir()
	rootPath := filepath.Join(dir, "root.json")

	if err := Init(InitOptions{Path: rootPath, Version: 1}); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	expires := time.Date(2030, 6, 15, 12, 0, 0, 0, time.UTC)
	if err := Expire(ExpireOptions{Path: rootPath, Expires: expires}); err != nil {
		t.Fatalf("Expire failed: %v", err)
	}

	md := &tufmeta.Metadata[tufmeta.RootType]{}
	if _, err := md.FromFile(rootPath); err != nil {
		t.Fatalf("failed to parse root.json: %v", err)
	}
	if !md.Signed.Expires.Equal(expires) {
		t.Fatalf("expected expires %v, got %v", expires, md.Signed.Expires)
	}
}

func TestSetThreshold(t *testing.T) {
	dir := t.TempDir()
	rootPath := filepath.Join(dir, "root.json")

	if err := Init(InitOptions{Path: rootPath, Version: 1}); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	if err := SetThreshold(SetThresholdOptions{Path: rootPath, Role: "root", Threshold: 2}); err != nil {
		t.Fatalf("SetThreshold failed: %v", err)
	}

	md := &tufmeta.Metadata[tufmeta.RootType]{}
	if _, err := md.FromFile(rootPath); err != nil {
		t.Fatalf("failed to parse root.json: %v", err)
	}
	if md.Signed.Roles["root"].Threshold != 2 {
		t.Fatalf("expected threshold 2, got %d", md.Signed.Roles["root"].Threshold)
	}
}

func TestAddKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	rootPath := filepath.Join(dir, "root.json")

	if err := Init(InitOptions{Path: rootPath, Version: 1}); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	keyIDs, err := AddKey(AddKeyOptions{
		Path:     rootPath,
		KeyPaths: []string{keyPath},
		Roles:    []string{"root", "targets", "snapshot", "timestamp"},
	})
	if err != nil {
		t.Fatalf("AddKey failed: %v", err)
	}
	if len(keyIDs) == 0 {
		t.Fatal("no key IDs returned")
	}

	md := &tufmeta.Metadata[tufmeta.RootType]{}
	if _, err := md.FromFile(rootPath); err != nil {
		t.Fatalf("failed to parse root.json: %v", err)
	}
	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		if len(md.Signed.Roles[role].KeyIDs) == 0 {
			t.Fatalf("role %s has no key IDs after AddKey", role)
		}
	}
	if _, ok := md.Signed.Keys[keyIDs[0]]; !ok {
		t.Fatalf("added key ID %s not found in keys map", keyIDs[0])
	}
}

func TestSign(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	rootPath := filepath.Join(dir, "root.json")

	if err := Init(InitOptions{Path: rootPath, Version: 1}); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	if _, err := AddKey(AddKeyOptions{
		Path:     rootPath,
		KeyPaths: []string{keyPath},
		Roles:    []string{"root", "targets", "snapshot", "timestamp"},
	}); err != nil {
		t.Fatalf("AddKey failed: %v", err)
	}

	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		if err := SetThreshold(SetThresholdOptions{Path: rootPath, Role: role, Threshold: 1}); err != nil {
			t.Fatalf("SetThreshold failed for %s: %v", role, err)
		}
	}

	if err := Sign(SignOptions{Path: rootPath, KeyPaths: []string{keyPath}}); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	md := &tufmeta.Metadata[tufmeta.RootType]{}
	if _, err := md.FromFile(rootPath); err != nil {
		t.Fatalf("failed to parse root.json: %v", err)
	}
	if len(md.Signatures) == 0 {
		t.Fatal("expected at least one signature after Sign")
	}
}
