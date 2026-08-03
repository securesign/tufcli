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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"
)

// mockSigner implements signature.Signer for testing.
type mockSigner struct {
	pubKey crypto.PublicKey
}

func (m *mockSigner) PublicKey(_ ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return m.pubKey, nil
}

func (m *mockSigner) SignMessage(_ io.Reader, _ ...signature.SignOption) ([]byte, error) {
	return []byte("mock-signature"), nil
}

func TestLoadVaultSigner_ECDSAKey(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	mock := &mockSigner{pubKey: &ecKey.PublicKey}
	origLoader := vaultSignerLoader
	vaultSignerLoader = func(ref string, _ crypto.Hash) (signature.Signer, error) {
		if ref != "hashivault://test-key" {
			return nil, fmt.Errorf("unexpected ref: %s", ref)
		}
		return mock, nil
	}
	defer func() { vaultSignerLoader = origLoader }()

	signer, tufKey, keyID, err := LoadVaultSigner("hashivault://test-key")
	if err != nil {
		t.Fatalf("LoadVaultSigner failed: %v", err)
	}
	if signer == nil {
		t.Fatal("signer should not be nil")
	}
	if tufKey == nil {
		t.Fatal("tufKey should not be nil")
	}
	if keyID == "" {
		t.Fatal("keyID should not be empty")
	}

	// Verify key ID matches what ParsePublicKey would produce from the same key
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})
	_, expectedKeyID, err := ParsePublicKey(pemData)
	if err != nil {
		t.Fatal(err)
	}
	if keyID != expectedKeyID {
		t.Fatalf("key ID mismatch: vault=%s, file=%s", keyID, expectedKeyID)
	}
}

func TestLoadVaultSigner_Ed25519Key(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	mock := &mockSigner{pubKey: pubKey}
	origLoader := vaultSignerLoader
	callCount := 0
	vaultSignerLoader = func(ref string, hashFunc crypto.Hash) (signature.Signer, error) {
		callCount++
		if callCount == 1 && hashFunc != crypto.SHA256 {
			t.Errorf("first call should use SHA256, got %v", hashFunc)
		}
		if callCount == 2 && hashFunc != crypto.Hash(0) {
			t.Errorf("second call (Ed25519 reload) should use Hash(0), got %v", hashFunc)
		}
		return mock, nil
	}
	defer func() { vaultSignerLoader = origLoader }()

	signer, _, keyID, err := LoadVaultSigner("hashivault://ed-key")
	if err != nil {
		t.Fatalf("LoadVaultSigner failed: %v", err)
	}
	if signer == nil {
		t.Fatal("signer should not be nil")
	}
	if keyID == "" {
		t.Fatal("keyID should not be empty")
	}
	if callCount != 2 {
		t.Fatalf("expected 2 loader calls for Ed25519 (initial + reload), got %d", callCount)
	}
}

func TestLoadVaultSigner_Error(t *testing.T) {
	origLoader := vaultSignerLoader
	vaultSignerLoader = func(_ string, _ crypto.Hash) (signature.Signer, error) {
		return nil, fmt.Errorf("vault connection refused")
	}
	defer func() { vaultSignerLoader = origLoader }()

	_, _, _, err := LoadVaultSigner("hashivault://bad-key")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParseVaultPublicKey(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	mock := &mockSigner{pubKey: &ecKey.PublicKey}
	origLoader := vaultSignerLoader
	vaultSignerLoader = func(_ string, _ crypto.Hash) (signature.Signer, error) {
		return mock, nil
	}
	defer func() { vaultSignerLoader = origLoader }()

	tufKey, keyID, err := ParseVaultPublicKey("hashivault://test-key")
	if err != nil {
		t.Fatalf("ParseVaultPublicKey failed: %v", err)
	}
	if tufKey == nil {
		t.Fatal("tufKey should not be nil")
	}
	if keyID == "" {
		t.Fatal("keyID should not be empty")
	}

	// Key ID should match LoadVaultSigner
	_, _, signerKeyID, err := LoadVaultSigner("hashivault://test-key")
	if err != nil {
		t.Fatal(err)
	}
	if keyID != signerKeyID {
		t.Fatalf("key ID mismatch: ParseVaultPublicKey=%s, LoadVaultSigner=%s", keyID, signerKeyID)
	}
}

func TestParseVaultPublicKey_Error(t *testing.T) {
	origLoader := vaultSignerLoader
	vaultSignerLoader = func(_ string, _ crypto.Hash) (signature.Signer, error) {
		return nil, fmt.Errorf("vault unavailable")
	}
	defer func() { vaultSignerLoader = origLoader }()

	_, _, err := ParseVaultPublicKey("hashivault://bad")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadSignerSetFromAll(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeTestKey(t, dir)

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mock := &mockSigner{pubKey: &ecKey.PublicKey}
	origLoader := vaultSignerLoader
	vaultSignerLoader = func(_ string, _ crypto.Hash) (signature.Signer, error) {
		return mock, nil
	}
	defer func() { vaultSignerLoader = origLoader }()

	ss, err := LoadSignerSetFromAll([]string{keyPath}, []string{"hashivault://test"})
	if err != nil {
		t.Fatalf("LoadSignerSetFromAll failed: %v", err)
	}
	if len(ss.entries) != 2 {
		t.Fatalf("expected 2 entries (1 file + 1 vault), got %d", len(ss.entries))
	}
}

func TestLoadSignerSetFromAll_OnlyVault(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mock := &mockSigner{pubKey: &ecKey.PublicKey}
	origLoader := vaultSignerLoader
	vaultSignerLoader = func(_ string, _ crypto.Hash) (signature.Signer, error) {
		return mock, nil
	}
	defer func() { vaultSignerLoader = origLoader }()

	ss, err := LoadSignerSetFromAll(nil, []string{"hashivault://test"})
	if err != nil {
		t.Fatalf("LoadSignerSetFromAll failed: %v", err)
	}
	if len(ss.entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(ss.entries))
	}
}

func TestLoadSignerSetFromAll_OnlyFiles(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeTestKey(t, dir)

	ss, err := LoadSignerSetFromAll([]string{keyPath}, nil)
	if err != nil {
		t.Fatalf("LoadSignerSetFromAll failed: %v", err)
	}
	if len(ss.entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(ss.entries))
	}
}

func TestLoadSignerSetFromAll_VaultError(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeTestKey(t, dir)

	origLoader := vaultSignerLoader
	vaultSignerLoader = func(_ string, _ crypto.Hash) (signature.Signer, error) {
		return nil, fmt.Errorf("vault error")
	}
	defer func() { vaultSignerLoader = origLoader }()

	_, err := LoadSignerSetFromAll([]string{keyPath}, []string{"hashivault://bad"})
	if err == nil {
		t.Fatal("expected error from Vault signer")
	}
}

func TestSignForRole_WithVaultSigner(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Write the private key to file so we can compute the expected key ID
	privBytes, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatalf("failed to marshal EC private key: %v", err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}), 0600); err != nil {
		t.Fatalf("failed to write test key file: %v", err)
	}

	// Load from file to get the reference key ID
	_, _, expectedKeyID, err := LoadSigner(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	// Create a mock vault signer with the same public key
	mock := &mockSigner{pubKey: &ecKey.PublicKey}
	origLoader := vaultSignerLoader
	vaultSignerLoader = func(_ string, _ crypto.Hash) (signature.Signer, error) {
		return mock, nil
	}
	defer func() { vaultSignerLoader = origLoader }()

	ss, err := LoadSignerSetFromAll(nil, []string{"hashivault://test"})
	if err != nil {
		t.Fatal(err)
	}

	// The Vault signer's key ID should match the file-based key ID
	if ss.entries[0].keyID != expectedKeyID {
		t.Fatalf("vault key ID doesn't match file key ID: %s vs %s", ss.entries[0].keyID, expectedKeyID)
	}

	md := tufmeta.Targets(time.Now().AddDate(1, 0, 0))
	err = SignForRole(ss, md, "targets", []string{expectedKeyID})
	if err != nil {
		t.Fatalf("SignForRole with vault signer failed: %v", err)
	}
	if len(md.Signatures) == 0 {
		t.Fatal("expected at least one signature")
	}
	if md.Signatures[0].KeyID != expectedKeyID {
		t.Fatalf("signature keyID mismatch: got %s, want %s", md.Signatures[0].KeyID, expectedKeyID)
	}
}

func TestAddVaultSigners(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mock := &mockSigner{pubKey: &ecKey.PublicKey}
	origLoader := vaultSignerLoader
	vaultSignerLoader = func(_ string, _ crypto.Hash) (signature.Signer, error) {
		return mock, nil
	}
	defer func() { vaultSignerLoader = origLoader }()

	ss := &SignerSet{}
	err = ss.AddVaultSigners([]string{"hashivault://key1", "hashivault://key2"})
	if err != nil {
		t.Fatalf("AddVaultSigners failed: %v", err)
	}
	if len(ss.entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(ss.entries))
	}
}

func TestAddVaultSigners_Error(t *testing.T) {
	origLoader := vaultSignerLoader
	vaultSignerLoader = func(_ string, _ crypto.Hash) (signature.Signer, error) {
		return nil, fmt.Errorf("vault error")
	}
	defer func() { vaultSignerLoader = origLoader }()

	ss := &SignerSet{}
	err := ss.AddVaultSigners([]string{"hashivault://bad"})
	if err == nil {
		t.Fatal("expected error")
	}
}
