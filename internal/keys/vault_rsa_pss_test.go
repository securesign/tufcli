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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/sigstore/sigstore/pkg/signature"
)

func TestParseVaultRef(t *testing.T) {
	tests := []struct {
		ref     string
		want    string
		wantErr bool
	}{
		{"hashivault://mykey", "mykey", false},
		{"hashivault://tuf-rsa", "tuf-rsa", false},
		{"hashivault://my.key.name", "my.key.name", false},
		{"openbao://mykey", "mykey", false},
		{"invalid://mykey", "", true},
		{"hashivault://", "", true},
		{"", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			got, err := parseVaultRef(tt.ref)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseVaultRef(%q) error = %v, wantErr %v", tt.ref, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseVaultRef(%q) = %q, want %q", tt.ref, got, tt.want)
			}
		})
	}
}

func TestLoadVaultSigner_RSAKey_UsesWrapper(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	mock := &mockSigner{pubKey: &rsaKey.PublicKey}
	origLoader := vaultSignerLoader
	vaultSignerLoader = func(ref string, _ crypto.Hash) (signature.Signer, error) {
		if ref != "hashivault://test-rsa" {
			return nil, fmt.Errorf("unexpected ref: %s", ref)
		}
		return mock, nil
	}
	defer func() { vaultSignerLoader = origLoader }()

	origWrapper := newVaultRSAPSSSigner
	wrapperCalled := false
	newVaultRSAPSSSigner = func(inner signature.Signer, ref string) (signature.Signer, error) {
		wrapperCalled = true
		if ref != "hashivault://test-rsa" {
			t.Errorf("wrapper got unexpected ref: %s", ref)
		}
		return inner, nil
	}
	defer func() { newVaultRSAPSSSigner = origWrapper }()

	signer, tufKey, keyID, err := LoadVaultSigner("hashivault://test-rsa")
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
	if !wrapperCalled {
		t.Fatal("RSA-PSS wrapper was not called for RSA key")
	}
	if tufKey.Type != "rsa" {
		t.Errorf("expected key type 'rsa', got %q", tufKey.Type)
	}
	if tufKey.Scheme != "rsassa-pss-sha256" {
		t.Errorf("expected scheme 'rsassa-pss-sha256', got %q", tufKey.Scheme)
	}
}

func TestLoadVaultSigner_ECDSAKey_NoWrapper(t *testing.T) {
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

	origWrapper := newVaultRSAPSSSigner
	wrapperCalled := false
	newVaultRSAPSSSigner = func(inner signature.Signer, _ string) (signature.Signer, error) {
		wrapperCalled = true
		return inner, nil
	}
	defer func() { newVaultRSAPSSSigner = origWrapper }()

	_, _, _, err = LoadVaultSigner("hashivault://test-ecdsa")
	if err != nil {
		t.Fatalf("LoadVaultSigner failed: %v", err)
	}
	if wrapperCalled {
		t.Fatal("RSA-PSS wrapper should NOT be called for ECDSA key")
	}
}
