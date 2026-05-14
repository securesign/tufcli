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

package sigstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// NOTE: DetectPublicKeyDetails was removed from this package and replaced by
// detectPublicKeyDetails in the rhtas package (uses sigstore/sigstore library).
// Tests for key detection now live in internal/rhtas/rhtas_test.go.

func writePEMFile(t *testing.T, dir, name string, pemType string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	block := &pem.Block{Type: pemType, Bytes: data}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatalf("failed to write PEM file: %v", err)
	}
	return path
}

func generateSelfSignedCert(t *testing.T, dir, name, org, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{org},
			CommonName:   cn,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		IsCA:      true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	return writePEMFile(t, dir, name, "CERTIFICATE", certBytes)
}

func generateECPublicKey(t *testing.T, dir, name string, curve elliptic.Curve) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	return writePEMFile(t, dir, name, "PUBLIC KEY", pubBytes)
}

func TestLoadDERBytes_SingleCert(t *testing.T) {
	dir := t.TempDir()
	certPath := generateSelfSignedCert(t, dir, "cert.pem", "TestOrg", "TestCN")

	derBlocks, err := LoadDERBytes(certPath)
	if err != nil {
		t.Fatalf("LoadDERBytes failed: %v", err)
	}
	if len(derBlocks) != 1 {
		t.Fatalf("expected 1 DER block, got %d", len(derBlocks))
	}
	if len(derBlocks[0]) == 0 {
		t.Fatal("DER block is empty")
	}
}

func TestLoadDERBytes_CertChain(t *testing.T) {
	dir := t.TempDir()

	// Create two certs and concatenate them
	key1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	cert1, _ := x509.CreateCertificate(rand.Reader, template, template, &key1.PublicKey, key1)
	template.SerialNumber = big.NewInt(2)
	cert2, _ := x509.CreateCertificate(rand.Reader, template, template, &key2.PublicKey, key2)

	chainPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert1})
	chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert2})...)

	path := filepath.Join(dir, "chain.pem")
	os.WriteFile(path, chainPEM, 0600)

	derBlocks, err := LoadDERBytes(path)
	if err != nil {
		t.Fatalf("LoadDERBytes failed: %v", err)
	}
	if len(derBlocks) != 2 {
		t.Fatalf("expected 2 DER blocks, got %d", len(derBlocks))
	}
}

func TestLoadDERBytes_NoPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notpem.txt")
	os.WriteFile(path, []byte("not a PEM file"), 0600)

	_, err := LoadDERBytes(path)
	if err == nil {
		t.Fatal("expected error for non-PEM file")
	}
}

func TestExtractSubjectFromCert(t *testing.T) {
	dir := t.TempDir()
	certPath := generateSelfSignedCert(t, dir, "cert.pem", "TestOrg", "TestCN")

	subject := ExtractSubjectFromCert(certPath)
	if subject.Organization != "TestOrg" {
		t.Fatalf("expected organization 'TestOrg', got %q", subject.Organization)
	}
	if subject.CommonName != "TestCN" {
		t.Fatalf("expected common name 'TestCN', got %q", subject.CommonName)
	}
}

func TestExtractSubjectFromCert_InvalidFile(t *testing.T) {
	subject := ExtractSubjectFromCert("/nonexistent/path")
	if subject.Organization != "" || subject.CommonName != "" {
		t.Fatal("expected empty subject for non-existent file")
	}
}

func TestExtractSubjectFromCert_NotACert(t *testing.T) {
	dir := t.TempDir()
	path := generateECPublicKey(t, dir, "key.pem", elliptic.P256())

	subject := ExtractSubjectFromCert(path)
	if subject.Organization != "" || subject.CommonName != "" {
		t.Fatal("expected empty subject for non-certificate PEM")
	}
}
