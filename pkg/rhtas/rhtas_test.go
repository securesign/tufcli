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

package rhtas

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

	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/securesign/tufcli/pkg/rootmeta"
)

func generateTestCert(t *testing.T, dir, name string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate cert key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"TestOrg"}, CommonName: "TestCN"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		IsCA:         true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	path := filepath.Join(dir, name)
	block := &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}
	return path
}

func setupTestRepo(t *testing.T) (dir, rootPath, keyPath, outDir string) {
	t.Helper()
	dir = t.TempDir()
	rootPath = filepath.Join(dir, "root.json")
	keyPath = filepath.Join(dir, "key.pem")

	if err := rootmeta.Init(rootmeta.InitOptions{Path: rootPath}); err != nil {
		t.Fatalf("failed to init root: %v", err)
	}
	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		if err := rootmeta.SetThreshold(rootmeta.SetThresholdOptions{Path: rootPath, Role: role, Threshold: 1}); err != nil {
			t.Fatalf("failed to set threshold: %v", err)
		}
	}
	if _, err := rootmeta.GenRsaKey(rootmeta.GenRsaKeyOptions{
		Path: rootPath, KeyPath: keyPath, Bits: 2048,
		Roles: []string{"root", "targets", "snapshot", "timestamp"},
	}); err != nil {
		t.Fatalf("failed to gen key: %v", err)
	}
	if err := rootmeta.Sign(rootmeta.SignOptions{Path: rootPath, KeyPaths: []string{keyPath}}); err != nil {
		t.Fatalf("failed to sign root: %v", err)
	}

	outDir = filepath.Join(dir, "repo")
	if err := os.MkdirAll(filepath.Join(outDir, "targets"), 0755); err != nil {
		t.Fatalf("failed to create output dir: %v", err)
	}

	return
}

func TestRun_Basic(t *testing.T) {
	dir, rootPath, keyPath, outDir := setupTestRepo(t)
	certPath := generateTestCert(t, dir, "fulcio.pem")

	err := Run(&Options{
		RootPath:     rootPath,
		KeyPaths:     []string{keyPath},
		OutDir:       outDir,
		FulcioTarget: certPath,
		FulcioURI:    "https://fulcio.test.dev",
		FulcioStatus: "Active",
		OIDCURIs:     []string{"https://oidc.test.dev"},
		Operator:     "test.dev",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	targetsPath := filepath.Join(outDir, "2.targets.json")
	if _, err := os.Stat(targetsPath); err != nil {
		t.Fatal("targets.json was not created")
	}

	md := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := md.FromFile(targetsPath); err != nil {
		t.Fatalf("failed to load targets.json: %v", err)
	}
	if _, ok := md.Signed.Targets["fulcio.pem"]; !ok {
		t.Fatal("fulcio.pem target not found")
	}
	if _, ok := md.Signed.Targets["trusted_root.json"]; !ok {
		t.Fatal("trusted_root.json target not found")
	}
	if _, ok := md.Signed.Targets["signing_config.v0.2.json"]; !ok {
		t.Fatal("signing_config.v0.2.json target not found")
	}

	if _, err := os.Stat(filepath.Join(outDir, "2.snapshot.json")); err != nil {
		t.Fatal("snapshot.json was not created")
	}
	if _, err := os.Stat(filepath.Join(outDir, "timestamp.json")); err != nil {
		t.Fatal("timestamp.json was not created")
	}
}
