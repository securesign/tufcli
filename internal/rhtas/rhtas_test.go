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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	commonpb "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/securesign/tufcli/internal/editor"
	"github.com/securesign/tufcli/internal/keys"
	"github.com/securesign/tufcli/internal/root"
	"github.com/securesign/tufcli/internal/sigstore"
	"github.com/securesign/tufcli/internal/utils"
)

func generateTestKey(t *testing.T, dir string) string {
	t.Helper()
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

func generateTestCert(t *testing.T, dir, name string) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"TestOrg"}, CommonName: "TestCN"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		IsCA:         true,
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	path := filepath.Join(dir, name)
	block := &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}
	os.WriteFile(path, pem.EncodeToMemory(block), 0600)
	return path
}

func generateTestPublicKey(t *testing.T, dir, name string) string {
	t.Helper()
	return generateTestPublicKeyWithCurve(t, dir, name, elliptic.P256())
}

func generateTestPublicKeyWithCurve(t *testing.T, dir, name string, curve elliptic.Curve) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(curve, rand.Reader)
	pubBytes, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	path := filepath.Join(dir, name)
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}
	os.WriteFile(path, pem.EncodeToMemory(block), 0600)
	return path
}

func setupTestRepo(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()

	keyPath := generateTestKey(t, dir)

	rootPath := filepath.Join(dir, "root.json")
	err := root.Init(root.InitOptions{
		Path:    rootPath,
		Version: 1,
	})
	if err != nil {
		t.Fatalf("failed to init root.json: %v", err)
	}

	// Add the generated key to all roles
	_, err = root.AddKey(root.AddKeyOptions{
		Path:     rootPath,
		KeyPaths: []string{keyPath},
		Roles:    []string{"root", "targets", "snapshot", "timestamp"},
	})
	if err != nil {
		t.Fatalf("failed to add key to roles: %v", err)
	}

	// Set a low threshold and future expiry so signing works
	md := &tufmeta.Metadata[tufmeta.RootType]{}
	if _, err := md.FromFile(rootPath); err != nil {
		t.Fatalf("failed to load root.json: %v", err)
	}
	for role := range md.Signed.Roles {
		md.Signed.Roles[role].Threshold = 1
	}
	md.Signed.Expires = time.Now().AddDate(1, 0, 0)

	signer, _, keyID, err := keys.LoadSigner(keyPath, nil)
	if err != nil {
		t.Fatalf("failed to load signer: %v", err)
	}
	md.ClearSignatures()
	if _, err := md.Sign(signer); err != nil {
		t.Fatalf("failed to sign root: %v", err)
	}
	if len(md.Signatures) > 0 {
		md.Signatures[len(md.Signatures)-1].KeyID = keyID
	}

	data, err := md.ToBytes(true)
	if err != nil {
		t.Fatalf("failed to serialize root.json: %v", err)
	}
	if err := utils.WriteFileAtomic(rootPath, data); err != nil {
		t.Fatalf("failed to write root.json: %v", err)
	}

	outDir := filepath.Join(dir, "repo")
	os.MkdirAll(filepath.Join(outDir, "targets"), 0755)

	return dir, rootPath, outDir
}

func TestValidateAndSetDefaults_Defaults(t *testing.T) {
	opts := &Options{
		FulcioTarget: "/tmp/fulcio.pem",
	}
	if err := opts.ValidateAndSetDefaults(); err != nil {
		t.Fatalf("ValidateAndSetDefaults failed: %v", err)
	}
	if opts.FulcioURI != "https://fulcio.sigstore.dev" {
		t.Fatalf("expected default Fulcio URI, got %q", opts.FulcioURI)
	}
	if opts.FulcioStatus != "Active" {
		t.Fatalf("expected default Fulcio status 'Active', got %q", opts.FulcioStatus)
	}
	if len(opts.OIDCURIs) != 1 || opts.OIDCURIs[0] != "https://oauth2.sigstore.dev/auth" {
		t.Fatalf("expected default OIDC URI, got %v", opts.OIDCURIs)
	}
	if opts.Operator != "sigstore.dev" {
		t.Fatalf("expected default operator, got %q", opts.Operator)
	}
}

func TestValidateAndSetDefaults_CtlogDefaults(t *testing.T) {
	opts := &Options{
		CtlogTarget: "/tmp/ctlog.pem",
	}
	opts.ValidateAndSetDefaults()
	if opts.CtlogURI != "https://ctfe.sigstore.dev/test" {
		t.Fatalf("expected default CTLog URI, got %q", opts.CtlogURI)
	}
	if opts.CtlogStatus != "Active" {
		t.Fatalf("expected default CTLog status, got %q", opts.CtlogStatus)
	}
}

func TestValidateAndSetDefaults_RekorDefaults(t *testing.T) {
	opts := &Options{
		RekorTarget: "/tmp/rekor.pem",
	}
	opts.ValidateAndSetDefaults()
	if opts.RekorURI != "https://rekor.sigstore.dev" {
		t.Fatalf("expected default Rekor URI, got %q", opts.RekorURI)
	}
}

func TestValidateAndSetDefaults_CrossServiceValidation(t *testing.T) {
	opts := &Options{
		FulcioTarget: "/tmp/fulcio.pem",
		CtlogURI:     "https://ctlog.dev",
	}
	err := opts.ValidateAndSetDefaults()
	if err == nil {
		t.Fatal("expected error for cross-service flag mixing")
	}
}

func TestValidateAndSetDefaults_ForceVersionRequired(t *testing.T) {
	v := int64(5)
	opts := &Options{
		TargetsVersion: &v,
	}
	err := opts.ValidateAndSetDefaults()
	if err == nil {
		t.Fatal("expected error when version flags used without --force-version")
	}
}

func TestValidateAndSetDefaults_ForceVersionOK(t *testing.T) {
	v := int64(5)
	opts := &Options{
		TargetsVersion: &v,
		ForceVersion:   true,
	}
	err := opts.ValidateAndSetDefaults()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRun_SetFulcioTarget(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	certPath := generateTestCert(t, dir, "fulcio.pem")
	keyPath := filepath.Join(dir, "key.pem")

	opts := &Options{
		RootPath:     rootPath,
		KeyPaths:     []string{keyPath},
		OutDir:       outDir,
		FulcioTarget: certPath,
		FulcioURI:    "https://fulcio.test.dev",
		FulcioStatus: "Active",
		OIDCURIs:     []string{"https://oidc.test.dev"},
		Operator:     "test.dev",
	}

	if err := Run(opts); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// Verify targets.json was created
	targetsPath := filepath.Join(outDir, "2.targets.json")
	if !utils.FileExists(targetsPath) {
		t.Fatal("targets.json was not created")
	}

	// Verify snapshot.json was created
	snapshotPath := filepath.Join(outDir, "2.snapshot.json")
	if !utils.FileExists(snapshotPath) {
		t.Fatal("snapshot.json was not created")
	}

	// Verify timestamp.json was created
	timestampPath := filepath.Join(outDir, "timestamp.json")
	if !utils.FileExists(timestampPath) {
		t.Fatal("timestamp.json was not created")
	}

	// Verify targets content
	md := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := md.FromFile(targetsPath); err != nil {
		t.Fatalf("failed to load targets.json: %v", err)
	}
	if _, ok := md.Signed.Targets["fulcio.pem"]; !ok {
		t.Fatal("fulcio.pem target not found in targets.json")
	}
	if _, ok := md.Signed.Targets["trusted_root.json"]; !ok {
		t.Fatal("trusted_root.json target not found in targets.json")
	}
	if _, ok := md.Signed.Targets["signing_config.v0.2.json"]; !ok {
		t.Fatal("signing_config.v0.2.json target not found in targets.json")
	}

	// Check custom metadata
	fulcioTarget := md.Signed.Targets["fulcio.pem"]
	if fulcioTarget.Custom == nil {
		t.Fatal("sigstore custom metadata missing")
	}
	var customMap map[string]interface{}
	if err := json.Unmarshal(*fulcioTarget.Custom, &customMap); err != nil {
		t.Fatalf("failed to unmarshal custom metadata: %v", err)
	}
	sigstoreCustom, ok := customMap["sigstore"].(map[string]interface{})
	if !ok {
		t.Fatal("sigstore custom metadata missing")
	}
	if sigstoreCustom["usage"] != "Fulcio" {
		t.Fatalf("expected usage 'Fulcio', got %v", sigstoreCustom["usage"])
	}
	if sigstoreCustom["status"] != "Active" {
		t.Fatalf("expected status 'Active', got %v", sigstoreCustom["status"])
	}

	// Verify signatures
	if len(md.Signatures) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(md.Signatures))
	}
}

func TestRun_SetCtlogTarget(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	pubKeyPath := generateTestPublicKey(t, dir, "ctlog.pub")

	opts := &Options{
		RootPath:    rootPath,
		KeyPaths:    []string{keyPath},
		OutDir:      outDir,
		CtlogTarget: pubKeyPath,
		CtlogURI:    "https://ctlog.test.dev",
		CtlogStatus: "Active",
		Operator:    "test.dev",
	}

	if err := Run(opts); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	targetsPath := filepath.Join(outDir, "2.targets.json")
	md := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := md.FromFile(targetsPath); err != nil {
		t.Fatalf("failed to load targets.json: %v", err)
	}

	if _, ok := md.Signed.Targets["ctlog.pub"]; !ok {
		t.Fatal("ctlog.pub target not found")
	}
}

func TestRun_SetRekorTarget(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	pubKeyPath := generateTestPublicKey(t, dir, "rekor.pub")

	opts := &Options{
		RootPath:    rootPath,
		KeyPaths:    []string{keyPath},
		OutDir:      outDir,
		RekorTarget: pubKeyPath,
		RekorURI:    "https://rekor.test.dev",
		RekorStatus: "Active",
		Operator:    "test.dev",
	}

	if err := Run(opts); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	targetsPath := filepath.Join(outDir, "2.targets.json")
	md := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := md.FromFile(targetsPath); err != nil {
		t.Fatalf("failed to load targets.json: %v", err)
	}

	if _, ok := md.Signed.Targets["rekor.pub"]; !ok {
		t.Fatal("rekor.pub target not found")
	}
}

func TestRun_SetTsaTarget(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	certPath := generateTestCert(t, dir, "tsa.pem")

	opts := &Options{
		RootPath:  rootPath,
		KeyPaths:  []string{keyPath},
		OutDir:    outDir,
		TsaTarget: certPath,
		TsaURI:    "https://tsa.test.dev",
		TsaStatus: "Active",
		Operator:  "test.dev",
	}

	if err := Run(opts); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	targetsPath := filepath.Join(outDir, "2.targets.json")
	md := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := md.FromFile(targetsPath); err != nil {
		t.Fatalf("failed to load targets.json: %v", err)
	}

	if _, ok := md.Signed.Targets["tsa.pem"]; !ok {
		t.Fatal("tsa.pem target not found")
	}
}

func TestRun_VersionBumping(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	certPath := generateTestCert(t, dir, "fulcio.pem")

	opts := &Options{
		RootPath:     rootPath,
		KeyPaths:     []string{keyPath},
		OutDir:       outDir,
		FulcioTarget: certPath,
	}

	Run(opts)

	// Check versions were bumped from default (1) to 2
	targetsMd := &tufmeta.Metadata[tufmeta.TargetsType]{}
	targetsMd.FromFile(filepath.Join(outDir, "2.targets.json"))
	if targetsMd.Signed.Version != 2 {
		t.Fatalf("expected targets version 2, got %d", targetsMd.Signed.Version)
	}

	snapshotMd := &tufmeta.Metadata[tufmeta.SnapshotType]{}
	snapshotMd.FromFile(filepath.Join(outDir, "2.snapshot.json"))
	if snapshotMd.Signed.Version != 2 {
		t.Fatalf("expected snapshot version 2, got %d", snapshotMd.Signed.Version)
	}

	timestampMd := &tufmeta.Metadata[tufmeta.TimestampType]{}
	timestampMd.FromFile(filepath.Join(outDir, "timestamp.json"))
	if timestampMd.Signed.Version != 2 {
		t.Fatalf("expected timestamp version 2, got %d", timestampMd.Signed.Version)
	}
}

func TestRun_ForceVersion(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	certPath := generateTestCert(t, dir, "fulcio.pem")

	tv := int64(10)
	sv := int64(20)
	tsv := int64(30)

	opts := &Options{
		RootPath:         rootPath,
		KeyPaths:         []string{keyPath},
		OutDir:           outDir,
		FulcioTarget:     certPath,
		ForceVersion:     true,
		TargetsVersion:   &tv,
		SnapshotVersion:  &sv,
		TimestampVersion: &tsv,
	}

	if err := Run(opts); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	md := &tufmeta.Metadata[tufmeta.TargetsType]{}
	md.FromFile(filepath.Join(outDir, "10.targets.json"))
	if md.Signed.Version != 10 {
		t.Fatalf("expected targets version 10, got %d", md.Signed.Version)
	}
}

func TestRun_InvalidStatus(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	certPath := generateTestCert(t, dir, "fulcio.pem")

	opts := &Options{
		RootPath:     rootPath,
		KeyPaths:     []string{keyPath},
		OutDir:       outDir,
		FulcioTarget: certPath,
		FulcioStatus: "Invalid",
	}

	err := Run(opts)
	if err == nil {
		t.Fatal("expected error for invalid status")
	}
}

// --- Validation tests for new flags ---

func TestValidateAndSetDefaults_TargetPathExists(t *testing.T) {
	// Empty defaults to "skip"
	opts := &Options{TargetPathExists: ""}
	if err := opts.ValidateAndSetDefaults(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.TargetPathExists != "skip" {
		t.Fatalf("expected default 'skip', got %q", opts.TargetPathExists)
	}

	// "replace" accepted
	opts = &Options{TargetPathExists: "replace"}
	if err := opts.ValidateAndSetDefaults(); err != nil {
		t.Fatalf("unexpected error for 'replace': %v", err)
	}

	// "fail" accepted
	opts = &Options{TargetPathExists: "fail"}
	if err := opts.ValidateAndSetDefaults(); err != nil {
		t.Fatalf("unexpected error for 'fail': %v", err)
	}

	// Invalid value rejected
	opts = &Options{TargetPathExists: "bogus"}
	if err := opts.ValidateAndSetDefaults(); err == nil {
		t.Fatal("expected error for invalid target-path-exists value")
	}
}

func TestValidateAndSetDefaults_IncomingMetadataRole(t *testing.T) {
	// Both set — OK
	opts := &Options{IncomingMetadata: "/tmp/delegated.json", DelegatedRole: "releases"}
	if err := opts.ValidateAndSetDefaults(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Neither set — OK
	opts = &Options{}
	if err := opts.ValidateAndSetDefaults(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only IncomingMetadata — error
	opts = &Options{IncomingMetadata: "/tmp/delegated.json"}
	if err := opts.ValidateAndSetDefaults(); err == nil {
		t.Fatal("expected error for IncomingMetadata without DelegatedRole")
	}

	// Only DelegatedRole — error
	opts = &Options{DelegatedRole: "releases"}
	if err := opts.ValidateAndSetDefaults(); err == nil {
		t.Fatal("expected error for DelegatedRole without IncomingMetadata")
	}
}

func TestValidateAndSetDefaults_MetadataURL(t *testing.T) {
	// file:// accepted
	opts := &Options{MetadataURL: "file:///tmp/repo"}
	if err := opts.ValidateAndSetDefaults(); err != nil {
		t.Fatalf("unexpected error for file:// URL: %v", err)
	}

	// https:// accepted
	opts = &Options{MetadataURL: "https://example.com/repo"}
	if err := opts.ValidateAndSetDefaults(); err != nil {
		t.Fatalf("unexpected error for https:// URL: %v", err)
	}

	// http:// accepted
	opts = &Options{MetadataURL: "http://example.com/repo"}
	if err := opts.ValidateAndSetDefaults(); err != nil {
		t.Fatalf("unexpected error for http:// URL: %v", err)
	}

	// Invalid scheme rejected
	opts = &Options{MetadataURL: "ftp://example.com/repo"}
	if err := opts.ValidateAndSetDefaults(); err == nil {
		t.Fatal("expected error for invalid URL scheme")
	}
}

// --- Integration tests for new flags ---

func TestRun_MetadataURL_FileScheme(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	certPath := generateTestCert(t, dir, "fulcio.pem")

	// First run: produce a repo
	opts := &Options{
		RootPath:         rootPath,
		KeyPaths:         []string{keyPath},
		OutDir:           outDir,
		FulcioTarget:     certPath,
		TargetPathExists: "replace",
	}
	if err := Run(opts); err != nil {
		t.Fatalf("first Run failed: %v", err)
	}

	// Second run: use file:// URL pointing to first repo, output to a fresh dir
	outDir2 := filepath.Join(dir, "repo2")
	os.MkdirAll(outDir2, 0755)

	opts2 := &Options{
		RootPath:         rootPath,
		KeyPaths:         []string{keyPath},
		OutDir:           outDir2,
		MetadataURL:      "file://" + outDir,
		FulcioTarget:     certPath,
		TargetPathExists: "replace",
	}
	if err := Run(opts2); err != nil {
		t.Fatalf("second Run with metadata-url failed: %v", err)
	}

	// Verify the targets version was bumped from 2 to 3 (loaded v2 from first repo, bumped)
	targetsPath := filepath.Join(outDir2, "3.targets.json")
	if !utils.FileExists(targetsPath) {
		t.Fatal("expected 3.targets.json in second repo")
	}
	md := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := md.FromFile(targetsPath); err != nil {
		t.Fatalf("failed to load targets: %v", err)
	}
	if md.Signed.Version != 3 {
		t.Fatalf("expected targets version 3, got %d", md.Signed.Version)
	}
}

func TestRun_AllowExpiredRepo(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	certPath := generateTestCert(t, dir, "fulcio.pem")

	// First run: create repo
	opts := &Options{
		RootPath:         rootPath,
		KeyPaths:         []string{keyPath},
		OutDir:           outDir,
		FulcioTarget:     certPath,
		TargetPathExists: "replace",
	}
	if err := Run(opts); err != nil {
		t.Fatalf("first Run failed: %v", err)
	}

	// Set all metadata expiration to the past
	setExpiredMetadata(t, outDir)

	// Run without --allow-expired-repo: should fail
	certPath2 := generateTestCert(t, dir, "fulcio2.pem")
	opts2 := &Options{
		RootPath:         rootPath,
		KeyPaths:         []string{keyPath},
		OutDir:           outDir,
		FulcioTarget:     certPath2,
		TargetPathExists: "replace",
	}
	err := Run(opts2)
	if err == nil {
		t.Fatal("expected error for expired metadata")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected 'expired' in error, got: %v", err)
	}

	// Run with --allow-expired-repo: should succeed
	opts2.AllowExpiredRepo = true
	if err := Run(opts2); err != nil {
		t.Fatalf("Run with AllowExpiredRepo failed: %v", err)
	}
}

func setExpiredMetadata(t *testing.T, dir string) {
	t.Helper()
	past := time.Now().Add(-24 * time.Hour)

	// Expire targets
	targetsMd := &tufmeta.Metadata[tufmeta.TargetsType]{}
	targetsPath, _, _ := editor.FindLatestVersionedFile(dir, "targets.json")
	if _, err := targetsMd.FromFile(targetsPath); err != nil {
		t.Fatalf("failed to load targets: %v", err)
	}
	targetsMd.Signed.Expires = past
	targetsMd.ClearSignatures()
	data, _ := targetsMd.ToBytes(true)
	os.WriteFile(targetsPath, data, 0600)

	// Expire snapshot
	snapMd := &tufmeta.Metadata[tufmeta.SnapshotType]{}
	snapPath, _, _ := editor.FindLatestVersionedFile(dir, "snapshot.json")
	if _, err := snapMd.FromFile(snapPath); err != nil {
		t.Fatalf("failed to load snapshot: %v", err)
	}
	snapMd.Signed.Expires = past
	snapMd.ClearSignatures()
	data, _ = snapMd.ToBytes(true)
	os.WriteFile(snapPath, data, 0600)

	// Expire timestamp
	tsMd := &tufmeta.Metadata[tufmeta.TimestampType]{}
	tsPath := filepath.Join(dir, "timestamp.json")
	if _, err := tsMd.FromFile(tsPath); err != nil {
		t.Fatalf("failed to load timestamp: %v", err)
	}
	tsMd.Signed.Expires = past
	tsMd.ClearSignatures()
	data, _ = tsMd.ToBytes(true)
	os.WriteFile(tsPath, data, 0600)
}

func TestRun_Follow_RejectsSymlink(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	certPath := generateTestCert(t, dir, "fulcio-real.pem")

	// Create symlink
	symlinkPath := filepath.Join(dir, "fulcio-link.pem")
	if err := os.Symlink(certPath, symlinkPath); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	// Without --follow: should fail
	opts := &Options{
		RootPath:         rootPath,
		KeyPaths:         []string{keyPath},
		OutDir:           outDir,
		FulcioTarget:     symlinkPath,
		Follow:           false,
		TargetPathExists: "replace",
	}
	err := Run(opts)
	if err == nil {
		t.Fatal("expected error for symlink without --follow")
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("expected 'symbolic link' in error, got: %v", err)
	}

	// With --follow: should succeed
	opts.Follow = true
	if err := Run(opts); err != nil {
		t.Fatalf("Run with Follow failed: %v", err)
	}
}

func TestRun_TargetPathExists_Skip(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	certPath := generateTestCert(t, dir, "fulcio.pem")

	// First run
	opts := &Options{
		RootPath:         rootPath,
		KeyPaths:         []string{keyPath},
		OutDir:           outDir,
		FulcioTarget:     certPath,
		TargetPathExists: "replace",
	}
	if err := Run(opts); err != nil {
		t.Fatalf("first Run failed: %v", err)
	}

	// Record file content - find the hash-prefixed file
	targetsDir := filepath.Join(outDir, "targets")
	entries, err := os.ReadDir(targetsDir)
	if err != nil {
		t.Fatalf("failed to read targets directory: %v", err)
	}
	var targetFile string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".fulcio.pem") {
			targetFile = filepath.Join(targetsDir, entry.Name())
			break
		}
	}
	if targetFile == "" {
		t.Fatal("hash-prefixed fulcio.pem not found in targets directory")
	}
	originalData, err := os.ReadFile(targetFile)
	if err != nil {
		t.Fatalf("failed to read target file: %v", err)
	}

	// Generate different cert
	certPath2 := generateTestCert(t, dir, "fulcio-new.pem")
	// Copy over the original name so it targets the same name
	newData, _ := os.ReadFile(certPath2)
	os.WriteFile(certPath2, newData, 0600)

	// Second run with "skip"
	opts2 := &Options{
		RootPath:         rootPath,
		KeyPaths:         []string{keyPath},
		OutDir:           outDir,
		FulcioTarget:     certPath,
		TargetPathExists: "skip",
	}
	if err := Run(opts2); err != nil {
		t.Fatalf("second Run with skip failed: %v", err)
	}

	// File should be unchanged
	afterData, _ := os.ReadFile(targetFile)
	if string(afterData) != string(originalData) {
		t.Fatal("target file was modified despite skip policy")
	}
}

func TestRun_TargetPathExists_Fail(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	certPath := generateTestCert(t, dir, "fulcio.pem")

	// First run
	opts := &Options{
		RootPath:         rootPath,
		KeyPaths:         []string{keyPath},
		OutDir:           outDir,
		FulcioTarget:     certPath,
		TargetPathExists: "replace",
	}
	if err := Run(opts); err != nil {
		t.Fatalf("first Run failed: %v", err)
	}

	// Second run with "fail"
	opts.TargetPathExists = "fail"
	err := Run(opts)
	if err == nil {
		t.Fatal("expected error for existing target with fail policy")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected 'already exists' in error, got: %v", err)
	}
}

func TestRun_TargetPathExists_Replace(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	certPath := generateTestCert(t, dir, "fulcio.pem")

	// First run
	opts := &Options{
		RootPath:         rootPath,
		KeyPaths:         []string{keyPath},
		OutDir:           outDir,
		FulcioTarget:     certPath,
		TargetPathExists: "replace",
	}
	if err := Run(opts); err != nil {
		t.Fatalf("first Run failed: %v", err)
	}

	// Second run with "replace" — should succeed
	if err := Run(opts); err != nil {
		t.Fatalf("second Run with replace failed: %v", err)
	}
}

func TestRun_IncomingMetadata(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	certPath := generateTestCert(t, dir, "fulcio.pem")

	// Create the actual target file and compute its hash
	targetContent := []byte("delegated artifact content")
	targetsDir := filepath.Join(outDir, "targets")
	if err := os.MkdirAll(targetsDir, 0755); err != nil {
		t.Fatalf("failed to create targets dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(targetsDir, "delegated-artifact.txt"), targetContent, 0600); err != nil {
		t.Fatalf("failed to write target file: %v", err)
	}

	hash, err := utils.HashFile(filepath.Join(targetsDir, "delegated-artifact.txt"))
	if err != nil {
		t.Fatalf("failed to hash target file: %v", err)
	}
	hashBytes, err := hex.DecodeString(hash)
	if err != nil {
		t.Fatalf("failed to decode hash: %v", err)
	}

	delegatedMd := tufmeta.Targets(time.Now().UTC().AddDate(0, 0, 365))
	delegatedTf := &tufmeta.TargetFiles{
		Length: int64(len(targetContent)),
		Hashes: tufmeta.Hashes{"sha256": hashBytes},
	}
	delegatedMd.Signed.Targets["delegated-artifact.txt"] = delegatedTf

	delegatedData, err := delegatedMd.ToBytes(true)
	if err != nil {
		t.Fatalf("failed to serialize delegated metadata: %v", err)
	}
	delegatedPath := filepath.Join(dir, "delegated.json")
	os.WriteFile(delegatedPath, delegatedData, 0600)

	opts := &Options{
		RootPath:         rootPath,
		KeyPaths:         []string{keyPath},
		OutDir:           outDir,
		FulcioTarget:     certPath,
		IncomingMetadata: delegatedPath,
		DelegatedRole:    "releases",
		TargetPathExists: "replace",
	}
	if err := Run(opts); err != nil {
		t.Fatalf("Run with IncomingMetadata failed: %v", err)
	}

	// Verify delegated target appears in targets.json
	targetsPath := filepath.Join(outDir, "2.targets.json")
	md := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := md.FromFile(targetsPath); err != nil {
		t.Fatalf("failed to load targets: %v", err)
	}
	if _, ok := md.Signed.Targets["delegated-artifact.txt"]; !ok {
		t.Fatal("delegated-artifact.txt not found in targets")
	}
}

// --- Delete target integration tests ---

func TestRun_DeleteFulcioTarget(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	certPath := generateTestCert(t, dir, "fulcio.pem")

	opts := &Options{
		RootPath:         rootPath,
		KeyPaths:         []string{keyPath},
		OutDir:           outDir,
		FulcioTarget:     certPath,
		FulcioURI:        "https://fulcio.test.dev",
		OIDCURIs:         []string{"https://oidc.test.dev"},
		Operator:         "test.dev",
		TargetPathExists: "replace",
	}
	if err := Run(opts); err != nil {
		t.Fatalf("set Run failed: %v", err)
	}

	// Verify target exists
	md := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := md.FromFile(filepath.Join(outDir, "2.targets.json")); err != nil {
		t.Fatalf("failed to load targets: %v", err)
	}
	if _, ok := md.Signed.Targets["fulcio.pem"]; !ok {
		t.Fatal("fulcio.pem should exist before delete")
	}

	// Delete the target
	deleteOpts := &Options{
		RootPath:            rootPath,
		KeyPaths:            []string{keyPath},
		OutDir:              outDir,
		DeleteFulcioTargets: []string{"fulcio.pem"},
		TargetPathExists:    "replace",
	}
	if err := Run(deleteOpts); err != nil {
		t.Fatalf("delete Run failed: %v", err)
	}

	// Verify target is removed
	md = &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := md.FromFile(filepath.Join(outDir, "3.targets.json")); err != nil {
		t.Fatalf("failed to load targets after delete: %v", err)
	}
	if _, ok := md.Signed.Targets["fulcio.pem"]; ok {
		t.Fatal("fulcio.pem should be removed after delete")
	}
	if _, ok := md.Signed.Targets["trusted_root.json"]; !ok {
		t.Fatal("trusted_root.json should still be present")
	}
}

func TestRun_DeleteFulcioTarget_UnauthorizedKeyKeepsRepositoryUnchanged(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	certPath := generateTestCert(t, dir, "fulcio.pem")

	if err := Run(&Options{
		RootPath:         rootPath,
		KeyPaths:         []string{keyPath},
		OutDir:           outDir,
		FulcioTarget:     certPath,
		FulcioURI:        "https://fulcio.test.dev",
		OIDCURIs:         []string{"https://oidc.test.dev"},
		TargetPathExists: "replace",
	}); err != nil {
		t.Fatalf("set Run failed: %v", err)
	}

	targetsPath, _, err := editor.FindLatestVersionedFile(outDir, "targets.json")
	if err != nil {
		t.Fatalf("find latest targets metadata: %v", err)
	}
	metadataBefore, err := os.ReadFile(targetsPath)
	if err != nil {
		t.Fatalf("read targets metadata before failed delete: %v", err)
	}

	targetsMd := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := targetsMd.FromBytes(metadataBefore); err != nil {
		t.Fatalf("parse targets metadata: %v", err)
	}
	targetMeta := targetsMd.Signed.Targets["fulcio.pem"]
	hashStr, err := utils.PreferredHash(targetMeta.Hashes)
	if err != nil {
		t.Fatalf("get target hash: %v", err)
	}
	targetPath := filepath.Join(outDir, "targets", hashStr+".fulcio.pem")
	targetBefore, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("read target before failed delete: %v", err)
	}

	wrongKeyPath := generateTestKey(t, t.TempDir())
	err = Run(&Options{
		RootPath:            rootPath,
		KeyPaths:            []string{wrongKeyPath},
		OutDir:              outDir,
		DeleteFulcioTargets: []string{"fulcio.pem"},
		TargetPathExists:    "replace",
	})
	if err == nil {
		t.Fatal("delete with unauthorized key should fail")
	}

	metadataAfter, err := os.ReadFile(targetsPath)
	if err != nil {
		t.Fatalf("read targets metadata after failed delete: %v", err)
	}
	if string(metadataAfter) != string(metadataBefore) {
		t.Fatal("targets metadata changed after failed delete")
	}
	targetsAfter := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := targetsAfter.FromBytes(metadataAfter); err != nil {
		t.Fatalf("parse targets metadata after failed delete: %v", err)
	}
	if _, ok := targetsAfter.Signed.Targets["fulcio.pem"]; !ok {
		t.Fatal("failed delete removed the target metadata reference")
	}

	targetAfter, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("target file should remain after failed delete: %v", err)
	}
	if string(targetAfter) != string(targetBefore) {
		t.Fatal("target file contents changed after failed delete")
	}
}

func TestRun_DeleteAndReAddIdenticalFulcioTargetKeepsTargetFile(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	certPath := generateTestCert(t, dir, "fulcio.pem")

	if err := Run(&Options{
		RootPath:         rootPath,
		KeyPaths:         []string{keyPath},
		OutDir:           outDir,
		FulcioTarget:     certPath,
		FulcioURI:        "https://fulcio.before.example",
		FulcioStatus:     "Active",
		OIDCURIs:         []string{"https://oidc.before.example"},
		TargetPathExists: "replace",
	}); err != nil {
		t.Fatalf("initial set Run failed: %v", err)
	}

	initialTargetsPath, _, err := editor.FindLatestVersionedFile(outDir, "targets.json")
	if err != nil {
		t.Fatalf("find initial targets metadata: %v", err)
	}
	initialTargets := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := initialTargets.FromFile(initialTargetsPath); err != nil {
		t.Fatalf("load initial targets metadata: %v", err)
	}
	initialTarget := initialTargets.Signed.Targets["fulcio.pem"]
	initialHash, err := utils.PreferredHash(initialTarget.Hashes)
	if err != nil {
		t.Fatalf("get initial target hash: %v", err)
	}
	initialTargetPath := filepath.Join(outDir, "targets", initialHash+".fulcio.pem")
	initialData, err := os.ReadFile(initialTargetPath)
	if err != nil {
		t.Fatalf("read initial target file: %v", err)
	}

	if err := Run(&Options{
		RootPath:            rootPath,
		KeyPaths:            []string{keyPath},
		OutDir:              outDir,
		FulcioTarget:        certPath,
		FulcioURI:           "https://fulcio.after.example",
		FulcioStatus:        "Expired",
		OIDCURIs:            []string{"https://oidc.after.example"},
		DeleteFulcioTargets: []string{"fulcio.pem"},
		TargetPathExists:    "replace",
	}); err != nil {
		t.Fatalf("delete and re-add Run failed: %v", err)
	}

	finalTargetsPath, _, err := editor.FindLatestVersionedFile(outDir, "targets.json")
	if err != nil {
		t.Fatalf("find final targets metadata: %v", err)
	}
	finalTargets := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := finalTargets.FromFile(finalTargetsPath); err != nil {
		t.Fatalf("load final targets metadata: %v", err)
	}
	finalTarget, ok := finalTargets.Signed.Targets["fulcio.pem"]
	if !ok {
		t.Fatal("fulcio.pem should remain in final targets metadata")
	}
	finalHash, err := utils.PreferredHash(finalTarget.Hashes)
	if err != nil {
		t.Fatalf("get final target hash: %v", err)
	}
	if finalHash != initialHash {
		t.Fatalf("final target hash = %q, want unchanged hash %q", finalHash, initialHash)
	}

	finalTargetPath := filepath.Join(outDir, "targets", finalHash+".fulcio.pem")
	finalData, err := os.ReadFile(finalTargetPath)
	if err != nil {
		t.Fatalf("re-added target file should remain available: %v", err)
	}
	if string(finalData) != string(initialData) {
		t.Fatal("re-added target file contents changed")
	}

	if finalTarget.Custom == nil {
		t.Fatal("final Fulcio custom metadata is missing")
	}
	var custom map[string]interface{}
	if err := json.Unmarshal(*finalTarget.Custom, &custom); err != nil {
		t.Fatalf("parse final Fulcio custom metadata: %v", err)
	}
	sigstoreCustom, ok := custom["sigstore"].(map[string]interface{})
	if !ok {
		t.Fatal("final sigstore custom metadata is missing")
	}
	if sigstoreCustom["uri"] != "https://fulcio.after.example" || sigstoreCustom["status"] != "Expired" {
		t.Fatalf("final Fulcio custom metadata = %#v, want updated URI and status", sigstoreCustom)
	}
}

func TestRun_RetryPublishedFulcioDeletionCleanup(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	certPath := generateTestCert(t, dir, "fulcio.pem")

	if err := Run(&Options{
		RootPath:         rootPath,
		KeyPaths:         []string{keyPath},
		OutDir:           outDir,
		FulcioTarget:     certPath,
		FulcioURI:        "https://fulcio.test.dev",
		TargetPathExists: "replace",
	}); err != nil {
		t.Fatalf("initial set Run failed: %v", err)
	}

	initialTargetsPath, _, err := editor.FindLatestVersionedFile(outDir, "targets.json")
	if err != nil {
		t.Fatalf("find initial targets metadata: %v", err)
	}
	initialTargets := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := initialTargets.FromFile(initialTargetsPath); err != nil {
		t.Fatalf("load initial targets metadata: %v", err)
	}
	initialTarget := initialTargets.Signed.Targets["fulcio.pem"]
	initialHash, err := utils.PreferredHash(initialTarget.Hashes)
	if err != nil {
		t.Fatalf("get initial target hash: %v", err)
	}
	initialTargetPath := filepath.Join(outDir, "targets", initialHash+".fulcio.pem")
	initialData, err := os.ReadFile(initialTargetPath)
	if err != nil {
		t.Fatalf("read initial target file: %v", err)
	}

	if err := Run(&Options{
		RootPath:            rootPath,
		KeyPaths:            []string{keyPath},
		OutDir:              outDir,
		DeleteFulcioTargets: []string{"fulcio.pem"},
		TargetPathExists:    "replace",
	}); err != nil {
		t.Fatalf("initial delete Run failed: %v", err)
	}

	// Simulate a published deletion whose physical cleanup failed.
	if err := os.WriteFile(initialTargetPath, initialData, 0600); err != nil {
		t.Fatalf("restore target file for cleanup retry: %v", err)
	}

	if err := Run(&Options{
		RootPath:            rootPath,
		KeyPaths:            []string{keyPath},
		OutDir:              outDir,
		DeleteFulcioTargets: []string{"fulcio.pem"},
	}); err != nil {
		t.Fatalf("cleanup retry Run failed: %v", err)
	}
	if utils.FileExists(initialTargetPath) {
		t.Fatal("cleanup retry should remove the orphaned target file")
	}
}

func TestRun_DeleteFulcioTarget_KeepsSharedURI(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	oldCertPath := generateTestCert(t, dir, "old-fulcio.pem")
	newCertPath := generateTestCert(t, dir, "new-fulcio.pem")
	fulcioURI := "https://fulcio.rotation.test.dev"
	oidcURI := "https://oidc.rotation.test.dev"

	if err := Run(&Options{
		RootPath:         rootPath,
		KeyPaths:         []string{keyPath},
		OutDir:           outDir,
		FulcioTarget:     oldCertPath,
		FulcioURI:        fulcioURI,
		FulcioStatus:     "Expired",
		OIDCURIs:         []string{oidcURI},
		Operator:         "test.dev",
		TargetPathExists: "replace",
	}); err != nil {
		t.Fatalf("set expired Fulcio target failed: %v", err)
	}

	if err := Run(&Options{
		RootPath:         rootPath,
		KeyPaths:         []string{keyPath},
		OutDir:           outDir,
		FulcioTarget:     newCertPath,
		FulcioURI:        fulcioURI,
		FulcioStatus:     "Active",
		OIDCURIs:         []string{oidcURI},
		Operator:         "test.dev",
		TargetPathExists: "replace",
	}); err != nil {
		t.Fatalf("set active Fulcio target failed: %v", err)
	}

	if err := Run(&Options{
		RootPath:            rootPath,
		KeyPaths:            []string{keyPath},
		OutDir:              outDir,
		DeleteFulcioTargets: []string{"old-fulcio.pem"},
		TargetPathExists:    "replace",
	}); err != nil {
		t.Fatalf("delete expired Fulcio target failed: %v", err)
	}

	targetsPath, _, err := editor.FindLatestVersionedFile(outDir, "targets.json")
	if err != nil {
		t.Fatalf("find latest targets metadata: %v", err)
	}
	targetsMd := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := targetsMd.FromFile(targetsPath); err != nil {
		t.Fatalf("load latest targets metadata: %v", err)
	}
	if _, ok := targetsMd.Signed.Targets["old-fulcio.pem"]; ok {
		t.Fatal("expired Fulcio target should be removed from metadata")
	}
	if _, ok := targetsMd.Signed.Targets["new-fulcio.pem"]; !ok {
		t.Fatal("active Fulcio target should remain in metadata")
	}

	rootMeta := targetsMd.Signed.Targets["trusted_root.json"]
	configMeta := targetsMd.Signed.Targets["signing_config.v0.2.json"]
	rootTargetPath := filepath.Join(outDir, "targets", hex.EncodeToString(rootMeta.Hashes["sha256"])+".trusted_root.json")
	configTargetPath := filepath.Join(outDir, "targets", hex.EncodeToString(configMeta.Hashes["sha256"])+".signing_config.v0.2.json")
	bundle, err := sigstore.LoadTrustBundle(rootTargetPath, configTargetPath)
	if err != nil {
		t.Fatalf("load generated trust bundle: %v", err)
	}

	newDER, err := sigstore.LoadDERBytes(newCertPath)
	if err != nil {
		t.Fatalf("load active Fulcio certificate: %v", err)
	}
	if got := bundle.GetURIForTarget(sigstore.TargetCertificateAuthority, newDER[0]); got != fulcioURI {
		t.Fatalf("active Fulcio target URI = %q, want %q", got, fulcioURI)
	}
	oldDER, err := sigstore.LoadDERBytes(oldCertPath)
	if err != nil {
		t.Fatalf("load expired Fulcio certificate: %v", err)
	}
	if got := bundle.GetURIForTarget(sigstore.TargetCertificateAuthority, oldDER[0]); got != "" {
		t.Fatalf("deleted expired Fulcio target should not remain in trusted root, got URI %q", got)
	}
	if len(bundle.SigningConfig.CaUrls) != 1 || bundle.SigningConfig.CaUrls[0].Url != fulcioURI {
		t.Fatalf("signing config should retain shared Fulcio URI, got %#v", bundle.SigningConfig.CaUrls)
	}
	if len(bundle.SigningConfig.OidcUrls) != 1 || bundle.SigningConfig.OidcUrls[0].Url != oidcURI {
		t.Fatalf("signing config should retain shared OIDC URI, got %#v", bundle.SigningConfig.OidcUrls)
	}
}

func TestRun_DeleteFulcioTarget_RemovesSharedURIWhenRemainingTargetExpired(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	oldCertPath := generateTestCert(t, dir, "old-fulcio.pem")
	newCertPath := generateTestCert(t, dir, "new-fulcio.pem")
	fulcioURI := "https://fulcio.expired-rotation.test.dev"

	for _, target := range []struct {
		path   string
		status string
	}{
		{path: oldCertPath, status: "Expired"},
		{path: newCertPath, status: "Active"},
	} {
		if err := Run(&Options{
			RootPath:         rootPath,
			KeyPaths:         []string{keyPath},
			OutDir:           outDir,
			FulcioTarget:     target.path,
			FulcioURI:        fulcioURI,
			FulcioStatus:     target.status,
			Operator:         "test.dev",
			TargetPathExists: "replace",
		}); err != nil {
			t.Fatalf("set %s Fulcio target failed: %v", target.status, err)
		}
	}

	if err := Run(&Options{
		RootPath:            rootPath,
		KeyPaths:            []string{keyPath},
		OutDir:              outDir,
		DeleteFulcioTargets: []string{"new-fulcio.pem"},
		TargetPathExists:    "replace",
	}); err != nil {
		t.Fatalf("delete active Fulcio target failed: %v", err)
	}

	targetsPath, _, err := editor.FindLatestVersionedFile(outDir, "targets.json")
	if err != nil {
		t.Fatalf("find latest targets metadata: %v", err)
	}
	targetsMd := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := targetsMd.FromFile(targetsPath); err != nil {
		t.Fatalf("load latest targets metadata: %v", err)
	}
	if _, ok := targetsMd.Signed.Targets["new-fulcio.pem"]; ok {
		t.Fatal("active Fulcio target should be removed from metadata")
	}
	if _, ok := targetsMd.Signed.Targets["old-fulcio.pem"]; !ok {
		t.Fatal("expired Fulcio target should remain in metadata")
	}

	rootMeta := targetsMd.Signed.Targets["trusted_root.json"]
	configMeta := targetsMd.Signed.Targets["signing_config.v0.2.json"]
	rootTargetPath := filepath.Join(outDir, "targets", hex.EncodeToString(rootMeta.Hashes["sha256"])+".trusted_root.json")
	configTargetPath := filepath.Join(outDir, "targets", hex.EncodeToString(configMeta.Hashes["sha256"])+".signing_config.v0.2.json")
	bundle, err := sigstore.LoadTrustBundle(rootTargetPath, configTargetPath)
	if err != nil {
		t.Fatalf("load generated trust bundle: %v", err)
	}

	oldDER, err := sigstore.LoadDERBytes(oldCertPath)
	if err != nil {
		t.Fatalf("load expired Fulcio certificate: %v", err)
	}
	if got := bundle.GetURIForTarget(sigstore.TargetCertificateAuthority, oldDER[0]); got != fulcioURI {
		t.Fatalf("trusted root should retain expired Fulcio target URI %q, got %q", fulcioURI, got)
	}
	for _, service := range bundle.SigningConfig.CaUrls {
		if service.Url == fulcioURI {
			t.Fatal("signing config should not advertise an expired Fulcio target")
		}
	}
}

func TestRun_DeleteFulcioTarget_DoesNotDeleteSimilarlyNamedTarget(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	certPath1 := generateTestCert(t, dir, "fulcio.pem")
	certPath2 := generateTestCert(t, dir, "new.fulcio.pem")

	// Add first target: fulcio.pem
	opts := &Options{
		RootPath:         rootPath,
		KeyPaths:         []string{keyPath},
		OutDir:           outDir,
		FulcioTarget:     certPath1,
		FulcioURI:        "https://fulcio1.test.dev",
		OIDCURIs:         []string{"https://oidc.test.dev"},
		Operator:         "test.dev",
		TargetPathExists: "replace",
	}
	if err := Run(opts); err != nil {
		t.Fatalf("first set Run failed: %v", err)
	}

	// Add second target: new.fulcio.pem
	opts2 := &Options{
		RootPath:         rootPath,
		KeyPaths:         []string{keyPath},
		OutDir:           outDir,
		FulcioTarget:     certPath2,
		FulcioURI:        "https://fulcio2.test.dev",
		OIDCURIs:         []string{"https://oidc.test.dev"},
		Operator:         "test.dev",
		TargetPathExists: "replace",
	}
	if err := Run(opts2); err != nil {
		t.Fatalf("second set Run failed: %v", err)
	}

	// Verify both targets exist
	targetsDir := filepath.Join(outDir, "targets")
	entriesBefore, _ := os.ReadDir(targetsDir)
	var newFulcioFilesBefore int
	for _, e := range entriesBefore {
		if strings.Contains(e.Name(), "new.fulcio.pem") {
			newFulcioFilesBefore++
		}
	}
	if newFulcioFilesBefore == 0 {
		t.Fatal("new.fulcio.pem file should exist before delete")
	}

	// Delete only fulcio.pem
	deleteOpts := &Options{
		RootPath:            rootPath,
		KeyPaths:            []string{keyPath},
		OutDir:              outDir,
		DeleteFulcioTargets: []string{"fulcio.pem"},
		TargetPathExists:    "replace",
	}
	if err := Run(deleteOpts); err != nil {
		t.Fatalf("delete Run failed: %v", err)
	}

	// Verify fulcio.pem is gone but new.fulcio.pem files are preserved
	entriesAfter, _ := os.ReadDir(targetsDir)
	var newFulcioFilesAfter int
	for _, e := range entriesAfter {
		if strings.Contains(e.Name(), "new.fulcio.pem") {
			newFulcioFilesAfter++
		}
	}
	if newFulcioFilesAfter != newFulcioFilesBefore {
		t.Fatalf("new.fulcio.pem files should be preserved: had %d before, %d after",
			newFulcioFilesBefore, newFulcioFilesAfter)
	}
}

func TestRun_DeleteCtlogTarget(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	pubKeyPath := generateTestPublicKey(t, dir, "ctlog.pub")

	opts := &Options{
		RootPath:         rootPath,
		KeyPaths:         []string{keyPath},
		OutDir:           outDir,
		CtlogTarget:      pubKeyPath,
		CtlogURI:         "https://ctlog.test.dev",
		Operator:         "test.dev",
		TargetPathExists: "replace",
	}
	if err := Run(opts); err != nil {
		t.Fatalf("set Run failed: %v", err)
	}

	deleteOpts := &Options{
		RootPath:           rootPath,
		KeyPaths:           []string{keyPath},
		OutDir:             outDir,
		DeleteCtlogTargets: []string{"ctlog.pub"},
		TargetPathExists:   "replace",
	}
	if err := Run(deleteOpts); err != nil {
		t.Fatalf("delete Run failed: %v", err)
	}

	md := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := md.FromFile(filepath.Join(outDir, "3.targets.json")); err != nil {
		t.Fatalf("failed to load targets after delete: %v", err)
	}
	if _, ok := md.Signed.Targets["ctlog.pub"]; ok {
		t.Fatal("ctlog.pub should be removed after delete")
	}
}

func TestRun_DeleteRekorTarget(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	pubKeyPath := generateTestPublicKey(t, dir, "rekor.pub")

	opts := &Options{
		RootPath:         rootPath,
		KeyPaths:         []string{keyPath},
		OutDir:           outDir,
		RekorTarget:      pubKeyPath,
		RekorURI:         "https://rekor.test.dev",
		Operator:         "test.dev",
		TargetPathExists: "replace",
	}
	if err := Run(opts); err != nil {
		t.Fatalf("set Run failed: %v", err)
	}

	deleteOpts := &Options{
		RootPath:           rootPath,
		KeyPaths:           []string{keyPath},
		OutDir:             outDir,
		DeleteRekorTargets: []string{"rekor.pub"},
		TargetPathExists:   "replace",
	}
	if err := Run(deleteOpts); err != nil {
		t.Fatalf("delete Run failed: %v", err)
	}

	md := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := md.FromFile(filepath.Join(outDir, "3.targets.json")); err != nil {
		t.Fatalf("failed to load targets after delete: %v", err)
	}
	if _, ok := md.Signed.Targets["rekor.pub"]; ok {
		t.Fatal("rekor.pub should be removed after delete")
	}
}

func TestRun_DeleteTsaTarget(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	certPath := generateTestCert(t, dir, "tsa.pem")

	opts := &Options{
		RootPath:         rootPath,
		KeyPaths:         []string{keyPath},
		OutDir:           outDir,
		TsaTarget:        certPath,
		TsaURI:           "https://tsa.test.dev",
		Operator:         "test.dev",
		TargetPathExists: "replace",
	}
	if err := Run(opts); err != nil {
		t.Fatalf("set Run failed: %v", err)
	}

	deleteOpts := &Options{
		RootPath:         rootPath,
		KeyPaths:         []string{keyPath},
		OutDir:           outDir,
		DeleteTsaTargets: []string{"tsa.pem"},
		TargetPathExists: "replace",
	}
	if err := Run(deleteOpts); err != nil {
		t.Fatalf("delete Run failed: %v", err)
	}

	md := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := md.FromFile(filepath.Join(outDir, "3.targets.json")); err != nil {
		t.Fatalf("failed to load targets after delete: %v", err)
	}
	if _, ok := md.Signed.Targets["tsa.pem"]; ok {
		t.Fatal("tsa.pem should be removed after delete")
	}
}

// --- Custom expiration tests ---

func TestRun_CustomExpiration(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	certPath := generateTestCert(t, dir, "fulcio.pem")

	targetsExp := time.Now().Add(365 * 24 * time.Hour).Truncate(time.Second)
	snapshotExp := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	timestampExp := time.Now().Add(24 * time.Hour).Truncate(time.Second)

	opts := &Options{
		RootPath:         rootPath,
		KeyPaths:         []string{keyPath},
		OutDir:           outDir,
		FulcioTarget:     certPath,
		TargetsExpires:   &targetsExp,
		SnapshotExpires:  &snapshotExp,
		TimestampExpires: &timestampExp,
	}
	if err := Run(opts); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	targetsMd := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := targetsMd.FromFile(filepath.Join(outDir, "2.targets.json")); err != nil {
		t.Fatalf("failed to load targets: %v", err)
	}
	if !targetsMd.Signed.Expires.Truncate(time.Second).Equal(targetsExp) {
		t.Fatalf("targets expires mismatch: got %v, want %v", targetsMd.Signed.Expires, targetsExp)
	}

	snapshotMd := &tufmeta.Metadata[tufmeta.SnapshotType]{}
	if _, err := snapshotMd.FromFile(filepath.Join(outDir, "2.snapshot.json")); err != nil {
		t.Fatalf("failed to load snapshot: %v", err)
	}
	if !snapshotMd.Signed.Expires.Truncate(time.Second).Equal(snapshotExp) {
		t.Fatalf("snapshot expires mismatch: got %v, want %v", snapshotMd.Signed.Expires, snapshotExp)
	}

	timestampMd := &tufmeta.Metadata[tufmeta.TimestampType]{}
	if _, err := timestampMd.FromFile(filepath.Join(outDir, "timestamp.json")); err != nil {
		t.Fatalf("failed to load timestamp: %v", err)
	}
	if !timestampMd.Signed.Expires.Truncate(time.Second).Equal(timestampExp) {
		t.Fatalf("timestamp expires mismatch: got %v, want %v", timestampMd.Signed.Expires, timestampExp)
	}
}

func TestRun_ExpirationOnlyUpdate(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	certPath := generateTestCert(t, dir, "fulcio.pem")

	if err := Run(&Options{
		RootPath:     rootPath,
		KeyPaths:     []string{keyPath},
		OutDir:       outDir,
		FulcioTarget: certPath,
	}); err != nil {
		t.Fatalf("initial Run failed: %v", err)
	}

	targetsExp := time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
	snapshotExp := time.Date(2035, 1, 2, 0, 0, 0, 0, time.UTC)
	timestampExp := time.Date(2035, 1, 3, 0, 0, 0, 0, time.UTC)
	if err := Run(&Options{
		RootPath:         rootPath,
		KeyPaths:         []string{keyPath},
		OutDir:           outDir,
		TargetsExpires:   &targetsExp,
		SnapshotExpires:  &snapshotExp,
		TimestampExpires: &timestampExp,
	}); err != nil {
		t.Fatalf("expiration-only Run failed: %v", err)
	}

	targetsMd := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := targetsMd.FromFile(filepath.Join(outDir, "3.targets.json")); err != nil {
		t.Fatalf("failed to load updated targets metadata: %v", err)
	}
	if targetsMd.Signed.Version != 3 {
		t.Fatalf("expected targets version 3, got %d", targetsMd.Signed.Version)
	}
	if !targetsMd.Signed.Expires.Equal(targetsExp) {
		t.Fatalf("targets expiration mismatch: got %v, want %v", targetsMd.Signed.Expires, targetsExp)
	}

	snapshotMd := &tufmeta.Metadata[tufmeta.SnapshotType]{}
	if _, err := snapshotMd.FromFile(filepath.Join(outDir, "3.snapshot.json")); err != nil {
		t.Fatalf("failed to load updated snapshot metadata: %v", err)
	}
	if snapshotMd.Signed.Version != 3 {
		t.Fatalf("expected snapshot version 3, got %d", snapshotMd.Signed.Version)
	}
	if !snapshotMd.Signed.Expires.Equal(snapshotExp) {
		t.Fatalf("snapshot expiration mismatch: got %v, want %v", snapshotMd.Signed.Expires, snapshotExp)
	}

	timestampMd := &tufmeta.Metadata[tufmeta.TimestampType]{}
	if _, err := timestampMd.FromFile(filepath.Join(outDir, "timestamp.json")); err != nil {
		t.Fatalf("failed to load updated timestamp metadata: %v", err)
	}
	if timestampMd.Signed.Version != 3 {
		t.Fatalf("expected timestamp version 3, got %d", timestampMd.Signed.Version)
	}
	if !timestampMd.Signed.Expires.Equal(timestampExp) {
		t.Fatalf("timestamp expiration mismatch: got %v, want %v", timestampMd.Signed.Expires, timestampExp)
	}
}

func TestRun_SnapshotOnlyUpdatePreservesTargetsFile(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	certPath := generateTestCert(t, dir, "fulcio.pem")

	if err := Run(&Options{
		RootPath:     rootPath,
		KeyPaths:     []string{keyPath},
		OutDir:       outDir,
		FulcioTarget: certPath,
	}); err != nil {
		t.Fatalf("initial Run failed: %v", err)
	}

	targetsPath := filepath.Join(outDir, "2.targets.json")
	before, err := os.ReadFile(targetsPath)
	if err != nil {
		t.Fatalf("failed to read targets metadata before update: %v", err)
	}
	snapshotExp := time.Date(2035, 1, 2, 0, 0, 0, 0, time.UTC)
	if err := Run(&Options{
		RootPath:        rootPath,
		KeyPaths:        []string{keyPath},
		OutDir:          outDir,
		SnapshotExpires: &snapshotExp,
	}); err != nil {
		t.Fatalf("snapshot-only Run failed: %v", err)
	}

	after, err := os.ReadFile(targetsPath)
	if err != nil {
		t.Fatalf("failed to read targets metadata after update: %v", err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("targets metadata changed during snapshot-only update")
	}

	snapshotMd := &tufmeta.Metadata[tufmeta.SnapshotType]{}
	if _, err := snapshotMd.FromFile(filepath.Join(outDir, "3.snapshot.json")); err != nil {
		t.Fatalf("failed to load updated snapshot metadata: %v", err)
	}
	if snapshotMd.Signed.Version != 3 {
		t.Fatalf("expected snapshot version 3, got %d", snapshotMd.Signed.Version)
	}
	if !snapshotMd.Signed.Expires.Equal(snapshotExp) {
		t.Fatalf("snapshot expiration mismatch: got %v, want %v", snapshotMd.Signed.Expires, snapshotExp)
	}
	if got := snapshotMd.Signed.Meta["targets.json"].Version; got != 2 {
		t.Fatalf("snapshot references targets version %d, want 2", got)
	}
}

func TestRun_TimestampOnlyUpdatePreservesTargetsFile(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	certPath := generateTestCert(t, dir, "fulcio.pem")

	if err := Run(&Options{
		RootPath:     rootPath,
		KeyPaths:     []string{keyPath},
		OutDir:       outDir,
		FulcioTarget: certPath,
	}); err != nil {
		t.Fatalf("initial Run failed: %v", err)
	}

	targetsPath := filepath.Join(outDir, "2.targets.json")
	before, err := os.ReadFile(targetsPath)
	if err != nil {
		t.Fatalf("failed to read targets metadata before update: %v", err)
	}
	timestampExp := time.Date(2035, 1, 3, 0, 0, 0, 0, time.UTC)
	if err := Run(&Options{
		RootPath:         rootPath,
		KeyPaths:         []string{keyPath},
		OutDir:           outDir,
		TimestampExpires: &timestampExp,
	}); err != nil {
		t.Fatalf("timestamp-only Run failed: %v", err)
	}

	after, err := os.ReadFile(targetsPath)
	if err != nil {
		t.Fatalf("failed to read targets metadata after update: %v", err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("targets metadata changed during timestamp-only update")
	}

	timestampMd := &tufmeta.Metadata[tufmeta.TimestampType]{}
	if _, err := timestampMd.FromFile(filepath.Join(outDir, "timestamp.json")); err != nil {
		t.Fatalf("failed to load updated timestamp metadata: %v", err)
	}
	if timestampMd.Signed.Version != 3 {
		t.Fatalf("expected timestamp version 3, got %d", timestampMd.Signed.Version)
	}
	if !timestampMd.Signed.Expires.Equal(timestampExp) {
		t.Fatalf("timestamp expiration mismatch: got %v, want %v", timestampMd.Signed.Expires, timestampExp)
	}
	if got := timestampMd.Signed.Meta["snapshot.json"].Version; got != 3 {
		t.Fatalf("timestamp references snapshot version %d, want 3", got)
	}
}

func TestDetectPublicKeyDetails(t *testing.T) {
	t.Run("P256 public key", func(t *testing.T) {
		dir := t.TempDir()
		keyPath := generateTestPublicKey(t, dir, "p256.pub")

		details, err := detectPublicKeyDetails(keyPath)
		if err != nil {
			t.Fatalf("detectPublicKeyDetails failed: %v", err)
		}
		if details != commonpb.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256 {
			t.Fatalf("expected PKIX_ECDSA_P256_SHA_256, got %v", details)
		}
	})

	t.Run("certificate PEM fallback", func(t *testing.T) {
		dir := t.TempDir()
		certPath := generateTestCert(t, dir, "cert.pem")

		details, err := detectPublicKeyDetails(certPath)
		if err != nil {
			t.Fatalf("detectPublicKeyDetails failed: %v", err)
		}
		if details != commonpb.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256 {
			t.Fatalf("expected PKIX_ECDSA_P256_SHA_256 for certificate, got %v", details)
		}
	})

	t.Run("P384 detection", func(t *testing.T) {
		dir := t.TempDir()
		keyPath := generateTestPublicKeyWithCurve(t, dir, "p384.pub", elliptic.P384())

		details, err := detectPublicKeyDetails(keyPath)
		if err != nil {
			t.Fatalf("detectPublicKeyDetails failed: %v", err)
		}
		if details != commonpb.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384 {
			t.Fatalf("expected PKIX_ECDSA_P384_SHA_384, got %v", details)
		}
	})

	t.Run("invalid file", func(t *testing.T) {
		_, err := detectPublicKeyDetails("/nonexistent/path")
		if err == nil {
			t.Fatal("expected error for nonexistent file")
		}
	})

	t.Run("non-PEM file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "notpem.txt")
		os.WriteFile(path, []byte("not a PEM file"), 0600)

		_, err := detectPublicKeyDetails(path)
		if err == nil {
			t.Fatal("expected error for non-PEM file")
		}
	})
}

func TestCheckExpiration(t *testing.T) {
	_, rootPath, outDir := setupTestRepo(t)

	re, err := LoadRepository(editor.LoadOptions{
		RootPath: rootPath,
		OutDir:   outDir,
	})
	if err != nil {
		t.Fatalf("LoadRepository failed: %v", err)
	}

	t.Run("all valid", func(t *testing.T) {
		if err := re.CheckExpiration(false); err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
	})

	t.Run("all expired allow=false", func(t *testing.T) {
		past := time.Now().Add(-24 * time.Hour)
		re.SetTargetsExpires(past)
		re.SetSnapshotExpires(past)
		re.SetTimestampExpires(past)

		err := re.CheckExpiration(false)
		if err == nil {
			t.Fatal("expected error for expired metadata")
		}
		for _, name := range []string{"targets.json", "snapshot.json", "timestamp.json"} {
			if !strings.Contains(err.Error(), name) {
				t.Errorf("expected error to mention %s, got: %v", name, err)
			}
		}
	})

	t.Run("all expired allow=true", func(t *testing.T) {
		past := time.Now().Add(-24 * time.Hour)
		re.SetTargetsExpires(past)
		re.SetSnapshotExpires(past)
		re.SetTimestampExpires(past)

		if err := re.CheckExpiration(true); err != nil {
			t.Fatalf("expected nil with allowExpired=true, got: %v", err)
		}
	})

	t.Run("only targets expired", func(t *testing.T) {
		re.SetTargetsExpires(time.Now().Add(-1 * time.Hour))
		re.SetSnapshotExpires(time.Now().Add(24 * time.Hour))
		re.SetTimestampExpires(time.Now().Add(24 * time.Hour))

		err := re.CheckExpiration(false)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "targets.json") {
			t.Errorf("expected error to mention targets.json, got: %v", err)
		}
		if strings.Contains(err.Error(), "snapshot.json") || strings.Contains(err.Error(), "timestamp.json") {
			t.Errorf("error should not mention valid metadata, got: %v", err)
		}
	})
}

func TestValidForFromStatus(t *testing.T) {
	now := timestamppb.Now()

	tests := []struct {
		name      string
		status    string
		wantStart bool
		wantEnd   bool
	}{
		{"Active", "Active", true, false},
		{"Expired", "Expired", false, true},
		{"empty defaults to active", "", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start, end := validForFromStatus(tt.status, now)
			if tt.wantStart && start == nil {
				t.Fatal("expected non-nil start")
			}
			if !tt.wantStart && start != nil {
				t.Fatal("expected nil start")
			}
			if tt.wantEnd && end == nil {
				t.Fatal("expected non-nil end")
			}
			if !tt.wantEnd && end != nil {
				t.Fatal("expected nil end")
			}
			if start != nil && !start.AsTime().Equal(now.AsTime()) {
				t.Fatalf("start should equal now, got %v", start.AsTime())
			}
			if end != nil && !end.AsTime().Equal(now.AsTime()) {
				t.Fatalf("end should equal now, got %v", end.AsTime())
			}
		})
	}
}

func TestFetchFile(t *testing.T) {
	t.Run("file:// existing", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "data.txt")
		if err := os.WriteFile(path, []byte("hello"), 0600); err != nil {
			t.Fatalf("failed to write fixture: %v", err)
		}

		got, err := utils.FetchFile("file://" + path)
		if err != nil {
			t.Fatalf("FetchFile failed: %v", err)
		}
		if string(got) != "hello" {
			t.Fatalf("expected 'hello', got %q", got)
		}
	})

	t.Run("file:// nonexistent", func(t *testing.T) {
		_, err := utils.FetchFile("file:///nonexistent/path.txt")
		if err == nil {
			t.Fatal("expected error for nonexistent file")
		}
	})

	t.Run("HTTP 200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, "response-body")
		}))
		defer srv.Close()

		got, err := utils.FetchFile(srv.URL + "/test")
		if err != nil {
			t.Fatalf("FetchFile failed: %v", err)
		}
		if string(got) != "response-body" {
			t.Fatalf("expected 'response-body', got %q", got)
		}
	})

	t.Run("HTTP 404", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		_, err := utils.FetchFile(srv.URL + "/missing")
		if err == nil {
			t.Fatal("expected error for 404")
		}
		if !strings.Contains(err.Error(), "404") {
			t.Fatalf("expected error to mention 404, got: %v", err)
		}
	})
}
