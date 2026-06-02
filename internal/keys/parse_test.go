package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func writeKeyFile(t *testing.T, dir, name, pemType string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	block := &pem.Block{Type: pemType, Bytes: data}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}
	return path
}

func generateECKeyFiles(t *testing.T, dir string) (pubPath, privPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pubPath = writeKeyFile(t, dir, "ec.pub", "PUBLIC KEY", pubBytes)

	privBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	privPath = writeKeyFile(t, dir, "ec.pem", "PRIVATE KEY", privBytes)

	return pubPath, privPath
}

func TestParsePublicKeyFromFile_ECPublicKey(t *testing.T) {
	dir := t.TempDir()
	pubPath, _ := generateECKeyFiles(t, dir)

	tufKey, keyID, err := ParsePublicKeyFromFile(pubPath)
	if err != nil {
		t.Fatalf("ParsePublicKeyFromFile failed: %v", err)
	}
	if tufKey == nil {
		t.Fatal("tufKey is nil")
	}
	if keyID == "" {
		t.Fatal("keyID is empty")
	}
	if tufKey.Type != "ecdsa" {
		t.Fatalf("expected key type 'ecdsa', got %q", tufKey.Type)
	}
}

func TestParsePublicKeyFromFile_ECPrivateKey(t *testing.T) {
	dir := t.TempDir()
	_, privPath := generateECKeyFiles(t, dir)

	tufKey, keyID, err := ParsePublicKeyFromFile(privPath)
	if err != nil {
		t.Fatalf("ParsePublicKeyFromFile from private key failed: %v", err)
	}
	if tufKey == nil || keyID == "" {
		t.Fatal("expected valid key and ID")
	}
}

func TestParsePublicKeyFromFile_NotFound(t *testing.T) {
	_, _, err := ParsePublicKeyFromFile("/nonexistent/key.pem")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestParsePublicKey_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	pubBytes, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	tufKey, keyID, err := ParsePublicKey(pemData)
	if err != nil {
		t.Fatalf("ParsePublicKey failed: %v", err)
	}
	if tufKey == nil || keyID == "" {
		t.Fatal("expected valid key and ID")
	}
	if tufKey.Type != "rsa" {
		t.Fatalf("expected key type 'rsa', got %q", tufKey.Type)
	}
}

func TestParsePublicKey_InvalidPEM(t *testing.T) {
	_, _, err := ParsePublicKey([]byte("not a PEM"))
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestLoadSigner_ECDSA(t *testing.T) {
	dir := t.TempDir()
	_, privPath := generateECKeyFiles(t, dir)

	signer, tufKey, keyID, err := LoadSigner(privPath)
	if err != nil {
		t.Fatalf("LoadSigner failed: %v", err)
	}
	if signer == nil {
		t.Fatal("signer is nil")
	}
	if tufKey == nil || keyID == "" {
		t.Fatal("expected valid key and ID")
	}
}

func TestLoadSigner_RSA(t *testing.T) {
	dir := t.TempDir()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	privBytes, _ := x509.MarshalPKCS8PrivateKey(key)
	privPath := writeKeyFile(t, dir, "rsa.pem", "PRIVATE KEY", privBytes)

	signer, tufKey, keyID, err := LoadSigner(privPath)
	if err != nil {
		t.Fatalf("LoadSigner failed: %v", err)
	}
	if signer == nil || tufKey == nil || keyID == "" {
		t.Fatal("expected valid signer, key, and ID")
	}
}

func TestLoadSigner_PKCS1RSA(t *testing.T) {
	dir := t.TempDir()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	privBytes := x509.MarshalPKCS1PrivateKey(key)
	privPath := writeKeyFile(t, dir, "rsa-pkcs1.pem", "RSA PRIVATE KEY", privBytes)

	signer, _, _, err := LoadSigner(privPath)
	if err != nil {
		t.Fatalf("LoadSigner PKCS1 failed: %v", err)
	}
	if signer == nil {
		t.Fatal("signer is nil")
	}
}

func TestLoadSigner_ECPrivateKey(t *testing.T) {
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privBytes, _ := x509.MarshalECPrivateKey(key)
	privPath := writeKeyFile(t, dir, "ec-sec1.pem", "EC PRIVATE KEY", privBytes)

	signer, _, _, err := LoadSigner(privPath)
	if err != nil {
		t.Fatalf("LoadSigner EC failed: %v", err)
	}
	if signer == nil {
		t.Fatal("signer is nil")
	}
}

func TestLoadSigner_Ed25519(t *testing.T) {
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	privBytes, _ := x509.MarshalPKCS8PrivateKey(priv)
	privPath := writeKeyFile(t, dir, "ed25519.pem", "PRIVATE KEY", privBytes)

	signer, tufKey, _, err := LoadSigner(privPath)
	if err != nil {
		t.Fatalf("LoadSigner Ed25519 failed: %v", err)
	}
	if signer == nil || tufKey == nil {
		t.Fatal("expected valid signer and key")
	}
}

func TestLoadSigner_NotFound(t *testing.T) {
	_, _, _, err := LoadSigner("/nonexistent/key.pem")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestLoadSigner_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pem")
	os.WriteFile(path, []byte("not a PEM"), 0600)

	_, _, _, err := LoadSigner(path)
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestLoadSigner_InvalidKeyFormat(t *testing.T) {
	dir := t.TempDir()
	path := writeKeyFile(t, dir, "garbage.pem", "PRIVATE KEY", []byte("garbage"))

	_, _, _, err := LoadSigner(path)
	if err == nil {
		t.Fatal("expected error for unrecognizable key format")
	}
}

func TestExtractPublicKey_RSAPublicKey(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubBytes := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubBytes})

	pub, err := extractPublicKey(pemData)
	if err != nil {
		t.Fatalf("extractPublicKey RSA PUBLIC KEY failed: %v", err)
	}
	if _, ok := pub.(*rsa.PublicKey); !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", pub)
	}
}

func TestExtractPublicKey_RSAPrivateKey(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	privBytes := x509.MarshalPKCS1PrivateKey(key)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})

	pub, err := extractPublicKey(pemData)
	if err != nil {
		t.Fatalf("extractPublicKey RSA PRIVATE KEY failed: %v", err)
	}
	if _, ok := pub.(*rsa.PublicKey); !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", pub)
	}
}

func TestExtractPublicKey_ECPrivateKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privBytes, _ := x509.MarshalECPrivateKey(key)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	pub, err := extractPublicKey(pemData)
	if err != nil {
		t.Fatalf("extractPublicKey EC PRIVATE KEY failed: %v", err)
	}
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}
}

func TestExtractPublicKey_PKCS8PrivateKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privBytes, _ := x509.MarshalPKCS8PrivateKey(key)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	pub, err := extractPublicKey(pemData)
	if err != nil {
		t.Fatalf("extractPublicKey PKCS8 failed: %v", err)
	}
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}
}

func TestExtractPublicKey_FallbackPKCS8(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privBytes, _ := x509.MarshalPKCS8PrivateKey(key)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "UNKNOWN TYPE", Bytes: privBytes})

	pub, err := extractPublicKey(pemData)
	if err != nil {
		t.Fatalf("extractPublicKey fallback failed: %v", err)
	}
	if pub == nil {
		t.Fatal("expected non-nil public key from fallback")
	}
}

func TestExtractPublicKey_UnsupportedType(t *testing.T) {
	pemData := pem.EncodeToMemory(&pem.Block{Type: "UNKNOWN TYPE", Bytes: []byte("garbage")})

	_, err := extractPublicKey(pemData)
	if err == nil {
		t.Fatal("expected error for unsupported PEM type")
	}
}

func TestExtractPublicKey_NoPEM(t *testing.T) {
	_, err := extractPublicKey([]byte("not pem data"))
	if err == nil {
		t.Fatal("expected error for non-PEM data")
	}
}

func TestPublicKeyOf_RSA(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub, err := publicKeyOf(key)
	if err != nil {
		t.Fatalf("publicKeyOf RSA failed: %v", err)
	}
	if _, ok := pub.(*rsa.PublicKey); !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", pub)
	}
}

func TestPublicKeyOf_ECDSA(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, err := publicKeyOf(key)
	if err != nil {
		t.Fatalf("publicKeyOf ECDSA failed: %v", err)
	}
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}
}

func TestPublicKeyOf_Ed25519(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub, err := publicKeyOf(priv)
	if err != nil {
		t.Fatalf("publicKeyOf Ed25519 failed: %v", err)
	}
	if _, ok := pub.(ed25519.PublicKey); !ok {
		t.Fatalf("expected ed25519.PublicKey, got %T", pub)
	}
}

func TestPublicKeyOf_Unsupported(t *testing.T) {
	_, err := publicKeyOf("not a key")
	if err == nil {
		t.Fatal("expected error for unsupported type")
	}
}

func TestParsePublicKey_DeterministicKeyID(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubBytes, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	_, id1, _ := ParsePublicKey(pemData)
	_, id2, _ := ParsePublicKey(pemData)

	if id1 != id2 {
		t.Fatalf("key IDs not deterministic: %s vs %s", id1, id2)
	}
}

func TestLoadSigner_ConsistentKeyID(t *testing.T) {
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	pubBytes, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pubPath := writeKeyFile(t, dir, "key.pub", "PUBLIC KEY", pubBytes)

	privBytes, _ := x509.MarshalPKCS8PrivateKey(key)
	privPath := writeKeyFile(t, dir, "key.pem", "PRIVATE KEY", privBytes)

	_, pubID, _ := ParsePublicKeyFromFile(pubPath)
	_, _, privID, _ := LoadSigner(privPath)

	if pubID != privID {
		t.Fatalf("key IDs from pub and priv don't match: %s vs %s", pubID, privID)
	}
}
