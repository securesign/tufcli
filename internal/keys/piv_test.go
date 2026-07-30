//go:build piv

package keys

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/go-piv/piv-go/v2/piv"
)

// --- Mock PIVClient ---

type mockPIVClient struct {
	cert    *x509.Certificate
	privKey crypto.PrivateKey
	closed  bool
	certErr error
	privErr error
}

func (m *mockPIVClient) Certificate(_ piv.Slot) (*x509.Certificate, error) {
	if m.certErr != nil {
		return nil, m.certErr
	}
	return m.cert, nil
}

func (m *mockPIVClient) PrivateKey(_ piv.Slot, _ crypto.PublicKey, _ piv.KeyAuth) (crypto.PrivateKey, error) {
	if m.privErr != nil {
		return nil, m.privErr
	}
	return m.privKey, nil
}

func (m *mockPIVClient) Close() error {
	m.closed = true
	return nil
}

func withMockYubiKey(t *testing.T, client PIVClient) {
	t.Helper()
	orig := openYubiKey
	openYubiKey = func() (PIVClient, error) { return client, nil }
	t.Cleanup(func() { openYubiKey = orig })
}

func generateSelfSignedCert(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return cert, key
}

// --- URI parsing tests ---

func TestIsYubiKeyURI(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"yubikey:", true},
		{"yubikey://", true},
		{"yubikey://slot/9c", true},
		{"/path/to/key.pem", false},
		{"file://key.pem", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := isYubiKeyURI(tt.input); got != tt.want {
			t.Errorf("isYubiKeyURI(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestParseYubiKeySlot(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		want    piv.Slot
		wantErr bool
	}{
		{"bare scheme", "yubikey:", piv.SlotSignature, false},
		{"empty authority", "yubikey://", piv.SlotSignature, false},
		{"slot 9a", "yubikey://slot/9a", piv.SlotAuthentication, false},
		{"slot 9c", "yubikey://slot/9c", piv.SlotSignature, false},
		{"slot 9d", "yubikey://slot/9d", piv.SlotKeyManagement, false},
		{"slot 9e", "yubikey://slot/9e", piv.SlotCardAuthentication, false},
		{"uppercase slot", "yubikey://slot/9C", piv.SlotSignature, false},
		{"trailing slash", "yubikey://slot/9c/", piv.SlotSignature, false},
		{"invalid slot", "yubikey://slot/ff", piv.Slot{}, true},
		{"bad path", "yubikey://foo/bar", piv.Slot{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseYubiKeySlot(tt.uri)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tt.uri)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got slot %v, want %v", got, tt.want)
			}
		})
	}
}

// --- loadPIVSigner tests ---

func TestLoadPIVSigner_Success(t *testing.T) {
	cert, key := generateSelfSignedCert(t)
	mock := &mockPIVClient{cert: cert, privKey: key}
	withMockYubiKey(t, mock)
	t.Setenv("PIV_PIN", "123456")

	signer, tufKey, keyID, err := loadPIVSigner("yubikey://slot/9c")
	if err != nil {
		t.Fatalf("loadPIVSigner failed: %v", err)
	}
	if signer == nil {
		t.Fatal("signer is nil")
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

func TestLoadPIVSigner_DefaultSlot(t *testing.T) {
	cert, key := generateSelfSignedCert(t)
	mock := &mockPIVClient{cert: cert, privKey: key}
	withMockYubiKey(t, mock)
	t.Setenv("PIV_PIN", "123456")

	signer, _, _, err := loadPIVSigner("yubikey:")
	if err != nil {
		t.Fatalf("loadPIVSigner with default slot failed: %v", err)
	}
	if signer == nil {
		t.Fatal("signer is nil")
	}
}

func TestLoadPIVSigner_MissingPIN(t *testing.T) {
	cert, key := generateSelfSignedCert(t)
	mock := &mockPIVClient{cert: cert, privKey: key}
	withMockYubiKey(t, mock)
	t.Setenv("PIV_PIN", "")

	_, _, _, err := loadPIVSigner("yubikey://slot/9c")
	if err == nil {
		t.Fatal("expected error for missing PIV_PIN")
	}
	if !strings.Contains(err.Error(), "PIV_PIN") {
		t.Fatalf("expected error about PIV_PIN, got: %v", err)
	}
	if !mock.closed {
		t.Fatal("expected client to be closed on error")
	}
}

func TestLoadPIVSigner_CertError(t *testing.T) {
	mock := &mockPIVClient{certErr: fmt.Errorf("no cert in slot")}
	withMockYubiKey(t, mock)
	t.Setenv("PIV_PIN", "123456")

	_, _, _, err := loadPIVSigner("yubikey://slot/9c")
	if err == nil {
		t.Fatal("expected error for cert failure")
	}
	if !mock.closed {
		t.Fatal("expected client to be closed on error")
	}
}

func TestLoadPIVSigner_PrivKeyError(t *testing.T) {
	cert, _ := generateSelfSignedCert(t)
	mock := &mockPIVClient{cert: cert, privErr: fmt.Errorf("wrong PIN")}
	withMockYubiKey(t, mock)
	t.Setenv("PIV_PIN", "000000")

	_, _, _, err := loadPIVSigner("yubikey://slot/9c")
	if err == nil {
		t.Fatal("expected error for privkey failure")
	}
	if !mock.closed {
		t.Fatal("expected client to be closed on error")
	}
}

func TestLoadPIVSigner_InvalidURI(t *testing.T) {
	_, _, _, err := loadPIVSigner("yubikey://slot/ff")
	if err == nil {
		t.Fatal("expected error for invalid slot")
	}
}

// --- PIVSigner.SignMessage tests ---

func TestPIVSigner_SignMessage(t *testing.T) {
	cert, key := generateSelfSignedCert(t)
	mock := &mockPIVClient{cert: cert, privKey: key}
	withMockYubiKey(t, mock)
	t.Setenv("PIV_PIN", "123456")

	signer, _, _, err := loadPIVSigner("yubikey://slot/9c")
	if err != nil {
		t.Fatalf("loadPIVSigner failed: %v", err)
	}

	msg := []byte("test message for signing")
	sig, err := signer.SignMessage(bytes.NewReader(msg))
	if err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("signature is empty")
	}

	h := crypto.SHA256.New()
	h.Write(msg)
	if !ecdsa.VerifyASN1(&key.PublicKey, h.Sum(nil), sig) {
		t.Fatal("signature verification failed")
	}
}

// --- Routing tests ---

func TestLoadSigner_RoutesToPIV(t *testing.T) {
	cert, key := generateSelfSignedCert(t)
	mock := &mockPIVClient{cert: cert, privKey: key}
	withMockYubiKey(t, mock)
	t.Setenv("PIV_PIN", "123456")

	signer, tufKey, keyID, err := LoadSigner("yubikey://slot/9c")
	if err != nil {
		t.Fatalf("LoadSigner with yubikey URI failed: %v", err)
	}
	if signer == nil || tufKey == nil || keyID == "" {
		t.Fatal("expected valid signer, key, and ID")
	}
}

func TestParsePublicKeyFromFile_RoutesToPIV(t *testing.T) {
	cert, _ := generateSelfSignedCert(t)
	mock := &mockPIVClient{cert: cert}
	withMockYubiKey(t, mock)

	tufKey, keyID, err := ParsePublicKeyFromFile("yubikey://slot/9c")
	if err != nil {
		t.Fatalf("ParsePublicKeyFromFile with yubikey URI failed: %v", err)
	}
	if tufKey == nil || keyID == "" {
		t.Fatal("expected valid key and ID")
	}
}

// --- Key ID consistency ---

func TestLoadPIVSigner_KeyIDConsistency(t *testing.T) {
	cert, key := generateSelfSignedCert(t)

	// Get key ID via PIV signer path
	mock := &mockPIVClient{cert: cert, privKey: key}
	withMockYubiKey(t, mock)
	t.Setenv("PIV_PIN", "123456")

	_, _, pivKeyID, err := loadPIVSigner("yubikey://slot/9c")
	if err != nil {
		t.Fatalf("loadPIVSigner failed: %v", err)
	}

	// Get key ID via PIV public key path
	mock2 := &mockPIVClient{cert: cert}
	withMockYubiKey(t, mock2)

	_, pubKeyID, err := parsePIVPublicKey("yubikey://slot/9c")
	if err != nil {
		t.Fatalf("parsePIVPublicKey failed: %v", err)
	}

	if pivKeyID != pubKeyID {
		t.Fatalf("key IDs don't match: signer=%s, pubkey=%s", pivKeyID, pubKeyID)
	}

	// Also verify against the PEM-based key ID pipeline
	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	_, pemKeyID, err := ParsePublicKey(pemData)
	if err != nil {
		t.Fatalf("ParsePublicKey failed: %v", err)
	}

	if pivKeyID != pemKeyID {
		t.Fatalf("PIV key ID doesn't match PEM key ID: %s vs %s", pivKeyID, pemKeyID)
	}
}
