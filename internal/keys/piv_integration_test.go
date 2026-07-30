//go:build piv && integration

package keys

import (
	"bytes"
	"os"
	"testing"
)

func skipWithoutYubiKey(t *testing.T) {
	t.Helper()
	if os.Getenv("PIV_PIN") == "" {
		t.Skip("PIV_PIN not set; skipping YubiKey integration test")
	}
}

func TestIntegration_LoadPIVSigner(t *testing.T) {
	skipWithoutYubiKey(t)

	signer, tufKey, keyID, err := loadPIVSigner("yubikey://slot/9c")
	if err != nil {
		t.Fatalf("loadPIVSigner failed: %v", err)
	}
	if signer == nil || tufKey == nil || keyID == "" {
		t.Fatal("expected valid signer, key, and ID")
	}

	msg := []byte("integration test message")
	sig, err := signer.SignMessage(bytes.NewReader(msg))
	if err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("signature is empty")
	}

	t.Logf("Signed with key ID: %s (type: %s)", keyID, tufKey.Type)
}

func TestIntegration_ParsePIVPublicKey(t *testing.T) {
	skipWithoutYubiKey(t)

	tufKey, keyID, err := parsePIVPublicKey("yubikey://slot/9c")
	if err != nil {
		t.Fatalf("parsePIVPublicKey failed: %v", err)
	}
	if tufKey == nil || keyID == "" {
		t.Fatal("expected valid key and ID")
	}

	t.Logf("Public key ID: %s (type: %s)", keyID, tufKey.Type)
}

func TestIntegration_KeyIDConsistency(t *testing.T) {
	skipWithoutYubiKey(t)

	_, _, signerKeyID, err := loadPIVSigner("yubikey://slot/9c")
	if err != nil {
		t.Fatalf("loadPIVSigner failed: %v", err)
	}

	_, pubKeyID, err := parsePIVPublicKey("yubikey://slot/9c")
	if err != nil {
		t.Fatalf("parsePIVPublicKey failed: %v", err)
	}

	if signerKeyID != pubKeyID {
		t.Fatalf("key IDs don't match: signer=%s, pubkey=%s", signerKeyID, pubKeyID)
	}
}
