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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/securesign/tufcli/internal/schema"
)

// Sign signs the provided data with a private key
func Sign(privateKey *PrivateKey, data []byte) ([]byte, error) {
	switch k := privateKey.raw.(type) {
	case *rsa.PrivateKey:
		return signRSA(k, data)
	case *ecdsa.PrivateKey:
		return signECDSA(k, data)
	case ed25519.PrivateKey:
		return signED25519(k, data)
	default:
		return nil, fmt.Errorf("unsupported key type for signing: %T", privateKey.raw)
	}
}

// signRSA signs data with an RSA private key using PSS
func signRSA(key *rsa.PrivateKey, data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	signature, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, hash[:], nil)
	if err != nil {
		return nil, fmt.Errorf("RSA PSS signing failed: %w", err)
	}
	return signature, nil
}

// signECDSA signs data with an ECDSA private key
func signECDSA(key *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	signature, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	if err != nil {
		return nil, fmt.Errorf("ECDSA signing failed: %w", err)
	}
	return signature, nil
}

// signED25519 signs data with an ED25519 private key
func signED25519(key ed25519.PrivateKey, data []byte) ([]byte, error) {
	signature := ed25519.Sign(key, data)
	return signature, nil
}

// GetKeyID computes the key ID from a private key
func GetKeyID(privateKey *PrivateKey) (string, error) {
	tufKey, keyID, err := convertPrivateKey(privateKey.raw)
	if err != nil {
		return "", err
	}
	_ = tufKey // unused but returned from convertPrivateKey
	return keyID, nil
}

// CanonicalJSON produces canonical JSON encoding for TUF
// This ensures consistent signing across implementations
func CanonicalJSON(v interface{}) ([]byte, error) {
	// For TUF, we use compact JSON (no extra whitespace) with sorted keys
	// The standard library's json.Marshal already sorts map keys
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}
	return data, nil
}

// SignMetadata signs a metadata object and returns a signature
func SignMetadata(privateKey *PrivateKey, metadata *schema.Root) (*schema.Signature, error) {
	// Get key ID
	keyID, err := GetKeyID(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get key ID: %w", err)
	}

	// Serialize to canonical JSON
	canonicalData, err := CanonicalJSON(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize metadata: %w", err)
	}

	// Sign the canonical data
	signature, err := Sign(privateKey, canonicalData)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return &schema.Signature{
		KeyID: keyID,
		Sig:   hex.EncodeToString(signature),
	}, nil
}
