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
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/securesign/tufcli/internal/schema"
)

// ParseKeyFromFile parses a private key from a PEM file
func ParseKeyFromFile(path string) (*schema.Key, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read key file: %w", err)
	}

	return ParseKey(data)
}

// ParseKey parses a private key from PEM-encoded data
func ParseKey(data []byte) (*schema.Key, string, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, "", fmt.Errorf("failed to decode PEM block")
	}

	// Try parsing as PKCS8
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return convertPrivateKey(key)
	}

	// Try parsing as PKCS1 RSA
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return convertPrivateKey(key)
	}

	// Try parsing as EC private key
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return convertPrivateKey(key)
	}

	return nil, "", fmt.Errorf("unrecognized key format")
}

// convertPrivateKey converts a crypto.PrivateKey to a TUF Key and computes its ID
func convertPrivateKey(privateKey interface{}) (*schema.Key, string, error) {
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		return convertRSAKey(k)
	case *ecdsa.PrivateKey:
		return convertECDSAKey(k)
	case ed25519.PrivateKey:
		return convertED25519Key(k)
	default:
		return nil, "", fmt.Errorf("unsupported key type: %T", privateKey)
	}
}

// convertRSAKey converts an RSA private key to TUF format.
func convertRSAKey(key *rsa.PrivateKey) (*schema.Key, string, error) {
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal RSA public key: %w", err)
	}

	publicKeyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	}))

	tufKey := &schema.Key{
		KeyType: "rsa",
		Scheme:  "rsassa-pss-sha256",
		KeyVal:  map[string]interface{}{"public": publicKeyPEM},
	}

	keyID, err := computeKeyID(tufKey)
	if err != nil {
		return nil, "", err
	}

	return tufKey, keyID, nil
}

// convertECDSAKey converts an ECDSA private key to TUF format.
func convertECDSAKey(key *ecdsa.PrivateKey) (*schema.Key, string, error) {
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal ECDSA public key: %w", err)
	}

	publicKeyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	}))

	tufKey := &schema.Key{
		KeyType: "ecdsa",
		Scheme:  "ecdsa-sha2-nistp256",
		KeyVal:  map[string]interface{}{"public": publicKeyPEM},
	}

	keyID, err := computeKeyID(tufKey)
	if err != nil {
		return nil, "", err
	}

	return tufKey, keyID, nil
}

// convertED25519Key converts an ED25519 private key to TUF format.
func convertED25519Key(key ed25519.PrivateKey) (*schema.Key, string, error) {
	publicKey := key.Public().(ed25519.PublicKey)

	tufKey := &schema.Key{
		KeyType: "ed25519",
		Scheme:  "ed25519",
		KeyVal:  map[string]interface{}{"public": hex.EncodeToString(publicKey)},
	}

	keyID, err := computeKeyID(tufKey)
	if err != nil {
		return nil, "", err
	}

	return tufKey, keyID, nil
}

// computeKeyID computes the TUF key ID as SHA256 of the canonical JSON encoding of the key.
// This matches the TUF specification for key IDs.
func computeKeyID(key *schema.Key) (string, error) {
	// Key struct fields are in alphabetical JSON-tag order, so json.Marshal
	// produces canonical JSON suitable for key ID computation.
	data, err := json.Marshal(key)
	if err != nil {
		return "", fmt.Errorf("failed to marshal key for ID computation: %w", err)
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// PrivateKey wraps different key types for signing
type PrivateKey struct {
	raw interface{}
}

// LoadPrivateKey loads a private key from a file
func LoadPrivateKey(path string) (*PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try parsing as PKCS8
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return &PrivateKey{raw: key}, nil
	}

	// Try parsing as PKCS1 RSA
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return &PrivateKey{raw: key}, nil
	}

	// Try parsing as EC private key
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return &PrivateKey{raw: key}, nil
	}

	return nil, fmt.Errorf("unrecognized key format")
}

// Raw returns the raw key material
func (pk *PrivateKey) Raw() crypto.PrivateKey {
	return pk.raw
}
