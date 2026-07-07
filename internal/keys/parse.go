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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/sigstore/sigstore/pkg/signature"
	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"
)

// ParsePublicKeyFromFile parses a key file (public or private PEM) and returns
// the corresponding TUF Key and its computed key ID.
func ParsePublicKeyFromFile(path string) (*tufmeta.Key, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read key file: %w", err)
	}
	return ParsePublicKey(data)
}

// ParsePublicKey parses PEM-encoded key material (public or private) and returns
// the corresponding TUF Key and its computed key ID.
func ParsePublicKey(data []byte) (*tufmeta.Key, string, error) {
	pubKey, err := extractPublicKey(data)
	if err != nil {
		return nil, "", err
	}

	tufKey, err := tufmeta.KeyFromPublicKey(pubKey)
	if err != nil {
		return nil, "", fmt.Errorf("failed to convert to TUF key: %w", err)
	}

	// Strip trailing newline from PEM-encoded public key for compatibility with tuftool (backward compatibility).
	// Go's pem.EncodeToMemory() adds a trailing newline, but tuftool does not include it.
	tufKey.Value.PublicKey = strings.TrimSuffix(tufKey.Value.PublicKey, "\n")

	keyID, err := tufKey.ID()
	if err != nil {
		return nil, "", fmt.Errorf("failed to compute key ID: %w", err)
	}

	return tufKey, keyID, nil
}

// LoadSigner loads a private key file and returns a sigstore Signer along with
// the corresponding TUF Key and key ID. The signer uses the algorithm-appropriate
// hash function (SHA-256 for RSA/ECDSA; none for Ed25519).
func LoadSigner(path string) (signature.Signer, *tufmeta.Key, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to read key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, nil, "", fmt.Errorf("failed to decode PEM block from %s", path)
	}

	var privKey interface{}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		privKey = k
	} else if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		privKey = k
	} else if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		privKey = k
	} else {
		return nil, nil, "", fmt.Errorf("unrecognized private key format in %s", path)
	}

	var signer signature.Signer
	var pubKey crypto.PublicKey

	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		var err error
		signer, err = signature.LoadRSAPSSSigner(k, crypto.SHA256, &rsa.PSSOptions{Hash: crypto.SHA256})
		if err != nil {
			return nil, nil, "", fmt.Errorf("failed to create RSA PSS signer: %w", err)
		}
		pubKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		var err error
		signer, err = signature.LoadSigner(k, crypto.SHA256)
		if err != nil {
			return nil, nil, "", fmt.Errorf("failed to create ECDSA signer: %w", err)
		}
		pubKey = &k.PublicKey
	case ed25519.PrivateKey:
		var err error
		signer, err = signature.LoadSigner(k, crypto.Hash(0))
		if err != nil {
			return nil, nil, "", fmt.Errorf("failed to create Ed25519 signer: %w", err)
		}
		pubKey = k.Public()
	default:
		return nil, nil, "", fmt.Errorf("unsupported key type: %T", privKey)
	}

	tufKey, err := tufmeta.KeyFromPublicKey(pubKey)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to convert to TUF key: %w", err)
	}

	// Strip trailing newline from PEM-encoded public key for compatibility with tuftool (backward compatibility).
	// Go's pem.EncodeToMemory() adds a trailing newline, but tuftool does not include it.
	tufKey.Value.PublicKey = strings.TrimSuffix(tufKey.Value.PublicKey, "\n")

	keyID, err := tufKey.ID()
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to compute key ID: %w", err)
	}

	return signer, tufKey, keyID, nil
}

// extractPublicKey extracts a crypto.PublicKey from PEM data.
// Handles PKIX public keys and all common private key formats.
func extractPublicKey(data []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	switch block.Type {
	case "PUBLIC KEY":
		return x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return publicKeyOf(k)
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return &k.PublicKey, nil
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return &k.PublicKey, nil
	default:
		// Fallback: try PKCS8
		if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			return publicKeyOf(k)
		}
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}
}

func publicKeyOf(priv interface{}) (crypto.PublicKey, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	case ed25519.PrivateKey:
		return k.Public(), nil
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", priv)
	}
}
