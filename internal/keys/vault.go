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
	"crypto/ed25519"
	"fmt"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms/hashivault"
	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"
)

// vaultSignerLoader creates a Vault-backed signer. It is a package-level
// variable so tests can inject a mock without a live Vault instance.
var vaultSignerLoader = func(ref string, hashFunc crypto.Hash) (signature.Signer, error) {
	return hashivault.LoadSignerVerifier(ref, hashFunc)
}

// LoadVaultSigner loads a signer from HashiCorp Vault's Transit secrets engine.
// The reference string must use the "hashivault://keyname" format.
// Vault connection parameters (VAULT_ADDR, VAULT_TOKEN, TRANSIT_SECRET_ENGINE_PATH)
// are read from the environment by the underlying hashivault library.
func LoadVaultSigner(ref string) (signature.Signer, *tufmeta.Key, string, error) {
	signer, err := vaultSignerLoader(ref, crypto.SHA256)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to load Vault signer for %s: %w", ref, err)
	}

	pubKey, err := signer.PublicKey()
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to get public key from Vault for %s: %w", ref, err)
	}

	// Ed25519 keys require crypto.Hash(0) — reload with the correct hash func.
	if _, ok := pubKey.(ed25519.PublicKey); ok {
		signer, err = vaultSignerLoader(ref, crypto.Hash(0))
		if err != nil {
			return nil, nil, "", fmt.Errorf("failed to reload Vault Ed25519 signer for %s: %w", ref, err)
		}
	}

	tufKey, err := tufmeta.KeyFromPublicKey(pubKey)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to convert Vault public key to TUF key: %w", err)
	}

	keyID, err := finalizeTufKey(tufKey)
	if err != nil {
		return nil, nil, "", err
	}

	return signer, tufKey, keyID, nil
}

// ParseVaultPublicKey fetches the public key from a Vault Transit key and
// returns the corresponding TUF Key and computed key ID. This is used by
// "root add-key --vault-key" to register a Vault-managed key in root.json
// without needing the private key material.
func ParseVaultPublicKey(ref string) (*tufmeta.Key, string, error) {
	signer, err := vaultSignerLoader(ref, crypto.SHA256)
	if err != nil {
		return nil, "", fmt.Errorf("failed to connect to Vault for %s: %w", ref, err)
	}

	pubKey, err := signer.PublicKey()
	if err != nil {
		return nil, "", fmt.Errorf("failed to get public key from Vault for %s: %w", ref, err)
	}

	tufKey, err := tufmeta.KeyFromPublicKey(pubKey)
	if err != nil {
		return nil, "", fmt.Errorf("failed to convert Vault public key to TUF key: %w", err)
	}

	keyID, err := finalizeTufKey(tufKey)
	if err != nil {
		return nil, "", err
	}

	return tufKey, keyID, nil
}
