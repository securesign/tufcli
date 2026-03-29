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

package root

import (
	"fmt"

	"github.com/securesign/tufcli/internal/keys"
	"github.com/securesign/tufcli/internal/schema"
	"github.com/securesign/tufcli/internal/utils"
)

// SignOptions contains options for the Sign function
type SignOptions struct {
	Path            string
	KeyPaths        []string
	CrossSignPath   string
	IgnoreThreshold bool
}

// Sign signs root.json with the provided keys
func Sign(opts SignOptions) error {
	// Load root.json to be signed
	var signed schema.Signed
	if err := utils.ReadJSONFile(opts.Path, &signed); err != nil {
		return fmt.Errorf("failed to read root.json: %w", err)
	}

	// Load cross-sign root if provided
	var crossSignRoot *schema.Signed
	if opts.CrossSignPath != "" {
		crossSignRoot = &schema.Signed{}
		if err := utils.ReadJSONFile(opts.CrossSignPath, crossSignRoot); err != nil {
			return fmt.Errorf("failed to read cross-sign root.json: %w", err)
		}
	}

	// Determine which root to use for key validation
	validationRoot := &signed
	if crossSignRoot != nil {
		validationRoot = crossSignRoot
	}

	// Load private keys and create signatures
	newSignatures := []schema.Signature{}
	for _, keyPath := range opts.KeyPaths {
		privateKey, err := keys.LoadPrivateKey(keyPath)
		if err != nil {
			return fmt.Errorf("failed to load key %s: %w", keyPath, err)
		}

		// Sign the metadata
		signature, err := keys.SignMetadata(privateKey, &signed.Signed)
		if err != nil {
			return fmt.Errorf("failed to sign with key %s: %w", keyPath, err)
		}

		// Check if key ID exists in validation root
		if _, exists := validationRoot.Signed.Keys[signature.KeyID]; !exists {
			return fmt.Errorf("key %s not found in root.json", signature.KeyID)
		}

		newSignatures = append(newSignatures, *signature)
	}

	// Merge with existing signatures (avoid duplicates)
	existingSignatures := signed.Signatures
	for _, newSig := range newSignatures {
		found := false
		for i, existingSig := range existingSignatures {
			if existingSig.KeyID == newSig.KeyID {
				// Replace existing signature
				existingSignatures[i] = newSig
				found = true
				break
			}
		}
		if !found {
			existingSignatures = append(existingSignatures, newSig)
		}
	}
	signed.Signatures = existingSignatures

	// Validate threshold for all roles
	for roleType, roleKeys := range signed.Signed.Roles {
		threshold := roleKeys.Threshold
		keyCount := uint64(len(roleKeys.KeyIDs))

		if threshold > keyCount && !opts.IgnoreThreshold {
			return fmt.Errorf("unstable root: role '%s' has threshold %d but only %d keys", roleType, threshold, keyCount)
		}
	}

	// Validate signature count for root role
	rootRole, exists := signed.Signed.Roles[schema.RoleTypeRoot]
	if !exists {
		return fmt.Errorf("root role not found in root.json")
	}

	signatureCount := uint64(len(signed.Signatures))
	if rootRole.Threshold > signatureCount && !opts.IgnoreThreshold {
		return fmt.Errorf("insufficient signatures: root role requires %d signatures but only %d provided", rootRole.Threshold, signatureCount)
	}

	// Write signed root.json
	if err := utils.WriteJSONFile(opts.Path, signed); err != nil {
		return fmt.Errorf("failed to write root.json: %w", err)
	}

	return nil
}
