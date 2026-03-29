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
	"time"

	"github.com/securesign/tufcli/internal/keys"
	"github.com/securesign/tufcli/internal/schema"
	"github.com/securesign/tufcli/internal/utils"
)

// ExpireOptions contains options for the Expire function
type ExpireOptions struct {
	Path    string
	Expires time.Time
}

// Expire sets the expiration time for root.json
func Expire(opts ExpireOptions) error {
	// Load existing root.json
	var signed schema.Signed
	if err := utils.ReadJSONFile(opts.Path, &signed); err != nil {
		return fmt.Errorf("failed to read root.json: %w", err)
	}

	// Update expiration time (rounded to remove nanoseconds)
	signed.Signed.Expires = roundTime(opts.Expires)

	// Clear signatures since content changed
	signed.Signatures = []schema.Signature{}

	// Write back to file
	if err := utils.WriteJSONFile(opts.Path, signed); err != nil {
		return fmt.Errorf("failed to write root.json: %w", err)
	}

	return nil
}

// SetThresholdOptions contains options for the SetThreshold function
type SetThresholdOptions struct {
	Path      string
	Role      schema.RoleType
	Threshold uint64
}

// SetThreshold sets the signature threshold for a role
func SetThreshold(opts SetThresholdOptions) error {
	// Validate threshold
	if opts.Threshold == 0 {
		return fmt.Errorf("threshold must be greater than 0")
	}

	// Load existing root.json
	var signed schema.Signed
	if err := utils.ReadJSONFile(opts.Path, &signed); err != nil {
		return fmt.Errorf("failed to read root.json: %w", err)
	}

	// Update or create role with new threshold
	roleKeys := signed.Signed.Roles[opts.Role]
	roleKeys.Threshold = opts.Threshold
	signed.Signed.Roles[opts.Role] = roleKeys

	// Clear signatures since content changed
	signed.Signatures = []schema.Signature{}

	// Write back to file
	if err := utils.WriteJSONFile(opts.Path, signed); err != nil {
		return fmt.Errorf("failed to write root.json: %w", err)
	}

	return nil
}

// BumpVersionOptions contains options for the BumpVersion function
type BumpVersionOptions struct {
	Path string
}

// BumpVersion increments the version number by 1
func BumpVersion(opts BumpVersionOptions) error {
	// Load existing root.json
	var signed schema.Signed
	if err := utils.ReadJSONFile(opts.Path, &signed); err != nil {
		return fmt.Errorf("failed to read root.json: %w", err)
	}

	// Increment version
	signed.Signed.Version++

	// Clear signatures since content changed
	signed.Signatures = []schema.Signature{}

	// Write back to file
	if err := utils.WriteJSONFile(opts.Path, signed); err != nil {
		return fmt.Errorf("failed to write root.json: %w", err)
	}

	return nil
}

// SetVersionOptions contains options for the SetVersion function
type SetVersionOptions struct {
	Path    string
	Version uint64
}

// SetVersion sets a specific version number
func SetVersion(opts SetVersionOptions) error {
	// Validate version
	if opts.Version == 0 {
		return fmt.Errorf("version must be greater than 0")
	}

	// Load existing root.json
	var signed schema.Signed
	if err := utils.ReadJSONFile(opts.Path, &signed); err != nil {
		return fmt.Errorf("failed to read root.json: %w", err)
	}

	// Set version
	signed.Signed.Version = opts.Version

	// Clear signatures since content changed
	signed.Signatures = []schema.Signature{}

	// Write back to file
	if err := utils.WriteJSONFile(opts.Path, signed); err != nil {
		return fmt.Errorf("failed to write root.json: %w", err)
	}

	return nil
}

// RemoveKeyOptions contains options for the RemoveKey function
type RemoveKeyOptions struct {
	Path  string
	KeyID string
	Role  *schema.RoleType // Optional - if nil, removes from all roles and keys map
}

// RemoveKey removes a key ID from role(s) or entirely from root.json
func RemoveKey(opts RemoveKeyOptions) error {
	// Load existing root.json
	var signed schema.Signed
	if err := utils.ReadJSONFile(opts.Path, &signed); err != nil {
		return fmt.Errorf("failed to read root.json: %w", err)
	}

	if opts.Role != nil {
		// Remove key ID from specific role
		if roleKeys, exists := signed.Signed.Roles[*opts.Role]; exists {
			newKeyIDs := []string{}
			found := false
			for _, keyID := range roleKeys.KeyIDs {
				if keyID != opts.KeyID {
					newKeyIDs = append(newKeyIDs, keyID)
				} else {
					found = true
				}
			}
			if found {
				roleKeys.KeyIDs = newKeyIDs
				signed.Signed.Roles[*opts.Role] = roleKeys
			}
		}
	} else {
		// Remove key ID from all roles and delete from keys map
		for role, roleKeys := range signed.Signed.Roles {
			newKeyIDs := []string{}
			for _, keyID := range roleKeys.KeyIDs {
				if keyID != opts.KeyID {
					newKeyIDs = append(newKeyIDs, keyID)
				}
			}
			roleKeys.KeyIDs = newKeyIDs
			signed.Signed.Roles[role] = roleKeys
		}
		// Remove from keys map
		delete(signed.Signed.Keys, opts.KeyID)
	}

	// Clear signatures since content changed
	signed.Signatures = []schema.Signature{}

	// Write back to file
	if err := utils.WriteJSONFile(opts.Path, signed); err != nil {
		return fmt.Errorf("failed to write root.json: %w", err)
	}

	return nil
}

// AddKeyOptions contains options for the AddKey function
type AddKeyOptions struct {
	Path     string
	KeyPaths []string
	Roles    []schema.RoleType
}

// AddKey adds one or more keys to specified roles
func AddKey(opts AddKeyOptions) ([]string, error) {
	// Load existing root.json
	var signed schema.Signed
	if err := utils.ReadJSONFile(opts.Path, &signed); err != nil {
		return nil, fmt.Errorf("failed to read root.json: %w", err)
	}

	addedKeyIDs := []string{}

	for _, keyPath := range opts.KeyPaths {
		// Parse the key
		tufKey, keyID, err := keys.ParseKeyFromFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse key %s: %w", keyPath, err)
		}

		// Check if key already exists
		if existingKey, exists := signed.Signed.Keys[keyID]; exists {
			// Verify it's the same key
			if !keysEqual(existingKey, *tufKey) {
				return nil, fmt.Errorf("key ID collision: different key with same ID %s", keyID)
			}
		} else {
			// Add key to keys map
			signed.Signed.Keys[keyID] = *tufKey
		}

		// Add key ID to roles
		for _, role := range opts.Roles {
			roleKeys := signed.Signed.Roles[role]

			// Check if key ID already in role
			found := false
			for _, existingKeyID := range roleKeys.KeyIDs {
				if existingKeyID == keyID {
					found = true
					break
				}
			}

			if !found {
				roleKeys.KeyIDs = append(roleKeys.KeyIDs, keyID)
				signed.Signed.Roles[role] = roleKeys
			}
		}

		addedKeyIDs = append(addedKeyIDs, keyID)
	}

	// Clear signatures since content changed
	signed.Signatures = []schema.Signature{}

	// Write back to file
	if err := utils.WriteJSONFile(opts.Path, signed); err != nil {
		return nil, fmt.Errorf("failed to write root.json: %w", err)
	}

	return addedKeyIDs, nil
}

// keysEqual checks if two keys are equal
func keysEqual(k1, k2 schema.Key) bool {
	if k1.KeyType != k2.KeyType || k1.Scheme != k2.Scheme {
		return false
	}

	pub1, ok1 := k1.KeyVal["public"].(string)
	pub2, ok2 := k2.KeyVal["public"].(string)

	return ok1 && ok2 && pub1 == pub2
}

// GenRsaKeyOptions contains options for the GenRsaKey function
type GenRsaKeyOptions struct {
	Path     string
	KeyPath  string
	Bits     int
	Exponent int
	Roles    []schema.RoleType
}

// GenRsaKey generates an RSA key pair and adds it to roles
func GenRsaKey(opts GenRsaKeyOptions) (string, error) {
	// Load existing root.json
	var signed schema.Signed
	if err := utils.ReadJSONFile(opts.Path, &signed); err != nil {
		return "", fmt.Errorf("failed to read root.json: %w", err)
	}

	// Generate RSA key using openssl
	keyPEM, err := generateRSAKey(opts.Bits, opts.Exponent)
	if err != nil {
		return "", fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Parse the generated key
	tufKey, keyID, err := keys.ParseKey([]byte(keyPEM))
	if err != nil {
		return "", fmt.Errorf("failed to parse generated key: %w", err)
	}

	// Add key to root.json
	signed.Signed.Keys[keyID] = *tufKey

	// Add key ID to roles
	for _, role := range opts.Roles {
		roleKeys := signed.Signed.Roles[role]
		if !containsKeyID(roleKeys.KeyIDs, keyID) {
			roleKeys.KeyIDs = append(roleKeys.KeyIDs, keyID)
			signed.Signed.Roles[role] = roleKeys
		}
	}

	// Clear signatures since content changed
	signed.Signatures = []schema.Signature{}

	// Write back to file
	if err := utils.WriteJSONFile(opts.Path, signed); err != nil {
		return "", fmt.Errorf("failed to write root.json: %w", err)
	}

	// Write key to file
	if err := utils.WriteFile(opts.KeyPath, []byte(keyPEM)); err != nil {
		return "", fmt.Errorf("failed to write key file: %w", err)
	}

	return keyID, nil
}

// generateRSAKey uses openssl to generate an RSA private key
func generateRSAKey(bits, exponent int) (string, error) {
	cmd := fmt.Sprintf("openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:%d -pkeyopt rsa_keygen_pubexp:%d",
		bits, exponent)

	output, err := utils.RunCommand(cmd)
	if err != nil {
		return "", fmt.Errorf("openssl command failed: %w", err)
	}

	return string(output), nil
}

// containsKeyID checks if a key ID is in a list
func containsKeyID(keyIDs []string, keyID string) bool {
	for _, id := range keyIDs {
		if id == keyID {
			return true
		}
	}
	return false
}

// roundTime rounds time to remove nanoseconds (matches Rust implementation)
func roundTime(t time.Time) time.Time {
	return t.Truncate(time.Second)
}
