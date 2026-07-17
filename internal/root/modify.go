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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/securesign/tufcli/internal/keys"
	"github.com/securesign/tufcli/internal/utils"
)

// loadRoot reads a root.json file and returns its parsed metadata.
func loadRoot(path string) (*tufmeta.Metadata[tufmeta.RootType], error) {
	md := &tufmeta.Metadata[tufmeta.RootType]{}
	if _, err := md.FromFile(path); err != nil {
		return nil, fmt.Errorf("failed to read root.json: %w", err)
	}
	return md, nil
}

// saveRoot serialises and atomically writes root.json.
func saveRoot(path string, md *tufmeta.Metadata[tufmeta.RootType]) error {
	data, err := md.ToBytes(false)
	if err != nil {
		return fmt.Errorf("failed to serialize root.json: %w", err)
	}
	data, err = utils.IndentJSON(data)
	if err != nil {
		return fmt.Errorf("failed to format root.json: %w", err)
	}
	return utils.WriteFileAtomic(path, data)
}

// ExpireOptions contains options for the Expire function.
type ExpireOptions struct {
	Path    string
	Expires time.Time
}

// Expire sets the expiration time on root.json and clears signatures.
func Expire(opts ExpireOptions) error {
	md, err := loadRoot(opts.Path)
	if err != nil {
		return err
	}

	md.Signed.Expires = opts.Expires.UTC().Truncate(time.Second)
	md.ClearSignatures()

	return saveRoot(opts.Path, md)
}

// SetThresholdOptions contains options for the SetThreshold function.
type SetThresholdOptions struct {
	Path      string
	Role      string
	Threshold uint64
}

// SetThreshold sets the signature threshold for a role.
func SetThreshold(opts SetThresholdOptions) error {
	if opts.Threshold == 0 {
		return fmt.Errorf("threshold must be greater than 0")
	}

	md, err := loadRoot(opts.Path)
	if err != nil {
		return err
	}

	role, ok := md.Signed.Roles[opts.Role]
	if !ok {
		return fmt.Errorf("role %s not found in root.json", opts.Role)
	}
	role.Threshold = int(opts.Threshold)
	md.ClearSignatures()

	return saveRoot(opts.Path, md)
}

// BumpVersionOptions contains options for the BumpVersion function.
type BumpVersionOptions struct {
	Path string
}

// BumpVersion increments the root.json version by 1.
func BumpVersion(opts BumpVersionOptions) error {
	md, err := loadRoot(opts.Path)
	if err != nil {
		return err
	}

	md.Signed.Version++
	md.ClearSignatures()

	return saveRoot(opts.Path, md)
}

// SetVersionOptions contains options for the SetVersion function.
type SetVersionOptions struct {
	Path    string
	Version uint64
}

// SetVersion sets a specific version number on root.json.
func SetVersion(opts SetVersionOptions) error {
	if opts.Version == 0 {
		return fmt.Errorf("version must be greater than 0")
	}

	md, err := loadRoot(opts.Path)
	if err != nil {
		return err
	}

	md.Signed.Version = int64(opts.Version)
	md.ClearSignatures()

	return saveRoot(opts.Path, md)
}

// RemoveKeyOptions contains options for the RemoveKey function.
type RemoveKeyOptions struct {
	Path  string
	KeyID string
	Role  *string // nil = remove from all roles and the keys map
}

// RemoveKey removes a key ID from a specific role or from all roles.
// When Role is nil the key is also deleted from the keys map.
func RemoveKey(opts RemoveKeyOptions) error {
	md, err := loadRoot(opts.Path)
	if err != nil {
		return err
	}

	if opts.Role != nil {
		// Remove only from the named role; RevokeKey keeps the key in the map
		// as long as another role still references it.
		if err := md.Signed.RevokeKey(opts.KeyID, *opts.Role); err != nil {
			var errVal *tufmeta.ErrValue
			if !errors.As(err, &errVal) {
				return fmt.Errorf("failed to remove key from role %s: %w", *opts.Role, err)
			}
			// key was not in this role — silently ignore
		}
	} else {
		// Remove from every role; after the last removal RevokeKey automatically
		// deletes the key from the keys map.
		for role := range md.Signed.Roles {
			if err := md.Signed.RevokeKey(opts.KeyID, role); err != nil {
				var errVal *tufmeta.ErrValue
				if !errors.As(err, &errVal) {
					return fmt.Errorf("failed to remove key from role %s: %w", role, err)
				}
				// key was not in this role — continue
			}
		}
	}

	md.ClearSignatures()
	return saveRoot(opts.Path, md)
}

// AddKeyOptions contains options for the AddKey function.
type AddKeyOptions struct {
	Path     string
	KeyPaths []string
	Roles    []string
}

// AddKey adds one or more public keys to the specified roles.
func AddKey(opts AddKeyOptions) ([]string, error) {
	md, err := loadRoot(opts.Path)
	if err != nil {
		return nil, err
	}

	var addedKeyIDs []string

	for _, keyPath := range opts.KeyPaths {
		tufKey, keyID, err := keys.ParsePublicKeyFromFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse key %s: %w", keyPath, err)
		}

		for _, role := range opts.Roles {
			if err := md.Signed.AddKey(tufKey, role); err != nil {
				return nil, fmt.Errorf("failed to add key to role %s: %w", role, err)
			}
		}

		addedKeyIDs = append(addedKeyIDs, keyID)
	}

	md.ClearSignatures()
	return addedKeyIDs, saveRoot(opts.Path, md)
}

// GenRsaKeyOptions contains options for the GenRsaKey function.
type GenRsaKeyOptions struct {
	Path    string
	KeyPath string
	Bits    int
	Roles   []string
}

// GenRsaKey generates an RSA key pair, adds its public key to the specified roles,
// and saves the private key to KeyPath.
func GenRsaKey(opts GenRsaKeyOptions) (string, error) {
	md, err := loadRoot(opts.Path)
	if err != nil {
		return "", err
	}

	keyPEM, err := generateRSAKey(opts.Bits)
	if err != nil {
		return "", fmt.Errorf("failed to generate RSA key: %w", err)
	}

	tufKey, keyID, err := keys.ParsePublicKey([]byte(keyPEM))
	if err != nil {
		return "", fmt.Errorf("failed to parse generated key: %w", err)
	}

	for _, role := range opts.Roles {
		if err := md.Signed.AddKey(tufKey, role); err != nil {
			return "", fmt.Errorf("failed to add key to role %s: %w", role, err)
		}
	}

	md.ClearSignatures()

	if err := saveRoot(opts.Path, md); err != nil {
		return "", err
	}

	if err := utils.WriteFile(opts.KeyPath, []byte(keyPEM)); err != nil {
		return "", fmt.Errorf("failed to write key file: %w", err)
	}

	return keyID, nil
}

func generateRSAKey(bits int) (string, error) {
	if bits < 2048 {
		return "", fmt.Errorf("RSA key size must be at least 2048 bits, got %d", bits)
	}

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", fmt.Errorf("failed to generate RSA key: %w", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("failed to marshal private key: %w", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return string(pemBytes), nil
}
