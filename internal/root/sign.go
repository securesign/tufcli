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
	"errors"
	"fmt"
	"io"

	"github.com/sigstore/sigstore/pkg/signature"
	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/securesign/tufcli/internal/keys"
)

// SignOptions contains options for the Sign function.
type SignOptions struct {
	Path            string
	KeyPaths        []string
	VaultKeyRefs    []string
	CrossSignPath   string
	IgnoreThreshold bool
	GetPassphrase   keys.PassphraseFunc
}

// Sign signs root.json with the provided keys.
// Signing is incremental: an existing signature for the same key ID is replaced
// rather than duplicated. Cross-signing uses an older root to authorise keys.
func Sign(opts SignOptions) (retErr error) {
	md, err := loadRoot(opts.Path)
	if err != nil {
		return err
	}

	// Load the cross-sign root when provided; it is used to authorise the signing keys.
	var validationMd *tufmeta.Metadata[tufmeta.RootType]
	if opts.CrossSignPath != "" {
		crossMd, err := loadRoot(opts.CrossSignPath)
		if err != nil {
			return fmt.Errorf("failed to read cross-sign root.json: %w", err)
		}
		validationMd = crossMd
	} else {
		validationMd = md
	}

	for _, keyPath := range opts.KeyPaths {
		signer, _, keyID, err := keys.LoadSigner(keyPath, opts.GetPassphrase)
		if err != nil {
			return fmt.Errorf("failed to load key %s: %w", keyPath, err)
		}
		if c, ok := signer.(io.Closer); ok {
			defer func() { retErr = errors.Join(retErr, c.Close()) }()
		}

		if err := signRootWithKey(md, validationMd, signer, keyID, keyPath); err != nil {
			return err
		}
	}

	for _, vaultRef := range opts.VaultKeyRefs {
		signer, _, keyID, err := keys.LoadVaultSigner(vaultRef)
		if err != nil {
			return fmt.Errorf("failed to load Vault key %s: %w", vaultRef, err)
		}

		if err := signRootWithKey(md, validationMd, signer, keyID, vaultRef); err != nil {
			return err
		}
	}

	if !opts.IgnoreThreshold {
		if err := validateThreshold(md, validationMd); err != nil {
			return err
		}
	}

	return saveRoot(opts.Path, md)
}

func signRootWithKey(md, validationMd *tufmeta.Metadata[tufmeta.RootType], signer signature.Signer, keyID, label string) error {
	rootRole, ok := validationMd.Signed.Roles[tufmeta.ROOT]
	if !ok || rootRole == nil {
		return fmt.Errorf("root role not found in root.json")
	}
	if key, ok := validationMd.Signed.Keys[keyID]; !ok || key == nil {
		return fmt.Errorf("key %s not found in root.json", keyID)
	}

	authorized := false
	for _, authorizedKeyID := range rootRole.KeyIDs {
		if authorizedKeyID == keyID {
			authorized = true
			break
		}
	}
	if !authorized {
		return fmt.Errorf("key %s is not authorized for the root role", keyID)
	}

	filtered := make([]tufmeta.Signature, 0, len(md.Signatures))
	for _, sig := range md.Signatures {
		if sig.KeyID != keyID {
			filtered = append(filtered, sig)
		}
	}
	md.Signatures = filtered

	if _, err := md.Sign(signer); err != nil {
		return fmt.Errorf("failed to sign with key %s: %w", label, err)
	}

	if len(md.Signatures) > 0 {
		md.Signatures[len(md.Signatures)-1].KeyID = keyID
	}

	return nil
}

// validateThreshold checks that md has valid role thresholds and that its
// root signatures satisfy the root role in validationMd. During
// cross-signing, validationMd is the older root that authorizes the
// signatures; otherwise it is md itself.
func validateThreshold(md, validationMd *tufmeta.Metadata[tufmeta.RootType]) error {
	for roleName, role := range md.Signed.Roles {
		if role == nil {
			return fmt.Errorf("invalid root: role '%s' is null", roleName)
		}
		if role.Threshold > len(role.KeyIDs) {
			return fmt.Errorf("unstable root: role '%s' has threshold %d but only %d keys",
				roleName, role.Threshold, len(role.KeyIDs))
		}
	}

	rootRole, ok := md.Signed.Roles[tufmeta.ROOT]
	if !ok {
		return fmt.Errorf("invalid root: role '%s' is missing", tufmeta.ROOT)
	}
	for _, keyID := range rootRole.KeyIDs {
		if key, ok := md.Signed.Keys[keyID]; !ok || key == nil {
			return fmt.Errorf("invalid root: key %s referenced by root role is missing", keyID)
		}
	}

	validationRootRole, ok := validationMd.Signed.Roles[tufmeta.ROOT]
	if !ok || validationRootRole == nil {
		return fmt.Errorf("invalid validating root: role '%s' is missing", tufmeta.ROOT)
	}
	for _, keyID := range validationRootRole.KeyIDs {
		if key, ok := validationMd.Signed.Keys[keyID]; !ok || key == nil {
			return fmt.Errorf("invalid validating root: key %s referenced by root role is missing", keyID)
		}
	}

	if err := validationMd.VerifyDelegate(tufmeta.ROOT, md); err != nil {
		return fmt.Errorf("insufficient valid root signatures: %w", err)
	}

	return nil
}
