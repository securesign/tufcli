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

	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/securesign/tufcli/internal/keys"
	"github.com/securesign/tufcli/internal/utils"
)

// SignOptions contains options for the Sign function.
type SignOptions struct {
	Path            string
	KeyPaths        []string
	CrossSignPath   string
	IgnoreThreshold bool
}

// Sign signs root.json with the provided keys.
// Signing is incremental: an existing signature for the same key ID is replaced
// rather than duplicated. Cross-signing uses an older root to authorise keys.
func Sign(opts SignOptions) error {
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
		signer, _, keyID, err := keys.LoadSigner(keyPath)
		if err != nil {
			return fmt.Errorf("failed to load key %s: %w", keyPath, err)
		}

		if _, ok := validationMd.Signed.Keys[keyID]; !ok {
			return fmt.Errorf("key %s not found in root.json", keyID)
		}

		// Drop any existing signature for this key ID so we don't accumulate duplicates.
		filtered := make([]tufmeta.Signature, 0, len(md.Signatures))
		for _, sig := range md.Signatures {
			if sig.KeyID != keyID {
				filtered = append(filtered, sig)
			}
		}
		md.Signatures = filtered

		// Sign — this appends one new signature.
		if _, err := md.Sign(signer); err != nil {
			return fmt.Errorf("failed to sign with key %s: %w", keyPath, err)
		}

		// Fix the signature keyid to match our corrected keyID (without trailing newline).
		// go-tuf's Sign() method computes the keyid using its own KeyFromPublicKey() which
		// includes a trailing newline, but we've stripped it from our keys for tuftool compatibility.
		if len(md.Signatures) > 0 {
			md.Signatures[len(md.Signatures)-1].KeyID = keyID
		}
	}

	if !opts.IgnoreThreshold {
		if err := validateThreshold(md); err != nil {
			return err
		}
	}

	data, err := md.ToBytes(false)
	if err != nil {
		return fmt.Errorf("failed to serialize root.json: %w", err)
	}
	data, err = utils.IndentJSON(data)
	if err != nil {
		return fmt.Errorf("failed to format root.json: %w", err)
	}

	return utils.WriteFileAtomic(opts.Path, data)
}

// validateThreshold checks that every role has enough keys and that the root
// role has enough signatures.
func validateThreshold(md *tufmeta.Metadata[tufmeta.RootType]) error {
	for roleName, role := range md.Signed.Roles {
		if role.Threshold > len(role.KeyIDs) {
			return fmt.Errorf("unstable root: role '%s' has threshold %d but only %d keys",
				roleName, role.Threshold, len(role.KeyIDs))
		}
	}

	rootRole := md.Signed.Roles[tufmeta.ROOT]
	if rootRole.Threshold > len(md.Signatures) {
		return fmt.Errorf("insufficient signatures: root role requires %d signatures but only %d provided",
			rootRole.Threshold, len(md.Signatures))
	}

	return nil
}
