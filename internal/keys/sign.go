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
	"errors"
	"fmt"
	"io"

	"github.com/sigstore/sigstore/pkg/signature"
	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"
)

// SignerSet holds a set of loaded private key signers.
type SignerSet struct {
	entries []signerEntry
}

type signerEntry struct {
	signer signature.Signer
	keyID  string
}

// Close closes any signers that implement io.Closer (e.g. PIV/YubiKey signers).
func (ss *SignerSet) Close() error {
	var errs []error
	for _, e := range ss.entries {
		if c, ok := e.signer.(io.Closer); ok {
			if err := c.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// LoadSignerSet loads private keys from the given file paths and returns a SignerSet.
// On error, any already-opened signers (e.g. PIV handles) are closed before returning.
func LoadSignerSet(paths []string) (*SignerSet, error) {
	ss := &SignerSet{}
	for _, path := range paths {
		signer, _, keyID, err := LoadSigner(path)
		if err != nil {
			ss.Close()
			return nil, fmt.Errorf("failed to load key from %s: %w", path, err)
		}
		ss.entries = append(ss.entries, signerEntry{signer: signer, keyID: keyID})
	}
	return ss, nil
}

// AddVaultSigners loads signers from Vault Transit key references and adds
// them to the set.
func (ss *SignerSet) AddVaultSigners(refs []string) error {
	for _, ref := range refs {
		signer, _, keyID, err := LoadVaultSigner(ref)
		if err != nil {
			return fmt.Errorf("failed to load Vault key %s: %w", ref, err)
		}
		ss.entries = append(ss.entries, signerEntry{signer: signer, keyID: keyID})
	}
	return nil
}

// LoadSignerSetFromAll loads signers from both file paths and Vault Transit
// key references into a single SignerSet.
// On error, any already-opened signers are closed before returning.
func LoadSignerSetFromAll(filePaths, vaultRefs []string) (*SignerSet, error) {
	ss, err := LoadSignerSet(filePaths)
	if err != nil {
		return nil, err
	}
	if err := ss.AddVaultSigners(vaultRefs); err != nil {
		ss.Close()
		return nil, err
	}
	return ss, nil
}

// SignForRole signs TUF metadata using only the signers whose key IDs are
// authorized for the given role. It clears existing signatures first, then
// signs with each matching key and corrects the key IDs for tuftool compatibility.
//
// authorizedKeyIDs lists the key IDs allowed for this role (from root.json).
// roleName is used only for error messages.
func SignForRole[T tufmeta.Roles](ss *SignerSet, md *tufmeta.Metadata[T], roleName string, authorizedKeyIDs []string) error {
	if len(authorizedKeyIDs) == 0 {
		return fmt.Errorf("no keys defined for role %s in root.json", roleName)
	}

	// Find matching signers
	var matched []signerEntry
	for _, e := range ss.entries {
		for _, authID := range authorizedKeyIDs {
			if e.keyID == authID {
				matched = append(matched, e)
				break
			}
		}
	}

	if len(matched) == 0 {
		return fmt.Errorf("none of the provided keys match role %s (expected key IDs: %v)", roleName, authorizedKeyIDs)
	}

	md.ClearSignatures()
	for _, m := range matched {
		if _, err := md.Sign(m.signer); err != nil {
			return fmt.Errorf("failed to sign %s: %w", roleName, err)
		}
		// Fix the signature keyid to match our corrected keyID (without trailing newline).
		// go-tuf's Sign() method computes the keyid using its own KeyFromPublicKey() which
		// includes a trailing newline, but we've stripped it from our keys for tuftool compatibility.
		if len(md.Signatures) > 0 {
			md.Signatures[len(md.Signatures)-1].KeyID = m.keyID
		}
	}

	return nil
}
