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

package rhtas

import (
	"fmt"
	"path/filepath"

	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/securesign/tufcli/internal/editor"
	"github.com/securesign/tufcli/internal/sigstore"
	"github.com/securesign/tufcli/internal/utils"
)

// Editor wraps the generic TUF Editor with RHTAS-specific trust bundle support.
type Editor struct {
	*editor.Editor
	TrustBundle *sigstore.TrustBundle
}

// LoadRepository loads a TUF repository and its RHTAS trust bundle.
func LoadRepository(opts editor.LoadOptions) (*Editor, error) {
	e, err := editor.LoadRepository(opts)
	if err != nil {
		return nil, err
	}

	// Load trust bundle
	targetsDir := filepath.Join(opts.OutDir, "targets")
	trustedRootPath := filepath.Join(targetsDir, "trusted_root.json")
	signingConfigPath := filepath.Join(targetsDir, "signing_config.v0.2.json")

	actualTrustedRootPath := findLatestTrustBundleFile(opts.OutDir, "trusted_root.json", e.Targets())
	if actualTrustedRootPath != "" {
		trustedRootPath = actualTrustedRootPath
	}

	actualSigningConfigPath := findLatestTrustBundleFile(opts.OutDir, "signing_config.v0.2.json", e.Targets())
	if actualSigningConfigPath != "" {
		signingConfigPath = actualSigningConfigPath
	}

	tb, err := sigstore.LoadTrustBundle(trustedRootPath, signingConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load trust bundle: %w", err)
	}

	return &Editor{
		Editor:      e,
		TrustBundle: tb,
	}, nil
}

// findLatestTrustBundleFile looks for a hash-prefixed version of a trust bundle file
// by scanning the targets metadata for the entry.
func findLatestTrustBundleFile(repoDir, filename string, targets *tufmeta.Metadata[tufmeta.TargetsType]) string {
	targetsDir := filepath.Join(repoDir, "targets")

	if targets == nil {
		return ""
	}

	targetEntry, ok := targets.Signed.Targets[filename]
	if !ok || targetEntry == nil {
		return ""
	}

	sha256Hash, ok := targetEntry.Hashes["sha256"]
	if !ok {
		return ""
	}

	hashPrefixedPath := filepath.Join(targetsDir, sha256Hash.String()+"."+filename)
	if utils.FileExists(hashPrefixedPath) {
		return hashPrefixedPath
	}

	return ""
}
