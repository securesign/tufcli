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

package editor

import (
	"fmt"
	"os"
	"path/filepath"

	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/securesign/tufcli/internal/keys"
	"github.com/securesign/tufcli/internal/utils"
)

// SignAndWriteOptions configures the sign and write operation.
type SignAndWriteOptions struct {
	KeyPaths      []string
	VaultKeyRefs  []string
	OutDir        string
	HashAlgo      string
	GetPassphrase keys.PassphraseFunc
}

// SignAndWrite signs all metadata files and writes them to the output directory.
// The signing order is: targets -> snapshot -> timestamp (each depends on the previous).
func (e *Editor) SignAndWrite(opts SignAndWriteOptions) error {
	// Load all signers (from both file paths and Vault references)
	signers, err := keys.LoadSignerSetFromAll(opts.KeyPaths, opts.VaultKeyRefs, opts.GetPassphrase)
	if err != nil {
		return err
	}

	outDir := opts.OutDir
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// 0. Load root.json to determine which keys are authorized for each role
	rootData, err := os.ReadFile(e.rootPath)
	if err != nil {
		return fmt.Errorf("failed to read root.json: %w", err)
	}
	rootMd := &tufmeta.Metadata[tufmeta.RootType]{}
	if _, err := rootMd.FromBytes(rootData); err != nil {
		return fmt.Errorf("failed to parse root.json: %w", err)
	}

	// Build a map of role -> authorized key IDs
	roleKeys := make(map[string][]string)
	for roleName, role := range rootMd.Signed.Roles {
		roleKeys[roleName] = role.KeyIDs
	}

	// Copy root.json to the output directory as <version>.root.json
	versionedRootPath := filepath.Join(outDir, fmt.Sprintf("%d.root.json", rootMd.Signed.Version))
	if err := utils.WriteFileAtomic(versionedRootPath, rootData); err != nil {
		return fmt.Errorf("failed to write versioned root.json: %w", err)
	}
	// Also write root.json (non-versioned) for convenience
	rootPath := filepath.Join(outDir, "root.json")
	if err := utils.WriteFileAtomic(rootPath, rootData); err != nil {
		return fmt.Errorf("failed to write root.json: %w", err)
	}

	// 1. Sign targets.json with only the targets key(s)
	if err := keys.SignForRole(signers, e.targets, "targets", roleKeys["targets"]); err != nil {
		return fmt.Errorf("failed to sign targets: %w", err)
	}

	targetsPath := filepath.Join(outDir, fmt.Sprintf("%d.targets.json", e.targets.Signed.Version))
	targetsData, err := e.targets.ToBytes(false)
	if err != nil {
		return fmt.Errorf("failed to serialize targets.json: %w", err)
	}
	targetsData, err = utils.IndentJSON(targetsData)
	if err != nil {
		return fmt.Errorf("failed to format targets.json: %w", err)
	}
	if err := utils.WriteFileAtomic(targetsPath, targetsData); err != nil {
		return fmt.Errorf("failed to write targets.json: %w", err)
	}

	// 2. Update snapshot with targets info
	hashAlgo := opts.HashAlgo
	targetsMeta, err := utils.ComputeMetaFileInfo(targetsPath, e.targets.Signed.Version, hashAlgo)
	if err != nil {
		return fmt.Errorf("failed to compute targets hash: %w", err)
	}
	e.snapshot.Signed.Meta["targets.json"] = targetsMeta

	// 2a. Sign snapshot.json with only the snapshot key(s)
	if err := keys.SignForRole(signers, e.snapshot, "snapshot", roleKeys["snapshot"]); err != nil {
		return fmt.Errorf("failed to sign snapshot: %w", err)
	}

	snapshotPath := filepath.Join(outDir, fmt.Sprintf("%d.snapshot.json", e.snapshot.Signed.Version))
	snapshotData, err := e.snapshot.ToBytes(false)
	if err != nil {
		return fmt.Errorf("failed to serialize snapshot.json: %w", err)
	}
	snapshotData, err = utils.IndentJSON(snapshotData)
	if err != nil {
		return fmt.Errorf("failed to format snapshot.json: %w", err)
	}
	if err := utils.WriteFileAtomic(snapshotPath, snapshotData); err != nil {
		return fmt.Errorf("failed to write snapshot.json: %w", err)
	}

	// 3. Update timestamp with snapshot info
	snapshotMeta, err := utils.ComputeMetaFileInfo(snapshotPath, e.snapshot.Signed.Version, hashAlgo)
	if err != nil {
		return fmt.Errorf("failed to compute snapshot hash: %w", err)
	}
	e.timestamp.Signed.Meta["snapshot.json"] = snapshotMeta

	// 3a. Sign timestamp.json with only the timestamp key(s)
	if err := keys.SignForRole(signers, e.timestamp, "timestamp", roleKeys["timestamp"]); err != nil {
		return fmt.Errorf("failed to sign timestamp: %w", err)
	}

	timestampPath := filepath.Join(outDir, "timestamp.json")
	timestampData, err := e.timestamp.ToBytes(false)
	if err != nil {
		return fmt.Errorf("failed to serialize timestamp.json: %w", err)
	}
	timestampData, err = utils.IndentJSON(timestampData)
	if err != nil {
		return fmt.Errorf("failed to format timestamp.json: %w", err)
	}
	if err := utils.WriteFileAtomic(timestampPath, timestampData); err != nil {
		return fmt.Errorf("failed to write timestamp.json: %w", err)
	}

	// 4. Copy target files to outdir/targets/ with hash-prefixed names
	targetsOutDir := filepath.Join(outDir, "targets")
	if err := os.MkdirAll(targetsOutDir, 0755); err != nil {
		return fmt.Errorf("failed to create targets directory: %w", err)
	}

	for name, meta := range e.targets.Signed.Targets {
		hashStr, err := utils.PreferredHash(meta.Hashes)
		if err != nil {
			return fmt.Errorf("target %q: %w", name, err)
		}
		srcPath := filepath.Join(targetsOutDir, name)
		hashPrefixedPath := filepath.Join(targetsOutDir, hashStr+"."+name)

		if utils.FileExists(hashPrefixedPath) {
			switch e.targetPathExists {
			case "skip", "":
				continue
			case "fail":
				return fmt.Errorf("target file %s already exists (TargetPathExists policy is fail)", hashPrefixedPath)
			}
		}

		if utils.FileExists(srcPath) {
			if err := copyTargetFile(srcPath, targetsOutDir, hashStr); err != nil {
				return fmt.Errorf("failed to copy target %s: %w", name, err)
			}
			// Remove the non-hash-prefixed copy (consistent_snapshot only)
			os.Remove(srcPath)
		} else if !utils.FileExists(hashPrefixedPath) {
			return fmt.Errorf("target %q referenced in targets.json but file not found in %s", name, targetsOutDir)
		}
	}

	return nil
}
