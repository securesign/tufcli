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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/securesign/tufcli/internal/keys"
	"github.com/securesign/tufcli/internal/sigstore"
	"github.com/securesign/tufcli/internal/utils"
)

// Editor manages TUF repository metadata for RHTAS operations.
type Editor struct {
	rootPath         string
	outDir           string
	follow           bool
	targetPathExists string
	targets          *tufmeta.Metadata[tufmeta.TargetsType]
	snapshot         *tufmeta.Metadata[tufmeta.SnapshotType]
	timestamp        *tufmeta.Metadata[tufmeta.TimestampType]
	TrustBundle      *sigstore.TrustBundle
}

// LoadOptions configures how the repository is loaded.
type LoadOptions struct {
	RootPath         string
	OutDir           string
	MetadataURL      string
	Follow           bool
	TargetPathExists string
}

// LoadRepository loads an existing TUF repository from the output directory,
// or creates default metadata if the repository doesn't exist yet.
func LoadRepository(opts LoadOptions) (*Editor, error) {
	if !utils.FileExists(opts.RootPath) {
		return nil, fmt.Errorf("root.json not found at %s", opts.RootPath)
	}

	if opts.MetadataURL != "" {
		if err := fetchMetadataFromURL(opts.MetadataURL, opts.OutDir); err != nil {
			return nil, fmt.Errorf("failed to fetch metadata from %s: %w", opts.MetadataURL, err)
		}
	}

	editor := &Editor{
		rootPath:         opts.RootPath,
		outDir:           opts.OutDir,
		follow:           opts.Follow,
		targetPathExists: opts.TargetPathExists,
	}

	targets, err := loadTargetsMetadata(opts.OutDir)
	if err != nil {
		if !errors.Is(err, errMetadataNotFound) {
			return nil, fmt.Errorf("failed to load targets metadata: %w", err)
		}
		targets = newDefaultTargets()
	}
	// Ensure delegations field exists for TUF spec 1.0.0 compatibility
	if targets.Signed.Delegations == nil {
		targets.Signed.Delegations = &tufmeta.Delegations{
			Keys:  make(map[string]*tufmeta.Key),
			Roles: []tufmeta.DelegatedRole{},
		}
	}
	editor.targets = targets

	snapshot, err := loadSnapshotMetadata(opts.OutDir)
	if err != nil {
		if !errors.Is(err, errMetadataNotFound) {
			return nil, fmt.Errorf("failed to load snapshot metadata: %w", err)
		}
		snapshot = newDefaultSnapshot()
	}
	editor.snapshot = snapshot

	timestamp, err := loadTimestampMetadata(opts.OutDir)
	if err != nil {
		if !errors.Is(err, errMetadataNotFound) {
			return nil, fmt.Errorf("failed to load timestamp metadata: %w", err)
		}
		timestamp = newDefaultTimestamp()
	}
	editor.timestamp = timestamp

	// Load trust bundle
	targetsDir := filepath.Join(opts.OutDir, "targets")
	trustedRootPath := filepath.Join(targetsDir, "trusted_root.json")
	signingConfigPath := filepath.Join(targetsDir, "signing_config.v0.2.json")

	actualTrustedRootPath := findLatestTrustBundleFile(opts.OutDir, "trusted_root.json", editor.targets)
	if actualTrustedRootPath != "" {
		trustedRootPath = actualTrustedRootPath
	}

	actualSigningConfigPath := findLatestTrustBundleFile(opts.OutDir, "signing_config.v0.2.json", editor.targets)
	if actualSigningConfigPath != "" {
		signingConfigPath = actualSigningConfigPath
	}

	tb, err := sigstore.LoadTrustBundle(trustedRootPath, signingConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load trust bundle: %w", err)
	}
	editor.TrustBundle = tb

	return editor, nil
}

// AddTarget adds a target to the targets metadata.
func (e *Editor) AddTarget(name string, meta *tufmeta.TargetFiles) {
	e.targets.Signed.Targets[name] = meta
}

// RemoveTarget removes a target from the targets metadata.
func (e *Editor) RemoveTarget(name string) error {
	if _, ok := e.targets.Signed.Targets[name]; !ok {
		return fmt.Errorf("target %q not found", name)
	}
	delete(e.targets.Signed.Targets, name)
	return nil
}

// BumpTargetsVersion increments the targets metadata version by 1.
func (e *Editor) BumpTargetsVersion() {
	e.targets.Signed.Version++
}

// BumpSnapshotVersion increments the snapshot metadata version by 1.
func (e *Editor) BumpSnapshotVersion() {
	e.snapshot.Signed.Version++
}

// BumpTimestampVersion increments the timestamp metadata version by 1.
func (e *Editor) BumpTimestampVersion() {
	e.timestamp.Signed.Version++
}

// SetTargetsExpires sets the targets metadata expiration time.
func (e *Editor) SetTargetsExpires(t time.Time) {
	e.targets.Signed.Expires = t
}

// SetSnapshotExpires sets the snapshot metadata expiration time.
func (e *Editor) SetSnapshotExpires(t time.Time) {
	e.snapshot.Signed.Expires = t
}

// SetTimestampExpires sets the timestamp metadata expiration time.
func (e *Editor) SetTimestampExpires(t time.Time) {
	e.timestamp.Signed.Expires = t
}

// SetTargetsVersion sets the targets metadata version explicitly.
func (e *Editor) SetTargetsVersion(v int64) {
	e.targets.Signed.Version = v
}

// SetSnapshotVersion sets the snapshot metadata version explicitly.
func (e *Editor) SetSnapshotVersion(v int64) {
	e.snapshot.Signed.Version = v
}

// SetTimestampVersion sets the timestamp metadata version explicitly.
func (e *Editor) SetTimestampVersion(v int64) {
	e.timestamp.Signed.Version = v
}

// SignAndWriteOptions configures the sign and write operation.
type SignAndWriteOptions struct {
	KeyPaths []string
	OutDir   string
}

// SignAndWrite signs all metadata files and writes them to the output directory.
// The signing order is: targets -> snapshot -> timestamp (each depends on the previous).
func (e *Editor) SignAndWrite(opts SignAndWriteOptions) error {
	var signers []signature.Signer
	for _, keyPath := range opts.KeyPaths {
		signer, _, _, err := keys.LoadSigner(keyPath)
		if err != nil {
			return fmt.Errorf("failed to load key from %s: %w", keyPath, err)
		}
		signers = append(signers, signer)
	}

	outDir := opts.OutDir
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// 0. Copy root.json to the output directory as <version>.root.json
	rootData, err := os.ReadFile(e.rootPath)
	if err != nil {
		return fmt.Errorf("failed to read root.json: %w", err)
	}
	// Parse root metadata to get version
	rootMd := &tufmeta.Metadata[tufmeta.RootType]{}
	if _, err := rootMd.FromBytes(rootData); err != nil {
		return fmt.Errorf("failed to parse root.json: %w", err)
	}
	versionedRootPath := filepath.Join(outDir, fmt.Sprintf("%d.root.json", rootMd.Signed.Version))
	if err := utils.WriteFileAtomic(versionedRootPath, rootData); err != nil {
		return fmt.Errorf("failed to write versioned root.json: %w", err)
	}
	// Also write root.json (non-versioned) for convenience
	rootPath := filepath.Join(outDir, "root.json")
	if err := utils.WriteFileAtomic(rootPath, rootData); err != nil {
		return fmt.Errorf("failed to write root.json: %w", err)
	}

	// 1. Sign targets.json
	e.targets.ClearSignatures()
	for _, signer := range signers {
		if _, err := e.targets.Sign(signer); err != nil {
			return fmt.Errorf("failed to sign targets: %w", err)
		}
	}

	targetsPath := filepath.Join(outDir, fmt.Sprintf("%d.targets.json", e.targets.Signed.Version))
	targetsData, err := e.targets.ToBytes(true)
	if err != nil {
		return fmt.Errorf("failed to serialize targets.json: %w", err)
	}
	if err := utils.WriteFileAtomic(targetsPath, targetsData); err != nil {
		return fmt.Errorf("failed to write targets.json: %w", err)
	}

	// 2. Update snapshot with targets info
	targetsMeta, err := computeMetaFileInfo(targetsPath, e.targets.Signed.Version)
	if err != nil {
		return fmt.Errorf("failed to compute targets hash: %w", err)
	}
	e.snapshot.Signed.Meta["targets.json"] = targetsMeta

	e.snapshot.ClearSignatures()
	for _, signer := range signers {
		if _, err := e.snapshot.Sign(signer); err != nil {
			return fmt.Errorf("failed to sign snapshot: %w", err)
		}
	}

	snapshotPath := filepath.Join(outDir, fmt.Sprintf("%d.snapshot.json", e.snapshot.Signed.Version))
	snapshotData, err := e.snapshot.ToBytes(true)
	if err != nil {
		return fmt.Errorf("failed to serialize snapshot.json: %w", err)
	}
	if err := utils.WriteFileAtomic(snapshotPath, snapshotData); err != nil {
		return fmt.Errorf("failed to write snapshot.json: %w", err)
	}

	// 3. Update timestamp with snapshot info
	snapshotMeta, err := computeMetaFileInfo(snapshotPath, e.snapshot.Signed.Version)
	if err != nil {
		return fmt.Errorf("failed to compute snapshot hash: %w", err)
	}
	e.timestamp.Signed.Meta["snapshot.json"] = snapshotMeta

	e.timestamp.ClearSignatures()
	for _, signer := range signers {
		if _, err := e.timestamp.Sign(signer); err != nil {
			return fmt.Errorf("failed to sign timestamp: %w", err)
		}
	}

	timestampPath := filepath.Join(outDir, "timestamp.json")
	timestampData, err := e.timestamp.ToBytes(true)
	if err != nil {
		return fmt.Errorf("failed to serialize timestamp.json: %w", err)
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
		sha256Hash, ok := meta.Hashes["sha256"]
		if !ok {
			continue
		}

		hashStr := sha256Hash.String()
		srcPath := filepath.Join(targetsOutDir, name)
		hashPrefixedPath := filepath.Join(targetsOutDir, hashStr+"."+name)

		if utils.FileExists(hashPrefixedPath) {
			switch e.targetPathExists {
			case "skip", "":
				continue
			case "fail":
				return fmt.Errorf("target file %s already exists (--target-path-exists=fail)", hashPrefixedPath)
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

// CopyTargetToRepo copies a target file into the repository's targets directory,
// both as the plain name and with hash prefix for consistent_snapshot.
func (e *Editor) CopyTargetToRepo(srcPath, targetName string) error {
	if !e.follow {
		fi, err := os.Lstat(srcPath)
		if err != nil {
			return fmt.Errorf("failed to stat source file %s: %w", srcPath, err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("source file %s is a symbolic link; use --follow to allow symlinks", srcPath)
		}
	}

	targetsDir := filepath.Join(e.outDir, "targets")
	if err := os.MkdirAll(targetsDir, 0755); err != nil {
		return fmt.Errorf("failed to create targets directory: %w", err)
	}

	destPath := filepath.Join(targetsDir, targetName)
	if utils.FileExists(destPath) {
		switch e.targetPathExists {
		case "skip":
			return nil
		case "fail":
			return fmt.Errorf("target file %s already exists (--target-path-exists=fail)", targetName)
		}
	}

	data, err := os.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("failed to read source file %s: %w", srcPath, err)
	}

	hash, err := utils.HashFile(srcPath)
	if err != nil {
		return fmt.Errorf("failed to hash target file: %w", err)
	}

	// Only write hash-prefixed file for consistent_snapshot
	hashPrefixedPath := filepath.Join(targetsDir, hash+"."+targetName)
	if err := os.WriteFile(hashPrefixedPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write hash-prefixed target file: %w", err)
	}

	return nil
}

func (e *Editor) checkExpiration(allowExpired bool) error {
	now := time.Now()
	var expired []string

	if e.targets.Signed.Expires.Before(now) {
		expired = append(expired, "targets.json")
	}
	if e.snapshot.Signed.Expires.Before(now) {
		expired = append(expired, "snapshot.json")
	}
	if e.timestamp.Signed.Expires.Before(now) {
		expired = append(expired, "timestamp.json")
	}

	if len(expired) == 0 {
		return nil
	}

	if allowExpired {
		fmt.Fprintf(os.Stderr, "WARNING: expired metadata detected: %v — continuing because --allow-expired-repo is set\n", expired)
		return nil
	}

	return fmt.Errorf("metadata has expired: %v (use --allow-expired-repo to override)", expired)
}

// LoadDelegatedMetadata loads delegated targets metadata and merges targets into the editor.
func (e *Editor) LoadDelegatedMetadata(metadataSource, roleName string) error {
	var data []byte
	var err error

	if strings.HasPrefix(metadataSource, "http://") ||
		strings.HasPrefix(metadataSource, "https://") ||
		strings.HasPrefix(metadataSource, "file://") {
		data, err = fetchFile(metadataSource)
	} else {
		data, err = os.ReadFile(metadataSource)
	}
	if err != nil {
		return fmt.Errorf("failed to read delegated metadata from %s: %w", metadataSource, err)
	}

	delegatedMd := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := delegatedMd.FromBytes(data); err != nil {
		return fmt.Errorf("failed to parse delegated metadata for role %q: %w", roleName, err)
	}

	for name, tf := range delegatedMd.Signed.Targets {
		e.targets.Signed.Targets[name] = tf
	}
	return nil
}

func newDefaultTargets() *tufmeta.Metadata[tufmeta.TargetsType] {
	expires := time.Now().UTC().Truncate(time.Second).AddDate(0, 0, 365)
	md := tufmeta.Targets(expires)
	// Initialize empty delegations for TUF spec compatibility
	md.Signed.Delegations = &tufmeta.Delegations{
		Keys:  make(map[string]*tufmeta.Key),
		Roles: []tufmeta.DelegatedRole{},
	}
	return md
}

func newDefaultSnapshot() *tufmeta.Metadata[tufmeta.SnapshotType] {
	expires := time.Now().UTC().Truncate(time.Second).AddDate(0, 0, 365)
	return tufmeta.Snapshot(expires)
}

func newDefaultTimestamp() *tufmeta.Metadata[tufmeta.TimestampType] {
	expires := time.Now().UTC().Truncate(time.Second).AddDate(0, 0, 1)
	return tufmeta.Timestamp(expires)
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
