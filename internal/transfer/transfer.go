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

package transfer

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"

	"github.com/securesign/tufcli/internal/keys"
	"github.com/securesign/tufcli/internal/tufclient"
	"github.com/securesign/tufcli/internal/utils"
)

// Options contains all configuration for a transfer-metadata operation.
type Options struct {
	CurrentRoot  string
	NewRoot      string
	KeyPaths     []string
	VaultKeyRefs []string
	MetadataURL  string
	TargetsURL   string
	OutDir       string

	TargetsExpires   time.Time
	TargetsVersion   int64
	SnapshotExpires  time.Time
	SnapshotVersion  int64
	TimestampExpires time.Time
	TimestampVersion int64

	AllowExpiredRepo bool
	Output           io.Writer
	HashAlgo         string
	GetPassphrase    keys.PassphraseFunc
}

// ValidateAndSetDefaults validates options and applies defaults.
func (opts *Options) ValidateAndSetDefaults() error {
	if !utils.FileExists(opts.CurrentRoot) {
		return fmt.Errorf("current root.json not found at %s", opts.CurrentRoot)
	}
	if !utils.FileExists(opts.NewRoot) {
		return fmt.Errorf("new root.json not found at %s", opts.NewRoot)
	}

	if opts.TargetsVersion <= 0 {
		return fmt.Errorf("targets-version must be > 0")
	}
	if opts.SnapshotVersion <= 0 {
		return fmt.Errorf("snapshot-version must be > 0")
	}
	if opts.TimestampVersion <= 0 {
		return fmt.Errorf("timestamp-version must be > 0")
	}

	if opts.TargetsExpires.IsZero() {
		return fmt.Errorf("targets-expires is required")
	}
	if opts.SnapshotExpires.IsZero() {
		return fmt.Errorf("snapshot-expires is required")
	}
	if opts.TimestampExpires.IsZero() {
		return fmt.Errorf("timestamp-expires is required")
	}

	if opts.HashAlgo == "" {
		opts.HashAlgo = "sha256"
	}
	if err := utils.ValidateHashAlgo(opts.HashAlgo); err != nil {
		return err
	}

	return nil
}

// Run executes the transfer-metadata command.
func Run(opts *Options) error {
	output := utils.SafeWriter(opts.Output)

	if err := opts.ValidateAndSetDefaults(); err != nil {
		return err
	}

	if _, err := os.Stat(opts.OutDir); err == nil {
		return fmt.Errorf("output directory %q already exists", opts.OutDir)
	}

	// 1. Load the existing repository under the current root
	currentRootBytes, err := os.ReadFile(opts.CurrentRoot)
	if err != nil {
		return fmt.Errorf("failed to read current root.json: %w", err)
	}

	metadataURL := strings.TrimRight(opts.MetadataURL, "/")
	targetsURL := strings.TrimRight(opts.TargetsURL, "/")

	tmpDir, err := os.MkdirTemp("", "tufcli-transfer-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg, err := config.New(metadataURL, currentRootBytes)
	if err != nil {
		return fmt.Errorf("failed to create updater config: %w", err)
	}
	cfg.LocalMetadataDir = tmpDir
	cfg.LocalTargetsDir = filepath.Join(tmpDir, "targets")
	cfg.RemoteTargetsURL = targetsURL
	cfg.PrefixTargetsWithHash = true
	cfg.DisableLocalCache = true
	cfg.Fetcher = tufclient.NewLocalFetcher(cfg.Fetcher)

	up, err := updater.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create TUF updater: %w", err)
	}

	if opts.AllowExpiredRepo {
		fmt.Fprintf(output, "=================================================================\n")
		fmt.Fprintf(output, "Transferring metadata from %s to %s\n", opts.CurrentRoot, opts.NewRoot)
		fmt.Fprintf(output, "WARNING: AllowExpiredRepo is set; this is unsafe and\n")
		fmt.Fprintf(output, "will not establish trust, use only for testing!\n")
		fmt.Fprintf(output, "=================================================================\n")
		up.UnsafeSetRefTime(time.Time{})
	}

	if err := up.Refresh(); err != nil {
		return fmt.Errorf("failed to refresh TUF metadata: %w", err)
	}

	// 2. Get target entries from the old repo
	trusted := up.GetTrustedMetadataSet()
	oldTargets, ok := trusted.Targets["targets"]
	if !ok {
		return fmt.Errorf("no targets metadata found in current repository")
	}

	// 3. Create fresh metadata under the new root
	newTargets := tufmeta.Targets(opts.TargetsExpires)
	newTargets.Signed.Version = opts.TargetsVersion

	for name, tf := range oldTargets.Signed.Targets {
		newTargets.Signed.Targets[name] = tf
	}

	newSnapshot := tufmeta.Snapshot(opts.SnapshotExpires)
	newSnapshot.Signed.Version = opts.SnapshotVersion

	newTimestamp := tufmeta.Timestamp(opts.TimestampExpires)
	newTimestamp.Signed.Version = opts.TimestampVersion

	// 4. Sign and write using the new root
	if err := signAndWriteTransfer(opts, newTargets, newSnapshot, newTimestamp); err != nil {
		return err
	}

	return nil
}

type signerInfo struct {
	signer signature.Signer
	keyID  string
}

func signAndWriteTransfer(
	opts *Options,
	targets *tufmeta.Metadata[tufmeta.TargetsType],
	snapshot *tufmeta.Metadata[tufmeta.SnapshotType],
	timestamp *tufmeta.Metadata[tufmeta.TimestampType],
) (retErr error) {
	// Load the new root to determine authorized keys
	newRootData, err := os.ReadFile(opts.NewRoot)
	if err != nil {
		return fmt.Errorf("failed to read new root.json: %w", err)
	}
	newRootMd := &tufmeta.Metadata[tufmeta.RootType]{}
	if _, err := newRootMd.FromBytes(newRootData); err != nil {
		return fmt.Errorf("failed to parse new root.json: %w", err)
	}

	// Load all signers (from both file paths and Vault references)
	var allSigners []signerInfo
	for _, keyPath := range opts.KeyPaths {
		signer, _, keyID, err := keys.LoadSigner(keyPath, opts.GetPassphrase)
		if err != nil {
			return fmt.Errorf("failed to load key from %s: %w", keyPath, err)
		}
		if c, ok := signer.(io.Closer); ok {
			defer func() { retErr = errors.Join(retErr, c.Close()) }()
		}
		allSigners = append(allSigners, signerInfo{signer: signer, keyID: keyID})
	}
	for _, vaultRef := range opts.VaultKeyRefs {
		signer, _, keyID, err := keys.LoadVaultSigner(vaultRef)
		if err != nil {
			return fmt.Errorf("failed to load Vault key %s: %w", vaultRef, err)
		}
		allSigners = append(allSigners, signerInfo{signer: signer, keyID: keyID})
	}

	// Build role -> authorized key IDs map
	roleKeys := make(map[string][]string)
	for roleName, role := range newRootMd.Signed.Roles {
		roleKeys[roleName] = role.KeyIDs
	}

	findSignersForRole := func(roleName string) ([]signerInfo, error) {
		authorizedKeyIDs := roleKeys[roleName]
		if len(authorizedKeyIDs) == 0 {
			return nil, fmt.Errorf("no keys defined for role %s in new root.json", roleName)
		}
		var matched []signerInfo
		for _, si := range allSigners {
			for _, authKeyID := range authorizedKeyIDs {
				if si.keyID == authKeyID {
					matched = append(matched, si)
					break
				}
			}
		}
		if len(matched) == 0 {
			return nil, fmt.Errorf("none of the provided keys match role %s in new root.json (expected key IDs: %v)", roleName, authorizedKeyIDs)
		}
		return matched, nil
	}

	outDir := opts.OutDir
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Copy new root.json to outdir
	versionedRootPath := filepath.Join(outDir, fmt.Sprintf("%d.root.json", newRootMd.Signed.Version))
	if err := utils.WriteFileAtomic(versionedRootPath, newRootData); err != nil {
		return fmt.Errorf("failed to write versioned root.json: %w", err)
	}
	if err := utils.WriteFileAtomic(filepath.Join(outDir, "root.json"), newRootData); err != nil {
		return fmt.Errorf("failed to write root.json: %w", err)
	}

	// Sign targets
	targetsSigners, err := findSignersForRole("targets")
	if err != nil {
		return fmt.Errorf("failed to find signers for targets role: %w", err)
	}
	targets.ClearSignatures()
	for _, si := range targetsSigners {
		if _, err := targets.Sign(si.signer); err != nil {
			return fmt.Errorf("failed to sign targets: %w", err)
		}
		if len(targets.Signatures) > 0 {
			targets.Signatures[len(targets.Signatures)-1].KeyID = si.keyID
		}
	}

	targetsPath := filepath.Join(outDir, fmt.Sprintf("%d.targets.json", targets.Signed.Version))
	targetsData, err := targets.ToBytes(false)
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

	// Update snapshot with targets info and sign
	hashAlgo := opts.HashAlgo
	targetsMeta, err := utils.ComputeMetaFileInfo(targetsPath, targets.Signed.Version, hashAlgo)
	if err != nil {
		return fmt.Errorf("failed to compute targets hash: %w", err)
	}
	snapshot.Signed.Meta["targets.json"] = targetsMeta

	snapshotSigners, err := findSignersForRole("snapshot")
	if err != nil {
		return fmt.Errorf("failed to find signers for snapshot role: %w", err)
	}
	snapshot.ClearSignatures()
	for _, si := range snapshotSigners {
		if _, err := snapshot.Sign(si.signer); err != nil {
			return fmt.Errorf("failed to sign snapshot: %w", err)
		}
		if len(snapshot.Signatures) > 0 {
			snapshot.Signatures[len(snapshot.Signatures)-1].KeyID = si.keyID
		}
	}

	snapshotPath := filepath.Join(outDir, fmt.Sprintf("%d.snapshot.json", snapshot.Signed.Version))
	snapshotData, err := snapshot.ToBytes(false)
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

	// Update timestamp with snapshot info and sign
	snapshotMeta, err := utils.ComputeMetaFileInfo(snapshotPath, snapshot.Signed.Version, hashAlgo)
	if err != nil {
		return fmt.Errorf("failed to compute snapshot hash: %w", err)
	}
	timestamp.Signed.Meta["snapshot.json"] = snapshotMeta

	timestampSigners, err := findSignersForRole("timestamp")
	if err != nil {
		return fmt.Errorf("failed to find signers for timestamp role: %w", err)
	}
	timestamp.ClearSignatures()
	for _, si := range timestampSigners {
		if _, err := timestamp.Sign(si.signer); err != nil {
			return fmt.Errorf("failed to sign timestamp: %w", err)
		}
		if len(timestamp.Signatures) > 0 {
			timestamp.Signatures[len(timestamp.Signatures)-1].KeyID = si.keyID
		}
	}

	timestampPath := filepath.Join(outDir, "timestamp.json")
	timestampData, err := timestamp.ToBytes(false)
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

	return nil
}
