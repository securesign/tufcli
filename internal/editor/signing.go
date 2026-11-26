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
	"errors"
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
	ReuseTargets  bool
	GetPassphrase keys.PassphraseFunc
}

// SignAndWrite signs metadata files and writes them to the output directory.
// The signing order is: targets -> snapshot -> timestamp (each depends on the previous).
// When ReuseTargets is set, the existing versioned targets file is preserved
// and only snapshot and timestamp are signed.
func (e *Editor) SignAndWrite(opts SignAndWriteOptions) (retErr error) {
	// Load all signers (from both file paths and Vault references)
	signers, err := keys.LoadSignerSetFromAll(opts.KeyPaths, opts.VaultKeyRefs, opts.GetPassphrase)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, signers.Close()) }()

	outDir := opts.OutDir
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Load root.json to determine which keys are authorized for each role
	rootData, err := os.ReadFile(e.rootPath)
	if err != nil {
		return fmt.Errorf("failed to read root.json: %w", err)
	}
	rootMd := &tufmeta.Metadata[tufmeta.RootType]{}
	if _, err := rootMd.FromBytes(rootData); err != nil {
		return fmt.Errorf("failed to parse root.json: %w", err)
	}
	// Ordered publication only protects clients when every published file has
	// a unique name; refuse before anything is written.
	if !rootMd.Signed.ConsistentSnapshot {
		return ErrNotConsistentSnapshot
	}

	// Build maps of role -> authorized key IDs and role -> threshold
	roleKeys := make(map[string][]string)
	roleThresholds := make(map[string]int)
	for roleName, role := range rootMd.Signed.Roles {
		roleKeys[roleName] = role.KeyIDs
		roleThresholds[roleName] = role.Threshold
	}

	// Refuse to roll the repository back: clients that already hold newer
	// metadata reject anything older, so publishing it would break them (e.g. "create" run again over a live repository).
	if err := checkNoRollback(outDir, rootMd.Signed.Version, e.timestamp.Signed.Version, e.snapshot.Signed.Version, e.targets.Signed.Version); err != nil {
		return err
	}
	liveSnapshotPath, liveTargetsPath := liveChainPaths(outDir)

	// A writer killed mid-copy leaves a temp file behind. Sweep old ones (callers
	// hold the repository lock, so none is in use). Files the targets metadata
	// references are never touched, whatever their name: below targets/ the
	// names come from users. The legacy prefix is only swept at the top level.
	referenced := e.referencedTargetPaths(outDir)
	keep := func(path string) bool { return referenced[filepath.Clean(path)] }
	utils.SweepStaleTemp(outDir, utils.TempFilePrefix, staleTempAge, false, keep)
	utils.SweepStaleTemp(filepath.Join(outDir, "targets"), utils.TempFilePrefix, staleTempAge, true, keep)
	utils.SweepStaleTemp(outDir, utils.LegacyTempFilePrefix, staleTempAge, false, keep)
	utils.SweepStaleTemp(filepath.Join(outDir, "targets"), utils.LegacyTempFilePrefix, staleTempAge, false, keep)

	// Phase 1 - build everything in memory; the output directory is not touched.
	// The signing order is: targets -> snapshot -> timestamp (each depends on the previous).
	var steps []publishStep

	// Target files first (hash-prefixed, as the new targets.json will name them).
	// Validating them here means a missing target fails the run before any write.
	targetsOutDir := filepath.Join(outDir, "targets")
	targetsPath := filepath.Join(outDir, fmt.Sprintf("%d.targets.json", e.targets.Signed.Version))
	publishedTargets := e.targets.Signed.Targets
	var reusedTargetsData []byte
	if opts.ReuseTargets {
		// The existing targets file is published as is, so the target files to
		// place are the ones it references, not whatever is in memory (callers
		// may have regenerated files that this run does not publish).
		reusedTargetsData, err = os.ReadFile(targetsPath)
		if err != nil {
			return fmt.Errorf("existing targets metadata not found at %s", targetsPath)
		}
		reused := &tufmeta.Metadata[tufmeta.TargetsType]{}
		if _, err := reused.FromBytes(reusedTargetsData); err != nil {
			return fmt.Errorf("failed to parse existing targets metadata %s: %w", targetsPath, err)
		}
		publishedTargets = reused.Signed.Targets
	}
	var staleSources []string
	for name, meta := range publishedTargets {
		localName, err := filepath.Localize(name)
		if err != nil || localName == "." {
			return fmt.Errorf("invalid target name %q: expected a relative file path", name)
		}
		srcPath := filepath.Join(targetsOutDir, localName)
		if err := utils.ValidatePathInDir(targetsOutDir, srcPath); err != nil {
			return fmt.Errorf("target %q source: %w", name, err)
		}

		hashStr, err := utils.PreferredHash(meta.Hashes)
		if err != nil {
			return fmt.Errorf("target %q: %w", name, err)
		}
		// tufcli's naming for nested targets is <hash>.<target-path> (see
		// tufclient.DownloadTarget), the same everywhere in this package.
		hashPrefixedPath := filepath.Join(targetsOutDir, hashStr+"."+localName)

		if err := utils.ValidatePathInDir(targetsOutDir, hashPrefixedPath); err != nil {
			return fmt.Errorf("target %q: %w", name, err)
		}

		if info, err := os.Stat(hashPrefixedPath); err == nil && info.Size() != meta.Length {
			// The name promises the content, but the file is damaged (e.g. a
			// truncated copy left by an older, non-atomic tufcli). Re-copy it
			// from a staged source when there is one; otherwise say so, since
			// clients will reject it.
			if !utils.FileExists(srcPath) {
				fmt.Fprintf(e.output, "WARNING: %s has %d bytes but targets.json records %d; clients will reject it\n", hashPrefixedPath, info.Size(), meta.Length)
			} else {
				steps = append(steps, publishStep{path: hashPrefixedPath, copyFrom: srcPath, perm: 0o644})
				staleSources = append(staleSources, srcPath)
				continue
			}
		}

		if utils.FileExists(hashPrefixedPath) && e.targetPathExists != "replace" {
			// The name carries the content hash, so a file already in place has
			// exactly the content being published: nothing to do, and not a
			// conflict even under "fail". That policy is applied where targets
			// supplied by the user enter the repository (CopyTargetToRepo);
			// sources staged here (e.g. the generated trust bundle) are
			// regenerated on every run and often unchanged. A staging copy of it
			// is still dropped after publication, as for any other target.
			if utils.FileExists(srcPath) {
				staleSources = append(staleSources, srcPath)
			}
			continue
		}

		if utils.FileExists(srcPath) {
			steps = append(steps, publishStep{
				path:     hashPrefixedPath,
				copyFrom: srcPath,
				perm:     0o644,
			})
			// The non-hash-prefixed copy is removed after publication
			// (consistent_snapshot only).
			staleSources = append(staleSources, srcPath)
		} else if !utils.FileExists(hashPrefixedPath) {
			return fmt.Errorf("target %q referenced in targets.json but file not found in %s", name, targetsOutDir)
		}
	}

	var targetsData []byte
	if !opts.ReuseTargets {
		if live, state := compareLive(targetsPath, "targets", rootMd, e.targets); state == liveSame {
			// Unchanged at the same version: keep the published bytes. Re-signing
			// would give different bytes under the same name, which clients that
			// already hold the old hash would reject.
			targetsData = live
		} else {
			e.warnOverwrite(state, targetsPath, liveTargetsPath)
			// Sign targets.json with only the targets key(s)
			if err := keys.SignForRole(signers, e.targets, "targets", roleKeys["targets"], roleThresholds["targets"]); err != nil {
				return fmt.Errorf("failed to sign targets: %w", err)
			}
			targetsData, err = e.targets.ToBytes(false)
			if err != nil {
				return fmt.Errorf("failed to serialize targets.json: %w", err)
			}
			targetsData, err = utils.IndentJSON(targetsData)
			if err != nil {
				return fmt.Errorf("failed to format targets.json: %w", err)
			}
		}
		steps = append(steps, publishStep{path: targetsPath, data: targetsData})
	} else {
		targetsData = reusedTargetsData
	}

	// Update snapshot with targets info
	hashAlgo := opts.HashAlgo
	snapshotPath := filepath.Join(outDir, fmt.Sprintf("%d.snapshot.json", e.snapshot.Signed.Version))
	snapshotIsLive := liveSnapshotPath != "" && filepath.Clean(snapshotPath) == filepath.Clean(liveSnapshotPath)
	targetsMeta, err := metaFor(e.snapshot.Signed.Meta["targets.json"], snapshotIsLive, targetsData, e.targets.Signed.Version, hashAlgo)
	if err != nil {
		return fmt.Errorf("failed to compute targets hash: %w", err)
	}
	e.snapshot.Signed.Meta["targets.json"] = targetsMeta

	snapshotData, snapState := compareLive(snapshotPath, "snapshot", rootMd, e.snapshot)
	if snapState != liveSame {
		e.warnOverwrite(snapState, snapshotPath, liveSnapshotPath)
		// Sign snapshot.json with only the snapshot key(s)
		if err := keys.SignForRole(signers, e.snapshot, "snapshot", roleKeys["snapshot"], roleThresholds["snapshot"]); err != nil {
			return fmt.Errorf("failed to sign snapshot: %w", err)
		}
		snapshotData, err = e.snapshot.ToBytes(false)
		if err != nil {
			return fmt.Errorf("failed to serialize snapshot.json: %w", err)
		}
		snapshotData, err = utils.IndentJSON(snapshotData)
		if err != nil {
			return fmt.Errorf("failed to format snapshot.json: %w", err)
		}
	}
	steps = append(steps, publishStep{path: snapshotPath, data: snapshotData})

	// Update timestamp with snapshot info
	timestampIsLive := e.timestamp.Signed.Version == liveTimestampVersion(outDir)
	snapshotMeta, err := metaFor(e.timestamp.Signed.Meta["snapshot.json"], timestampIsLive, snapshotData, e.snapshot.Signed.Version, hashAlgo)
	if err != nil {
		return fmt.Errorf("failed to compute snapshot hash: %w", err)
	}
	e.timestamp.Signed.Meta["snapshot.json"] = snapshotMeta

	// An unchanged timestamp keeps its published bytes, so a run that changes
	// nothing publishes nothing.
	timestampData, tsState := compareLive(filepath.Join(outDir, "timestamp.json"), "timestamp", rootMd, e.timestamp)
	if tsState != liveSame {
		// Sign timestamp.json with only the timestamp key(s)
		if err := keys.SignForRole(signers, e.timestamp, "timestamp", roleKeys["timestamp"], roleThresholds["timestamp"]); err != nil {
			return fmt.Errorf("failed to sign timestamp: %w", err)
		}
		timestampData, err = e.timestamp.ToBytes(false)
		if err != nil {
			return fmt.Errorf("failed to serialize timestamp.json: %w", err)
		}
		timestampData, err = utils.IndentJSON(timestampData)
		if err != nil {
			return fmt.Errorf("failed to format timestamp.json: %w", err)
		}
	}

	// Root: the versioned copy, then root.json, both before timestamp.json. This
	// is the one step a failed run cannot take back: a client may pick up the new
	// root before the new timestamp. TUF clients handle that (they keep using
	// the timestamp they trust), and it is inherent to publishing a root.
	steps = append(steps,
		publishStep{path: filepath.Join(outDir, fmt.Sprintf("%d.root.json", rootMd.Signed.Version)), data: rootData},
		publishStep{path: filepath.Join(outDir, "root.json"), data: rootData},
	)

	// Phase 2 - publish in order, each file by atomic rename. Until the very
	// last step, everything written is a new, unreferenced file (or root.json,
	// which is unchanged unless the root version changed), so a failure leaves
	// clients on the previous, complete version.
	if err := e.checkLiveTimestampUnchanged(outDir); err != nil {
		return err
	}
	for _, step := range steps {
		if step.data != nil && sameContent(step.path, step.data) {
			continue
		}
		if err := step.run(); err != nil {
			return fmt.Errorf("failed to publish %s: %w", filepath.Base(step.path), err)
		}
	}

	// timestamp.json is the commit point: clients that see it find everything
	// it leads to already in place. Re-check the safeguard right before it.
	if err := e.checkLiveTimestampUnchanged(outDir); err != nil {
		return err
	}
	// An unchanged timestamp is left alone: rewriting it, even with the same
	// bytes, changes its inode and mtime, which caches and mirrors see as a
	// publication.
	if tsPath := filepath.Join(outDir, "timestamp.json"); !sameContent(tsPath, timestampData) {
		if err := (publishStep{path: tsPath, data: timestampData}).run(); err != nil {
			return fmt.Errorf("failed to write timestamp.json: %w", err)
		}
	}
	// Our own publication is not "another writer": remember it for a later run
	// on the same editor. If it cannot be read back, drop the record and say so
	// rather than silently keeping a stale one.
	if recorded, err := readLiveTimestamp(outDir); err == nil {
		e.loadedTimestamp = recorded
	} else {
		e.loadedTimestamp = timestampSnapshot{}
		fmt.Fprintf(e.output, "WARNING: could not record the published timestamp.json: %v\n", err)
	}

	// Only now drop the non-hash-prefixed staging copies of targets.
	for _, src := range staleSources {
		_ = os.Remove(src)
	}

	return nil
}
