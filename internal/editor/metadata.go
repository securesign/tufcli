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
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"

	"github.com/securesign/tufcli/internal/utils"
)

var errMetadataNotFound = errors.New("metadata not found")

// FindLatestVersionedFile scans dir for files matching <N>.<suffix> and returns
// the path with the highest version number.
func FindLatestVersionedFile(dir, suffix string) (string, int64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", 0, fmt.Errorf("%w: directory %s does not exist", errMetadataNotFound, dir)
		}
		return "", 0, fmt.Errorf("failed to read directory %s: %w", dir, err)
	}

	var latestPath string
	var latestVersion int64

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, "."+suffix) {
			continue
		}
		versionStr := strings.TrimSuffix(name, "."+suffix)
		version, err := strconv.ParseInt(versionStr, 10, 64)
		if err != nil || version < 0 {
			continue
		}
		if latestPath == "" || version > latestVersion {
			latestVersion = version
			latestPath = filepath.Join(dir, name)
		}
	}

	if latestPath == "" {
		return "", 0, fmt.Errorf("%w: no versioned %s file found in %s", errMetadataNotFound, suffix, dir)
	}

	return latestPath, latestVersion, nil
}

// loadTargetsMetadata loads targets.json from the repository directory.
func loadTargetsMetadata(dir string) (*tufmeta.Metadata[tufmeta.TargetsType], error) {
	path, _, err := FindLatestVersionedFile(dir, "targets.json")
	if err != nil {
		return nil, err
	}

	md := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := md.FromFile(path); err != nil {
		return nil, fmt.Errorf("failed to load targets metadata from %s: %w", path, err)
	}

	return md, nil
}

// loadSnapshotMetadata loads snapshot.json from the repository directory.
func loadSnapshotMetadata(dir string) (*tufmeta.Metadata[tufmeta.SnapshotType], error) {
	path, _, err := FindLatestVersionedFile(dir, "snapshot.json")
	if err != nil {
		return nil, err
	}

	md := &tufmeta.Metadata[tufmeta.SnapshotType]{}
	if _, err := md.FromFile(path); err != nil {
		return nil, fmt.Errorf("failed to load snapshot metadata from %s: %w", path, err)
	}

	return md, nil
}

// loadTimestampMetadata loads timestamp.json from the repository directory.
func loadTimestampMetadata(dir string) (*tufmeta.Metadata[tufmeta.TimestampType], error) {
	path := filepath.Join(dir, "timestamp.json")
	if !utils.FileExists(path) {
		return nil, fmt.Errorf("%w: timestamp.json not found in %s", errMetadataNotFound, dir)
	}

	md := &tufmeta.Metadata[tufmeta.TimestampType]{}
	if _, err := md.FromFile(path); err != nil {
		return nil, fmt.Errorf("failed to load timestamp metadata from %s: %w", path, err)
	}

	return md, nil
}

// copyTargetFile copies a target file to the destination directory with consistent_snapshot naming.
func copyTargetFile(srcPath, destDir, hashHex string) error {
	filename := filepath.Base(srcPath)
	destPath := filepath.Join(destDir, hashHex+"."+filename)

	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed to create targets directory: %w", err)
	}

	src, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open source file %s: %w", srcPath, err)
	}
	defer src.Close()

	dst, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file %s: %w", destPath, err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("failed to copy target file: %w", err)
	}

	return nil
}

// BuildTargetFiles builds a TargetFiles for a single file using go-tuf's built-in hashing.
// hashAlgo must be "sha256" or "sha512".
func BuildTargetFiles(path string, hashAlgo string) (*tufmeta.TargetFiles, error) {
	tf := tufmeta.TargetFile()
	return tf.FromFile(path, hashAlgo)
}

// SetTargetCustom sets custom metadata on a TargetFiles.
func SetTargetCustom(tf *tufmeta.TargetFiles, custom map[string]interface{}) error {
	data, err := json.Marshal(custom)
	if err != nil {
		return fmt.Errorf("failed to marshal custom metadata: %w", err)
	}
	raw := json.RawMessage(data)
	tf.Custom = &raw
	return nil
}

// verifyMetadataChain verifies the TUF metadata chain (timestamp → snapshot → targets)
// against a trusted root using signature verification, hash chain validation, threshold
// checks, and rollback protection. Expiry is not checked here; the caller's
// CheckExpiration handles it.
//
// priorTimestamp and priorSnapshot are the previously trusted metadata from the
// output directory. When non-nil they seed rollback protection so that a validly
// signed but older chain cannot overwrite newer metadata already on disk.
func verifyMetadataChain(
	rootData, timestampData, snapshotData, targetsData []byte,
	priorTimestamp *tufmeta.Metadata[tufmeta.TimestampType],
	priorSnapshot *tufmeta.Metadata[tufmeta.SnapshotType],
) error {
	trusted, err := trustedmetadata.New(rootData)
	if err != nil {
		return fmt.Errorf("failed to load trusted root for verification: %w", err)
	}
	// Bypass expiry — the editor's CheckExpiration handles expiry policy.
	trusted.RefTime = time.Time{}

	if priorTimestamp != nil {
		trusted.Timestamp = priorTimestamp
	}

	if _, err := trusted.UpdateTimestamp(timestampData); err != nil {
		// Equal version is expected when fetching from the same repo being
		// updated (outdir == metadata-url). The signature was already verified;
		// the prior Timestamp remains set for UpdateSnapshot to use.
		if !errors.Is(err, &tufmeta.ErrEqualVersionNumber{}) {
			return fmt.Errorf("timestamp verification failed: %w", err)
		}
	}

	if priorSnapshot != nil {
		trusted.Snapshot = priorSnapshot
	}

	if _, err := trusted.UpdateSnapshot(snapshotData, false); err != nil {
		return fmt.Errorf("snapshot verification failed: %w", err)
	}
	if _, err := trusted.UpdateTargets(targetsData); err != nil {
		return fmt.Errorf("targets verification failed: %w", err)
	}
	return nil
}

// fetchMetadataFromURL downloads TUF metadata files from a base URL into outDir.
// It follows the TUF chain: timestamp -> snapshot (versioned) -> targets (versioned).
// All metadata is verified against rootData before being written to disk.
//
// priorMetadataDir is the directory containing previously trusted metadata for
// rollback protection. When non-empty, the existing timestamp and snapshot from
// that directory seed version floors so that a validly signed but older chain
// cannot overwrite newer metadata. It may differ from outDir (e.g. when outDir
// is a staging temp dir).
func fetchMetadataFromURL(baseURL, outDir string, rootData []byte, priorMetadataDir string) error {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	baseURL = strings.TrimRight(baseURL, "/")

	// 1. Fetch timestamp.json
	tsData, err := utils.FetchFile(baseURL + "/timestamp.json")
	if err != nil {
		return fmt.Errorf("failed to fetch timestamp.json: %w", err)
	}

	tsMd := &tufmeta.Metadata[tufmeta.TimestampType]{}
	if _, err := tsMd.FromBytes(tsData); err != nil {
		return fmt.Errorf("failed to parse timestamp.json: %w", err)
	}

	// 2. Fetch versioned snapshot.json
	snapshotMeta, ok := tsMd.Signed.Meta["snapshot.json"]
	if !ok {
		return fmt.Errorf("timestamp.json does not reference snapshot.json")
	}
	snapshotFilename := fmt.Sprintf("%d.snapshot.json", snapshotMeta.Version)
	snapData, err := utils.FetchFile(baseURL + "/" + snapshotFilename)
	if err != nil {
		return fmt.Errorf("failed to fetch %s: %w", snapshotFilename, err)
	}

	snapMd := &tufmeta.Metadata[tufmeta.SnapshotType]{}
	if _, err := snapMd.FromBytes(snapData); err != nil {
		return fmt.Errorf("failed to parse %s: %w", snapshotFilename, err)
	}

	// 3. Fetch versioned targets.json
	targetsMeta, ok := snapMd.Signed.Meta["targets.json"]
	if !ok {
		return fmt.Errorf("snapshot.json does not reference targets.json")
	}
	targetsFilename := fmt.Sprintf("%d.targets.json", targetsMeta.Version)
	targetsData, err := utils.FetchFile(baseURL + "/" + targetsFilename)
	if err != nil {
		return fmt.Errorf("failed to fetch %s: %w", targetsFilename, err)
	}

	// 4. Load existing metadata for rollback protection.
	// Use priorMetadataDir (the real output directory) when available, so that
	// staging to a temp dir still has a version floor from previously committed
	// metadata. A missing prior state (errMetadataNotFound) is fine — it means
	// a fresh output directory with no rollback floor. Any other error (corrupt
	// or unreadable file) is treated as a hard failure so that a damaged
	// timestamp/snapshot cannot silently disable rollback protection.
	rollbackDir := priorMetadataDir
	if rollbackDir == "" {
		rollbackDir = outDir
	}
	var priorTimestamp *tufmeta.Metadata[tufmeta.TimestampType]
	var priorSnapshot *tufmeta.Metadata[tufmeta.SnapshotType]
	if ts, err := loadTimestampMetadata(rollbackDir); err == nil {
		priorTimestamp = ts
	} else if !errors.Is(err, errMetadataNotFound) {
		return fmt.Errorf("existing timestamp metadata is corrupt, cannot ensure rollback safety: %w", err)
	}
	if snap, err := loadSnapshotMetadata(rollbackDir); err == nil {
		priorSnapshot = snap
	} else if !errors.Is(err, errMetadataNotFound) {
		return fmt.Errorf("existing snapshot metadata is corrupt, cannot ensure rollback safety: %w", err)
	}

	// 5. Verify the metadata chain against the trusted root before writing to disk
	if err := verifyMetadataChain(rootData, tsData, snapData, targetsData, priorTimestamp, priorSnapshot); err != nil {
		return fmt.Errorf("metadata verification failed: %w", err)
	}

	// 6. Verification passed — write metadata files to disk
	if err := utils.WriteFileAtomic(filepath.Join(outDir, "timestamp.json"), tsData); err != nil {
		return fmt.Errorf("failed to write timestamp.json: %w", err)
	}
	if err := utils.WriteFileAtomic(filepath.Join(outDir, snapshotFilename), snapData); err != nil {
		return fmt.Errorf("failed to write %s: %w", snapshotFilename, err)
	}
	if err := utils.WriteFileAtomic(filepath.Join(outDir, targetsFilename), targetsData); err != nil {
		return fmt.Errorf("failed to write %s: %w", targetsFilename, err)
	}

	// 7. Fetch target files referenced in targets metadata
	targetsMd := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := targetsMd.FromBytes(targetsData); err != nil {
		return fmt.Errorf("failed to parse %s: %w", targetsFilename, err)
	}

	targetsDir := filepath.Join(outDir, "targets")
	if err := os.MkdirAll(targetsDir, 0755); err != nil {
		return fmt.Errorf("failed to create targets directory: %w", err)
	}

	for name, tf := range targetsMd.Signed.Targets {
		hashStr, err := utils.PreferredHash(tf.Hashes)
		if err != nil {
			return fmt.Errorf("target %q: %w", name, err)
		}
		hashPrefixedName := hashStr + "." + name
		destPath := filepath.Join(targetsDir, hashPrefixedName)
		if err := utils.ValidatePathInDir(targetsDir, destPath); err != nil {
			return fmt.Errorf("target %q: %w", name, err)
		}
		if utils.FileExists(destPath) {
			continue
		}

		targetURL := baseURL + "/targets/" + hashPrefixedName
		data, err := utils.FetchFile(targetURL)
		if err != nil {
			targetURL = baseURL + "/targets/" + name
			data, err = utils.FetchFile(targetURL)
			if err != nil {
				return fmt.Errorf("failed to fetch target %q from %s: %w", name, baseURL, err)
			}
		}

		if tf.Length > 0 && int64(len(data)) != tf.Length {
			return fmt.Errorf("target %q: expected length %d, got %d (from %s)", name, tf.Length, len(data), targetURL)
		}
		if sha256Hash, ok := tf.Hashes["sha256"]; ok {
			actual := sha256.Sum256(data)
			if !bytes.Equal(actual[:], sha256Hash) {
				return fmt.Errorf("target %q: sha256 mismatch (from %s)", name, targetURL)
			}
		}
		if sha512Hash, ok := tf.Hashes["sha512"]; ok {
			actual := sha512.Sum512(data)
			if !bytes.Equal(actual[:], sha512Hash) {
				return fmt.Errorf("target %q: sha512 mismatch (from %s)", name, targetURL)
			}
		}

		if err := utils.WriteFileAtomic(destPath, data); err != nil {
			return fmt.Errorf("failed to write target %q: %w", name, err)
		}
	}

	return nil
}

// stagedFile holds a file's relative path and contents collected from the staging directory.
type stagedFile struct {
	rel  string
	data []byte
}

type fileBackup struct {
	destPath   string
	backupPath string
	existed    bool
}

// commitStagedMetadata copies all files from stagingDir to outDir using a
// write-then-rename strategy with rollback to prevent mixed repository
// versions on failure.
//
// Phase 1 (collect): reads every staged file into memory using os.Root to
// prevent symlink TOCTOU races (gosec G122).
// Phase 2 (stage): writes each file to outDir with a ".staged" suffix.
// Phase 3 (backup): backs up existing destination files with a ".backup"
// suffix so they can be restored on failure.
// Phase 4 (swap): renames each ".staged" file to its final name (atomic per
// file). If any rename fails, already-swapped files are restored from their
// ".backup" copies and remaining ".staged" files are cleaned up.
func commitStagedMetadata(stagingDir, outDir string) error {
	root, err := os.OpenRoot(stagingDir)
	if err != nil {
		return fmt.Errorf("failed to open staging directory: %w", err)
	}
	defer root.Close()

	var files []stagedFile
	if err := collectStagedFiles(root, ".", &files); err != nil {
		return err
	}

	// Phase 2: write all files with a temporary suffix
	var stagedPaths []string
	for _, f := range files {
		destPath := filepath.Join(outDir, f.rel)
		stagedPath := destPath + ".staged"
		if err := utils.WriteFileAtomic(stagedPath, f.data); err != nil {
			cleanupStagedFiles(stagedPaths)
			return fmt.Errorf("failed to write staged file %s: %w", f.rel, err)
		}
		stagedPaths = append(stagedPaths, stagedPath)
	}

	// Phase 3: back up existing files so we can restore on rename failure
	backups := make([]fileBackup, len(files))
	for i, f := range files {
		destPath := filepath.Join(outDir, f.rel)
		backupPath := destPath + ".backup"
		if _, statErr := os.Stat(destPath); statErr == nil {
			if err := os.Rename(destPath, backupPath); err != nil {
				// Restore any backups already created
				restoreBackups(backups[:i])
				cleanupStagedFiles(stagedPaths)
				return fmt.Errorf("failed to back up %s: %w", f.rel, err)
			}
			backups[i] = fileBackup{destPath: destPath, backupPath: backupPath, existed: true}
		} else {
			backups[i] = fileBackup{destPath: destPath, backupPath: backupPath, existed: false}
		}
	}

	// Phase 4: rename all ".staged" files to final names
	for i, f := range files {
		destPath := filepath.Join(outDir, f.rel)
		if err := os.Rename(stagedPaths[i], destPath); err != nil {
			// Rollback: undo already-swapped files, restore current and remaining backups
			rollbackSwapped(backups[:i])
			restoreBackups(backups[i:])
			cleanupStagedFiles(stagedPaths[i:])
			return fmt.Errorf("failed to commit staged file %s: %w", f.rel, err)
		}
	}

	// Phase 5: clean up backup files on success
	for _, b := range backups {
		if b.existed {
			_ = os.Remove(b.backupPath)
		}
	}
	return nil
}

func cleanupStagedFiles(paths []string) {
	for _, p := range paths {
		_ = os.Remove(p)
	}
}

// restoreBackups moves .backup files back to their original paths (best-effort).
func restoreBackups(backups []fileBackup) {
	for _, b := range backups {
		if b.existed {
			_ = os.Rename(b.backupPath, b.destPath)
		}
	}
}

// rollbackSwapped undoes files that were already swapped in phase 4: files
// with a backup are restored from the backup, files without one are removed.
func rollbackSwapped(backups []fileBackup) {
	for _, b := range backups {
		if b.existed {
			_ = os.Rename(b.backupPath, b.destPath)
		} else {
			_ = os.Remove(b.destPath)
		}
	}
}

// collectStagedFiles recursively reads all regular files under dir via the
// root-scoped handle, appending them to files.
func collectStagedFiles(root *os.Root, dir string, files *[]stagedFile) error {
	entries, err := readDirRoot(root, dir)
	if err != nil {
		return fmt.Errorf("failed to read staged directory %s: %w", dir, err)
	}

	for _, entry := range entries {
		rel := filepath.Join(dir, entry.Name())
		if entry.IsDir() {
			if err := collectStagedFiles(root, rel, files); err != nil {
				return err
			}
			continue
		}
		f, err := root.Open(rel)
		if err != nil {
			return fmt.Errorf("failed to open staged file %s: %w", rel, err)
		}
		data, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			return fmt.Errorf("failed to read staged file %s: %w", rel, err)
		}
		*files = append(*files, stagedFile{rel: rel, data: data})
	}
	return nil
}

// readDirRoot reads directory entries via an os.Root handle.
func readDirRoot(root *os.Root, name string) ([]os.DirEntry, error) {
	d, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	return d.ReadDir(-1)
}
