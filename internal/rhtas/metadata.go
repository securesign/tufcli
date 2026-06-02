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
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/securesign/tufcli/internal/utils"
)

var errMetadataNotFound = errors.New("metadata not found")

// findLatestVersionedFile scans dir for files matching <N>.<suffix> and returns
// the path with the highest version number.
func findLatestVersionedFile(dir, suffix string) (string, int64, error) {
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
		if err != nil {
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
	path, _, err := findLatestVersionedFile(dir, "targets.json")
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
	path, _, err := findLatestVersionedFile(dir, "snapshot.json")
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

// computeMetaFileInfo computes the SHA256 hash, length, and version for a metadata file.
// Used to populate snapshot.Meta["targets.json"] and timestamp.Meta["snapshot.json"].
func computeMetaFileInfo(path string, version int64) (*tufmeta.MetaFiles, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	h := sha256.Sum256(data)
	return &tufmeta.MetaFiles{
		Version: version,
		Length:  int64(len(data)),
		Hashes:  tufmeta.Hashes{"sha256": h[:]},
	}, nil
}

// copyTargetFile copies a target file to the destination directory with consistent_snapshot naming.
// The file is copied as <sha256hash>.<filename>.
func copyTargetFile(srcPath, destDir, sha256Hash string) error {
	filename := filepath.Base(srcPath)
	destPath := filepath.Join(destDir, sha256Hash+"."+filename)

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

// buildTargetFiles builds a TargetFiles for a single file using go-tuf's built-in hashing.
func buildTargetFiles(path string) (*tufmeta.TargetFiles, error) {
	tf := tufmeta.TargetFile()
	return tf.FromFile(path, "sha256")
}

// setTargetCustom sets custom metadata on a TargetFiles.
func setTargetCustom(tf *tufmeta.TargetFiles, custom map[string]interface{}) error {
	data, err := json.Marshal(custom)
	if err != nil {
		return fmt.Errorf("failed to marshal custom metadata: %w", err)
	}
	raw := json.RawMessage(data)
	tf.Custom = &raw
	return nil
}

// fetchFile fetches the contents of a file from a URL (file://, http://, https://).
func fetchFile(rawURL string) ([]byte, error) {
	if strings.HasPrefix(rawURL, "file://") {
		path := strings.TrimPrefix(rawURL, "file://")
		return os.ReadFile(path)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %s: %w", rawURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch %s: HTTP %d", rawURL, resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// fetchMetadataFromURL downloads TUF metadata files from a base URL into outDir.
// It follows the TUF chain: timestamp -> snapshot (versioned) -> targets (versioned).
func fetchMetadataFromURL(baseURL, outDir string) error {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	baseURL = strings.TrimRight(baseURL, "/")

	// 1. Fetch timestamp.json
	tsData, err := fetchFile(baseURL + "/timestamp.json")
	if err != nil {
		return fmt.Errorf("failed to fetch timestamp.json: %w", err)
	}
	if err := utils.WriteFileAtomic(filepath.Join(outDir, "timestamp.json"), tsData); err != nil {
		return fmt.Errorf("failed to write timestamp.json: %w", err)
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
	snapData, err := fetchFile(baseURL + "/" + snapshotFilename)
	if err != nil {
		return fmt.Errorf("failed to fetch %s: %w", snapshotFilename, err)
	}
	if err := utils.WriteFileAtomic(filepath.Join(outDir, snapshotFilename), snapData); err != nil {
		return fmt.Errorf("failed to write %s: %w", snapshotFilename, err)
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
	targetsData, err := fetchFile(baseURL + "/" + targetsFilename)
	if err != nil {
		return fmt.Errorf("failed to fetch %s: %w", targetsFilename, err)
	}
	if err := utils.WriteFileAtomic(filepath.Join(outDir, targetsFilename), targetsData); err != nil {
		return fmt.Errorf("failed to write %s: %w", targetsFilename, err)
	}

	// 4. Fetch target files referenced in targets metadata
	targetsMd := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := targetsMd.FromBytes(targetsData); err != nil {
		return fmt.Errorf("failed to parse %s: %w", targetsFilename, err)
	}

	targetsDir := filepath.Join(outDir, "targets")
	if err := os.MkdirAll(targetsDir, 0755); err != nil {
		return fmt.Errorf("failed to create targets directory: %w", err)
	}

	for name, tf := range targetsMd.Signed.Targets {
		sha256Hash, ok := tf.Hashes["sha256"]
		if !ok {
			continue
		}
		hashPrefixedName := sha256Hash.String() + "." + name
		destPath := filepath.Join(targetsDir, hashPrefixedName)
		if utils.FileExists(destPath) {
			continue
		}

		targetURL := baseURL + "/targets/" + hashPrefixedName
		data, err := fetchFile(targetURL)
		if err != nil {
			targetURL = baseURL + "/targets/" + name
			data, err = fetchFile(targetURL)
			if err != nil {
				return fmt.Errorf("failed to fetch target %q from %s: %w", name, baseURL, err)
			}
		}

		if tf.Length > 0 && int64(len(data)) != tf.Length {
			return fmt.Errorf("target %q: expected length %d, got %d (from %s)", name, tf.Length, len(data), targetURL)
		}
		actualHash := sha256.Sum256(data)
		if !bytes.Equal(actualHash[:], sha256Hash) {
			return fmt.Errorf("target %q: sha256 mismatch (from %s)", name, targetURL)
		}

		if err := utils.WriteFileAtomic(destPath, data); err != nil {
			return fmt.Errorf("failed to write target %q: %w", name, err)
		}
	}

	return nil
}
