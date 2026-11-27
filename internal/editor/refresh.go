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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/securesign/tufcli/internal/keys"
	"github.com/securesign/tufcli/internal/utils"
	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"
)

// ErrInconsistentRepository indicates that the live metadata chain is invalid.
var ErrInconsistentRepository = errors.New("inconsistent repository")

// LoadLiveRepository loads and verifies exactly the chain published through
// timestamp.json. Refresh cannot bootstrap a repository or use orphan versions
// left behind by a failed publication.
func LoadLiveRepository(rootPath, outDir string, output io.Writer) (*Editor, error) {
	publishedPath := filepath.Join(outDir, "root.json")
	root, rootData, err := readLiveMetadata[tufmeta.RootType](outDir, "root.json")
	if err != nil {
		return nil, fmt.Errorf("%w: reading published root: %w", ErrInconsistentRepository, err)
	}
	if rootPath != publishedPath {
		if err := checkRefreshRoot(rootPath, publishedPath, root); err != nil {
			return nil, err
		}
	}
	if !root.Signed.ConsistentSnapshot {
		return nil, ErrNotConsistentSnapshot
	}
	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		auth := root.Signed.Roles[role]
		if auth == nil {
			return nil, fmt.Errorf("%w: root.json has no %s role", ErrInconsistentRepository, role)
		}
		for _, keyID := range auth.KeyIDs {
			if root.Signed.Keys[keyID] == nil {
				return nil, fmt.Errorf("%w: root.json has no key %q for %s", ErrInconsistentRepository, keyID, role)
			}
		}
	}

	ed := &Editor{rootPath: publishedPath, outDir: outDir, root: root, output: utils.SafeWriter(output)}
	if err := ed.loadLiveChain(rootData); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInconsistentRepository, err)
	}
	return ed, nil
}

// checkRefreshRoot compares the signed content so an external copy can differ
// in formatting or carry a different set of signatures.
func checkRefreshRoot(path, publishedPath string, published *tufmeta.Metadata[tufmeta.RootType]) error {
	supplied := &tufmeta.Metadata[tufmeta.RootType]{}
	if _, err := supplied.FromFile(path); err != nil {
		return fmt.Errorf("failed to load --root %q: %w", path, err)
	}
	want, err := json.Marshal(published.Signed)
	if err != nil {
		return fmt.Errorf("failed to encode published root: %w", err)
	}
	got, err := json.Marshal(supplied.Signed)
	if err != nil {
		return fmt.Errorf("failed to encode --root: %w", err)
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("%w: --root %q differs from published root %q", ErrInconsistentRepository, path, publishedPath)
	}
	return nil
}

func (e *Editor) loadLiveChain(rootData []byte) error {
	timestamp, timestampData, err := readLiveMetadata[tufmeta.TimestampType](e.outDir, "timestamp.json")
	if err != nil {
		return err
	}
	if timestamp.Signed.Version < 1 {
		return fmt.Errorf("timestamp.json has an invalid version")
	}
	snapshotName, err := versionedMetadataName(timestamp.Signed.Meta, "snapshot.json")
	if err != nil {
		return err
	}
	snapshot, snapshotData, err := readLiveMetadata[tufmeta.SnapshotType](e.outDir, snapshotName)
	if err != nil {
		return err
	}
	targetsName, err := versionedMetadataName(snapshot.Signed.Meta, "targets.json")
	if err != nil {
		return err
	}
	targets, targetsData, err := readLiveMetadata[tufmeta.TargetsType](e.outDir, targetsName)
	if err != nil {
		return err
	}
	if err := verifyMetadataChain(rootData, timestampData, snapshotData, targetsData, nil, nil); err != nil {
		return err
	}
	e.timestamp, e.snapshot, e.targets = timestamp, snapshot, targets
	e.loadedTimestamp = timestampSnapshot{recorded: true, exists: true, digest: sha256.Sum256(timestampData)}
	return nil
}

func versionedMetadataName(refs map[string]*tufmeta.MetaFiles, name string) (string, error) {
	ref := refs[name]
	if ref == nil || ref.Version < 1 {
		return "", fmt.Errorf("missing or invalid reference to %s", name)
	}
	return fmt.Sprintf("%d.%s", ref.Version, name), nil
}

func readLiveMetadata[T tufmeta.Roles](dir, name string) (*tufmeta.Metadata[T], []byte, error) {
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read %s: %w", name, err)
	}
	md := &tufmeta.Metadata[T]{}
	if _, err := md.FromBytes(data); err != nil {
		return nil, nil, fmt.Errorf("failed to parse %s: %w", name, err)
	}
	return md, data, nil
}

// SignAndWriteRefresh signs the updated chain and publishes only its metadata.
// The caller holds the repository lock and has bumped the updated versions.
func (e *Editor) SignAndWriteRefresh(role string, keyPaths, vaultKeyRefs []string, getPassphrase keys.PassphraseFunc) error {
	if err := e.CheckNoRollback(); err != nil {
		return err
	}
	signers, err := keys.LoadSignerSetFromAll(keyPaths, vaultKeyRefs, getPassphrase)
	if err != nil {
		return err
	}

	steps, timestamp, signErr := e.signRefresh(role, signers)
	if err := errors.Join(signErr, signers.Close()); err != nil {
		return err
	}
	return e.publish(e.outDir, steps, timestamp)
}

func (e *Editor) signRefresh(role string, signers *keys.SignerSet) ([]publishStep, []byte, error) {
	var steps []publishStep
	if role == "targets" {
		data, err := signRefreshMetadata(e.root, signers, e.targets, "targets")
		if err != nil {
			return nil, nil, err
		}
		version := e.targets.Signed.Version
		steps = append(steps, publishStep{path: filepath.Join(e.outDir, fmt.Sprintf("%d.targets.json", version)), data: data})
		if err := updateRefreshReference(e.snapshot.Signed.Meta, "targets.json", data, version); err != nil {
			return nil, nil, err
		}
	}
	if role == "targets" || role == "snapshot" {
		data, err := signRefreshMetadata(e.root, signers, e.snapshot, "snapshot")
		if err != nil {
			return nil, nil, err
		}
		version := e.snapshot.Signed.Version
		steps = append(steps, publishStep{path: filepath.Join(e.outDir, fmt.Sprintf("%d.snapshot.json", version)), data: data})
		if err := updateRefreshReference(e.timestamp.Signed.Meta, "snapshot.json", data, version); err != nil {
			return nil, nil, err
		}
	}
	timestamp, err := signRefreshMetadata(e.root, signers, e.timestamp, "timestamp")
	return steps, timestamp, err
}

func signRefreshMetadata[T tufmeta.Roles](root *tufmeta.Metadata[tufmeta.RootType], signers *keys.SignerSet, md *tufmeta.Metadata[T], role string) ([]byte, error) {
	auth := root.Signed.Roles[role]
	if err := keys.SignForRole(signers, md, role, auth.KeyIDs, auth.Threshold); err != nil {
		return nil, err
	}
	if err := root.VerifyDelegate(role, md); err != nil {
		return nil, fmt.Errorf("failed to verify newly signed %s: %w", role, err)
	}
	data, err := md.ToBytes(false)
	if err != nil {
		return nil, err
	}
	return utils.IndentJSON(data)
}

func updateRefreshReference(refs map[string]*tufmeta.MetaFiles, name string, data []byte, version int64) error {
	previous := refs[name]
	ref := *previous
	ref.Version = version
	if previous.Length != 0 {
		ref.Length = int64(len(data))
	}
	if len(previous.Hashes) != 0 {
		ref.Hashes = make(tufmeta.Hashes, len(previous.Hashes))
		for algo := range previous.Hashes {
			info, err := utils.MetaFileInfoFromBytes(data, version, algo)
			if err != nil {
				return err
			}
			ref.Hashes[algo] = info.Hashes[algo]
		}
	}
	refs[name] = &ref
	return nil
}
