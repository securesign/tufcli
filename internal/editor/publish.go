package editor

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/securesign/tufcli/internal/utils"
)

var (
	// ErrNotConsistentSnapshot is returned, before anything is written, when
	// root.json does not enable consistent_snapshot. Ordered publication only
	// protects clients when every published file has a unique name, so such a
	// repository cannot be published to safely. Retrying will not help: the
	// repository itself must change.
	ErrNotConsistentSnapshot = errors.New("repository does not use consistent snapshots (root.json consistent_snapshot is false); ordered publication is not safe")

	// ErrLiveTimestampChanged is returned when timestamp.json in the output
	// directory differs from the one that was loaded at the start of the run,
	// meaning another writer published in between. The repository lock is what
	// normally prevents this; this check is the safeguard behind it.
	ErrLiveTimestampChanged = errors.New("timestamp.json changed since this run started; another writer published concurrently")

	// ErrRollback is returned, before anything is written, when publishing
	// would make the repository older than what is already published (see
	// checkNoRollback).
	ErrRollback = errors.New("refusing to publish older metadata than the live repository")
)

// staleTempAge is how old a leftover temp file must be before SignAndWrite
// removes it. Generous on purpose: a copy of a very large target may legitimately
// take a while, and a writer that crashed leaves its file for later sweeps.
const staleTempAge = time.Hour

// timestampSnapshot remembers the live timestamp.json seen at load time.
type timestampSnapshot struct {
	recorded bool
	exists   bool
	digest   [sha256.Size]byte
}

func readLiveTimestamp(outDir string) (timestampSnapshot, error) {
	data, err := os.ReadFile(filepath.Join(outDir, "timestamp.json"))
	if errors.Is(err, os.ErrNotExist) {
		return timestampSnapshot{recorded: true}, nil
	}
	if err != nil {
		return timestampSnapshot{}, fmt.Errorf("failed to read live timestamp.json: %w", err)
	}
	return timestampSnapshot{recorded: true, exists: true, digest: sha256.Sum256(data)}, nil
}

// checkLiveTimestampUnchanged compares the live timestamp.json with the one
// recorded at load time. It does nothing for editors that did not record one.
func (e *Editor) checkLiveTimestampUnchanged(outDir string) error {
	if !e.loadedTimestamp.recorded {
		return nil
	}
	now, err := readLiveTimestamp(outDir)
	if err != nil {
		return err
	}
	if now != e.loadedTimestamp {
		return ErrLiveTimestampChanged
	}
	return nil
}

// publishStep is one file of an ordered publication.
type publishStep struct {
	path string
	data []byte
	// copyFrom, when set, is streamed from this file instead of using data.
	copyFrom string
	perm     os.FileMode
}

// publishHook, when set (tests only), is called with each path just before it
// is published, in publication order; a non-nil error aborts the run there.
var publishHook func(path string) error

func (s publishStep) run() error {
	if publishHook != nil {
		if err := publishHook(s.path); err != nil {
			return err
		}
	}
	if s.copyFrom != "" {
		return utils.CopyFileAtomic(s.copyFrom, s.path, s.perm)
	}
	return utils.WriteFileAtomic(s.path, s.data)
}

// publish commits an ordered set of metadata writes with timestamp.json last.
func (e *Editor) publish(outDir string, steps []publishStep, timestampData []byte) error {
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

	return nil
}

type liveState int

const (
	liveAbsent  liveState = iota // no file at that path yet
	liveSame                     // live file carries exactly the same signed payload
	liveDiffers                  // live file exists with a different payload (or is unreadable)
)

// ensureDelegations gives targets metadata the (empty) delegations field the
// editor always carries, for TUF spec 1.0.0 compatibility.
func ensureDelegations(targets *tufmeta.Metadata[tufmeta.TargetsType]) {
	if targets.Signed.Delegations == nil {
		targets.Signed.Delegations = &tufmeta.Delegations{
			Keys:  make(map[string]*tufmeta.Key),
			Roles: []tufmeta.DelegatedRole{},
		}
	}
}

// compareLive checks the live file at path against current's signed payload.
// Signatures are not deterministic, so re-signing unchanged content would give
// different bytes under the same name; callers use liveSame to keep the existing
// bytes instead. A live file only counts as the same if it also still verifies
// against the current root for role: after a key rotation or a raised threshold
// the old signatures no longer satisfy it and the file has to be signed again.
func compareLive[T tufmeta.Roles](path, role string, root *tufmeta.Metadata[tufmeta.RootType], current *tufmeta.Metadata[T]) ([]byte, liveState) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, liveAbsent
	}
	if err != nil {
		return nil, liveDiffers
	}
	// Verify the file exactly as published: its signatures cover its own bytes.
	live := &tufmeta.Metadata[T]{}
	if _, err := live.FromBytes(data); err != nil {
		return nil, liveDiffers
	}
	if err := root.VerifyDelegate(role, live); err != nil {
		return nil, liveDiffers
	}
	// Compare on a second copy: the editor adds an empty delegations field on
	// load, and a repository written by another tool may lack it. Normalizing
	// the copy keeps like-for-like without invalidating the signatures above.
	same := &tufmeta.Metadata[T]{}
	if _, err := same.FromBytes(data); err != nil {
		return nil, liveDiffers
	}
	if targets, ok := any(same).(*tufmeta.Metadata[tufmeta.TargetsType]); ok {
		ensureDelegations(targets)
	}
	a, errA := json.Marshal(same.Signed)
	b, errB := json.Marshal(current.Signed)
	if errA != nil || errB != nil || !bytes.Equal(a, b) {
		return nil, liveDiffers
	}
	return data, liveSame
}

// liveChainPaths follows the live timestamp.json in dir to the snapshot and
// targets files it actually references. A failed run can leave a higher
// numbered snapshot behind (published before timestamp.json); "the highest
// number" would then pick that unreferenced file. Empty strings mean the chain
// could not be resolved (no timestamp.json, or a referenced file is missing),
// in which case callers fall back to the highest-numbered file.
func liveChainPaths(dir string) (snapshotPath, targetsPath string) {
	tsData, err := os.ReadFile(filepath.Join(dir, "timestamp.json"))
	if err != nil {
		return "", ""
	}
	ts := &tufmeta.Metadata[tufmeta.TimestampType]{}
	if _, err := ts.FromBytes(tsData); err != nil {
		return "", ""
	}
	ref, ok := ts.Signed.Meta["snapshot.json"]
	if !ok {
		return "", ""
	}
	snapPath := filepath.Join(dir, fmt.Sprintf("%d.snapshot.json", ref.Version))
	snapData, err := os.ReadFile(snapPath)
	if err != nil {
		return "", ""
	}
	snapshotPath = snapPath
	snap := &tufmeta.Metadata[tufmeta.SnapshotType]{}
	if _, err := snap.FromBytes(snapData); err != nil {
		return snapshotPath, ""
	}
	tref, ok := snap.Signed.Meta["targets.json"]
	if !ok {
		return snapshotPath, ""
	}
	tPath := filepath.Join(dir, fmt.Sprintf("%d.targets.json", tref.Version))
	if !utils.FileExists(tPath) {
		return snapshotPath, ""
	}
	return snapshotPath, tPath
}

// warnOverwrite notes when a file the live chain references is replaced in
// place with different content or signatures (an explicit --force-version, a
// key rotation, or a repository written by another tool): clients holding its
// old hash fail verification until the new timestamp.json is published.
// Replacing an unreferenced file (an orphan left by a failed run, or the
// first run of a repository) is silent: no client can hold it.
func (e *Editor) warnOverwrite(state liveState, path, livePath string) {
	if state == liveDiffers && livePath != "" && filepath.Clean(path) == filepath.Clean(livePath) {
		fmt.Fprintf(e.output, "WARNING: %s is referenced by the published timestamp.json and is replaced in place with different content or signatures; clients holding its old hash may fail verification until the new timestamp.json is published\n", filepath.Base(path))
	}
}

// referencedTargetPaths returns the cleaned paths of every target file the
// in-memory targets metadata or the live chain's targets metadata refers to,
// both the hash-prefixed file and the non-prefixed staging copy.
func (e *Editor) referencedTargetPaths(outDir string) map[string]bool {
	targetsDir := filepath.Join(outDir, "targets")
	paths := map[string]bool{}
	add := func(targets map[string]*tufmeta.TargetFiles) {
		for name, meta := range targets {
			paths[filepath.Clean(filepath.Join(targetsDir, name))] = true
			if hash, err := utils.PreferredHash(meta.Hashes); err == nil {
				paths[filepath.Clean(filepath.Join(targetsDir, hash+"."+name))] = true
			}
		}
	}
	add(e.targets.Signed.Targets)
	if _, livePath := liveChainPaths(outDir); livePath != "" {
		live := &tufmeta.Metadata[tufmeta.TargetsType]{}
		if _, err := live.FromFile(livePath); err == nil {
			add(live.Signed.Targets)
		}
	}
	return paths
}

// CheckNoRollback runs the rollback check SignAndWrite runs, with the versions
// set so far. Callers run it after setting versions and before copying target
// files, so a refused run leaves nothing behind in the repository.
func (e *Editor) CheckNoRollback() error {
	rootMd := &tufmeta.Metadata[tufmeta.RootType]{}
	if _, err := rootMd.FromFile(e.rootPath); err != nil {
		return fmt.Errorf("failed to parse root.json: %w", err)
	}
	return checkNoRollback(e.outDir, rootMd.Signed.Version, e.timestamp.Signed.Version, e.snapshot.Signed.Version, e.targets.Signed.Version)
}

// metaFor returns the snapshot or timestamp entry describing data. When the
// role holding the entry keeps its live version (keep), an existing entry that
// still describes data is kept, whatever hash algorithm it uses: recomputing
// it with another algorithm would change that role's bytes without a new
// version, and clients that hold the old ones would reject them. Roles that get
// a new version always use hashAlgo.
func metaFor(existing *tufmeta.MetaFiles, keep bool, data []byte, version int64, hashAlgo string) (*tufmeta.MetaFiles, error) {
	if keep && existing != nil && existing.Version == version && len(existing.Hashes) > 0 && existing.VerifyLengthHashes(data) == nil {
		return existing, nil
	}
	return utils.MetaFileInfoFromBytes(data, version, hashAlgo)
}

// liveTimestampVersion returns the version of timestamp.json in dir, or -1
// when there is none or it cannot be read.
func liveTimestampVersion(dir string) int64 {
	live := &tufmeta.Metadata[tufmeta.TimestampType]{}
	if _, err := live.FromFile(filepath.Join(dir, "timestamp.json")); err != nil {
		return -1
	}
	return live.Signed.Version
}

// checkNoRollback refuses a timestamp version lower than the live
// timestamp.json, snapshot and targets versions lower than the ones the live
// chain references, and a root version lower than the live root.json. Equal
// versions are allowed (e.g. an init script re-publishing version 1).
func checkNoRollback(outDir string, rootVersion, timestampVersion, snapshotVersion, targetsVersion int64) error {
	liveSnapshot, liveTargets := liveChainPaths(outDir)
	for _, c := range []struct {
		role, path string
		version    int64
	}{{"snapshot", liveSnapshot, snapshotVersion}, {"targets", liveTargets, targetsVersion}} {
		if c.path == "" {
			continue
		}
		v, ok := strings.CutSuffix(filepath.Base(c.path), "."+c.role+".json")
		if !ok {
			continue
		}
		if live, err := strconv.ParseInt(v, 10, 64); err == nil && c.version < live {
			return fmt.Errorf("%w: %s.json version %d is older than the published version %d", ErrRollback, c.role, c.version, live)
		}
	}
	if data, err := os.ReadFile(filepath.Join(outDir, "timestamp.json")); err == nil {
		live := &tufmeta.Metadata[tufmeta.TimestampType]{}
		if _, err := live.FromBytes(data); err == nil && timestampVersion < live.Signed.Version {
			return fmt.Errorf("%w: timestamp.json version %d is older than the published version %d", ErrRollback, timestampVersion, live.Signed.Version)
		}
	}
	if data, err := os.ReadFile(filepath.Join(outDir, "root.json")); err == nil {
		live := &tufmeta.Metadata[tufmeta.RootType]{}
		if _, err := live.FromBytes(data); err == nil && rootVersion < live.Signed.Version {
			return fmt.Errorf("%w: root.json version %d is older than the published version %d", ErrRollback, rootVersion, live.Signed.Version)
		}
	}
	return nil
}
