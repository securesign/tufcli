package rhtas

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/securesign/tufcli/internal/utils"
)

// deletedTargetGrace is how long the file of a deleted target stays published
// after the version that dropped it, so clients that were part-way through the
// previous version can still fetch it. Variable so tests can shorten it.
var deletedTargetGrace = time.Hour

// collectDeletedTargetFiles removes the hash-prefixed files of targets that a
// published version deleted at least grace ago. A target counts as deleted
// when a targets version on disk drops it by name and neither the current
// targets (current) nor the newest version on disk references it; its grace
// period runs from the latest such drop. Only files under the exact
// hash-prefixed name an older version recorded are removed, so replaced
// targets (same name, new content) and anything else in targets/ are left
// alone.
func collectDeletedTargetFiles(outDir string, current map[string]*tufmeta.TargetFiles, grace time.Duration) error {
	versions, err := targetsVersionsOnDisk(outDir)
	if err != nil || len(versions) < 2 {
		return err
	}
	targetsDir := filepath.Join(outDir, "targets")

	// Walk versions oldest to newest; when a name present in version i is
	// absent from version i+1, version i+1 is the publication that dropped it.
	// A target can be dropped, re-added and dropped again: its file's grace
	// period runs from the latest drop.
	droppedAt := map[string]time.Time{} // hash-prefixed file -> when the dropping version was written
	prev, err := readTargetsVersion(outDir, versions[0])
	if err != nil {
		return nil // unreadable history: nothing to collect safely
	}
	for _, v := range versions[1:] {
		next, err := readTargetsVersion(outDir, v)
		if err != nil {
			return nil
		}
		info, err := os.Stat(filepath.Join(outDir, fmt.Sprintf("%d.targets.json", v)))
		if err != nil {
			return nil
		}
		for name, meta := range prev {
			if _, still := next[name]; still {
				continue
			}
			hash, err := utils.PreferredHash(meta.Hashes)
			if err != nil {
				continue
			}
			// Keep the newest drop time: an older file (an orphan left by a
			// failed run) must not shorten the grace of a recent drop.
			file := filepath.Clean(filepath.Join(targetsDir, hash+"."+name))
			if t := info.ModTime(); t.After(droppedAt[file]) {
				droppedAt[file] = t
			}
		}
		prev = next
	}

	// Never remove anything the current or newest published targets reference.
	keep := map[string]bool{}
	for _, refs := range []map[string]*tufmeta.TargetFiles{current, prev} {
		for name, meta := range refs {
			if hash, err := utils.PreferredHash(meta.Hashes); err == nil {
				keep[filepath.Clean(filepath.Join(targetsDir, hash+"."+name))] = true
			}
		}
	}

	for file, removed := range droppedAt {
		if keep[file] || time.Since(removed) < grace {
			continue
		}
		if err := utils.ValidatePathInDir(targetsDir, file); err != nil {
			continue
		}
		if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove deleted target file %s: %w", filepath.Base(file), err)
		}
	}
	return nil
}

// targetsVersionsOnDisk lists the versions of <N>.targets.json in outDir, ascending.
func targetsVersionsOnDisk(outDir string) ([]int64, error) {
	entries, err := os.ReadDir(outDir)
	if err != nil {
		return nil, err
	}
	var versions []int64
	for _, e := range entries {
		v, ok := strings.CutSuffix(e.Name(), ".targets.json")
		if !ok || e.IsDir() {
			continue
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			continue
		}
		versions = append(versions, n)
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })
	return versions, nil
}

func readTargetsVersion(outDir string, version int64) (map[string]*tufmeta.TargetFiles, error) {
	md := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := md.FromFile(filepath.Join(outDir, fmt.Sprintf("%d.targets.json", version))); err != nil {
		return nil, err
	}
	return md.Signed.Targets, nil
}
