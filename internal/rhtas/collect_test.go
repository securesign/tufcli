package rhtas

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/securesign/tufcli/internal/utils"
)

func publishedTargetFile(t *testing.T, outDir string, version int, name string) string {
	t.Helper()
	md := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := md.FromFile(filepath.Join(outDir, strconv.Itoa(version)+".targets.json")); err != nil {
		t.Fatal(err)
	}
	tf, ok := md.Signed.Targets[name]
	if !ok {
		t.Fatalf("%s not in version %d", name, version)
	}
	hash, err := utils.PreferredHash(tf.Hashes)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(outDir, "targets", hash+"."+name)
}

// A deleted target's file stays published for the grace period (clients that
// were part-way through the previous version still fetch it) and is removed by
// a later run once the grace period is over.
func TestRun_DeletedTargetFileKeptForGracePeriodThenCollected(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	pubKeyPath := generateTestPublicKey(t, dir, "rekor.pub")

	if err := Run(&Options{
		RootPath: rootPath, KeyPaths: []string{keyPath}, OutDir: outDir,
		RekorTarget: pubKeyPath, RekorURI: "https://rekor.test.dev", Operator: "test.dev",
		TargetPathExists: "replace",
	}); err != nil {
		t.Fatalf("set Run failed: %v", err)
	}
	file := publishedTargetFile(t, outDir, 2, "rekor.pub")

	if err := Run(&Options{
		RootPath: rootPath, KeyPaths: []string{keyPath}, OutDir: outDir,
		DeleteRekorTargets: []string{"rekor.pub"}, TargetPathExists: "replace",
	}); err != nil {
		t.Fatalf("delete Run failed: %v", err)
	}
	if !utils.FileExists(file) {
		t.Fatal("the deleted target's file must stay for in-flight clients")
	}

	// a later run within the grace period keeps it
	expires := time.Now().AddDate(0, 0, 30)
	if err := Run(&Options{
		RootPath: rootPath, KeyPaths: []string{keyPath}, OutDir: outDir,
		TimestampExpires: &expires, TargetPathExists: "replace",
	}); err != nil {
		t.Fatalf("renewal Run failed: %v", err)
	}
	if !utils.FileExists(file) {
		t.Fatal("still within the grace period: the file must stay")
	}

	// once the grace period is over, the next run removes it
	old := deletedTargetGrace
	deletedTargetGrace = 0
	t.Cleanup(func() { deletedTargetGrace = old })
	expires = expires.AddDate(0, 0, 1)
	if err := Run(&Options{
		RootPath: rootPath, KeyPaths: []string{keyPath}, OutDir: outDir,
		TimestampExpires: &expires, TargetPathExists: "replace",
	}); err != nil {
		t.Fatalf("renewal Run failed: %v", err)
	}
	if utils.FileExists(file) {
		t.Fatal("the deleted target's file should be collected after the grace period")
	}
}

// Replaced targets (same name, new content) and files of current targets are
// never collected.
func TestCollectDeletedTargetFiles_LeavesReplacedAndCurrentTargets(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	first := generateTestPublicKey(t, dir, "rekor.pub")
	if err := Run(&Options{
		RootPath: rootPath, KeyPaths: []string{keyPath}, OutDir: outDir,
		RekorTarget: first, RekorURI: "https://rekor.test.dev", Operator: "test.dev",
		TargetPathExists: "replace",
	}); err != nil {
		t.Fatal(err)
	}
	oldFile := publishedTargetFile(t, outDir, 2, "rekor.pub")
	second := generateTestPublicKey(t, t.TempDir(), "rekor.pub")
	if err := Run(&Options{
		RootPath: rootPath, KeyPaths: []string{keyPath}, OutDir: outDir,
		RekorTarget: second, RekorURI: "https://rekor.test.dev", Operator: "test.dev",
		TargetPathExists: "replace",
	}); err != nil {
		t.Fatal(err)
	}
	newFile := publishedTargetFile(t, outDir, 3, "rekor.pub")

	md := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := md.FromFile(filepath.Join(outDir, "3.targets.json")); err != nil {
		t.Fatal(err)
	}
	if err := collectDeletedTargetFiles(outDir, md.Signed.Targets, 0); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{oldFile, newFile} {
		if _, err := os.Stat(f); err != nil {
			t.Fatalf("%s must be kept: %v", filepath.Base(f), err)
		}
	}
}

// A target deleted and later re-added with the same content shares its file
// with the old one; collecting the deletion must not remove it.
func TestRun_ReAddedTargetIsNotCollected(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	pubKeyPath := generateTestPublicKey(t, dir, "rekor.pub")
	set := func() {
		t.Helper()
		if err := Run(&Options{
			RootPath: rootPath, KeyPaths: []string{keyPath}, OutDir: outDir,
			RekorTarget: pubKeyPath, RekorURI: "https://rekor.test.dev", Operator: "test.dev",
			TargetPathExists: "replace",
		}); err != nil {
			t.Fatalf("set Run failed: %v", err)
		}
	}
	set()
	file := publishedTargetFile(t, outDir, 2, "rekor.pub")
	if err := Run(&Options{
		RootPath: rootPath, KeyPaths: []string{keyPath}, OutDir: outDir,
		DeleteRekorTargets: []string{"rekor.pub"}, TargetPathExists: "replace",
	}); err != nil {
		t.Fatalf("delete Run failed: %v", err)
	}

	old := deletedTargetGrace
	deletedTargetGrace = 0
	t.Cleanup(func() { deletedTargetGrace = old })
	set() // re-add the same key: same file
	if !utils.FileExists(file) {
		t.Fatal("a re-added target's file must not be collected")
	}
}

// A target dropped, re-added and dropped again keeps its file for the grace
// period after the latest drop, not the first one.
func TestCollectDeletedTargetFiles_GraceRunsFromLatestDrop(t *testing.T) {
	outDir := t.TempDir()
	targetsDir := filepath.Join(outDir, "targets")
	if err := os.MkdirAll(targetsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := []byte("trust bundle")
	tf, err := tufmeta.TargetFile().FromBytes("bundle.pem", content, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(targetsDir, tf.Hashes["sha256"].String()+".bundle.pem")
	if err := os.WriteFile(file, content, 0o644); err != nil {
		t.Fatal(err)
	}

	// v1 has it, v2 drops it (long ago), v3 re-adds it, v4 drops it (just now).
	longAgo := time.Now().Add(-48 * time.Hour)
	for v, with := range map[int]bool{1: true, 2: false, 3: true, 4: false} {
		md := tufmeta.Targets(time.Now().AddDate(1, 0, 0))
		md.Signed.Version = int64(v)
		if with {
			md.Signed.Targets["bundle.pem"] = tf
		}
		path := filepath.Join(outDir, strconv.Itoa(v)+".targets.json")
		if err := md.ToFile(path, false); err != nil {
			t.Fatal(err)
		}
		mtime := longAgo.Add(time.Duration(v) * time.Minute)
		if v == 4 {
			mtime = time.Now()
		}
		if err := os.Chtimes(path, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}

	if err := collectDeletedTargetFiles(outDir, map[string]*tufmeta.TargetFiles{}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if !utils.FileExists(file) {
		t.Fatal("dropped again just now: the file must stay for the grace period")
	}
	if err := collectDeletedTargetFiles(outDir, map[string]*tufmeta.TargetFiles{}, 0); err != nil {
		t.Fatal(err)
	}
	if utils.FileExists(file) {
		t.Fatal("after the grace period the file must be collected")
	}
}

// Repeating a published deletion within the grace period (e.g. a retried job)
// must not remove the file early; once the grace period is over it does.
func TestRun_RepeatedDeletionKeepsGracePeriod(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	pubKeyPath := generateTestPublicKey(t, dir, "rekor.pub")
	if err := Run(&Options{
		RootPath: rootPath, KeyPaths: []string{keyPath}, OutDir: outDir,
		RekorTarget: pubKeyPath, RekorURI: "https://rekor.test.dev", Operator: "test.dev",
		TargetPathExists: "replace",
	}); err != nil {
		t.Fatalf("set Run failed: %v", err)
	}
	file := publishedTargetFile(t, outDir, 2, "rekor.pub")
	del := func() {
		t.Helper()
		if err := Run(&Options{
			RootPath: rootPath, KeyPaths: []string{keyPath}, OutDir: outDir,
			DeleteRekorTargets: []string{"rekor.pub"}, TargetPathExists: "replace",
		}); err != nil {
			t.Fatalf("delete Run failed: %v", err)
		}
	}
	del()
	del() // already deleted from metadata: the cleanup-only path
	if !utils.FileExists(file) {
		t.Fatal("a repeated deletion within the grace period must keep the file")
	}

	old := deletedTargetGrace
	deletedTargetGrace = 0
	t.Cleanup(func() { deletedTargetGrace = old })
	del()
	if utils.FileExists(file) {
		t.Fatal("after the grace period a repeated deletion should remove the file")
	}
}

// Orphan targets files left by failed runs (older, higher-numbered) must not
// shorten the grace period of a recent published drop.
func TestCollectDeletedTargetFiles_OrphanDoesNotShortenGrace(t *testing.T) {
	outDir := t.TempDir()
	targetsDir := filepath.Join(outDir, "targets")
	if err := os.MkdirAll(targetsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := []byte("trust bundle")
	tf, err := tufmeta.TargetFile().FromBytes("bundle.pem", content, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(targetsDir, tf.Hashes["sha256"].String()+".bundle.pem")
	if err := os.WriteFile(file, content, 0o644); err != nil {
		t.Fatal(err)
	}

	// v1 has it, v2 drops it (published just now); v3 re-adds and v4 drops it,
	// both orphans written long ago by failed runs.
	longAgo := time.Now().Add(-48 * time.Hour)
	for v, with := range map[int]bool{1: true, 2: false, 3: true, 4: false} {
		md := tufmeta.Targets(time.Now().AddDate(1, 0, 0))
		md.Signed.Version = int64(v)
		if with {
			md.Signed.Targets["bundle.pem"] = tf
		}
		path := filepath.Join(outDir, strconv.Itoa(v)+".targets.json")
		if err := md.ToFile(path, false); err != nil {
			t.Fatal(err)
		}
		mtime := longAgo.Add(time.Duration(v) * time.Minute)
		if v == 2 {
			mtime = time.Now()
		}
		if err := os.Chtimes(path, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}

	if err := collectDeletedTargetFiles(outDir, map[string]*tufmeta.TargetFiles{}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if !utils.FileExists(file) {
		t.Fatal("dropped just now: an older orphan must not shorten the grace period")
	}
}

// Deleting a target with --force-version at the published targets version is
// refused before anything is written: no version would record the target, so
// its file could not get the grace period.
func TestRun_SameVersionForcedDeletionRefused(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	pubKeyPath := generateTestPublicKey(t, dir, "rekor.pub")
	if err := Run(&Options{
		RootPath: rootPath, KeyPaths: []string{keyPath}, OutDir: outDir,
		RekorTarget: pubKeyPath, RekorURI: "https://rekor.test.dev", Operator: "test.dev",
		TargetPathExists: "replace",
	}); err != nil {
		t.Fatalf("set Run failed: %v", err)
	}
	file := publishedTargetFile(t, outDir, 2, "rekor.pub")
	before, err := os.ReadFile(filepath.Join(outDir, "2.targets.json"))
	if err != nil {
		t.Fatal(err)
	}
	liveVersion := int64(2)
	err = Run(&Options{
		RootPath: rootPath, KeyPaths: []string{keyPath}, OutDir: outDir,
		DeleteRekorTargets: []string{"rekor.pub"}, TargetPathExists: "replace",
		ForceVersion: true, TargetsVersion: &liveVersion,
	})
	if !errors.Is(err, ErrDeleteNeedsNewVersion) {
		t.Fatalf("expected ErrDeleteNeedsNewVersion, got %v", err)
	}
	after, err := os.ReadFile(filepath.Join(outDir, "2.targets.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) || !utils.FileExists(file) {
		t.Fatal("a refused deletion must leave the repository untouched")
	}

	// A higher forced version is fine and keeps the grace period.
	next := int64(3)
	if err := Run(&Options{
		RootPath: rootPath, KeyPaths: []string{keyPath}, OutDir: outDir,
		DeleteRekorTargets: []string{"rekor.pub"}, TargetPathExists: "replace",
		ForceVersion: true, TargetsVersion: &next,
	}); err != nil {
		t.Fatalf("forced delete at a new version failed: %v", err)
	}
	if !utils.FileExists(file) {
		t.Fatal("the deleted target's file must stay for the grace period")
	}
}

// A run that changes nothing must not rewrite the snapshot or timestamp just
// because the default hash algorithm differs from the one in their entries.
func TestRun_NoOpKeepsEntriesOfAnotherHashAlgorithm(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	keyPath := filepath.Join(dir, "key.pem")
	pubKeyPath := generateTestPublicKey(t, dir, "rekor.pub")
	if err := Run(&Options{
		RootPath: rootPath, KeyPaths: []string{keyPath}, OutDir: outDir,
		RekorTarget: pubKeyPath, RekorURI: "https://rekor.test.dev", Operator: "test.dev",
		TargetPathExists: "replace", HashAlgo: "sha512",
	}); err != nil {
		t.Fatalf("set Run failed: %v", err)
	}
	read := func() map[string]string {
		t.Helper()
		out := map[string]string{}
		entries, err := os.ReadDir(outDir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.IsDir() || e.Name() == ".tufcli.lock" {
				continue
			}
			data, err := os.ReadFile(filepath.Join(outDir, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			out[e.Name()] = string(data)
		}
		return out
	}
	before := read()
	if err := Run(&Options{
		RootPath: rootPath, KeyPaths: []string{keyPath}, OutDir: outDir,
		TargetPathExists: "replace", HashAlgo: "sha256",
	}); err != nil {
		t.Fatalf("no-op Run failed: %v", err)
	}
	after := read()
	if len(after) != len(before) {
		t.Fatalf("no-op run changed the file set: %d before, %d after", len(before), len(after))
	}
	for name, data := range before {
		if after[name] != data {
			t.Fatalf("no-op run rewrote %s", name)
		}
	}
}
