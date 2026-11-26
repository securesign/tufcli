package editor

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/securesign/tufcli/internal/keys"
	"github.com/securesign/tufcli/internal/utils"
)

func signOpts(keyPath, outDir string) SignAndWriteOptions {
	return SignAndWriteOptions{KeyPaths: []string{keyPath}, OutDir: outDir, HashAlgo: "sha256"}
}

func loadForUpdate(t *testing.T, rootPath, outDir string) *Editor {
	t.Helper()
	ed, err := LoadRepository(LoadOptions{RootPath: rootPath, OutDir: outDir, TargetPathExists: "skip"})
	if err != nil {
		t.Fatalf("LoadRepository failed: %v", err)
	}
	future := time.Now().AddDate(1, 0, 0)
	ed.SetTargetsExpires(future)
	ed.SetSnapshotExpires(future)
	ed.SetTimestampExpires(future)
	return ed
}

// addStagedTarget places name in <outDir>/targets (the layout rhtas uses) and
// registers it in the targets metadata.
func addStagedTarget(t *testing.T, ed *Editor, outDir, name, content string) {
	t.Helper()
	path := filepath.Join(outDir, "targets", name)
	if err := utils.WriteFileAtomic(path, []byte(content)); err != nil {
		t.Fatal(err)
	}
	tf, err := BuildTargetFiles(path, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	ed.AddTarget(name, tf)
}

func recordPublishOrder(t *testing.T) *[]string {
	t.Helper()
	var order []string
	publishHook = func(path string) error {
		order = append(order, filepath.Base(path))
		return nil
	}
	t.Cleanup(func() { publishHook = nil })
	return &order
}

func writeNonConsistentRoot(t *testing.T, rootPath string) {
	t.Helper()
	md := &tufmeta.Metadata[tufmeta.RootType]{}
	if _, err := md.FromFile(rootPath); err != nil {
		t.Fatal(err)
	}
	md.Signed.ConsistentSnapshot = false
	data, err := md.ToBytes(true)
	if err != nil {
		t.Fatal(err)
	}
	if err := utils.WriteFileAtomic(rootPath, data); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRepository_RefusesNonConsistentSnapshot(t *testing.T) {
	rootPath, _ := setupTestRoot(t)
	writeNonConsistentRoot(t, rootPath)
	outDir := t.TempDir()

	_, err := LoadRepository(LoadOptions{RootPath: rootPath, OutDir: outDir})
	if !errors.Is(err, ErrNotConsistentSnapshot) {
		t.Fatalf("expected ErrNotConsistentSnapshot, got %v", err)
	}
	if entries, _ := os.ReadDir(outDir); len(entries) != 0 {
		t.Fatalf("nothing may be written for a rejected repository, found %d entries", len(entries))
	}
}

// Defence in depth: the root can change between load and publish.
func TestSignAndWrite_RefusesNonConsistentSnapshot(t *testing.T) {
	rootPath, keyPath := setupTestRoot(t)
	outDir := t.TempDir()
	ed := loadForUpdate(t, rootPath, outDir)
	writeNonConsistentRoot(t, rootPath)

	err := ed.SignAndWrite(signOpts(keyPath, outDir))
	if !errors.Is(err, ErrNotConsistentSnapshot) {
		t.Fatalf("expected ErrNotConsistentSnapshot, got %v", err)
	}
	if entries, _ := os.ReadDir(outDir); len(entries) != 0 {
		t.Fatalf("nothing may be written for a rejected repository, found %d entries", len(entries))
	}
}

func TestSignAndWrite_PublishesInOrderTimestampLast(t *testing.T) {
	rootPath, keyPath := setupTestRoot(t)
	outDir := t.TempDir()
	ed := loadForUpdate(t, rootPath, outDir)
	addStagedTarget(t, ed, outDir, "a.txt", "alpha")
	order := recordPublishOrder(t)

	if err := ed.SignAndWrite(signOpts(keyPath, outDir)); err != nil {
		t.Fatalf("SignAndWrite failed: %v", err)
	}

	idx := func(match func(string) bool, what string) int {
		for i, p := range *order {
			if match(p) {
				return i
			}
		}
		t.Fatalf("%s was not published: %v", what, *order)
		return -1
	}
	exact := func(name string) func(string) bool { return func(p string) bool { return p == name } }
	want := []int{
		idx(func(p string) bool { return strings.HasSuffix(p, ".a.txt") }, "hash-prefixed target"),
		idx(exact("1.targets.json"), "1.targets.json"),
		idx(exact("1.snapshot.json"), "1.snapshot.json"),
		idx(exact("1.root.json"), "1.root.json"),
		idx(exact("root.json"), "root.json"),
		idx(exact("timestamp.json"), "timestamp.json"),
	}
	for i := 1; i < len(want); i++ {
		if want[i-1] >= want[i] {
			t.Fatalf("unexpected publish order (target, targets, snapshot, versioned root, root, timestamp): %v", *order)
		}
	}
	if got := (*order)[len(*order)-1]; got != "timestamp.json" {
		t.Fatalf("timestamp.json must be published last, order: %v", *order)
	}
	// the hash-prefixed target exists and the staging copy is gone
	if utils.FileExists(filepath.Join(outDir, "targets", "a.txt")) {
		t.Fatal("non-hash-prefixed staging copy should be removed after publication")
	}
}

func TestSignAndWrite_FailureBeforeTimestampKeepsPreviousVersion(t *testing.T) {
	rootPath, keyPath := setupTestRoot(t)
	outDir := setupSignedRepo(t, rootPath, keyPath)
	oldTimestamp, err := os.ReadFile(filepath.Join(outDir, "timestamp.json"))
	if err != nil {
		t.Fatal(err)
	}
	oldRoot, _ := os.ReadFile(filepath.Join(outDir, "root.json"))

	ed := loadForUpdate(t, rootPath, outDir)
	ed.BumpTargetsVersion()
	ed.BumpSnapshotVersion()
	ed.BumpTimestampVersion()
	addStagedTarget(t, ed, outDir, "b.txt", "bravo")

	publishHook = func(path string) error {
		if strings.HasSuffix(path, ".snapshot.json") {
			return errors.New("injected failure")
		}
		return nil
	}
	t.Cleanup(func() { publishHook = nil })

	if err := ed.SignAndWrite(signOpts(keyPath, outDir)); err == nil {
		t.Fatal("expected the injected failure")
	}

	gotTimestamp, _ := os.ReadFile(filepath.Join(outDir, "timestamp.json"))
	if !bytes.Equal(gotTimestamp, oldTimestamp) {
		t.Fatal("timestamp.json must be untouched when publication fails before it")
	}
	gotRoot, _ := os.ReadFile(filepath.Join(outDir, "root.json"))
	if !bytes.Equal(gotRoot, oldRoot) {
		t.Fatal("root.json must be untouched")
	}
	// Whatever was written before the failure is unreferenced: the snapshot the
	// old timestamp points to is still there and the new one is not.
	if !utils.FileExists(filepath.Join(outDir, "1.snapshot.json")) {
		t.Fatal("previous snapshot must still exist")
	}
	if utils.FileExists(filepath.Join(outDir, "2.snapshot.json")) {
		t.Fatal("new snapshot must not exist after the failure")
	}
	// The repository must still load and verify through the chain the live
	// timestamp.json references.
	if _, err := LoadRepository(LoadOptions{RootPath: rootPath, OutDir: t.TempDir(), MetadataURL: "file://" + outDir}); err != nil {
		t.Fatalf("previous version must still verify after a failed publication: %v", err)
	}
	matches, _ := filepath.Glob(filepath.Join(outDir, "*", utils.TempFilePrefix+"*"))
	top, _ := filepath.Glob(filepath.Join(outDir, utils.TempFilePrefix+"*"))
	if len(matches)+len(top) != 0 {
		t.Fatalf("temp files left behind: %v %v", matches, top)
	}
}

func TestSignAndWrite_RefusesWhenLiveTimestampChanged(t *testing.T) {
	rootPath, keyPath := setupTestRoot(t)
	outDir := setupSignedRepo(t, rootPath, keyPath)
	ed := loadForUpdate(t, rootPath, outDir)
	ed.BumpTargetsVersion()
	ed.BumpSnapshotVersion()
	ed.BumpTimestampVersion()

	// another writer publishes after our load
	if err := utils.WriteFileAtomic(filepath.Join(outDir, "timestamp.json"), []byte(`{"changed":true}`)); err != nil {
		t.Fatal(err)
	}

	err := ed.SignAndWrite(signOpts(keyPath, outDir))
	if !errors.Is(err, ErrLiveTimestampChanged) {
		t.Fatalf("expected ErrLiveTimestampChanged, got %v", err)
	}
	if utils.FileExists(filepath.Join(outDir, "2.snapshot.json")) {
		t.Fatal("nothing may be published once the live timestamp changed")
	}
}

func TestSignAndWrite_RejectsInvalidTargetName(t *testing.T) {
	rootPath, keyPath := setupTestRoot(t)
	outDir := t.TempDir()
	ed := loadForUpdate(t, rootPath, outDir)
	addStagedTarget(t, ed, outDir, "target.txt", "content")
	ed.AddTarget(".", ed.targets.Signed.Targets["target.txt"])

	err := ed.SignAndWrite(signOpts(keyPath, outDir))
	if err == nil || !strings.Contains(err.Error(), `invalid target name "."`) {
		t.Fatalf("expected invalid target name error, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "timestamp.json")); !os.IsNotExist(err) {
		t.Fatalf("timestamp should not be published, stat returned %v", err)
	}
}

func TestSignAndWrite_MissingTargetFailsBeforeAnyWrite(t *testing.T) {
	rootPath, keyPath := setupTestRoot(t)
	outDir := t.TempDir()
	ed := loadForUpdate(t, rootPath, outDir)
	tf := tufmeta.TargetFile()
	tf.Length = 1
	tf.Hashes = tufmeta.Hashes{"sha256": bytes.Repeat([]byte{1}, 32)}
	ed.AddTarget("ghost.txt", tf)

	if err := ed.SignAndWrite(signOpts(keyPath, outDir)); err == nil || !strings.Contains(err.Error(), "ghost.txt") {
		t.Fatalf("expected a missing-target error, got %v", err)
	}
	if entries, _ := os.ReadDir(outDir); len(entries) != 0 {
		t.Fatalf("a missing target must fail before anything is written, found %d entries", len(entries))
	}
}

func TestSignAndWrite_SecondRunInSameEditorStillPasses(t *testing.T) {
	rootPath, keyPath := setupTestRoot(t)
	outDir := t.TempDir()
	ed := loadForUpdate(t, rootPath, outDir)
	if err := ed.SignAndWrite(signOpts(keyPath, outDir)); err != nil {
		t.Fatal(err)
	}
	ed.BumpTargetsVersion()
	ed.BumpSnapshotVersion()
	ed.BumpTimestampVersion()
	if err := ed.SignAndWrite(signOpts(keyPath, outDir)); err != nil {
		t.Fatalf("our own earlier publication must not trip the safeguard: %v", err)
	}
}

func TestCommitStagedMetadata_LeavesIdenticalFilesAlone(t *testing.T) {
	staging, out := t.TempDir(), t.TempDir()
	for _, dir := range []string{staging, out} {
		if err := os.WriteFile(filepath.Join(dir, "timestamp.json"), []byte("same"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	before, _ := os.Stat(filepath.Join(out, "timestamp.json"))

	if err := commitStagedMetadata(staging, out); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(filepath.Join(out, "timestamp.json"))
	if !os.SameFile(before, after) {
		t.Fatal("an identical live file must not be replaced (it would briefly disappear)")
	}
	if utils.FileExists(filepath.Join(out, "timestamp.json.backup")) {
		t.Fatal("no backup should be made for an identical file")
	}
}

func readAll(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() == ".tufcli.lock" {
			return err
		}
		data, _ := os.ReadFile(path)
		rel, _ := filepath.Rel(dir, path)
		out[rel] = string(data)
		return nil
	})
	return out
}

// A run that changes nothing must publish nothing: re-signing would give new
// bytes under the same names (signatures are not deterministic).
func TestSignAndWrite_NoChangeRunLeavesRepositoryByteIdentical(t *testing.T) {
	rootPath, keyPath := setupTestRoot(t)
	outDir := setupSignedRepo(t, rootPath, keyPath)
	before := readAll(t, outDir)

	ed, err := LoadRepository(LoadOptions{RootPath: rootPath, OutDir: outDir, TargetPathExists: "skip"})
	if err != nil {
		t.Fatal(err)
	}
	opts := signOpts(keyPath, outDir)
	opts.ReuseTargets = true // what rhtas does when no target changed
	if err := ed.SignAndWrite(opts); err != nil {
		t.Fatal(err)
	}
	after := readAll(t, outDir)
	for name, content := range before {
		if after[name] != content {
			t.Errorf("%s changed in a no-change run", name)
		}
	}
	if len(after) != len(before) {
		t.Errorf("file set changed: %d -> %d", len(before), len(after))
	}
}

// update always re-signs targets; with no target change and no bump the
// published N.targets.json must keep its bytes (clients hold its hash).
func TestSignAndWrite_UnchangedTargetsKeepPublishedBytesWhenOthersBump(t *testing.T) {
	rootPath, keyPath := setupTestRoot(t)
	outDir := setupSignedRepo(t, rootPath, keyPath)
	before, err := os.ReadFile(filepath.Join(outDir, "1.targets.json"))
	if err != nil {
		t.Fatal(err)
	}

	// load without touching expiries; ReuseTargets stays false, as in `update`
	ed, err := LoadRepository(LoadOptions{RootPath: rootPath, OutDir: outDir, TargetPathExists: "skip"})
	if err != nil {
		t.Fatal(err)
	}
	ed.BumpSnapshotVersion()
	ed.BumpTimestampVersion()
	if err := ed.SignAndWrite(signOpts(keyPath, outDir)); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(outDir, "1.targets.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("1.targets.json was rewritten although its content did not change")
	}
	if !utils.FileExists(filepath.Join(outDir, "2.snapshot.json")) {
		t.Fatal("the bumped snapshot must be published")
	}
	if _, err := LoadRepository(LoadOptions{RootPath: rootPath, OutDir: t.TempDir(), MetadataURL: "file://" + outDir}); err != nil {
		t.Fatalf("repository must verify: %v", err)
	}
}

// A failure after N+1.snapshot.json but before timestamp.json leaves an
// orphan snapshot; later runs must follow the live chain, not "highest number".
func TestFailureAfterSnapshotDoesNotBlockLaterRuns(t *testing.T) {
	rootPath, keyPath := setupTestRoot(t)
	outDir := setupSignedRepo(t, rootPath, keyPath)

	ed := loadForUpdate(t, rootPath, outDir)
	ed.BumpTargetsVersion()
	ed.BumpSnapshotVersion()
	ed.BumpTimestampVersion()
	publishHook = func(path string) error {
		if filepath.Base(path) == "timestamp.json" {
			return errors.New("injected failure before the commit point")
		}
		return nil
	}
	err := ed.SignAndWrite(signOpts(keyPath, outDir))
	publishHook = nil
	if err == nil {
		t.Fatal("expected the injected failure")
	}
	if !utils.FileExists(filepath.Join(outDir, "2.snapshot.json")) {
		t.Fatal("test premise: the orphan snapshot should exist")
	}

	// the rollback floor must come from what timestamp.json references (1)
	if _, err := LoadRepository(LoadOptions{RootPath: rootPath, OutDir: outDir, MetadataURL: "file://" + outDir}); err != nil {
		t.Fatalf("an orphan snapshot must not block loading: %v", err)
	}
	// and a retry succeeds
	ed2 := loadForUpdate(t, rootPath, outDir)
	if got := ed2.snapshot.Signed.Version; got != 1 {
		t.Fatalf("a retry must start from the live snapshot (version 1), got %d", got)
	}
	ed2.BumpTargetsVersion()
	ed2.BumpSnapshotVersion()
	ed2.BumpTimestampVersion()
	if err := ed2.SignAndWrite(signOpts(keyPath, outDir)); err != nil {
		t.Fatalf("retry after a failed publication: %v", err)
	}
	if _, err := LoadRepository(LoadOptions{RootPath: rootPath, OutDir: t.TempDir(), MetadataURL: "file://" + outDir}); err != nil {
		t.Fatalf("repository must verify after the retry: %v", err)
	}
}

// With --target-path-exists fail, files CopyTargetToRepo just wrote are not conflicts.
func TestSignAndWrite_FailPolicyAcceptsFilesCopiedInTheSameRun(t *testing.T) {
	rootPath, keyPath := setupTestRoot(t)
	outDir := t.TempDir()
	ed, err := LoadRepository(LoadOptions{RootPath: rootPath, OutDir: outDir, TargetPathExists: "fail"})
	if err != nil {
		t.Fatal(err)
	}
	future := time.Now().AddDate(1, 0, 0)
	ed.SetTargetsExpires(future)
	ed.SetSnapshotExpires(future)
	ed.SetTimestampExpires(future)

	src := filepath.Join(t.TempDir(), "n.txt")
	if err := os.WriteFile(src, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	tf, err := BuildTargetFiles(src, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	ed.AddTarget("n.txt", tf)
	if err := ed.CopyTargetToRepo(src, "n.txt"); err != nil {
		t.Fatal(err)
	}
	if err := ed.SignAndWrite(signOpts(keyPath, outDir)); err != nil {
		t.Fatalf("the fail policy must not reject a file copied in this very run: %v", err)
	}
}

// A nested target name is published where tufcli's own client looks for it
// (<hash>.<target-path>, see tufclient.DownloadTarget), for both ways a target
// reaches the repository. Before, files staged in <outdir>/targets lost their
// directory and landed at <hash>.<base>.
func TestNestedTargetNamesFollowTufcliNaming(t *testing.T) {
	rootPath, keyPath := setupTestRoot(t)
	outDir := t.TempDir()
	ed, err := LoadRepository(LoadOptions{RootPath: rootPath, OutDir: outDir, TargetPathExists: "skip"})
	if err != nil {
		t.Fatal(err)
	}
	future := time.Now().AddDate(1, 0, 0)
	ed.SetTargetsExpires(future)
	ed.SetSnapshotExpires(future)
	ed.SetTimestampExpires(future)

	src := filepath.Join(t.TempDir(), "n.txt")
	_ = os.WriteFile(src, []byte("added"), 0600)
	added, _ := BuildTargetFiles(src, "sha256")
	ed.AddTarget("dir/n.txt", added)
	if err := ed.CopyTargetToRepo(src, "dir/n.txt"); err != nil {
		t.Fatal(err)
	}
	addStagedTarget(t, ed, outDir, "deep/m.txt", "staged")

	if err := ed.SignAndWrite(signOpts(keyPath, outDir)); err != nil {
		t.Fatalf("SignAndWrite: %v", err)
	}

	hashOf := func(name string) string {
		h, _ := utils.PreferredHash(ed.Targets().Signed.Targets[name].Hashes)
		return h
	}
	for name, want := range map[string]string{
		"dir/n.txt":  filepath.Join(outDir, "targets", hashOf("dir/n.txt")+".dir", "n.txt"),
		"deep/m.txt": filepath.Join(outDir, "targets", hashOf("deep/m.txt")+".deep", "m.txt"),
	} {
		if !utils.FileExists(want) {
			t.Errorf("%s not published at %s", name, want)
		}
	}
	if utils.FileExists(filepath.Join(outDir, "targets", hashOf("deep/m.txt")+".m.txt")) {
		t.Error("a staged nested target must not lose its directory (<hash>.<base>)")
	}
	// the repository loads and fetches its nested targets back
	if _, err := LoadRepository(LoadOptions{RootPath: rootPath, OutDir: t.TempDir(), MetadataURL: "file://" + outDir}); err != nil {
		t.Fatalf("a repository with nested targets must fetch and verify: %v", err)
	}
}

func TestSignAndWrite_SweepsStaleTempFilesButNotFreshOnes(t *testing.T) {
	rootPath, keyPath := setupTestRoot(t)
	outDir := t.TempDir()
	nested := filepath.Join(outDir, "targets", "1111.dir")
	if err := os.MkdirAll(nested, 0755); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-3 * time.Hour)
	mk := func(path string, mtime time.Time) string {
		t.Helper()
		if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, mtime, mtime); err != nil {
			t.Fatal(err)
		}
		return path
	}
	staleTop := mk(filepath.Join(outDir, utils.TempFilePrefix+"101"), old)
	staleTargets := mk(filepath.Join(outDir, "targets", utils.TempFilePrefix+"202"), old)
	staleNested := mk(filepath.Join(nested, utils.TempFilePrefix+"303"), old)
	legacyTop := mk(filepath.Join(outDir, utils.LegacyTempFilePrefix+"404"), old)
	legacyTargets := mk(filepath.Join(outDir, "targets", utils.LegacyTempFilePrefix+"505"), old)
	fresh := mk(filepath.Join(outDir, "targets", utils.TempFilePrefix+"606"), time.Now())
	// a published nested target that happens to be named like an old temp file
	userFile := mk(filepath.Join(nested, utils.LegacyTempFilePrefix+"707"), old)

	ed := loadForUpdate(t, rootPath, outDir)
	if err := ed.SignAndWrite(signOpts(keyPath, outDir)); err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{staleTop, staleTargets, staleNested, legacyTop, legacyTargets} {
		if utils.FileExists(gone) {
			t.Errorf("stale temp file %s should be swept", gone)
		}
	}
	if !utils.FileExists(fresh) {
		t.Error("a fresh temp file may belong to a write in progress and must be kept")
	}
	if !utils.FileExists(userFile) {
		t.Error("a user file below a target directory must never be swept, whatever its name")
	}
}

// Published targets are named by users: one called ".tmp-x" must survive the sweep
// and keep the repository usable on the next run.
func TestSweepNeverRemovesAPublishedTargetNamedLikeATempFile(t *testing.T) {
	rootPath, keyPath := setupTestRoot(t)
	outDir := t.TempDir()
	ed := loadForUpdate(t, rootPath, outDir)
	src := filepath.Join(t.TempDir(), ".tmp-hidden")
	_ = os.WriteFile(src, []byte("payload"), 0600)
	tf, _ := BuildTargetFiles(src, "sha256")
	ed.AddTarget("dir/.tmp-hidden", tf)
	if err := ed.CopyTargetToRepo(src, "dir/.tmp-hidden"); err != nil {
		t.Fatal(err)
	}
	if err := ed.SignAndWrite(signOpts(keyPath, outDir)); err != nil {
		t.Fatal(err)
	}
	hash, _ := utils.PreferredHash(tf.Hashes)
	published := filepath.Join(outDir, "targets", hash+".dir", ".tmp-hidden")
	old := time.Now().Add(-3 * time.Hour)
	_ = os.Chtimes(published, old, old)

	ed2, err := LoadRepository(LoadOptions{RootPath: rootPath, OutDir: outDir, TargetPathExists: "skip"})
	if err != nil {
		t.Fatal(err)
	}
	ed2.BumpSnapshotVersion()
	ed2.BumpTimestampVersion()
	if err := ed2.SignAndWrite(signOpts(keyPath, outDir)); err != nil {
		t.Fatalf("the next run must not fail because a target looks like a temp file: %v", err)
	}
	if !utils.FileExists(published) {
		t.Fatal("the published target was swept")
	}
}

// After a key rotation (new root keys) an unchanged payload at the same version
// must be signed again, not kept with signatures the root no longer accepts.
func TestSignAndWrite_ReSignsWhenRootKeysChanged(t *testing.T) {
	rootPath1, keyPath1 := setupTestRoot(t)
	outDir := setupSignedRepo(t, rootPath1, keyPath1)

	rootPath2, keyPath2 := setupTestRoot(t) // a different key set
	before, _ := os.ReadFile(filepath.Join(outDir, "1.targets.json"))
	ed, err := LoadRepository(LoadOptions{RootPath: rootPath2, OutDir: outDir, TargetPathExists: "skip"})
	if err != nil {
		t.Fatal(err)
	}
	// payload and versions stay exactly as published
	if err := ed.SignAndWrite(signOpts(keyPath2, outDir)); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(outDir, "1.targets.json"))
	if bytes.Equal(before, after) {
		t.Fatal("1.targets.json kept signatures from keys the current root does not authorise")
	}
	if _, err := LoadRepository(LoadOptions{RootPath: rootPath2, OutDir: t.TempDir(), MetadataURL: "file://" + outDir}); err != nil {
		t.Fatalf("the repository must verify against the rotated root: %v", err)
	}
}

// A live targets file written by another tool may lack the empty "delegations"
// the editor adds; that alone must not count as a change.
func TestSignAndWrite_LiveTargetsWithoutDelegationsAreStillTheSame(t *testing.T) {
	rootPath, keyPath := setupTestRoot(t)
	outDir := setupSignedRepo(t, rootPath, keyPath)

	path := filepath.Join(outDir, "1.targets.json")
	md := &tufmeta.Metadata[tufmeta.TargetsType]{}
	if _, err := md.FromFile(path); err != nil {
		t.Fatal(err)
	}
	md.Signed.Delegations = nil
	signer, _, keyID, err := keys.LoadSigner(keyPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	md.ClearSignatures()
	if _, err := md.Sign(signer); err != nil {
		t.Fatal(err)
	}
	md.Signatures[len(md.Signatures)-1].KeyID = keyID
	data, err := md.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	if err := utils.WriteFileAtomic(path, data); err != nil {
		t.Fatal(err)
	}
	live, _ := os.ReadFile(path)

	ed, err := LoadRepository(LoadOptions{RootPath: rootPath, OutDir: outDir, TargetPathExists: "skip"})
	if err != nil {
		t.Fatal(err)
	}
	ed.BumpSnapshotVersion()
	ed.BumpTimestampVersion()
	if err := ed.SignAndWrite(signOpts(keyPath, outDir)); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(live, after) {
		t.Fatal("a targets file written without delegations was rewritten in place")
	}
}

// Nothing may be rewritten by a run that changes nothing, not even with the same
// bytes: a new inode/mtime looks like a publication to caches and mirrors.
func TestSignAndWrite_NoChangeRunDoesNotTouchFiles(t *testing.T) {
	rootPath, keyPath := setupTestRoot(t)
	outDir := setupSignedRepo(t, rootPath, keyPath)
	names := []string{"timestamp.json", "root.json", "1.root.json", "1.snapshot.json", "1.targets.json"}
	before := map[string]os.FileInfo{}
	for _, n := range names {
		fi, err := os.Stat(filepath.Join(outDir, n))
		if err != nil {
			t.Fatal(err)
		}
		before[n] = fi
	}
	ed, err := LoadRepository(LoadOptions{RootPath: rootPath, OutDir: outDir, TargetPathExists: "skip"})
	if err != nil {
		t.Fatal(err)
	}
	opts := signOpts(keyPath, outDir)
	opts.ReuseTargets = true
	if err := ed.SignAndWrite(opts); err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		fi, err := os.Stat(filepath.Join(outDir, n))
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(before[n], fi) || !fi.ModTime().Equal(before[n].ModTime()) {
			t.Errorf("%s was rewritten by a run that changed nothing", n)
		}
	}
}

// The second safeguard check, right before timestamp.json, catches a writer that
// slipped in after the first one.
func TestSignAndWrite_SecondSafeguardCheckBeforeTimestamp(t *testing.T) {
	rootPath, keyPath := setupTestRoot(t)
	outDir := setupSignedRepo(t, rootPath, keyPath)
	ed := loadForUpdate(t, rootPath, outDir)
	ed.BumpTargetsVersion()
	ed.BumpSnapshotVersion()
	ed.BumpTimestampVersion()

	intruder := []byte(`{"intruder":true}`)
	publishHook = func(path string) error {
		if filepath.Base(path) == "2.snapshot.json" { // after the first check, before timestamp.json
			return utils.WriteFileAtomic(filepath.Join(outDir, "timestamp.json"), intruder)
		}
		return nil
	}
	t.Cleanup(func() { publishHook = nil })

	err := ed.SignAndWrite(signOpts(keyPath, outDir))
	if !errors.Is(err, ErrLiveTimestampChanged) {
		t.Fatalf("expected ErrLiveTimestampChanged, got %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(outDir, "timestamp.json"))
	if !bytes.Equal(got, intruder) {
		t.Fatal("our timestamp.json must not overwrite the other writer's")
	}
}

// A published target named exactly like one of tufcli's own temp files
// (prefix plus digits) is referenced by the metadata and must survive.
func TestSweepNeverRemovesAReferencedTargetNamedLikeOurTempFiles(t *testing.T) {
	rootPath, keyPath := setupTestRoot(t)
	outDir := t.TempDir()
	ed := loadForUpdate(t, rootPath, outDir)
	name := "dir/" + utils.TempFilePrefix + "12345"
	src := filepath.Join(t.TempDir(), "x")
	_ = os.WriteFile(src, []byte("payload"), 0600)
	tf, _ := BuildTargetFiles(src, "sha256")
	ed.AddTarget(name, tf)
	if err := ed.CopyTargetToRepo(src, name); err != nil {
		t.Fatal(err)
	}
	if err := ed.SignAndWrite(signOpts(keyPath, outDir)); err != nil {
		t.Fatal(err)
	}
	hash, _ := utils.PreferredHash(tf.Hashes)
	published := filepath.Join(outDir, "targets", hash+".dir", utils.TempFilePrefix+"12345")
	old := time.Now().Add(-3 * time.Hour)
	if err := os.Chtimes(published, old, old); err != nil {
		t.Fatal(err)
	}

	ed2, err := LoadRepository(LoadOptions{RootPath: rootPath, OutDir: outDir, TargetPathExists: "skip"})
	if err != nil {
		t.Fatal(err)
	}
	ed2.BumpSnapshotVersion()
	ed2.BumpTimestampVersion()
	if err := ed2.SignAndWrite(signOpts(keyPath, outDir)); err != nil {
		t.Fatalf("next run: %v", err)
	}
	if !utils.FileExists(published) {
		t.Fatal("a referenced target was swept as a temp file")
	}
}

// Under "fail", a regenerated source whose hash-prefixed file is already
// published (same content by construction) is not a conflict.
func TestSignAndWrite_FailPolicyAcceptsUnchangedRegeneratedSource(t *testing.T) {
	rootPath, keyPath := setupTestRoot(t)
	outDir := t.TempDir()
	ed := loadForUpdate(t, rootPath, outDir)
	addStagedTarget(t, ed, outDir, "trusted_root.json", `{"same":true}`)
	if err := ed.SignAndWrite(signOpts(keyPath, outDir)); err != nil {
		t.Fatal(err)
	}

	ed2, err := LoadRepository(LoadOptions{RootPath: rootPath, OutDir: outDir, TargetPathExists: "fail"})
	if err != nil {
		t.Fatal(err)
	}
	future := time.Now().AddDate(0, 0, 11)
	ed2.SetTargetsExpires(future)
	ed2.BumpTargetsVersion()
	ed2.BumpSnapshotVersion()
	ed2.BumpTimestampVersion()
	addStagedTarget(t, ed2, outDir, "trusted_root.json", `{"same":true}`) // regenerated, unchanged
	if err := ed2.SignAndWrite(signOpts(keyPath, outDir)); err != nil {
		t.Fatalf("an unchanged regenerated source must not trip the fail policy: %v", err)
	}
	if utils.FileExists(filepath.Join(outDir, "targets", "trusted_root.json")) {
		t.Fatal("the staging copy should be removed")
	}
}

// A real non-consistent repository has no versioned file names; the refusal
// must come before any fetch tries to read them.
func TestLoadRepository_RefusesNonConsistentBeforeFetching(t *testing.T) {
	rootPath, _ := setupTestRoot(t)
	writeNonConsistentRoot(t, rootPath)
	flat := t.TempDir()
	for _, n := range []string{"timestamp.json", "snapshot.json", "targets.json"} {
		_ = os.WriteFile(filepath.Join(flat, n), []byte("{}"), 0600)
	}
	_, err := LoadRepository(LoadOptions{RootPath: rootPath, OutDir: t.TempDir(), MetadataURL: "file://" + flat})
	if !errors.Is(err, ErrNotConsistentSnapshot) {
		t.Fatalf("expected ErrNotConsistentSnapshot, got %v", err)
	}
}

// Publishing an older timestamp (e.g. "create" again over a live repository)
// would make every client reject the repository.
func TestSignAndWrite_RefusesTimestampRollback(t *testing.T) {
	rootPath, keyPath := setupTestRoot(t)
	outDir := setupSignedRepo(t, rootPath, keyPath)
	for i := 0; i < 2; i++ { // live timestamp at version 3
		ed := loadForUpdate(t, rootPath, outDir)
		ed.BumpSnapshotVersion()
		ed.BumpTimestampVersion()
		if err := ed.SignAndWrite(signOpts(keyPath, outDir)); err != nil {
			t.Fatal(err)
		}
	}
	before, _ := os.ReadFile(filepath.Join(outDir, "timestamp.json"))

	ed := loadForUpdate(t, rootPath, outDir)
	ed.SetTimestampVersion(1)
	err := ed.SignAndWrite(signOpts(keyPath, outDir))
	if !errors.Is(err, ErrRollback) {
		t.Fatalf("expected ErrRollback, got %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(outDir, "timestamp.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("timestamp.json must be untouched")
	}
}

func TestSignAndWrite_RefusesRootRollback(t *testing.T) {
	rootPath, keyPath := setupTestRoot(t)
	outDir := setupSignedRepo(t, rootPath, keyPath)
	// pretend the live root is already at version 2
	live := &tufmeta.Metadata[tufmeta.RootType]{}
	if _, err := live.FromFile(filepath.Join(outDir, "root.json")); err != nil {
		t.Fatal(err)
	}
	live.Signed.Version = 2
	data, _ := live.ToBytes(true)
	if err := utils.WriteFileAtomic(filepath.Join(outDir, "root.json"), data); err != nil {
		t.Fatal(err)
	}
	ed := loadForUpdate(t, rootPath, outDir) // -r root is version 1
	ed.BumpSnapshotVersion()
	ed.BumpTimestampVersion()
	if err := ed.SignAndWrite(signOpts(keyPath, outDir)); !errors.Is(err, ErrRollback) {
		t.Fatalf("expected ErrRollback, got %v", err)
	}
}

// With ReuseTargets the published targets file is the existing one, so only
// the files it references may be placed; regenerated files it does not
// reference must not be written into the repository.
func TestSignAndWrite_ReuseTargetsPlacesOnlyReferencedFiles(t *testing.T) {
	rootPath, keyPath := setupTestRoot(t)
	outDir := setupSignedRepo(t, rootPath, keyPath)
	ed, err := LoadRepository(LoadOptions{RootPath: rootPath, OutDir: outDir, TargetPathExists: "skip"})
	if err != nil {
		t.Fatal(err)
	}
	addStagedTarget(t, ed, outDir, "trusted_root.json", `{"regenerated":true}`)
	opts := signOpts(keyPath, outDir)
	opts.ReuseTargets = true
	if err := ed.SignAndWrite(opts); err != nil {
		t.Fatal(err)
	}
	matches, _ := filepath.Glob(filepath.Join(outDir, "targets", "*.trusted_root.json"))
	if len(matches) != 0 {
		t.Fatalf("an unreferenced file was published: %v", matches)
	}
}

// The overwrite warning is for files clients may hold, not for orphans.
func TestSignAndWrite_NoWarningWhenReplacingAnOrphan(t *testing.T) {
	rootPath, keyPath := setupTestRoot(t)
	outDir := setupSignedRepo(t, rootPath, keyPath)
	// an orphan 2.snapshot.json left by a failed run
	if err := os.WriteFile(filepath.Join(outDir, "2.snapshot.json"), []byte(`{"orphan":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	ed, err := LoadRepository(LoadOptions{RootPath: rootPath, OutDir: outDir, TargetPathExists: "skip", Output: &out})
	if err != nil {
		t.Fatal(err)
	}
	ed.BumpSnapshotVersion()
	ed.BumpTimestampVersion()
	if err := ed.SignAndWrite(signOpts(keyPath, outDir)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "replaced in place") {
		t.Fatalf("no warning expected for an orphan: %s", out.String())
	}
}

func TestCommitStagedMetadata_OrdersTimestampLastAndKeepsLiveFilesInPlace(t *testing.T) {
	staging, out := t.TempDir(), t.TempDir()
	// enough files that directory order putting root.json and timestamp.json
	// last by accident is practically impossible
	// (written in the middle, so neither creation order, its reverse nor
	// alphabetical order ends with them)
	var names []string
	for i := 0; i < 40; i++ {
		names = append(names, fmt.Sprintf("%d.extra.json", i), fmt.Sprintf("x%d.json", i))
		if i == 20 {
			names = append(names, "timestamp.json", "root.json")
		}
	}
	for _, n := range names {
		_ = os.WriteFile(filepath.Join(staging, n), []byte("new-"+n), 0600)
		_ = os.WriteFile(filepath.Join(out, n), []byte("old-"+n), 0600)
	}
	// a stale backup left by an earlier crash must not block the commit
	_ = os.WriteFile(filepath.Join(out, "timestamp.json.backup"), []byte("stale"), 0600)

	var order []string
	commitHook = func(rel string) {
		order = append(order, rel)
		// every live file must still be there at every step: none is ever
		// moved out of the way (a missing timestamp.json is a client error)
		for _, n := range names {
			if !utils.FileExists(filepath.Join(out, n)) {
				t.Errorf("%s missing while committing %s", n, rel)
			}
		}
	}
	t.Cleanup(func() { commitHook = nil })

	if err := commitStagedMetadata(staging, out); err != nil {
		t.Fatal(err)
	}
	if n := len(order); n != len(names) || order[n-1] != "timestamp.json" || order[n-2] != "root.json" {
		t.Fatalf("commit order must end with root.json, timestamp.json: %v", order)
	}
	for _, n := range names {
		got, _ := os.ReadFile(filepath.Join(out, n))
		if string(got) != "new-"+n {
			t.Fatalf("%s = %q", n, got)
		}
	}
	if m, _ := filepath.Glob(filepath.Join(out, "*.backup")); len(m) != 0 {
		t.Fatalf("backups left: %v", m)
	}
}

func TestSignAndWrite_RefusesSnapshotRollback(t *testing.T) {
	rootPath, keyPath := setupTestRoot(t)
	outDir := setupSignedRepo(t, rootPath, keyPath)
	ed := loadForUpdate(t, rootPath, outDir)
	ed.BumpSnapshotVersion()
	ed.BumpTimestampVersion()
	if err := ed.SignAndWrite(signOpts(keyPath, outDir)); err != nil { // live snapshot 2
		t.Fatal(err)
	}
	ed2 := loadForUpdate(t, rootPath, outDir)
	ed2.SetSnapshotVersion(1)
	ed2.BumpTimestampVersion()
	if err := ed2.SignAndWrite(signOpts(keyPath, outDir)); !errors.Is(err, ErrRollback) {
		t.Fatalf("expected ErrRollback, got %v", err)
	}
}

// A damaged hash-prefixed file (wrong size) is re-copied from a staged source
// instead of being kept because of its name.
func TestSignAndWrite_RecopiesDamagedTargetFile(t *testing.T) {
	rootPath, keyPath := setupTestRoot(t)
	outDir := t.TempDir()
	ed := loadForUpdate(t, rootPath, outDir)
	addStagedTarget(t, ed, outDir, "a.txt", "complete content")
	hash, _ := utils.PreferredHash(ed.Targets().Signed.Targets["a.txt"].Hashes)
	published := filepath.Join(outDir, "targets", hash+".a.txt")
	if err := os.WriteFile(published, []byte("trunc"), 0600); err != nil { // left by a crash
		t.Fatal(err)
	}
	if err := ed.SignAndWrite(signOpts(keyPath, outDir)); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(published)
	if string(got) != "complete content" {
		t.Fatalf("damaged file kept: %q", got)
	}
}
