package targetscan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanSymlinkDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "root.txt"), []byte("root"), 0600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(t.TempDir(), "linked")
	if err := os.Mkdir(linked, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(linked, "nested.txt"), []byte("nested"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(linked, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}

	targets, cleanup, err := Scan(root, true, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	seen := map[string]bool{}
	for _, target := range targets {
		seen[target.Name] = true
	}
	if len(targets) != 2 || !seen["root.txt"] || !seen[filepath.Join("link", "nested.txt")] {
		t.Fatalf("unexpected targets: %v", seen)
	}
}

func TestScanSymlinkAliasKeepsBothLogicalPaths(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "z")
	if err := os.Mkdir(realDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realDir, "file.txt"), []byte("file"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDir, filepath.Join(root, "a")); err != nil {
		t.Fatal(err)
	}

	targets, cleanup, err := Scan(root, true, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	seen := map[string]bool{}
	for _, target := range targets {
		seen[target.Name] = true
	}
	for _, name := range []string{filepath.Join("a", "file.txt"), filepath.Join("z", "file.txt")} {
		if !seen[name] {
			t.Fatalf("expected aliased target %q, got %v", name, seen)
		}
	}
}

func TestScanSymlinkedRootRespectsFollow(t *testing.T) {
	realRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(realRoot, "target.txt"), []byte("target"), 0600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(realRoot, root); err != nil {
		t.Fatal(err)
	}

	withoutFollow, cleanup, err := Scan(root, false, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	if len(withoutFollow) != 0 {
		t.Fatalf("expected symlinked root to be skipped without follow, got %d targets", len(withoutFollow))
	}

	withFollow, cleanup, err := Scan(root, true, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if len(withFollow) != 1 || withFollow[0].Name != "target.txt" {
		t.Fatalf("expected target through symlinked root, got %+v", withFollow)
	}
}

func TestScanSymlinkDirectoryCycle(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "dir"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "dir", "file.txt"), []byte("file"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(root, filepath.Join(root, "dir", "cycle")); err != nil {
		t.Fatal(err)
	}

	targets, cleanup, err := Scan(root, true, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if len(targets) != 1 || targets[0].Name != filepath.Join("dir", "file.txt") {
		t.Fatalf("unexpected targets after cycle detection: %+v", targets)
	}
}

func TestScanPublishesStagedBytesAfterSourceMutation(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "target.txt")
	if err := os.WriteFile(source, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}

	targets, cleanup, err := Scan(root, false, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if err := os.WriteFile(source, []byte("mutated after scan"), 0600); err != nil {
		t.Fatal(err)
	}

	staged, err := os.ReadFile(targets[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	if string(staged) != "original" {
		t.Fatalf("staged bytes changed after source mutation: %q", staged)
	}
	if targets[0].Meta.Length != int64(len(staged)) {
		t.Fatalf("metadata length=%d, staged length=%d", targets[0].Meta.Length, len(staged))
	}
	cleanup()
	if _, err := os.Stat(targets[0].Path); !os.IsNotExist(err) {
		t.Fatalf("staging path still exists after cleanup: %v", err)
	}
}
