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

	targets, err := Scan(root, true, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, target := range targets {
		seen[target.Name] = true
	}
	if len(targets) != 2 || !seen["root.txt"] || !seen[filepath.Join("link", "nested.txt")] {
		t.Fatalf("unexpected targets: %v", seen)
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

	targets, err := Scan(root, true, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].Name != filepath.Join("dir", "file.txt") {
		t.Fatalf("unexpected targets after cycle detection: %+v", targets)
	}
}
