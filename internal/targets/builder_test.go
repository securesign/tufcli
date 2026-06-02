package targets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildTargets_SingleFile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("hello"), 0600)

	targets, err := BuildTargets(dir, false)
	if err != nil {
		t.Fatalf("BuildTargets failed: %v", err)
	}

	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}

	target, ok := targets["test.txt"]
	if !ok {
		t.Fatal("target 'test.txt' not found")
	}
	if target.Name != "test.txt" {
		t.Fatalf("expected name 'test.txt', got %q", target.Name)
	}
	if target.Length != 5 {
		t.Fatalf("expected length 5, got %d", target.Length)
	}
	if target.Hashes["sha256"] == "" {
		t.Fatal("expected sha256 hash")
	}
}

func TestBuildTargets_MultipleFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("aaa"), 0600)
	os.WriteFile(filepath.Join(dir, "b.txt"), []byte("bbb"), 0600)

	targets, err := BuildTargets(dir, false)
	if err != nil {
		t.Fatalf("BuildTargets failed: %v", err)
	}

	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}
}

func TestBuildTargets_NestedDirectories(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "sub", "deep"), 0755)
	os.WriteFile(filepath.Join(dir, "top.txt"), []byte("top"), 0600)
	os.WriteFile(filepath.Join(dir, "sub", "mid.txt"), []byte("mid"), 0600)
	os.WriteFile(filepath.Join(dir, "sub", "deep", "bot.txt"), []byte("bot"), 0600)

	targets, err := BuildTargets(dir, false)
	if err != nil {
		t.Fatalf("BuildTargets failed: %v", err)
	}

	if len(targets) != 3 {
		t.Fatalf("expected 3 targets, got %d", len(targets))
	}

	if _, ok := targets[filepath.Join("sub", "deep", "bot.txt")]; !ok {
		t.Fatal("nested target not found")
	}
}

func TestBuildTargets_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()

	targets, err := BuildTargets(dir, false)
	if err != nil {
		t.Fatalf("BuildTargets failed: %v", err)
	}

	if len(targets) != 0 {
		t.Fatalf("expected 0 targets, got %d", len(targets))
	}
}

func TestBuildTargets_NonexistentDir(t *testing.T) {
	_, err := BuildTargets("/nonexistent/dir", false)
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
}

func TestBuildTargets_FollowLinks(t *testing.T) {
	dir := t.TempDir()
	realFile := filepath.Join(dir, "real.txt")
	os.WriteFile(realFile, []byte("content"), 0600)

	subDir := filepath.Join(dir, "targets")
	os.MkdirAll(subDir, 0755)
	os.WriteFile(filepath.Join(subDir, "direct.txt"), []byte("direct"), 0600)

	targets, err := BuildTargets(subDir, true)
	if err != nil {
		t.Fatalf("BuildTargets with followLinks failed: %v", err)
	}

	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}
}

func TestBuildTargets_HashConsistency(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("deterministic"), 0600)

	targets1, _ := BuildTargets(dir, false)
	targets2, _ := BuildTargets(dir, false)

	if targets1["test.txt"].Hashes["sha256"] != targets2["test.txt"].Hashes["sha256"] {
		t.Fatal("hashes not deterministic across runs")
	}
}

func TestBuildTargets_CustomFieldInitialized(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("data"), 0600)

	targets, _ := BuildTargets(dir, false)
	target := targets["test.txt"]

	if target.Custom == nil {
		t.Fatal("Custom map should be initialized")
	}
}
