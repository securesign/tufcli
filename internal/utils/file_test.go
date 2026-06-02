package utils

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")

	data := []byte("hello world")
	if err := WriteFileAtomic(path, data); err != nil {
		t.Fatalf("WriteFileAtomic failed: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	if string(got) != string(data) {
		t.Fatalf("expected %q, got %q", data, got)
	}
}

func TestWriteFileAtomic_CreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "dir", "test.txt")

	if err := WriteFileAtomic(path, []byte("data")); err != nil {
		t.Fatalf("WriteFileAtomic failed: %v", err)
	}

	if !FileExists(path) {
		t.Fatal("file was not created")
	}
}

func TestWriteFileAtomic_OverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")

	WriteFileAtomic(path, []byte("old"))
	WriteFileAtomic(path, []byte("new"))

	got, _ := os.ReadFile(path)
	if string(got) != "new" {
		t.Fatalf("expected 'new', got %q", got)
	}
}

func TestWriteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")

	if err := WriteFile(path, []byte("content")); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	got, _ := os.ReadFile(path)
	if string(got) != "content" {
		t.Fatalf("expected 'content', got %q", got)
	}

	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions, got %o", info.Mode().Perm())
	}
}

func TestWriteFile_CreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "file.txt")

	if err := WriteFile(path, []byte("data")); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	if !FileExists(path) {
		t.Fatal("file was not created")
	}
}

func TestHashFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	os.WriteFile(path, []byte("hello"), 0600)

	hash, err := HashFile(path)
	if err != nil {
		t.Fatalf("HashFile failed: %v", err)
	}

	// SHA-256 of "hello"
	expected := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if hash != expected {
		t.Fatalf("expected %s, got %s", expected, hash)
	}
}

func TestHashFile_NotFound(t *testing.T) {
	_, err := HashFile("/nonexistent/path")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestFileExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exists.txt")
	os.WriteFile(path, []byte(""), 0600)

	if !FileExists(path) {
		t.Fatal("expected file to exist")
	}

	if FileExists(filepath.Join(dir, "nope.txt")) {
		t.Fatal("expected file to not exist")
	}
}

func TestReadJSONFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.json")
	os.WriteFile(path, []byte(`{"name":"test","value":42}`), 0600)

	var result struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}
	if err := ReadJSONFile(path, &result); err != nil {
		t.Fatalf("ReadJSONFile failed: %v", err)
	}
	if result.Name != "test" || result.Value != 42 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestReadJSONFile_NotFound(t *testing.T) {
	var v interface{}
	if err := ReadJSONFile("/nonexistent.json", &v); err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestReadJSONFile_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	os.WriteFile(path, []byte("not json"), 0600)

	var v interface{}
	if err := ReadJSONFile(path, &v); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestWriteJSONFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")

	data := map[string]string{"key": "value"}
	if err := WriteJSONFile(path, data); err != nil {
		t.Fatalf("WriteJSONFile failed: %v", err)
	}

	var result map[string]string
	if err := ReadJSONFile(path, &result); err != nil {
		t.Fatalf("failed to read back: %v", err)
	}
	if result["key"] != "value" {
		t.Fatalf("expected key=value, got %v", result)
	}
}

func TestWriteFileAtomic_InvalidParent(t *testing.T) {
	err := WriteFileAtomic("/dev/null/impossible/file.txt", []byte("data"))
	if err == nil {
		t.Fatal("expected error when parent cannot be created")
	}
}

func TestWriteFile_InvalidParent(t *testing.T) {
	err := WriteFile("/dev/null/impossible/file.txt", []byte("data"))
	if err == nil {
		t.Fatal("expected error when parent cannot be created")
	}
}

func TestWriteJSONFile_MarshalError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")

	err := WriteJSONFile(path, func() {})
	if err == nil {
		t.Fatal("expected error for unmarshalable value")
	}
}

func TestWriteJSONFile_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rt.json")

	type sample struct {
		A int    `json:"a"`
		B string `json:"b"`
	}

	original := sample{A: 1, B: "hello"}
	WriteJSONFile(path, original)

	var loaded sample
	ReadJSONFile(path, &loaded)

	if loaded.A != 1 || loaded.B != "hello" {
		t.Fatalf("roundtrip failed: %+v", loaded)
	}
}
