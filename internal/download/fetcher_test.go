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

package download

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

type mockFetcher struct {
	called  bool
	urlPath string
}

func (m *mockFetcher) DownloadFile(urlPath string, maxLength int64, timeout time.Duration) ([]byte, error) {
	m.called = true
	m.urlPath = urlPath
	return []byte("mock response"), nil
}

func TestLocalFetcher_FileURL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")
	content := []byte(`{"version": 1}`)
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}

	f := &localFetcher{httpFetcher: &mockFetcher{}}
	data, err := f.DownloadFile("file://"+path, 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != string(content) {
		t.Fatalf("got %q, want %q", data, content)
	}
}

func TestLocalFetcher_FileNotFound(t *testing.T) {
	f := &localFetcher{httpFetcher: &mockFetcher{}}
	_, err := f.DownloadFile("file:///nonexistent/path.json", 0, 0)
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestLocalFetcher_FileExceedsMaxLength(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.json")
	if err := os.WriteFile(path, make([]byte, 100), 0600); err != nil {
		t.Fatal(err)
	}

	f := &localFetcher{httpFetcher: &mockFetcher{}}
	_, err := f.DownloadFile("file://"+path, 50, 0)
	if err == nil {
		t.Fatal("expected error for file exceeding max length")
	}
}

func TestLocalFetcher_HTTPDelegation(t *testing.T) {
	mock := &mockFetcher{}
	f := &localFetcher{httpFetcher: mock}

	httpURL := "https://example.com/metadata/1.root.json"
	data, err := f.DownloadFile(httpURL, 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mock.called {
		t.Fatal("expected HTTP fetcher to be called")
	}
	if mock.urlPath != httpURL {
		t.Fatalf("HTTP fetcher got URL %q, want %q", mock.urlPath, httpURL)
	}
	if string(data) != "mock response" {
		t.Fatalf("got %q, want %q", data, "mock response")
	}
}
