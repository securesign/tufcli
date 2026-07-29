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

package utils

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFetchFile_FileURL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	os.WriteFile(path, []byte("hello"), 0644)

	data, err := FetchFile("file://" + path)
	if err != nil {
		t.Fatalf("FetchFile file:// failed: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("expected 'hello', got %q", string(data))
	}
}

func TestFetchFile_FileURL_NotFound(t *testing.T) {
	_, err := FetchFile("file:///nonexistent/path.txt")
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}

func TestFetchFile_HTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("http-content"))
	}))
	defer server.Close()

	data, err := FetchFile(server.URL + "/test")
	if err != nil {
		t.Fatalf("FetchFile http failed: %v", err)
	}
	if string(data) != "http-content" {
		t.Fatalf("expected 'http-content', got %q", string(data))
	}
}

func TestFetchFile_HTTP_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	_, err := FetchFile(server.URL + "/missing")
	if err == nil {
		t.Fatal("expected error for HTTP 404")
	}
	if !strings.Contains(err.Error(), "HTTP 404") {
		t.Fatalf("expected HTTP 404 error, got: %v", err)
	}
}

func TestFetchFile_InvalidURL(t *testing.T) {
	_, err := FetchFile("http://[invalid-host]:99999/path")
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}
