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

package tufclient

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestObtainRoot_LocalFile(t *testing.T) {
	dir := t.TempDir()
	rootPath := filepath.Join(dir, "root.json")
	content := []byte(`{"signed":{"version":1},"signatures":[]}`)
	if err := os.WriteFile(rootPath, content, 0600); err != nil {
		t.Fatal(err)
	}

	data, err := ObtainRoot(rootPath, false, "", 1, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != string(content) {
		t.Fatalf("got %q, want %q", data, content)
	}
}

func TestObtainRoot_LocalFileNotFound(t *testing.T) {
	_, err := ObtainRoot("/nonexistent/root.json", false, "", 1, nil)
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestObtainRoot_AllowDownload(t *testing.T) {
	rootContent := []byte(`{"signed":{"version":1},"signatures":[]}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/1.root.json" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(rootContent)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	data, err := ObtainRoot("", true, srv.URL, 1, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != string(rootContent) {
		t.Fatalf("got %q, want %q", data, rootContent)
	}
}

func TestObtainRoot_NoRootNoDownload(t *testing.T) {
	_, err := ObtainRoot("", false, "http://example.com", 1, nil)
	if err == nil {
		t.Fatal("expected error when no root path and download not allowed")
	}
}

func TestObtainRoot_LocalFileTakesPrecedence(t *testing.T) {
	// When rootPath is provided, it should be used even if allowDownload is true
	dir := t.TempDir()
	rootPath := filepath.Join(dir, "root.json")
	content := []byte(`{"local":true}`)
	if err := os.WriteFile(rootPath, content, 0600); err != nil {
		t.Fatal(err)
	}

	data, err := ObtainRoot(rootPath, true, "http://should-not-be-called.invalid", 1, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != string(content) {
		t.Fatalf("got %q, want %q", data, content)
	}
}

func TestDownloadRoot(t *testing.T) {
	rootContent := []byte(`{"signed":{"version":1},"signatures":[]}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/1.root.json" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(rootContent)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	data, err := DownloadRoot(srv.URL, 1, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != string(rootContent) {
		t.Fatalf("got %q, want %q", data, rootContent)
	}
}

func TestDownloadRoot_InvalidVersion(t *testing.T) {
	_, err := DownloadRoot("http://example.com", 0, nil)
	if err == nil {
		t.Fatal("expected error for version 0")
	}
	_, err = DownloadRoot("http://example.com", -1, nil)
	if err == nil {
		t.Fatal("expected error for negative version")
	}
}

func TestDownloadRoot_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := DownloadRoot(srv.URL, 1, nil)
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
}

func TestDownloadRoot_TrailingSlash(t *testing.T) {
	rootContent := []byte(`{"signed":{"version":2},"signatures":[]}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/2.root.json" {
			w.Write(rootContent)
			return
		}
		t.Errorf("unexpected path: %s", r.URL.Path)
		http.NotFound(w, r)
	}))
	defer srv.Close()

	// URL with trailing slash should still work
	data, err := DownloadRoot(srv.URL+"/", 2, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != string(rootContent) {
		t.Fatalf("got %q, want %q", data, rootContent)
	}
}

func TestDownloadRoot_TooLargeContentLength(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", 11<<20))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, err := DownloadRoot(srv.URL, 1, nil)
	if err == nil {
		t.Fatal("expected error for oversized Content-Length")
	}
}

func TestDownloadRoot_TooLargeBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		buf := make([]byte, (10<<20)+100)
		w.Write(buf)
	}))
	defer srv.Close()

	_, err := DownloadRoot(srv.URL, 1, nil)
	if err == nil {
		t.Fatal("expected error for body exceeding max bytes")
	}
}

func TestDownloadRoot_ConnectionError(t *testing.T) {
	_, err := DownloadRoot("http://127.0.0.1:1", 1, nil)
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
}

func TestDownloadRoot_OutputWriter(t *testing.T) {
	rootContent := []byte(`{"signed":{"version":1},"signatures":[]}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(rootContent)
	}))
	defer srv.Close()

	var buf bytes.Buffer
	_, err := DownloadRoot(srv.URL, 1, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "WARNING") {
		t.Fatalf("expected WARNING in output, got: %q", buf.String())
	}
}

func TestDownloadRoot_OutputDiscard(t *testing.T) {
	rootContent := []byte(`{"signed":{"version":1},"signatures":[]}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(rootContent)
	}))
	defer srv.Close()

	data, err := DownloadRoot(srv.URL, 1, io.Discard)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != string(rootContent) {
		t.Fatalf("data mismatch")
	}
}

func TestObtainRoot_OutputPassthrough(t *testing.T) {
	rootContent := []byte(`{"signed":{"version":1},"signatures":[]}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(rootContent)
	}))
	defer srv.Close()

	var buf bytes.Buffer
	_, err := ObtainRoot("", true, srv.URL, 1, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "WARNING") {
		t.Fatalf("expected WARNING passed through to output, got: %q", buf.String())
	}
}
