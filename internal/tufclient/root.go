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
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"
)

// ObtainRoot reads root.json from a local file, or downloads it if
// allowDownload is set. Returns an error if neither source is available.
// output receives diagnostic messages; if nil, os.Stderr is used.
func ObtainRoot(rootPath string, allowDownload bool, metadataURL string, version int64, output io.Writer) ([]byte, error) {
	if rootPath != "" {
		data, err := os.ReadFile(rootPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read root.json from %s: %w", rootPath, err)
		}
		return data, nil
	}

	if allowDownload {
		return DownloadRoot(metadataURL, version, output)
	}

	return nil, fmt.Errorf("no root.json available; provide --root or use --allow-root-download")
}

// DownloadRoot downloads root.json from a TUF repository URL.
// output receives diagnostic messages; if nil, os.Stderr is used.
func DownloadRoot(metadataURL string, version int64, output io.Writer) ([]byte, error) {
	if output == nil || (reflect.ValueOf(output).Kind() == reflect.Pointer && reflect.ValueOf(output).IsNil()) {
		output = os.Stderr
	}
	if version < 1 {
		return nil, fmt.Errorf("invalid root version %d (must be >= 1)", version)
	}
	metadataURL = strings.TrimRight(metadataURL, "/")
	rootURL := fmt.Sprintf("%s/%d.root.json", metadataURL, version)

	fmt.Fprintf(output, "=================================================================\n")
	fmt.Fprintf(output, "WARNING: Downloading root.json from %s\n", rootURL)
	fmt.Fprintf(output, "This is unsafe and will not establish trust, use only for testing\n")
	fmt.Fprintf(output, "=================================================================\n")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(rootURL) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("failed to download root.json: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download root.json: HTTP %d", resp.StatusCode)
	}

	const maxRootBytes = 10 << 20
	if resp.ContentLength > maxRootBytes {
		return nil, fmt.Errorf("root.json response too large: %d bytes", resp.ContentLength)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxRootBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read root.json response: %w", err)
	}
	if len(data) > maxRootBytes {
		return nil, fmt.Errorf("root.json response too large: exceeded %d bytes", maxRootBytes)
	}

	return data, nil
}
