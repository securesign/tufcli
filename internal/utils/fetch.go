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
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const maxHTTPResponseBytes = 100 * 1024 * 1024 // 100 MB

// FetchFile fetches the contents of a file from a URL (file://, http://, https://).
// HTTP responses are limited to 100 MB to prevent OOM from malicious servers.
func FetchFile(rawURL string) ([]byte, error) {
	if strings.HasPrefix(rawURL, "file://") {
		path := strings.TrimPrefix(rawURL, "file://")
		return os.ReadFile(path)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %s: %w", rawURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch %s: HTTP %d", rawURL, resp.StatusCode)
	}

	limited := io.LimitReader(resp.Body, maxHTTPResponseBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("failed to read response from %s: %w", rawURL, err)
	}
	if int64(len(data)) > maxHTTPResponseBytes {
		return nil, fmt.Errorf("response from %s exceeds maximum size of %d bytes", rawURL, maxHTTPResponseBytes)
	}

	return data, nil
}
