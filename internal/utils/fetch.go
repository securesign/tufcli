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

// FetchFile fetches the contents of a file from a URL (file://, http://, https://).
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

	return io.ReadAll(resp.Body)
}
