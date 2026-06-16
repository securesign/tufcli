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
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
)

// localFetcher wraps go-tuf's Fetcher to add file:// URL support.
// go-tuf's DefaultFetcher only handles http/https; this matches Rust
// tuftool's DefaultTransport which dispatches file:// to FilesystemTransport.
type localFetcher struct {
	httpFetcher fetcher.Fetcher
}

func (f *localFetcher) DownloadFile(urlPath string, maxLength int64, timeout time.Duration) ([]byte, error) {
	u, err := url.Parse(urlPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL %q: %w", urlPath, err)
	}

	if u.Scheme != "file" {
		return f.httpFetcher.DownloadFile(urlPath, maxLength, timeout)
	}

	data, err := os.ReadFile(u.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, &metadata.ErrDownloadHTTP{StatusCode: http.StatusNotFound, URL: urlPath}
		}
		return nil, fmt.Errorf("failed to read %s: %w", u.Path, err)
	}

	if maxLength > 0 && int64(len(data)) > maxLength {
		return nil, fmt.Errorf("file %s is %d bytes, exceeds maximum %d", u.Path, len(data), maxLength)
	}

	return data, nil
}
