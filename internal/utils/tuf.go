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
	"crypto/sha256"
	"fmt"
	"os"

	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"
)

// ComputeMetaFileInfo computes the SHA256 hash, length, and version for a metadata file.
// Used to populate snapshot.Meta["targets.json"] and timestamp.Meta["snapshot.json"].
func ComputeMetaFileInfo(path string, version int64) (*tufmeta.MetaFiles, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	h := sha256.Sum256(data)
	return &tufmeta.MetaFiles{
		Version: version,
		Length:  int64(len(data)),
		Hashes:  tufmeta.Hashes{"sha256": h[:]},
	}, nil
}
