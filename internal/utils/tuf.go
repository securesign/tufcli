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
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"

	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"
)

// ComputeMetaFileInfo computes the hash, length, and version for a metadata file.
// hashAlgo must be "sha256" or "sha512".
// Used to populate snapshot.Meta["targets.json"] and timestamp.Meta["snapshot.json"].
func ComputeMetaFileInfo(path string, version int64, hashAlgo string) (*tufmeta.MetaFiles, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	var hashes tufmeta.Hashes
	switch hashAlgo {
	case "sha512":
		h := sha512.Sum512(data)
		hashes = tufmeta.Hashes{"sha512": h[:]}
	default:
		h := sha256.Sum256(data)
		hashes = tufmeta.Hashes{"sha256": h[:]}
	}

	return &tufmeta.MetaFiles{
		Version: version,
		Length:  int64(len(data)),
		Hashes:  hashes,
	}, nil
}

// PreferredHash returns the hex-encoded hash from a Hashes map, preferring
// SHA-256 and falling back to SHA-512. Used for consistent_snapshot filenames.
func PreferredHash(hashes tufmeta.Hashes) (string, error) {
	if h, ok := hashes["sha256"]; ok {
		return hex.EncodeToString(h), nil
	}
	if h, ok := hashes["sha512"]; ok {
		return hex.EncodeToString(h), nil
	}
	return "", fmt.Errorf("no supported hash found (need sha256 or sha512)")
}
