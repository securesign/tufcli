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
	"net/url"
	"path/filepath"
	"strings"

	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"

	"github.com/securesign/tufcli/internal/utils"
)

// ResolveTargets resolves target names to TargetFiles using the TUF updater.
// If names is empty, all top-level targets are returned.
func ResolveTargets(up *updater.Updater, names []string) (map[string]*metadata.TargetFiles, error) {
	if len(names) == 0 {
		targets := up.GetTopLevelTargets()
		if len(targets) == 0 {
			return nil, fmt.Errorf("no targets found in repository")
		}
		return targets, nil
	}

	targets := make(map[string]*metadata.TargetFiles, len(names))
	for _, name := range names {
		tf, err := up.GetTargetInfo(name)
		if err != nil {
			return nil, fmt.Errorf("target %q not found: %w", name, err)
		}
		targets[name] = tf
	}
	return targets, nil
}

// ValidateTargetPath validates that a target path is within the output directory.
func ValidateTargetPath(outDir, targetPath string) error {
	absOut, err := filepath.Abs(outDir)
	if err != nil {
		return fmt.Errorf("failed to resolve output directory: %w", err)
	}
	absTarget, err := filepath.Abs(targetPath)
	if err != nil {
		return fmt.Errorf("failed to resolve target path: %w", err)
	}
	rel, err := filepath.Rel(absOut, absTarget)
	if err != nil {
		return fmt.Errorf("failed to compute relative path: %w", err)
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("target path %q escapes output directory %q", targetPath, outDir)
	}
	return nil
}

// DownloadTarget fetches a target using tufcli's consistent-snapshot layout.
// The hash prefixes the complete target path, so nested targets are stored as
// <hash>.subdir/name rather than subdir/<hash>.name.
func DownloadTarget(f fetcher.Fetcher, targetsURL string, target *metadata.TargetFiles) ([]byte, error) {
	hash, err := utils.PreferredHash(target.Hashes)
	if err != nil {
		return nil, err
	}

	u, err := url.Parse(strings.TrimRight(targetsURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse targets URL %q: %w", targetsURL, err)
	}
	// URL.Path is decoded; URL.String performs one escape pass while retaining
	// the slashes between target path segments.
	u.Path = strings.TrimRight(u.Path, "/") + "/" + hash + "." + target.Path
	u.RawPath = ""

	data, err := f.DownloadFile(u.String(), target.Length, 0)
	if err != nil {
		return nil, err
	}
	if err := target.VerifyLengthHashes(data); err != nil {
		return nil, err
	}
	return data, nil
}
