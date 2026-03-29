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

package targets

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/securesign/tufcli/internal/common"
	"github.com/securesign/tufcli/internal/utils"
)

// BuildTargets walks a directory and builds a map of targets
func BuildTargets(inputDir string, followLinks bool) (map[string]*common.Target, error) {
	targets := make(map[string]*common.Target)

	err := filepath.Walk(inputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Skip symlinks unless followLinks is true
		if info.Mode()&os.ModeSymlink != 0 && !followLinks {
			return nil
		}

		// Compute hash
		hash, err := utils.HashFile(path)
		if err != nil {
			return fmt.Errorf("failed to hash file %s: %w", path, err)
		}

		// Get relative path
		relPath, err := filepath.Rel(inputDir, path)
		if err != nil {
			return fmt.Errorf("failed to get relative path: %w", err)
		}

		// Create target
		target := &common.Target{
			Name:   relPath,
			Length: info.Size(),
			Hashes: map[string]string{
				"sha256": hash,
			},
			Custom: make(map[string]interface{}),
		}

		targets[relPath] = target
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory: %w", err)
	}

	return targets, nil
}
