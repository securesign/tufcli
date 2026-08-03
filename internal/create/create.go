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

package create

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/securesign/tufcli/internal/editor"
	"github.com/securesign/tufcli/internal/utils"
)

// Options contains all configuration for a create operation.
type Options struct {
	RootPath      string
	KeyPaths      []string
	VaultKeyRefs  []string
	OutDir        string
	AddTargetsDir string

	TargetsExpires   time.Time
	TargetsVersion   int64
	SnapshotExpires  time.Time
	SnapshotVersion  int64
	TimestampExpires time.Time
	TimestampVersion int64

	Follow           bool
	TargetPathExists string
	HashAlgo         string
}

// ValidateAndSetDefaults validates options and applies defaults.
func (opts *Options) ValidateAndSetDefaults() error {
	if !utils.FileExists(opts.RootPath) {
		return fmt.Errorf("root.json not found at %s", opts.RootPath)
	}

	fi, err := os.Stat(opts.AddTargetsDir)
	if err != nil {
		return fmt.Errorf("add-targets directory not found: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("add-targets path %s is not a directory", opts.AddTargetsDir)
	}

	if opts.TargetsVersion <= 0 {
		return fmt.Errorf("targets-version must be > 0")
	}
	if opts.SnapshotVersion <= 0 {
		return fmt.Errorf("snapshot-version must be > 0")
	}
	if opts.TimestampVersion <= 0 {
		return fmt.Errorf("timestamp-version must be > 0")
	}

	if opts.TargetsExpires.IsZero() {
		return fmt.Errorf("targets-expires is required")
	}
	if opts.SnapshotExpires.IsZero() {
		return fmt.Errorf("snapshot-expires is required")
	}
	if opts.TimestampExpires.IsZero() {
		return fmt.Errorf("timestamp-expires is required")
	}

	validated, err := utils.ValidateTargetPathExists(opts.TargetPathExists)
	if err != nil {
		return err
	}
	opts.TargetPathExists = validated

	if opts.HashAlgo == "" {
		opts.HashAlgo = "sha256"
	}

	return nil
}

// Run executes the create command.
func Run(opts *Options) error {
	if err := opts.ValidateAndSetDefaults(); err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Join(opts.OutDir, "targets"), 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	ed, err := editor.LoadRepository(editor.LoadOptions{
		RootPath:         opts.RootPath,
		OutDir:           opts.OutDir,
		Follow:           opts.Follow,
		TargetPathExists: opts.TargetPathExists,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize repository: %w", err)
	}

	ed.SetTargetsVersion(opts.TargetsVersion)
	ed.SetTargetsExpires(opts.TargetsExpires)
	ed.SetSnapshotVersion(opts.SnapshotVersion)
	ed.SetSnapshotExpires(opts.SnapshotExpires)
	ed.SetTimestampVersion(opts.TimestampVersion)
	ed.SetTimestampExpires(opts.TimestampExpires)

	err = filepath.WalkDir(opts.AddTargetsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		if d.Type()&fs.ModeSymlink != 0 {
			if !opts.Follow {
				return nil
			}
			fi, err := os.Stat(path)
			if err != nil {
				return fmt.Errorf("failed to resolve symlink %s: %w", path, err)
			}
			if fi.IsDir() {
				return nil
			}
		}

		relPath, err := filepath.Rel(opts.AddTargetsDir, path)
		if err != nil {
			return fmt.Errorf("failed to compute relative path for %s: %w", path, err)
		}

		tf, err := tufmeta.TargetFile().FromFile(path, opts.HashAlgo)
		if err != nil {
			return fmt.Errorf("failed to hash target %s: %w", relPath, err)
		}

		ed.AddTarget(relPath, tf)

		if err := ed.CopyTargetToRepo(path, relPath); err != nil {
			return fmt.Errorf("failed to copy target %s: %w", relPath, err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to add targets: %w", err)
	}

	if err := ed.SignAndWrite(editor.SignAndWriteOptions{
		KeyPaths:     opts.KeyPaths,
		VaultKeyRefs: opts.VaultKeyRefs,
		OutDir:       opts.OutDir,
		HashAlgo:     opts.HashAlgo,
	}); err != nil {
		return fmt.Errorf("failed to sign and write repository: %w", err)
	}

	return nil
}
