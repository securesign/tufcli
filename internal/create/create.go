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

	"github.com/securesign/tufcli/internal/rhtas"
	"github.com/securesign/tufcli/internal/utils"
)

// Options contains all configuration for a create operation.
type Options struct {
	RootPath      string
	KeyPaths      []string
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

	if opts.TargetPathExists == "" {
		opts.TargetPathExists = "skip"
	}
	switch opts.TargetPathExists {
	case "skip", "replace", "fail":
	default:
		return fmt.Errorf("invalid --target-path-exists value %q (must be skip, replace, or fail)", opts.TargetPathExists)
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

	editor, err := rhtas.LoadRepository(rhtas.LoadOptions{
		RootPath:         opts.RootPath,
		OutDir:           opts.OutDir,
		Follow:           opts.Follow,
		TargetPathExists: opts.TargetPathExists,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize repository: %w", err)
	}

	editor.SetTargetsVersion(opts.TargetsVersion)
	editor.SetTargetsExpires(opts.TargetsExpires)
	editor.SetSnapshotVersion(opts.SnapshotVersion)
	editor.SetSnapshotExpires(opts.SnapshotExpires)
	editor.SetTimestampVersion(opts.TimestampVersion)
	editor.SetTimestampExpires(opts.TimestampExpires)

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

		tf, err := tufmeta.TargetFile().FromFile(path, "sha256")
		if err != nil {
			return fmt.Errorf("failed to hash target %s: %w", relPath, err)
		}

		editor.AddTarget(relPath, tf)

		if err := editor.CopyTargetToRepo(path, relPath); err != nil {
			return fmt.Errorf("failed to copy target %s: %w", relPath, err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to add targets: %w", err)
	}

	if err := editor.SignAndWrite(rhtas.SignAndWriteOptions{
		KeyPaths: opts.KeyPaths,
		OutDir:   opts.OutDir,
	}); err != nil {
		return fmt.Errorf("failed to sign and write repository: %w", err)
	}

	return nil
}
