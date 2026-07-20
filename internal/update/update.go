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

package update

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/securesign/tufcli/internal/rhtas"
)

// Options contains all configuration for an update operation.
type Options struct {
	RootPath string
	KeyPaths []string
	OutDir   string

	MetadataURL      string
	AllowExpiredRepo bool

	AddTargetsDir string

	TargetsExpires   *time.Time
	SnapshotExpires  *time.Time
	TimestampExpires *time.Time

	TargetsVersion   *int64
	SnapshotVersion  *int64
	TimestampVersion *int64
	ForceVersion     bool

	Follow           bool
	TargetPathExists string

	IncomingMetadata string
	DelegatedRole    string
}

// ValidateAndSetDefaults validates options and applies defaults.
func (opts *Options) ValidateAndSetDefaults() error {
	if opts.MetadataURL == "" {
		return fmt.Errorf("--metadata-url is required")
	}
	if !strings.HasPrefix(opts.MetadataURL, "file://") &&
		!strings.HasPrefix(opts.MetadataURL, "http://") &&
		!strings.HasPrefix(opts.MetadataURL, "https://") {
		return fmt.Errorf("invalid --metadata-url scheme (must be file://, http://, or https://)")
	}

	if !opts.ForceVersion && (opts.TargetsVersion != nil || opts.SnapshotVersion != nil || opts.TimestampVersion != nil) {
		return fmt.Errorf("explicit version flags require --force-version")
	}

	if opts.AddTargetsDir != "" {
		fi, err := os.Stat(opts.AddTargetsDir)
		if err != nil {
			return fmt.Errorf("add-targets directory not found: %w", err)
		}
		if !fi.IsDir() {
			return fmt.Errorf("add-targets path %s is not a directory", opts.AddTargetsDir)
		}
	}

	if opts.TargetPathExists == "" {
		opts.TargetPathExists = "skip"
	}
	switch opts.TargetPathExists {
	case "skip", "replace", "fail":
	default:
		return fmt.Errorf("invalid --target-path-exists value %q (must be skip, replace, or fail)", opts.TargetPathExists)
	}

	if (opts.IncomingMetadata != "") != (opts.DelegatedRole != "") {
		return fmt.Errorf("--incoming-metadata and --role must be used together")
	}

	return nil
}

// Run executes the update command.
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
		MetadataURL:      opts.MetadataURL,
		Follow:           opts.Follow,
		TargetPathExists: opts.TargetPathExists,
	})
	if err != nil {
		return fmt.Errorf("failed to load repository: %w", err)
	}

	if err := editor.CheckExpiration(opts.AllowExpiredRepo); err != nil {
		return err
	}

	if opts.IncomingMetadata != "" && opts.DelegatedRole != "" {
		if err := editor.LoadDelegatedMetadata(opts.IncomingMetadata, opts.DelegatedRole); err != nil {
			return fmt.Errorf("failed to load delegated metadata: %w", err)
		}
	}

	targetsModified := opts.AddTargetsDir != "" ||
		opts.TargetsVersion != nil ||
		opts.TargetsExpires != nil

	if targetsModified {
		if opts.TargetsExpires != nil {
			editor.SetTargetsExpires(*opts.TargetsExpires)
		}
		editor.BumpTargetsVersion()
	}

	if opts.SnapshotExpires != nil {
		editor.SetSnapshotExpires(*opts.SnapshotExpires)
	}
	editor.BumpSnapshotVersion()

	if opts.TimestampExpires != nil {
		editor.SetTimestampExpires(*opts.TimestampExpires)
	}
	editor.BumpTimestampVersion()

	if opts.ForceVersion {
		if opts.TargetsVersion != nil {
			editor.SetTargetsVersion(*opts.TargetsVersion)
		}
		if opts.SnapshotVersion != nil {
			editor.SetSnapshotVersion(*opts.SnapshotVersion)
		}
		if opts.TimestampVersion != nil {
			editor.SetTimestampVersion(*opts.TimestampVersion)
		}
	}

	if opts.AddTargetsDir != "" {
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
	}

	if err := editor.SignAndWrite(rhtas.SignAndWriteOptions{
		KeyPaths: opts.KeyPaths,
		OutDir:   opts.OutDir,
	}); err != nil {
		return fmt.Errorf("failed to sign and write repository: %w", err)
	}

	return nil
}
