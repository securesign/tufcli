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
	"time"

	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/securesign/tufcli/internal/editor"
	"github.com/securesign/tufcli/internal/keys"
	"github.com/securesign/tufcli/internal/utils"
)

// Options contains all configuration for an update operation.
type Options struct {
	RootPath     string
	KeyPaths     []string
	VaultKeyRefs []string
	OutDir       string

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
	HashAlgo         string
	GetPassphrase    keys.PassphraseFunc
}

// ValidateAndSetDefaults validates options and applies defaults.
func (opts *Options) ValidateAndSetDefaults() error {
	if opts.MetadataURL == "" {
		return fmt.Errorf("--metadata-url is required")
	}
	if err := utils.ValidateURLScheme(opts.MetadataURL); err != nil {
		return err
	}

	if err := utils.ValidateForceVersion(opts.ForceVersion, opts.TargetsVersion, opts.SnapshotVersion, opts.TimestampVersion); err != nil {
		return err
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

	validated, err := utils.ValidateTargetPathExists(opts.TargetPathExists)
	if err != nil {
		return err
	}
	opts.TargetPathExists = validated

	if err := utils.ValidateDelegationFlags(opts.IncomingMetadata, opts.DelegatedRole); err != nil {
		return err
	}

	if opts.HashAlgo == "" {
		opts.HashAlgo = "sha256"
	}
	if err := utils.ValidateHashAlgo(opts.HashAlgo); err != nil {
		return err
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

	ed, err := editor.LoadRepository(editor.LoadOptions{
		RootPath:         opts.RootPath,
		OutDir:           opts.OutDir,
		MetadataURL:      opts.MetadataURL,
		Follow:           opts.Follow,
		TargetPathExists: opts.TargetPathExists,
	})
	if err != nil {
		return fmt.Errorf("failed to load repository: %w", err)
	}

	if err := ed.CheckExpiration(opts.AllowExpiredRepo); err != nil {
		return err
	}

	if opts.IncomingMetadata != "" && opts.DelegatedRole != "" {
		if err := ed.LoadDelegatedMetadata(opts.IncomingMetadata, opts.DelegatedRole); err != nil {
			return fmt.Errorf("failed to load delegated metadata: %w", err)
		}
	}

	targetsModified := opts.AddTargetsDir != "" ||
		opts.TargetsVersion != nil ||
		opts.TargetsExpires != nil

	if targetsModified {
		if opts.TargetsExpires != nil {
			ed.SetTargetsExpires(*opts.TargetsExpires)
		}
		ed.BumpTargetsVersion()
	}

	if opts.SnapshotExpires != nil {
		ed.SetSnapshotExpires(*opts.SnapshotExpires)
	}
	ed.BumpSnapshotVersion()

	if opts.TimestampExpires != nil {
		ed.SetTimestampExpires(*opts.TimestampExpires)
	}
	ed.BumpTimestampVersion()

	if opts.ForceVersion {
		if opts.TargetsVersion != nil {
			ed.SetTargetsVersion(*opts.TargetsVersion)
		}
		if opts.SnapshotVersion != nil {
			ed.SetSnapshotVersion(*opts.SnapshotVersion)
		}
		if opts.TimestampVersion != nil {
			ed.SetTimestampVersion(*opts.TimestampVersion)
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
	}

	if err := ed.SignAndWrite(editor.SignAndWriteOptions{
		KeyPaths:      opts.KeyPaths,
		VaultKeyRefs:  opts.VaultKeyRefs,
		OutDir:        opts.OutDir,
		HashAlgo:      opts.HashAlgo,
		GetPassphrase: opts.GetPassphrase,
	}); err != nil {
		return fmt.Errorf("failed to sign and write repository: %w", err)
	}

	return nil
}
