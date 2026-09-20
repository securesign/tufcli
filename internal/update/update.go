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
	"os"
	"path/filepath"
	"time"

	"github.com/securesign/tufcli/internal/editor"
	"github.com/securesign/tufcli/internal/keys"
	"github.com/securesign/tufcli/internal/targetscan"
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
	if err := utils.ValidateVersionValues(opts.TargetsVersion, opts.SnapshotVersion, opts.TimestampVersion); err != nil {
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

	var scanned []targetscan.Target
	cleanup := func() {}
	var err error
	if opts.AddTargetsDir != "" {
		scanned, cleanup, err = targetscan.Scan(opts.AddTargetsDir, opts.Follow, opts.HashAlgo)
		if err != nil {
			return fmt.Errorf("failed to scan targets: %w", err)
		}
	}
	defer cleanup()

	if err := os.MkdirAll(filepath.Join(opts.OutDir, "targets"), 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	allowExpired := opts.AllowExpiredRepo
	ed, err := editor.LoadRepository(editor.LoadOptions{
		RootPath:         opts.RootPath,
		OutDir:           opts.OutDir,
		MetadataURL:      opts.MetadataURL,
		Follow:           opts.Follow,
		TargetPathExists: opts.TargetPathExists,
		AllowExpiredRepo: &allowExpired,
	})
	if err != nil {
		return fmt.Errorf("failed to load repository: %w", err)
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
		for _, target := range scanned {
			ed.AddTarget(target.Name, target.Meta)
			if err := ed.CopyTargetToRepo(target.Path, target.Name); err != nil {
				return fmt.Errorf("failed to copy target %s: %w", target.Name, err)
			}
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
