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
	"os"
	"path/filepath"
	"time"

	"github.com/securesign/tufcli/internal/editor"
	"github.com/securesign/tufcli/internal/keys"
	"github.com/securesign/tufcli/internal/targetscan"
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
	GetPassphrase    keys.PassphraseFunc
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
	if err := utils.ValidateHashAlgo(opts.HashAlgo); err != nil {
		return err
	}
	return nil
}

// Run executes the create command.
func Run(opts *Options) error {
	if err := opts.ValidateAndSetDefaults(); err != nil {
		return err
	}

	scanned, err := targetscan.Scan(opts.AddTargetsDir, opts.Follow, opts.HashAlgo)
	if err != nil {
		return fmt.Errorf("failed to scan targets: %w", err)
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

	for _, target := range scanned {
		ed.AddTarget(target.Name, target.Meta)
		if err := ed.CopyTargetToRepo(target.Path, target.Name); err != nil {
			return fmt.Errorf("failed to copy target %s: %w", target.Name, err)
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
