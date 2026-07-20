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

package cmd

import (
	"fmt"

	"github.com/securesign/tufcli/internal/update"
	"github.com/spf13/cobra"
)

var (
	updateRoot             string
	updateKeys             []string
	updateOutDir           string
	updateMetadataURL      string
	updateAddTargets       string
	updateTargetsExpires   string
	updateSnapshotExpires  string
	updateTimestampExpires string
	updateTargetsVersion   int64
	updateSnapshotVersion  int64
	updateTimestampVersion int64
	updateForceVersion     bool
	updateFollow           bool
	updateTargetPathExists string
	updateAllowExpiredRepo bool
	updateIncomingMetadata string
	updateDelegatedRole    string
)

// updateCmd represents the update command
var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update a TUF repository's metadata and optionally add targets",
	Long: `Update an existing TUF repository's metadata and optionally add or modify targets.

Loads existing metadata from the specified metadata URL, auto-bumps snapshot
and timestamp versions (and targets version if targets are modified), optionally
updates expiration times and target files, then signs and writes the repository.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		log.Info("Updating TUF repository...")

		opts := &update.Options{
			RootPath:         updateRoot,
			KeyPaths:         updateKeys,
			OutDir:           updateOutDir,
			MetadataURL:      updateMetadataURL,
			AllowExpiredRepo: updateAllowExpiredRepo,
			AddTargetsDir:    updateAddTargets,
			ForceVersion:     updateForceVersion,
			Follow:           updateFollow,
			TargetPathExists: updateTargetPathExists,
			IncomingMetadata: updateIncomingMetadata,
			DelegatedRole:    updateDelegatedRole,
		}

		if updateTargetsExpires != "" {
			t, err := parseTime(updateTargetsExpires)
			if err != nil {
				return fmt.Errorf("invalid --targets-expires: %w", err)
			}
			opts.TargetsExpires = &t
		}
		if updateSnapshotExpires != "" {
			t, err := parseTime(updateSnapshotExpires)
			if err != nil {
				return fmt.Errorf("invalid --snapshot-expires: %w", err)
			}
			opts.SnapshotExpires = &t
		}
		if updateTimestampExpires != "" {
			t, err := parseTime(updateTimestampExpires)
			if err != nil {
				return fmt.Errorf("invalid --timestamp-expires: %w", err)
			}
			opts.TimestampExpires = &t
		}

		if cmd.Flags().Changed("targets-version") {
			opts.TargetsVersion = &updateTargetsVersion
		}
		if cmd.Flags().Changed("snapshot-version") {
			opts.SnapshotVersion = &updateSnapshotVersion
		}
		if cmd.Flags().Changed("timestamp-version") {
			opts.TimestampVersion = &updateTimestampVersion
		}

		if err := update.Run(opts); err != nil {
			return fmt.Errorf("update command failed: %w", err)
		}

		log.Info("TUF repository updated successfully")
		return nil
	},
}

func init() {
	// Core flags
	updateCmd.Flags().StringVarP(&updateRoot, "root", "r", "", "Path to root.json file for the repository")
	updateCmd.Flags().StringSliceVarP(&updateKeys, "key", "k", nil, "Key files to sign with (can be specified multiple times)")
	updateCmd.Flags().StringVarP(&updateOutDir, "outdir", "o", "", "Output directory for the updated repository")
	updateCmd.Flags().StringVarP(&updateMetadataURL, "metadata-url", "m", "", "Base URL of existing TUF repository metadata (file:// or https://)")
	updateCmd.MarkFlagRequired("root")
	updateCmd.MarkFlagRequired("key")
	updateCmd.MarkFlagRequired("outdir")
	updateCmd.MarkFlagRequired("metadata-url")

	// Target flags
	updateCmd.Flags().StringVarP(&updateAddTargets, "add-targets", "t", "", "Directory of targets to add")
	updateCmd.Flags().BoolVarP(&updateFollow, "follow", "f", false, "Follow symbolic links when adding targets")
	updateCmd.Flags().StringVar(&updateTargetPathExists, "target-path-exists", "skip", "Behavior when target exists: skip, replace, or fail")

	// Metadata expiration flags
	updateCmd.Flags().StringVar(&updateTargetsExpires, "targets-expires", "", "Targets metadata expiration (RFC 3339 or relative like 'in 7 days')")
	updateCmd.Flags().StringVar(&updateSnapshotExpires, "snapshot-expires", "", "Snapshot metadata expiration (RFC 3339 or relative like 'in 7 days')")
	updateCmd.Flags().StringVar(&updateTimestampExpires, "timestamp-expires", "", "Timestamp metadata expiration (RFC 3339 or relative like 'in 7 days')")

	// Metadata version flags
	updateCmd.Flags().Int64Var(&updateTargetsVersion, "targets-version", 0, "Explicit targets.json version (requires --force-version)")
	updateCmd.Flags().Int64Var(&updateSnapshotVersion, "snapshot-version", 0, "Explicit snapshot.json version (requires --force-version)")
	updateCmd.Flags().Int64Var(&updateTimestampVersion, "timestamp-version", 0, "Explicit timestamp.json version (requires --force-version)")
	updateCmd.Flags().BoolVar(&updateForceVersion, "force-version", false, "Allow explicit version overrides")

	// Repository loading flags
	updateCmd.Flags().BoolVar(&updateAllowExpiredRepo, "allow-expired-repo", false, "Allow loading expired metadata (unsafe, prints warning)")

	// Delegated metadata flags
	updateCmd.Flags().StringVarP(&updateIncomingMetadata, "incoming-metadata", "i", "", "Path or URL to incoming delegated targets metadata")
	updateCmd.Flags().StringVar(&updateDelegatedRole, "role", "", "Delegated role name (requires --incoming-metadata)")
}
