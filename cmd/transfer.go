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
	"net/url"
	"strings"

	"github.com/securesign/tufcli/internal/transfer"
	"github.com/spf13/cobra"
)

var (
	transferCurrentRoot      string
	transferNewRoot          string
	transferKeys             []string
	transferMetadataURL      string
	transferTargetsURL       string
	transferOutDir           string
	transferTargetsExpires   string
	transferTargetsVersion   int64
	transferSnapshotExpires  string
	transferSnapshotVersion  int64
	transferTimestampExpires string
	transferTimestampVersion int64
	transferAllowExpiredRepo bool
)

// transferMetadataCmd represents the transfer-metadata command
var transferMetadataCmd = &cobra.Command{
	Use:   "transfer-metadata",
	Short: "Transfer a TUF repository's metadata from a previous root to a new root",
	Long: `Transfer metadata from a previous root to a new root in a TUF repository.

Loads an existing repository verified under the current root, creates fresh
metadata signed under the new root, and copies all target entries (metadata
only, not the target files themselves). Use this when rotating the root of
trust for a TUF repository.`,
	RunE: func(_ *cobra.Command, _ []string) error {
		// Validate metadata-url
		u, err := url.Parse(transferMetadataURL)
		if err != nil || u.Scheme == "" {
			return fmt.Errorf("--metadata-url must be a valid URL with a scheme (e.g. http://, https://, file://)")
		}
		if u.Scheme == "file" && !strings.HasPrefix(u.Path, "/") {
			return fmt.Errorf("--metadata-url: file:// URLs require an absolute path")
		}

		// Validate targets-url
		if transferTargetsURL != "" {
			u, err := url.Parse(transferTargetsURL)
			if err != nil || u.Scheme == "" {
				return fmt.Errorf("--targets-url must be a valid URL with a scheme (e.g. http://, https://, file://)")
			}
			_ = u
		}

		targetsExpires, err := parseTime(transferTargetsExpires)
		if err != nil {
			return fmt.Errorf("invalid --targets-expires: %w", err)
		}
		snapshotExpires, err := parseTime(transferSnapshotExpires)
		if err != nil {
			return fmt.Errorf("invalid --snapshot-expires: %w", err)
		}
		timestampExpires, err := parseTime(transferTimestampExpires)
		if err != nil {
			return fmt.Errorf("invalid --timestamp-expires: %w", err)
		}

		log.Info("Transferring metadata...")

		opts := &transfer.Options{
			CurrentRoot:      transferCurrentRoot,
			NewRoot:          transferNewRoot,
			KeyPaths:         transferKeys,
			MetadataURL:      transferMetadataURL,
			TargetsURL:       transferTargetsURL,
			OutDir:           transferOutDir,
			TargetsExpires:   targetsExpires,
			TargetsVersion:   transferTargetsVersion,
			SnapshotExpires:  snapshotExpires,
			SnapshotVersion:  transferSnapshotVersion,
			TimestampExpires: timestampExpires,
			TimestampVersion: transferTimestampVersion,
			AllowExpiredRepo: transferAllowExpiredRepo,
		}

		if err := transfer.Run(opts); err != nil {
			return fmt.Errorf("transfer-metadata failed: %w", err)
		}

		log.Info("Transfer completed successfully")
		return nil
	},
}

func init() {
	transferMetadataCmd.Flags().StringVarP(&transferCurrentRoot, "current-root", "r", "", "Path to the current/existing root.json")
	transferMetadataCmd.Flags().StringVarP(&transferNewRoot, "new-root", "n", "", "Path to the new root.json to sign with")
	transferMetadataCmd.Flags().StringSliceVarP(&transferKeys, "key", "k", nil, "Key files to sign with (can be specified multiple times)")
	transferMetadataCmd.Flags().StringVarP(&transferMetadataURL, "metadata-url", "m", "", "Base URL of the existing TUF repo metadata")
	transferMetadataCmd.Flags().StringVarP(&transferTargetsURL, "targets-url", "t", "", "Base URL of the existing TUF repo targets")
	transferMetadataCmd.Flags().StringVarP(&transferOutDir, "outdir", "o", "", "Output directory for the new repository")
	transferMetadataCmd.Flags().StringVar(&transferTargetsExpires, "targets-expires", "", "Expiration for targets.json (RFC 3339 or relative like 'in 7 days')")
	transferMetadataCmd.Flags().Int64Var(&transferTargetsVersion, "targets-version", 0, "Version for targets.json")
	transferMetadataCmd.Flags().StringVar(&transferSnapshotExpires, "snapshot-expires", "", "Expiration for snapshot.json (RFC 3339 or relative like 'in 7 days')")
	transferMetadataCmd.Flags().Int64Var(&transferSnapshotVersion, "snapshot-version", 0, "Version for snapshot.json")
	transferMetadataCmd.Flags().StringVar(&transferTimestampExpires, "timestamp-expires", "", "Expiration for timestamp.json (RFC 3339 or relative like 'in 7 days')")
	transferMetadataCmd.Flags().Int64Var(&transferTimestampVersion, "timestamp-version", 0, "Version for timestamp.json")
	transferMetadataCmd.Flags().BoolVar(&transferAllowExpiredRepo, "allow-expired-repo", false, "Allow loading expired metadata (unsafe, for testing)")

	transferMetadataCmd.MarkFlagRequired("current-root")
	transferMetadataCmd.MarkFlagRequired("new-root")
	transferMetadataCmd.MarkFlagRequired("key")
	transferMetadataCmd.MarkFlagRequired("metadata-url")
	transferMetadataCmd.MarkFlagRequired("targets-url")
	transferMetadataCmd.MarkFlagRequired("outdir")
	transferMetadataCmd.MarkFlagRequired("targets-expires")
	transferMetadataCmd.MarkFlagRequired("targets-version")
	transferMetadataCmd.MarkFlagRequired("snapshot-expires")
	transferMetadataCmd.MarkFlagRequired("snapshot-version")
	transferMetadataCmd.MarkFlagRequired("timestamp-expires")
	transferMetadataCmd.MarkFlagRequired("timestamp-version")
}
