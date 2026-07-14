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

	"github.com/securesign/tufcli/internal/create"
	"github.com/spf13/cobra"
)

var (
	createRoot             string
	createKeys             []string
	createOutDir           string
	createAddTargets       string
	createTargetsExpires   string
	createTargetsVersion   int64
	createSnapshotExpires  string
	createSnapshotVersion  int64
	createTimestampExpires string
	createTimestampVersion int64
	createFollow           bool
	createTargetPathExists string
)

// createCmd represents the create command
var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a TUF repository",
	Long: `Create a new TUF repository with the specified configuration.

Initializes targets, snapshot, and timestamp metadata, adds target files from
the given directory, signs all metadata with the provided keys, and writes
the repository to the output directory.`,
	RunE: func(_ *cobra.Command, _ []string) error {
		log.Info("Creating TUF repository...")

		targetsExpires, err := parseTime(createTargetsExpires)
		if err != nil {
			return fmt.Errorf("invalid --targets-expires: %w", err)
		}
		snapshotExpires, err := parseTime(createSnapshotExpires)
		if err != nil {
			return fmt.Errorf("invalid --snapshot-expires: %w", err)
		}
		timestampExpires, err := parseTime(createTimestampExpires)
		if err != nil {
			return fmt.Errorf("invalid --timestamp-expires: %w", err)
		}

		opts := &create.Options{
			RootPath:         createRoot,
			KeyPaths:         createKeys,
			OutDir:           createOutDir,
			AddTargetsDir:    createAddTargets,
			TargetsExpires:   targetsExpires,
			TargetsVersion:   createTargetsVersion,
			SnapshotExpires:  snapshotExpires,
			SnapshotVersion:  createSnapshotVersion,
			TimestampExpires: timestampExpires,
			TimestampVersion: createTimestampVersion,
			Follow:           createFollow,
			TargetPathExists: createTargetPathExists,
		}

		if err := create.Run(opts); err != nil {
			return fmt.Errorf("create command failed: %w", err)
		}

		log.Info("TUF repository created successfully")
		return nil
	},
}

func init() {
	createCmd.Flags().StringVarP(&createRoot, "root", "r", "", "Path to root.json file for the repository")
	createCmd.Flags().StringSliceVarP(&createKeys, "key", "k", nil, "Key files to sign with (can be specified multiple times)")
	createCmd.Flags().StringVarP(&createOutDir, "outdir", "o", "", "Output directory for the repository")
	createCmd.Flags().StringVarP(&createAddTargets, "add-targets", "t", "", "Directory of targets to add")
	createCmd.Flags().StringVar(&createTargetsExpires, "targets-expires", "", "Expiration of targets.json (RFC 3339 or relative like 'in 7 days')")
	createCmd.Flags().Int64Var(&createTargetsVersion, "targets-version", 0, "Version of targets.json")
	createCmd.Flags().StringVar(&createSnapshotExpires, "snapshot-expires", "", "Expiration of snapshot.json (RFC 3339 or relative like 'in 7 days')")
	createCmd.Flags().Int64Var(&createSnapshotVersion, "snapshot-version", 0, "Version of snapshot.json")
	createCmd.Flags().StringVar(&createTimestampExpires, "timestamp-expires", "", "Expiration of timestamp.json (RFC 3339 or relative like 'in 7 days')")
	createCmd.Flags().Int64Var(&createTimestampVersion, "timestamp-version", 0, "Version of timestamp.json")
	createCmd.Flags().BoolVarP(&createFollow, "follow", "f", false, "Follow symbolic links when adding targets")
	createCmd.Flags().StringVar(&createTargetPathExists, "target-path-exists", "skip", "Behavior when target exists: skip, replace, or fail")

	createCmd.MarkFlagRequired("root")
	createCmd.MarkFlagRequired("key")
	createCmd.MarkFlagRequired("outdir")
	createCmd.MarkFlagRequired("add-targets")
	createCmd.MarkFlagRequired("targets-expires")
	createCmd.MarkFlagRequired("targets-version")
	createCmd.MarkFlagRequired("snapshot-expires")
	createCmd.MarkFlagRequired("snapshot-version")
	createCmd.MarkFlagRequired("timestamp-expires")
	createCmd.MarkFlagRequired("timestamp-version")
}
