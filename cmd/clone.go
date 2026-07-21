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

	"github.com/securesign/tufcli/internal/clone"
	"github.com/spf13/cobra"
)

var (
	cloneRoot              string
	cloneMetadataURL       string
	cloneTargetsURL        string
	cloneMetadataDir       string
	cloneTargetsDir        string
	cloneTargetNames       []string
	cloneRootVersion       int64
	cloneMetadataOnly      bool
	cloneAllowExpiredRepo  bool
	cloneAllowRootDownload bool
)

// cloneCmd represents the clone command
var cloneCmd = &cobra.Command{
	Use:   "clone",
	Short: "Clone a TUF repository",
	Long: `Clone a TUF repository, including metadata and some or all targets.

Clones repository metadata to the specified metadata directory and optionally
downloads target files to the targets directory. Use --metadata-only to clone
only metadata without downloading targets.`,
	RunE: func(_ *cobra.Command, _ []string) error {
		// Validate metadata-url
		u, err := url.Parse(cloneMetadataURL)
		if err != nil || u.Scheme == "" {
			return fmt.Errorf("--metadata-url must be a valid URL with a scheme (e.g. http://, https://, file://)")
		}
		if u.Scheme == "file" && !strings.HasPrefix(u.Path, "/") {
			return fmt.Errorf("--metadata-url: file:// URLs require an absolute path")
		}

		// Validate targets-url if provided
		if cloneTargetsURL != "" {
			u, err := url.Parse(cloneTargetsURL)
			if err != nil || u.Scheme == "" {
				return fmt.Errorf("--targets-url must be a valid URL with a scheme (e.g. http://, https://, file://)")
			}
		}

		if !cloneMetadataOnly {
			if cloneTargetsDir == "" {
				return fmt.Errorf("--targets-dir is required unless --metadata-only is set")
			}
			if cloneTargetsURL == "" {
				return fmt.Errorf("--targets-url is required unless --metadata-only is set")
			}
		}

		log.Info("Cloning TUF repository...")

		opts := &clone.Options{
			Root:              cloneRoot,
			MetadataURL:       cloneMetadataURL,
			TargetsURL:        cloneTargetsURL,
			MetadataDir:       cloneMetadataDir,
			TargetsDir:        cloneTargetsDir,
			TargetNames:       cloneTargetNames,
			RootVersion:       cloneRootVersion,
			MetadataOnly:      cloneMetadataOnly,
			AllowExpiredRepo:  cloneAllowExpiredRepo,
			AllowRootDownload: cloneAllowRootDownload,
		}

		if err := clone.Run(opts); err != nil {
			return fmt.Errorf("clone failed: %w", err)
		}

		log.Info("Clone completed successfully")
		return nil
	},
}

func init() {
	cloneCmd.Flags().StringVarP(&cloneRoot, "root", "r", "", "Path to root.json file for the repository")
	cloneCmd.Flags().StringVarP(&cloneMetadataURL, "metadata-url", "m", "", "TUF repository metadata base URL")
	cloneCmd.Flags().StringVarP(&cloneTargetsURL, "targets-url", "t", "", "TUF repository targets base URL")
	cloneCmd.Flags().StringVar(&cloneMetadataDir, "metadata-dir", "", "Output directory for metadata")
	cloneCmd.Flags().StringVar(&cloneTargetsDir, "targets-dir", "", "Output directory for targets")
	cloneCmd.Flags().StringSliceVarP(&cloneTargetNames, "target-name", "n", nil, "Download only these targets (can be specified multiple times)")
	cloneCmd.Flags().Int64VarP(&cloneRootVersion, "root-version", "v", 1, "Remote root.json version number")
	cloneCmd.Flags().BoolVar(&cloneMetadataOnly, "metadata-only", false, "Only clone metadata, not targets")
	cloneCmd.Flags().BoolVar(&cloneAllowExpiredRepo, "allow-expired-repo", false, "Allow repo clone for expired metadata (unsafe)")
	cloneCmd.Flags().BoolVar(&cloneAllowRootDownload, "allow-root-download", false, "Allow downloading the root.json file (unsafe)")

	cloneCmd.MarkFlagRequired("metadata-url")
	cloneCmd.MarkFlagRequired("metadata-dir")
}
