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

	"github.com/securesign/tufcli/internal/download"
	"github.com/spf13/cobra"
)

var (
	downloadRoot              string
	downloadMetadataURL       string
	downloadTargetsURL        string
	downloadTargetNames       []string
	downloadRootVersion       int64
	downloadAllowExpiredRepo  bool
	downloadAllowRootDownload bool
)

var downloadCmd = &cobra.Command{
	Use:   "download <outdir>",
	Short: "Download a TUF repository's targets",
	Long: `Download targets from a TUF repository.

Downloads target files from a TUF repository after verifying metadata
integrity through the full TUF client workflow (root rotation, timestamp,
snapshot, and targets verification).

The output directory must not already exist.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		for _, flag := range []string{"metadata-url", "targets-url"} {
			val, _ := cmd.Flags().GetString(flag)
			u, err := url.Parse(val)
			if err != nil || u.Scheme == "" {
				return fmt.Errorf("--%s must be a valid URL with a scheme (e.g. http://, https://, file://)", flag)
			}
		}

		opts := &download.Options{
			Root:              downloadRoot,
			MetadataURL:       downloadMetadataURL,
			TargetsURL:        downloadTargetsURL,
			OutDir:            args[0],
			TargetNames:       downloadTargetNames,
			RootVersion:       downloadRootVersion,
			AllowExpiredRepo:  downloadAllowExpiredRepo,
			AllowRootDownload: downloadAllowRootDownload,
		}

		if err := download.Run(opts); err != nil {
			return fmt.Errorf("download failed: %w", err)
		}

		log.Info("Download completed successfully")
		return nil
	},
}

func init() {
	downloadCmd.Flags().StringVarP(&downloadRoot, "root", "r", "", "Path to root.json file for the repository")
	downloadCmd.Flags().StringVarP(&downloadMetadataURL, "metadata-url", "m", "", "TUF repository metadata base URL")
	downloadCmd.Flags().StringVarP(&downloadTargetsURL, "targets-url", "t", "", "TUF repository targets base URL")
	downloadCmd.Flags().StringSliceVarP(&downloadTargetNames, "target-name", "n", nil, "Download only these targets (can be specified multiple times)")
	downloadCmd.Flags().Int64VarP(&downloadRootVersion, "root-version", "v", 1, "Remote root.json version number")
	downloadCmd.Flags().BoolVar(&downloadAllowExpiredRepo, "allow-expired-repo", false, "Allow repo download for expired metadata (unsafe, for testing only)")
	downloadCmd.Flags().BoolVar(&downloadAllowRootDownload, "allow-root-download", false, "Allow downloading the root.json file (unsafe)")
	downloadCmd.MarkFlagRequired("metadata-url")
	downloadCmd.MarkFlagRequired("targets-url")
}
