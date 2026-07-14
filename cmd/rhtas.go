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

	"github.com/securesign/tufcli/internal/rhtas"
	"github.com/spf13/cobra"
)

var (
	rhtasRoot   string
	rhtasKeys   []string
	rhtasOutDir string

	// Service targets (set)
	rhtasFulcioTarget string
	rhtasFulcioURI    string
	rhtasFulcioStatus string
	rhtasOIDCURIs     []string
	rhtasCtlogTarget  string
	rhtasCtlogURI     string
	rhtasCtlogStatus  string
	rhtasRekorTarget  string
	rhtasRekorURI     string
	rhtasRekorStatus  string
	rhtasTsaTarget    string
	rhtasTsaURI       string
	rhtasTsaStatus    string

	// Service targets (delete)
	rhtasDeleteFulcioTargets []string
	rhtasDeleteCtlogTargets  []string
	rhtasDeleteRekorTargets  []string
	rhtasDeleteTsaTargets    []string

	// Metadata
	rhtasTargetsExpires   string
	rhtasSnapshotExpires  string
	rhtasTimestampExpires string
	rhtasTargetsVersion   int64
	rhtasSnapshotVersion  int64
	rhtasTimestampVersion int64
	rhtasForceVersion     bool
	rhtasChecksumAlgo     string
	rhtasOperator         string

	// Repository loading
	rhtasMetadataURL      string
	rhtasAllowExpiredRepo bool

	// Target copy behavior
	rhtasFollow           bool
	rhtasTargetPathExists string

	// Delegated metadata
	rhtasIncomingMetadata string
	rhtasDelegatedRole    string
)

// rhtasCmd represents the rhtas command
var rhtasCmd = &cobra.Command{
	Use:   "rhtas",
	Short: "Manage RHTAS TUF",
	Long: `Commands for managing RHTAS (Red Hat Trusted Artifact Signer) TUF repositories.

Manages Sigstore-specific targets (Fulcio, CTLog, Rekor, TSA) within a TUF
repository, including TrustedRoot and SigningConfig metadata bundles.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		log.Info("Managing RHTAS TUF...")

		opts := &rhtas.Options{
			RootPath:            rhtasRoot,
			KeyPaths:            rhtasKeys,
			OutDir:              rhtasOutDir,
			FulcioTarget:        rhtasFulcioTarget,
			FulcioURI:           rhtasFulcioURI,
			FulcioStatus:        rhtasFulcioStatus,
			OIDCURIs:            rhtasOIDCURIs,
			CtlogTarget:         rhtasCtlogTarget,
			CtlogURI:            rhtasCtlogURI,
			CtlogStatus:         rhtasCtlogStatus,
			RekorTarget:         rhtasRekorTarget,
			RekorURI:            rhtasRekorURI,
			RekorStatus:         rhtasRekorStatus,
			TsaTarget:           rhtasTsaTarget,
			TsaURI:              rhtasTsaURI,
			TsaStatus:           rhtasTsaStatus,
			DeleteFulcioTargets: rhtasDeleteFulcioTargets,
			DeleteCtlogTargets:  rhtasDeleteCtlogTargets,
			DeleteRekorTargets:  rhtasDeleteRekorTargets,
			DeleteTsaTargets:    rhtasDeleteTsaTargets,
			ForceVersion:        rhtasForceVersion,
			ChecksumAlgo:        rhtasChecksumAlgo,
			Operator:            rhtasOperator,
			MetadataURL:         rhtasMetadataURL,
			AllowExpiredRepo:    rhtasAllowExpiredRepo,
			Follow:              rhtasFollow,
			TargetPathExists:    rhtasTargetPathExists,
			IncomingMetadata:    rhtasIncomingMetadata,
			DelegatedRole:       rhtasDelegatedRole,
		}

		// Parse optional time flags
		if rhtasTargetsExpires != "" {
			t, err := parseTime(rhtasTargetsExpires)
			if err != nil {
				return fmt.Errorf("invalid --targets-expires: %w", err)
			}
			opts.TargetsExpires = &t
		}
		if rhtasSnapshotExpires != "" {
			t, err := parseTime(rhtasSnapshotExpires)
			if err != nil {
				return fmt.Errorf("invalid --snapshot-expires: %w", err)
			}
			opts.SnapshotExpires = &t
		}
		if rhtasTimestampExpires != "" {
			t, err := parseTime(rhtasTimestampExpires)
			if err != nil {
				return fmt.Errorf("invalid --timestamp-expires: %w", err)
			}
			opts.TimestampExpires = &t
		}

		// Handle explicit version flags (0 means not set)
		if cmd.Flags().Changed("targets-version") {
			opts.TargetsVersion = &rhtasTargetsVersion
		}
		if cmd.Flags().Changed("snapshot-version") {
			opts.SnapshotVersion = &rhtasSnapshotVersion
		}
		if cmd.Flags().Changed("timestamp-version") {
			opts.TimestampVersion = &rhtasTimestampVersion
		}

		if err := rhtas.Run(opts); err != nil {
			return fmt.Errorf("rhtas command failed: %w", err)
		}

		log.Info("RHTAS TUF repository updated successfully")
		return nil
	},
}

func init() {
	// Core flags
	rhtasCmd.Flags().StringVarP(&rhtasRoot, "root", "r", "", "Path to root.json file for the repository")
	rhtasCmd.Flags().StringSliceVarP(&rhtasKeys, "key", "k", nil, "Key files to sign with (can be specified multiple times)")
	rhtasCmd.Flags().StringVarP(&rhtasOutDir, "outdir", "o", "", "Output directory for the updated repository")
	rhtasCmd.MarkFlagRequired("root")
	rhtasCmd.MarkFlagRequired("key")
	rhtasCmd.MarkFlagRequired("outdir")

	// Fulcio target flags
	rhtasCmd.Flags().StringVar(&rhtasFulcioTarget, "set-fulcio-target", "", "Path to Fulcio certificate chain PEM file")
	rhtasCmd.Flags().StringVar(&rhtasFulcioURI, "fulcio-uri", "", "Fulcio endpoint URI (default: https://fulcio.sigstore.dev)")
	rhtasCmd.Flags().StringVar(&rhtasFulcioStatus, "fulcio-status", "", "Fulcio target status: Active or Expired (default: Active)")
	rhtasCmd.Flags().StringSliceVar(&rhtasOIDCURIs, "oidc-uri", nil, "OIDC provider URIs (can be specified multiple times)")

	// CTLog target flags
	rhtasCmd.Flags().StringVar(&rhtasCtlogTarget, "set-ctlog-target", "", "Path to CTLog public key PEM file")
	rhtasCmd.Flags().StringVar(&rhtasCtlogURI, "ctlog-uri", "", "CTLog endpoint URI (default: https://ctfe.sigstore.dev/test)")
	rhtasCmd.Flags().StringVar(&rhtasCtlogStatus, "ctlog-status", "", "CTLog target status: Active or Expired (default: Active)")

	// Rekor target flags
	rhtasCmd.Flags().StringVar(&rhtasRekorTarget, "set-rekor-target", "", "Path to Rekor public key PEM file")
	rhtasCmd.Flags().StringVar(&rhtasRekorURI, "rekor-uri", "", "Rekor endpoint URI (default: https://rekor.sigstore.dev)")
	rhtasCmd.Flags().StringVar(&rhtasRekorStatus, "rekor-status", "", "Rekor target status: Active or Expired (default: Active)")

	// TSA target flags
	rhtasCmd.Flags().StringVar(&rhtasTsaTarget, "set-tsa-target", "", "Path to TSA certificate chain PEM file")
	rhtasCmd.Flags().StringVar(&rhtasTsaURI, "tsa-uri", "", "TSA endpoint URI")
	rhtasCmd.Flags().StringVar(&rhtasTsaStatus, "tsa-status", "", "TSA target status: Active or Expired (default: Active)")

	// Delete target flags
	rhtasCmd.Flags().StringSliceVar(&rhtasDeleteFulcioTargets, "delete-fulcio-target", nil, "Fulcio target names to delete")
	rhtasCmd.Flags().StringSliceVar(&rhtasDeleteCtlogTargets, "delete-ctlog-target", nil, "CTLog target names to delete")
	rhtasCmd.Flags().StringSliceVar(&rhtasDeleteRekorTargets, "delete-rekor-target", nil, "Rekor target names to delete")
	rhtasCmd.Flags().StringSliceVar(&rhtasDeleteTsaTargets, "delete-tsa-target", nil, "TSA target names to delete")

	// Metadata flags
	rhtasCmd.Flags().StringVar(&rhtasTargetsExpires, "targets-expires", "", "Targets metadata expiration (RFC 3339 or relative like 'in 7 days')")
	rhtasCmd.Flags().StringVar(&rhtasSnapshotExpires, "snapshot-expires", "", "Snapshot metadata expiration (RFC 3339 or relative like 'in 7 days')")
	rhtasCmd.Flags().StringVar(&rhtasTimestampExpires, "timestamp-expires", "", "Timestamp metadata expiration (RFC 3339 or relative like 'in 7 days')")
	rhtasCmd.Flags().Int64Var(&rhtasTargetsVersion, "targets-version", 0, "Explicit targets.json version (requires --force-version)")
	rhtasCmd.Flags().Int64Var(&rhtasSnapshotVersion, "snapshot-version", 0, "Explicit snapshot.json version (requires --force-version)")
	rhtasCmd.Flags().Int64Var(&rhtasTimestampVersion, "timestamp-version", 0, "Explicit timestamp.json version (requires --force-version)")
	rhtasCmd.Flags().BoolVar(&rhtasForceVersion, "force-version", false, "Allow explicit version overrides")
	rhtasCmd.Flags().StringVar(&rhtasChecksumAlgo, "checksum-algo", "", "Checksum algorithm for public key detection (default: sha256)")
	rhtasCmd.Flags().StringVar(&rhtasOperator, "operator", "", "Operator name for signing config (default: sigstore.dev)")

	// Repository loading flags
	rhtasCmd.Flags().StringVarP(&rhtasMetadataURL, "metadata-url", "m", "", "Base URL of existing TUF repository metadata (file:// or https://)")
	rhtasCmd.Flags().BoolVar(&rhtasAllowExpiredRepo, "allow-expired-repo", false, "Allow loading expired metadata (unsafe, prints warning)")

	// Target copy behavior flags
	rhtasCmd.Flags().BoolVarP(&rhtasFollow, "follow", "f", false, "Follow symbolic links when copying target files")
	rhtasCmd.Flags().StringVar(&rhtasTargetPathExists, "target-path-exists", "skip", "Behavior when target file exists: skip, replace, or fail")

	// Delegated metadata flags
	rhtasCmd.Flags().StringVarP(&rhtasIncomingMetadata, "incoming-metadata", "i", "", "Path or URL to incoming delegated targets metadata")
	rhtasCmd.Flags().StringVar(&rhtasDelegatedRole, "role", "", "Delegated role name (requires --incoming-metadata)")
}
