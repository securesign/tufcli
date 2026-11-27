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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/securesign/tufcli/internal/keys"
	"github.com/securesign/tufcli/internal/refresh"
	"github.com/spf13/cobra"
)

const refreshTerminationLog = "/dev/termination-log"

func newRefreshCmd() *cobra.Command {
	opts := refresh.Options{}
	cmd := &cobra.Command{
		Use:   "refresh",
		Short: "Refresh an online TUF role and its dependent metadata when due",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts.Output = cmd.ErrOrStderr()
			opts.GetPassphrase = keys.NewPassphraseFunc(opts.KeyPaths)
			result, err := refresh.Run(opts)
			if err != nil {
				cmd.SilenceUsage = true
				result = refresh.Failure(opts.Role, err)
			}
			return errors.Join(err, writeRefreshResult(cmd.OutOrStdout(), cmd.ErrOrStderr(), refreshTerminationLog, result))
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.Role, "role", "", "Online role to refresh: targets, snapshot or timestamp")
	f.StringVarP(&opts.RootPath, "root", "r", "", "Path to root.json for the repository")
	f.StringVarP(&opts.OutDir, "outdir", "o", "", "Directory containing the live repository")
	f.StringSliceVarP(&opts.KeyPaths, "key", "k", nil, "Signing key: file path or yubikey://slot/<id> URI (repeatable)")
	f.StringSliceVar(&opts.VaultKeyRefs, "vault-key", nil, "Vault Transit signing key (hashivault://keyname, repeatable)")
	f.DurationVar(&opts.ExpirationPolicy, "expiration-policy", 0, "Validity to give the selected role, e.g. 8736h (required)")
	f.DurationVar(&opts.RefreshInterval, "refresh-interval", 0, "Time after issuance at which refresh is due, e.g. 8064h (required)")
	f.DurationVar(&opts.SnapshotPolicy, "snapshot-expiration-policy", refresh.DefaultExpirationPolicy, "Validity to give snapshot if it is an expired dependent")
	f.DurationVar(&opts.TimestampPolicy, "timestamp-expiration-policy", refresh.DefaultExpirationPolicy, "Validity to give timestamp if it is an expired dependent")
	f.BoolVar(&opts.AllowExpiredRepo, "allow-expired-repo", false, "Allow loading expired online metadata")
	return cmd
}

// writeRefreshResult reports an outcome even when the caller is outside a Job.
// A failed termination-log write is diagnostic only.
func writeRefreshResult(stdout, stderr io.Writer, path string, result refresh.Result) error {
	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("failed to encode refresh result: %w", err)
	}
	if _, err := os.Stat(path); err == nil {
		// Keep the Kubernetes termination message valid JSON within 4 KiB.
		logData := data
		if len(data) > 4096 && result.Error != nil {
			short := *result.Error
			short.Message = "See stderr for the full error"
			result.Error = &short
			if len(result.Role) > 16 {
				result.Role = ""
			}
			logData, _ = json.Marshal(result)
		}
		if err := os.WriteFile(path, logData, 0o600); err != nil {
			fmt.Fprintf(stderr, "WARNING: failed to write %s: %v\n", path, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(stderr, "WARNING: failed to check %s: %v\n", path, err)
	}
	if _, err := fmt.Fprintln(stdout, string(data)); err != nil {
		return fmt.Errorf("failed to write refresh result: %w", err)
	}
	return nil
}
