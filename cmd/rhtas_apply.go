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
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/securesign/tufcli/internal/keys"
	"github.com/securesign/tufcli/internal/rhtas"
	"github.com/securesign/tufcli/internal/rhtas/document"
)

var (
	rhtasApplyRoot             string
	rhtasApplyOutDir           string
	rhtasApplyKeys             []string
	rhtasApplyVaultKeys        []string
	rhtasApplyInput            string
	rhtasApplyOperator         string
	rhtasApplyHashAlgo         string
	rhtasApplyAllowExpiredRepo bool
)

// terminationLogPath is where Kubernetes reads a container's termination
// message. Variable for tests.
var terminationLogPath = "/dev/termination-log"

// terminationLogLimit is the size Kubernetes keeps of a termination message.
const terminationLogLimit = 4096

var rhtasApplyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Apply a JSON Patch to the RHTAS targets of a repository",
	Long: `Apply an RFC 6902 JSON Patch to the document describing the RHTAS targets
(CTlog, Fulcio, Rekor and TSA keys) of a TUF repository, and publish the result.

tufcli rebuilds the document from the repository, applies the patch, and when
the document changes writes the targets, trusted_root.json and
signing_config.v0.2.json, then signs targets, snapshot and timestamp once each,
in order, under the repository lock. The patch is applied all or nothing.

The patch must start with a test of the document version:

  [{"op":"test","path":"/apiVersion","value":"` + document.APIVersion + `"},
   {"op":"replace","path":"/components/rekor/rekor.pub/validFor/end","value":"2025-05-30T14:20:05Z"}]

Key and certificate material is carried inline in the patch (PEM, or base64 DER).
See the README section "rhtas apply" for the document format.

The result is printed to stdout as JSON, and written to /dev/termination-log
when that file exists.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		cmd.SilenceUsage = true

		result, err := runRhtasApply()
		if err != nil {
			result = &rhtas.ApplyResult{
				APIVersion: document.APIVersion,
				Result:     rhtas.ResultFailed,
				Error:      rhtas.ClassifyError(err),
			}
		}
		if werr := writeApplyResult(cmd.OutOrStdout(), cmd.ErrOrStderr(), result); werr != nil {
			err = errors.Join(err, werr)
		}
		if err != nil {
			return fmt.Errorf("rhtas apply failed: %w", err)
		}
		return nil
	},
}

func runRhtasApply() (*rhtas.ApplyResult, error) {
	if len(rhtasApplyKeys) == 0 && len(rhtasApplyVaultKeys) == 0 {
		return nil, fmt.Errorf("at least one of --key or --vault-key must be specified")
	}
	patch, err := readPatch(rhtasApplyInput)
	if err != nil {
		return nil, err
	}
	return rhtas.Apply(&rhtas.ApplyOptions{
		RootPath:         rhtasApplyRoot,
		OutDir:           rhtasApplyOutDir,
		KeyPaths:         rhtasApplyKeys,
		VaultKeyRefs:     rhtasApplyVaultKeys,
		Patch:            patch,
		Operator:         rhtasApplyOperator,
		HashAlgo:         rhtasApplyHashAlgo,
		AllowExpiredRepo: rhtasApplyAllowExpiredRepo,
		GetPassphrase:    keys.NewPassphraseFunc(rhtasApplyKeys),
		Output:           os.Stderr,
	})
}

func readPatch(path string) ([]byte, error) {
	if path == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("failed to read patch from stdin: %w", err)
		}
		return data, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read patch: %w", err)
	}
	return data, nil
}

// writeApplyResult prints the result as one JSON line and writes it to the
// termination log when one exists (a Kubernetes container). Termination log
// failures are warnings and do not affect the publication outcome.
func writeApplyResult(w, warnings io.Writer, result *rhtas.ApplyResult) error {
	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("failed to encode result: %w", err)
	}
	if _, err := fmt.Fprintln(w, string(data)); err != nil {
		return fmt.Errorf("failed to write result: %w", err)
	}
	if _, err := os.Stat(terminationLogPath); err == nil {
		if err := os.WriteFile(terminationLogPath, fitTerminationLog(result, data), 0o600); err != nil {
			fmt.Fprintf(warnings, "WARNING: failed to write %s: %v\n", terminationLogPath, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(warnings, "WARNING: failed to check %s: %v\n", terminationLogPath, err)
	}
	return nil
}

// fitTerminationLog returns result encoded within terminationLogLimit,
// still valid JSON: the error message is shortened first (on a character
// boundary), then the path dropped, and as a last resort only the outcome
// and reason are kept.
func fitTerminationLog(result *rhtas.ApplyResult, data []byte) []byte {
	if len(data) <= terminationLogLimit || result.Error == nil {
		return data
	}
	short := *result
	e := *result.Error
	short.Error = &e
	encode := func() []byte {
		d, err := json.Marshal(&short)
		if err != nil {
			return nil
		}
		return d
	}
	for len(data) > terminationLogLimit && e.Message != "" {
		over := len(data) - terminationLogLimit + len("...")
		keep := len(e.Message) - over
		if keep < 0 {
			keep = 0
		}
		for keep > 0 && !utf8.RuneStart(e.Message[keep]) {
			keep--
		}
		if keep == 0 {
			e.Message = ""
		} else {
			e.Message = e.Message[:keep] + "..."
		}
		data = encode()
	}
	if len(data) > terminationLogLimit {
		e.Path = ""
		data = encode()
	}
	if len(data) > terminationLogLimit {
		data, _ = json.Marshal(&rhtas.ApplyResult{APIVersion: result.APIVersion, Result: result.Result,
			Error: &rhtas.ApplyError{Reason: e.Reason}})
	}
	return data
}

func init() {
	rhtasCmd.AddCommand(rhtasApplyCmd)

	f := rhtasApplyCmd.Flags()
	f.StringVarP(&rhtasApplyRoot, "root", "r", "", "Path to root.json file for the repository")
	f.StringVarP(&rhtasApplyOutDir, "outdir", "o", "", "Repository directory to update")
	f.StringSliceVarP(&rhtasApplyKeys, "key", "k", nil, "Signing key: file path or yubikey://slot/<id> URI (can be specified multiple times)")
	f.StringSliceVar(&rhtasApplyVaultKeys, "vault-key", nil, "Vault Transit key reference (hashivault://keyname, can be specified multiple times)")
	f.StringVarP(&rhtasApplyInput, "input", "i", "", "Path to the JSON Patch file ('-' for stdin)")
	f.StringVar(&rhtasApplyOperator, "operator", "", "Operator name for new trusted root and signing config entries (default: sigstore.dev)")
	f.StringVar(&rhtasApplyHashAlgo, "hash-algo", "sha256", "Hash algorithm for target and metadata hashes (sha256 or sha512)")
	f.BoolVar(&rhtasApplyAllowExpiredRepo, "allow-expired-repo", false, "Allow loading expired metadata (unsafe, prints warning)")
	_ = rhtasApplyCmd.MarkFlagRequired("root")
	_ = rhtasApplyCmd.MarkFlagRequired("outdir")
	_ = rhtasApplyCmd.MarkFlagRequired("input")
}
