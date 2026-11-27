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

package rhtas

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/securesign/tufcli/internal/editor"
	"github.com/securesign/tufcli/internal/keys"
	"github.com/securesign/tufcli/internal/lock"
	"github.com/securesign/tufcli/internal/rhtas/document"
	"github.com/securesign/tufcli/internal/utils"
)

// ApplyOptions configures `tufcli rhtas apply`.
type ApplyOptions struct {
	RootPath     string
	OutDir       string
	KeyPaths     []string
	VaultKeyRefs []string
	// Patch is the RFC 6902 JSON Patch over the RHTAS targets document.
	Patch []byte
	// Operator is recorded on new trusted_root.json and signing config entries.
	Operator         string
	HashAlgo         string
	AllowExpiredRepo bool
	GetPassphrase    keys.PassphraseFunc
	// Output receives warnings (default stderr).
	Output io.Writer
}

// Apply results.
const (
	ResultApplied  = "Applied"
	ResultNoChange = "NoChange"
	ResultFailed   = "Failed"
)

// RoleResult is the version and expiry of a role after the run.
type RoleResult struct {
	Version int64     `json:"version"`
	Expires time.Time `json:"expires"`
}

// ApplyResult is the machine-readable outcome of an apply.
type ApplyResult struct {
	APIVersion string `json:"apiVersion"`
	// Result is Applied, NoChange or Failed.
	Result    string      `json:"result"`
	Targets   *RoleResult `json:"targets,omitempty"`
	Snapshot  *RoleResult `json:"snapshot,omitempty"`
	Timestamp *RoleResult `json:"timestamp,omitempty"`
	Error     *ApplyError `json:"error,omitempty"`
	Warnings  []string    `json:"warnings,omitempty"`
}

// Reasons of a failed apply, besides the document.Reason* ones.
const (
	ReasonSignerNotAuthorized    = "SignerNotAuthorized"
	ReasonNotConsistentSnapshot  = "NotConsistentSnapshot"
	ReasonInconsistentRepository = "InconsistentRepository"
	ReasonConcurrentUpdate       = "ConcurrentUpdate"
	ReasonRollback               = "Rollback"
	ReasonFailed                 = "Failed"
)

// ApplyError is the typed error of a failed apply.
type ApplyError struct {
	Reason  string `json:"reason"`
	Message string `json:"message"`
	// Operation is the zero-based index of the rejected patch operation.
	Operation *int   `json:"operation,omitempty"`
	Path      string `json:"path,omitempty"`
	// Role is the role the provided keys cannot sign.
	Role string `json:"role,omitempty"`
}

// ClassifyError turns an Apply error into its typed form.
func ClassifyError(err error) *ApplyError {
	ae := &ApplyError{Reason: ReasonFailed, Message: err.Error()}
	var pe *document.PatchError
	var se *keys.RoleSignerError
	switch {
	case errors.Is(err, document.ErrNameUnavailable) && !errors.As(err, &pe):
		ae.Reason = document.ReasonOperationRejected
	case errors.As(err, &pe):
		ae.Reason = pe.Reason
		ae.Path = pe.Path
		if pe.Index >= 0 {
			i := pe.Index
			ae.Operation = &i
		}
	case errors.As(err, &se):
		ae.Reason = ReasonSignerNotAuthorized
		ae.Role = se.Role
	case errors.Is(err, editor.ErrNotConsistentSnapshot):
		ae.Reason = ReasonNotConsistentSnapshot
	case errors.Is(err, ErrInconsistentRepository):
		ae.Reason = ReasonInconsistentRepository
	case errors.Is(err, editor.ErrLiveTimestampChanged):
		ae.Reason = ReasonConcurrentUpdate
	case errors.Is(err, editor.ErrRollback):
		ae.Reason = ReasonRollback
	}
	return ae
}

// Apply rebuilds the RHTAS targets document from the repository, applies the
// patch and, when the document changes, publishes the result: new targets,
// trusted_root.json and signing_config.v0.2.json, then targets, snapshot and
// timestamp each signed once with a new version, in order. It runs under the
// repository lock and is all or nothing: a rejected patch publishes nothing.
// Re-applying a patch that is already applied publishes nothing and reports
// NoChange.
func Apply(opts *ApplyOptions) (*ApplyResult, error) {
	if opts.HashAlgo == "" {
		opts.HashAlgo = "sha256"
	}
	if err := utils.ValidateHashAlgo(opts.HashAlgo); err != nil {
		return nil, err
	}
	if opts.Operator == "" {
		opts.Operator = "sigstore.dev"
	}
	if len(opts.KeyPaths) == 0 && len(opts.VaultKeyRefs) == 0 {
		return nil, fmt.Errorf("at least one signing key is required")
	}
	output := utils.SafeWriter(opts.Output)

	repoLock, err := lock.Acquire(opts.OutDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = repoLock.Release() }()

	allowExpired := opts.AllowExpiredRepo
	re, err := LoadRepository(editor.LoadOptions{
		RootPath:         opts.RootPath,
		OutDir:           opts.OutDir,
		TargetPathExists: "skip",
		Output:           output,
		AllowExpiredRepo: &allowExpired,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to load repository: %w", err)
	}

	current, err := buildDocument(re)
	if err != nil {
		return nil, err
	}
	next, err := document.Apply(current.doc, opts.Patch, current.otherTargets)
	if err != nil {
		return nil, err
	}

	if document.DocumentsEqual(current.doc, next) {
		result := re.result(ResultNoChange)
		collectRemovedTargets(opts.OutDir, re, output, result)
		return result, nil
	}

	staged, err := renderDocument(re, current, next, opts.Operator, opts.HashAlgo)
	if err != nil {
		return nil, err
	}

	re.BumpTargetsVersion()
	re.BumpSnapshotVersion()
	re.BumpTimestampVersion()
	if err := re.CheckNoRollback(); err != nil {
		return nil, err
	}

	// Stage new target files and the trust bundle under targets/; SignAndWrite
	// publishes them hash-prefixed and drops the staging copies. On failure the
	// deferred removals clean them up, so nothing is left behind.
	targetsDir := filepath.Join(opts.OutDir, "targets")
	if err := os.MkdirAll(targetsDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create targets directory: %w", err)
	}
	for _, st := range staged {
		path := filepath.Join(targetsDir, st.name)
		if err := utils.ValidatePathInDir(targetsDir, path); err != nil {
			return nil, err
		}
		if err := utils.WriteFileAtomic(path, st.data); err != nil {
			return nil, fmt.Errorf("failed to stage target %q: %w", st.name, err)
		}
		defer os.Remove(path)
	}
	trustedRootPath := filepath.Join(targetsDir, "trusted_root.json")
	if err := re.TrustBundle.SaveTrustedRoot(trustedRootPath); err != nil {
		return nil, fmt.Errorf("failed to save trusted root: %w", err)
	}
	defer os.Remove(trustedRootPath)
	signingConfigPath := filepath.Join(targetsDir, "signing_config.v0.2.json")
	if err := re.TrustBundle.SaveSigningConfig(signingConfigPath); err != nil {
		return nil, fmt.Errorf("failed to save signing config: %w", err)
	}
	defer os.Remove(signingConfigPath)
	if err := addTrustBundleTargets(re, trustedRootPath, signingConfigPath, opts.HashAlgo); err != nil {
		return nil, fmt.Errorf("failed to add trust bundle targets: %w", err)
	}

	if err := re.SignAndWrite(editor.SignAndWriteOptions{
		KeyPaths:      opts.KeyPaths,
		VaultKeyRefs:  opts.VaultKeyRefs,
		OutDir:        opts.OutDir,
		HashAlgo:      opts.HashAlgo,
		GetPassphrase: opts.GetPassphrase,
	}); err != nil {
		return nil, fmt.Errorf("failed to sign and write repository: %w", err)
	}

	result := re.result(ResultApplied)
	collectRemovedTargets(opts.OutDir, re, output, result)
	return result, nil
}

// collectRemovedTargets removes the files of removed targets whose grace
// period is over (clients of the previous version may still fetch them until
// then). It runs on NoChange too, so a caller that keeps re-applying the same
// patch still collects them. A failure is a warning: publication is done.
func collectRemovedTargets(outDir string, re *Editor, output io.Writer, result *ApplyResult) {
	if err := collectDeletedTargetFiles(outDir, re.Targets().Signed.Targets, deletedTargetGrace); err != nil {
		msg := postPublicationCleanupError{err: err}.Error()
		fmt.Fprintf(output, "WARNING: %s\n", msg)
		result.Warnings = append(result.Warnings, msg)
	}
}

func (re *Editor) result(outcome string) *ApplyResult {
	return &ApplyResult{
		APIVersion: document.APIVersion,
		Result:     outcome,
		Targets:    &RoleResult{Version: re.Targets().Signed.Version, Expires: re.Targets().Signed.Expires.UTC()},
		Snapshot:   &RoleResult{Version: re.Snapshot().Signed.Version, Expires: re.Snapshot().Signed.Expires.UTC()},
		Timestamp:  &RoleResult{Version: re.Timestamp().Signed.Version, Expires: re.Timestamp().Signed.Expires.UTC()},
	}
}
