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
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	commonpb "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	trustrootpb "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	sigstorepkg "github.com/sigstore/sigstore/pkg/signature"
	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/securesign/tufcli/internal/editor"
	"github.com/securesign/tufcli/internal/keys"
	"github.com/securesign/tufcli/internal/sigstore"
	"github.com/securesign/tufcli/internal/utils"
)

// Options contains all configuration for an RHTAS operation.
type Options struct {
	// Core
	RootPath     string
	KeyPaths     []string
	VaultKeyRefs []string
	OutDir       string

	// Service targets (set)
	FulcioTarget string
	FulcioURI    string
	FulcioStatus string
	OIDCURIs     []string
	CtlogTarget  string
	CtlogURI     string
	CtlogStatus  string
	RekorTarget  string
	RekorURI     string
	RekorStatus  string
	TsaTarget    string
	TsaURI       string
	TsaStatus    string

	// Service targets (delete)
	DeleteFulcioTargets []string
	DeleteCtlogTargets  []string
	DeleteRekorTargets  []string
	DeleteTsaTargets    []string

	// Metadata
	TargetsExpires   *time.Time
	SnapshotExpires  *time.Time
	TimestampExpires *time.Time
	TargetsVersion   *int64
	SnapshotVersion  *int64
	TimestampVersion *int64
	ForceVersion     bool
	Operator         string

	// Repository loading
	MetadataURL      string
	AllowExpiredRepo bool

	// Target copy behavior
	Follow           bool
	TargetPathExists string // "skip" (default), "replace", "fail"

	// Delegated metadata
	IncomingMetadata string
	DelegatedRole    string

	// Hash algorithm
	HashAlgo string

	// Passphrase
	GetPassphrase keys.PassphraseFunc
}

// ValidateAndSetDefaults validates flag combinations and applies defaults.
func (opts *Options) ValidateAndSetDefaults() error {
	// Validate cross-service flag mixing
	if opts.FulcioTarget != "" {
		if opts.CtlogURI != "" || opts.RekorURI != "" || opts.TsaURI != "" ||
			opts.CtlogStatus != "" || opts.RekorStatus != "" || opts.TsaStatus != "" {
			return fmt.Errorf("--set-fulcio-target only accepts --fulcio-uri, --fulcio-status, and --oidc-uri")
		}
	}
	if opts.CtlogTarget != "" {
		if opts.FulcioURI != "" || len(opts.OIDCURIs) > 0 || opts.RekorURI != "" || opts.TsaURI != "" ||
			opts.FulcioStatus != "" || opts.RekorStatus != "" || opts.TsaStatus != "" {
			return fmt.Errorf("--set-ctlog-target only accepts --ctlog-uri and --ctlog-status")
		}
	}
	if opts.RekorTarget != "" {
		if opts.FulcioURI != "" || len(opts.OIDCURIs) > 0 || opts.CtlogURI != "" || opts.TsaURI != "" ||
			opts.FulcioStatus != "" || opts.CtlogStatus != "" || opts.TsaStatus != "" {
			return fmt.Errorf("--set-rekor-target only accepts --rekor-uri and --rekor-status")
		}
	}
	if opts.TsaTarget != "" {
		if opts.FulcioURI != "" || len(opts.OIDCURIs) > 0 || opts.CtlogURI != "" || opts.RekorURI != "" ||
			opts.FulcioStatus != "" || opts.CtlogStatus != "" || opts.RekorStatus != "" {
			return fmt.Errorf("--set-tsa-target only accepts --tsa-uri and --tsa-status")
		}
	}

	// Validate force-version
	if err := utils.ValidateForceVersion(opts.ForceVersion, opts.TargetsVersion, opts.SnapshotVersion, opts.TimestampVersion); err != nil {
		return err
	}
	if err := utils.ValidateVersionValues(opts.TargetsVersion, opts.SnapshotVersion, opts.TimestampVersion); err != nil {
		return err
	}

	// Apply defaults
	if opts.FulcioTarget != "" {
		if opts.FulcioURI == "" {
			opts.FulcioURI = "https://fulcio.sigstore.dev"
		}
		if opts.FulcioStatus == "" {
			opts.FulcioStatus = "Active"
		}
		if len(opts.OIDCURIs) == 0 {
			opts.OIDCURIs = []string{"https://oauth2.sigstore.dev/auth"}
		}
	}
	if opts.CtlogTarget != "" {
		if opts.CtlogURI == "" {
			opts.CtlogURI = "https://ctfe.sigstore.dev/test"
		}
		if opts.CtlogStatus == "" {
			opts.CtlogStatus = "Active"
		}
	}
	if opts.RekorTarget != "" {
		if opts.RekorURI == "" {
			opts.RekorURI = "https://rekor.sigstore.dev"
		}
		if opts.RekorStatus == "" {
			opts.RekorStatus = "Active"
		}
	}
	if opts.TsaTarget != "" && opts.TsaStatus == "" {
		opts.TsaStatus = "Active"
	}

	if opts.Operator == "" {
		opts.Operator = "sigstore.dev"
	}
	// Validate --target-path-exists
	validated, err := utils.ValidateTargetPathExists(opts.TargetPathExists)
	if err != nil {
		return err
	}
	opts.TargetPathExists = validated

	// Validate --incoming-metadata and --role co-dependency
	if err := utils.ValidateDelegationFlags(opts.IncomingMetadata, opts.DelegatedRole); err != nil {
		return err
	}

	// Validate --metadata-url scheme
	if opts.MetadataURL != "" {
		if err := utils.ValidateURLScheme(opts.MetadataURL); err != nil {
			return err
		}
	}

	if opts.HashAlgo == "" {
		opts.HashAlgo = "sha256"
	}
	if err := utils.ValidateHashAlgo(opts.HashAlgo); err != nil {
		return err
	}

	return nil
}

// Run executes the RHTAS command.
func Run(opts *Options) error {
	if err := opts.ValidateAndSetDefaults(); err != nil {
		return err
	}

	allowExpired := opts.AllowExpiredRepo
	re, err := LoadRepository(editor.LoadOptions{
		RootPath:         opts.RootPath,
		OutDir:           opts.OutDir,
		MetadataURL:      opts.MetadataURL,
		Follow:           opts.Follow,
		TargetPathExists: opts.TargetPathExists,
		AllowExpiredRepo: &allowExpired,
	})
	if err != nil {
		return fmt.Errorf("failed to load repository: %w", err)
	}

	if opts.IncomingMetadata != "" && opts.DelegatedRole != "" {
		if err := re.LoadDelegatedMetadata(opts.IncomingMetadata, opts.DelegatedRole); err != nil {
			return fmt.Errorf("failed to load delegated metadata: %w", err)
		}
	}

	hasTargetChanges := opts.FulcioTarget != "" || opts.CtlogTarget != "" ||
		opts.RekorTarget != "" || opts.TsaTarget != "" ||
		len(opts.DeleteFulcioTargets) > 0 || len(opts.DeleteCtlogTargets) > 0 ||
		len(opts.DeleteRekorTargets) > 0 || len(opts.DeleteTsaTargets) > 0

	if hasTargetChanges {
		if opts.TargetsExpires != nil {
			re.SetTargetsExpires(*opts.TargetsExpires)
		}
		re.BumpTargetsVersion()

		if opts.SnapshotExpires != nil {
			re.SetSnapshotExpires(*opts.SnapshotExpires)
		}
		re.BumpSnapshotVersion()

		if opts.TimestampExpires != nil {
			re.SetTimestampExpires(*opts.TimestampExpires)
		}
		re.BumpTimestampVersion()
	}

	deletedTargetFiles, cleanupOnly, err := opts.deleteTargets(re)
	if err != nil {
		return fmt.Errorf("failed to delete targets: %w", err)
	}
	if cleanupOnly && !hasNonDeletionChanges(opts) {
		if err := cleanupPendingTargetFiles(re, deletedTargetFiles); err != nil {
			return postPublicationCleanupError{err: err}
		}
		return nil
	}

	if err := opts.setFulcioTarget(re); err != nil {
		return fmt.Errorf("failed to set Fulcio target: %w", err)
	}
	if err := opts.setCtlogTarget(re); err != nil {
		return fmt.Errorf("failed to set CTLog target: %w", err)
	}
	if err := opts.setRekorTarget(re); err != nil {
		return fmt.Errorf("failed to set Rekor target: %w", err)
	}
	if err := opts.setTsaTarget(re); err != nil {
		return fmt.Errorf("failed to set TSA target: %w", err)
	}

	if opts.ForceVersion {
		if opts.TargetsVersion != nil {
			re.SetTargetsVersion(*opts.TargetsVersion)
		}
		if opts.SnapshotVersion != nil {
			re.SetSnapshotVersion(*opts.SnapshotVersion)
		}
		if opts.TimestampVersion != nil {
			re.SetTimestampVersion(*opts.TimestampVersion)
		}
	}

	// Save trust bundle files
	targetsDir := filepath.Join(opts.OutDir, "targets")
	if err := os.MkdirAll(targetsDir, 0755); err != nil {
		return fmt.Errorf("failed to create targets directory: %w", err)
	}

	trustedRootPath := filepath.Join(targetsDir, "trusted_root.json")
	if err := re.TrustBundle.SaveTrustedRoot(trustedRootPath); err != nil {
		return fmt.Errorf("failed to save trusted root: %w", err)
	}
	defer os.Remove(trustedRootPath)

	signingConfigPath := filepath.Join(targetsDir, "signing_config.v0.2.json")
	if err := re.TrustBundle.SaveSigningConfig(signingConfigPath); err != nil {
		return fmt.Errorf("failed to save signing config: %w", err)
	}
	defer os.Remove(signingConfigPath)

	if err := addTrustBundleTargets(re, trustedRootPath, signingConfigPath, opts.HashAlgo); err != nil {
		return fmt.Errorf("failed to add trust bundle targets: %w", err)
	}

	if err := re.SignAndWrite(editor.SignAndWriteOptions{
		KeyPaths:      opts.KeyPaths,
		VaultKeyRefs:  opts.VaultKeyRefs,
		OutDir:        opts.OutDir,
		HashAlgo:      opts.HashAlgo,
		GetPassphrase: opts.GetPassphrase,
	}); err != nil {
		return fmt.Errorf("failed to sign and write repository: %w", err)
	}

	// Remove target files only after all metadata has been signed and written
	// successfully. A failed signing operation must not leave published
	// metadata pointing at a missing target.
	if err := cleanupPendingTargetFiles(re, deletedTargetFiles); err != nil {
		return postPublicationCleanupError{err: err}
	}

	return nil
}

type postPublicationCleanupError struct {
	err error
}

func (e postPublicationCleanupError) Error() string {
	return fmt.Sprintf("repository update was published but target cleanup is incomplete: %v", e.err)
}

func (e postPublicationCleanupError) Unwrap() error {
	return e.err
}

type pendingTargetDeletion struct {
	targetName string
	name       string
	path       string
}

func (p pendingTargetDeletion) isReferencedBy(re *Editor) (bool, error) {
	target, ok := re.Targets().Signed.Targets[p.targetName]
	if !ok {
		return false, nil
	}

	hash, err := utils.PreferredHash(target.Hashes)
	if err != nil {
		return false, err
	}

	referencedPath := filepath.Join(re.OutDir(), "targets", hash+"."+p.targetName)
	return filepath.Clean(p.path) == filepath.Clean(referencedPath), nil
}

func cleanupPendingTargetFiles(re *Editor, pendingFiles []pendingTargetDeletion) error {
	for _, targetFile := range pendingFiles {
		stillReferenced, err := targetFile.isReferencedBy(re)
		if err != nil {
			return fmt.Errorf("failed to check pending target file %q: %w", targetFile.name, err)
		}
		if stillReferenced {
			continue
		}
		if err := os.Remove(targetFile.path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove target file %q: %w", targetFile.name, err)
		}
	}
	return nil
}

func (opts *Options) deleteTargets(re *Editor) ([]pendingTargetDeletion, bool, error) {
	var deletedFiles []pendingTargetDeletion
	hasDeletion := len(opts.DeleteFulcioTargets) > 0 || len(opts.DeleteCtlogTargets) > 0 ||
		len(opts.DeleteRekorTargets) > 0 || len(opts.DeleteTsaTargets) > 0
	metadataChanged := false
	deleteTargetGroup := func(names []string, kind sigstore.TargetKind, label string) error {
		for _, name := range names {
			files, changed, err := deleteTarget(re, name, kind)
			if err != nil {
				return fmt.Errorf("failed to delete %s target %q: %w", label, name, err)
			}
			deletedFiles = append(deletedFiles, files...)
			metadataChanged = metadataChanged || changed
		}
		return nil
	}

	if err := deleteTargetGroup(opts.DeleteFulcioTargets, sigstore.TargetCertificateAuthority, "Fulcio"); err != nil {
		return nil, false, err
	}
	if err := deleteTargetGroup(opts.DeleteCtlogTargets, sigstore.TargetCtlog, "CTLog"); err != nil {
		return nil, false, err
	}
	if err := deleteTargetGroup(opts.DeleteRekorTargets, sigstore.TargetTlog, "Rekor"); err != nil {
		return nil, false, err
	}
	if err := deleteTargetGroup(opts.DeleteTsaTargets, sigstore.TargetTimestampAuthority, "TSA"); err != nil {
		return nil, false, err
	}

	return deletedFiles, hasDeletion && !metadataChanged, nil
}

func hasNonDeletionChanges(opts *Options) bool {
	return opts.FulcioTarget != "" || opts.CtlogTarget != "" ||
		opts.RekorTarget != "" || opts.TsaTarget != "" ||
		opts.TargetsExpires != nil || opts.SnapshotExpires != nil ||
		opts.TimestampExpires != nil || opts.TargetsVersion != nil ||
		opts.SnapshotVersion != nil || opts.TimestampVersion != nil ||
		opts.IncomingMetadata != ""
}

func deleteTarget(re *Editor, targetName string, kind sigstore.TargetKind) ([]pendingTargetDeletion, bool, error) {
	// Build the set of expected filenames from the metadata before removing the entry.
	var expectedNames []string
	expectedNames = append(expectedNames, targetName)
	_, targetInMetadata := re.Targets().Signed.Targets[targetName]
	var historicalName string
	if tf, ok := re.Targets().Signed.Targets[targetName]; ok {
		hashStr, err := utils.PreferredHash(tf.Hashes)
		if err == nil {
			expectedNames = append(expectedNames, hashStr+"."+targetName)
		}
	} else {
		var err error
		historicalName, err = findHistoricalTargetFile(re.OutDir(), targetName)
		if err != nil {
			return nil, false, err
		}
		if historicalName == "" {
			return nil, false, fmt.Errorf("target %q not found in metadata", targetName)
		}
		expectedNames = append(expectedNames, historicalName)
	}

	if targetInMetadata {
		if err := re.RemoveTarget(targetName); err != nil {
			return nil, false, fmt.Errorf("failed to remove target %q from metadata: %w", targetName, err)
		}
	}

	targetsDir := filepath.Join(re.OutDir(), "targets")
	entries, err := os.ReadDir(targetsDir)
	if err != nil {
		return nil, false, fmt.Errorf("targets directory does not exist: %w", err)
	}

	found := false
	var deletedFiles []pendingTargetDeletion
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		matched := false
		for _, expected := range expectedNames {
			if name == expected {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		found = true
		filePath := filepath.Join(targetsDir, name)

		derBytes, err := sigstore.LoadDERBytes(filePath)
		if err != nil {
			return nil, false, fmt.Errorf("failed to parse DER from target file %q: %w", name, err)
		}
		if len(derBytes) == 0 {
			return nil, false, fmt.Errorf("target file %q contains no DER blocks", name)
		}

		// A target missing from the latest metadata was already published as
		// deleted. Its remaining file only needs cleanup; the trust bundle was
		// updated by the committed operation and must not be edited again.
		if !targetInMetadata {
			deletedFiles = append(deletedFiles, pendingTargetDeletion{
				targetName: targetName,
				name:       name,
				path:       filePath,
			})
			continue
		}

		uri := re.TrustBundle.GetURIForTarget(kind, derBytes[0])

		if err := re.TrustBundle.DeleteTarget(kind, derBytes[0]); err != nil {
			return nil, false, fmt.Errorf("failed to delete target from trust bundle: %w", err)
		}

		if uri != "" {
			if err := re.TrustBundle.UpdateSigningConfigTarget(kind, uri); err != nil {
				return nil, false, fmt.Errorf("failed to update signing config target: %w", err)
			}
		}

		// Keep the file in place until SignAndWrite succeeds.
		deletedFiles = append(deletedFiles, pendingTargetDeletion{
			targetName: targetName,
			name:       name,
			path:       filePath,
		})
	}

	if !found {
		if !targetInMetadata && historicalName != "" {
			// The deletion was already published and the physical file is
			// already gone; cleanup retries are intentionally idempotent.
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("target file %q not found in targets directory", targetName)
	}

	return deletedFiles, targetInMetadata, nil
}

// findHistoricalTargetFile recovers the exact hash-prefixed target path from
// the newest versioned targets metadata that still references targetName. This
// supports retrying cleanup after a deletion was published but its physical
// file could not be removed.
func findHistoricalTargetFile(outDir, targetName string) (string, error) {
	entries, err := os.ReadDir(outDir)
	if err != nil {
		return "", fmt.Errorf("failed to read repository directory: %w", err)
	}

	var bestVersion int64 = -1
	var bestName string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".targets.json") {
			continue
		}
		versionText := strings.TrimSuffix(entry.Name(), ".targets.json")
		version, err := strconv.ParseInt(versionText, 10, 64)
		if err != nil || version < 0 || version <= bestVersion {
			continue
		}

		md := &tufmeta.Metadata[tufmeta.TargetsType]{}
		if _, err := md.FromFile(filepath.Join(outDir, entry.Name())); err != nil {
			continue
		}
		target, ok := md.Signed.Targets[targetName]
		if !ok {
			continue
		}
		hash, err := utils.PreferredHash(target.Hashes)
		if err != nil {
			return "", err
		}
		bestVersion = version
		bestName = hash + "." + targetName
	}

	return bestName, nil
}

func (opts *Options) setFulcioTarget(re *Editor) error {
	if opts.FulcioTarget == "" {
		return nil
	}

	if !isValidStatus(opts.FulcioStatus) {
		return fmt.Errorf("invalid Fulcio status: %q (must be Active or Expired)", opts.FulcioStatus)
	}

	targetName := filepath.Base(opts.FulcioTarget)
	tf, err := editor.BuildTargetFiles(opts.FulcioTarget, opts.HashAlgo)
	if err != nil {
		return fmt.Errorf("failed to build target metadata: %w", err)
	}
	if err := editor.SetTargetCustom(tf, map[string]interface{}{
		"sigstore": map[string]interface{}{
			"status": opts.FulcioStatus,
			"uri":    opts.FulcioURI,
			"usage":  "Fulcio",
		},
	}); err != nil {
		return fmt.Errorf("failed to set custom metadata: %w", err)
	}
	re.AddTarget(targetName, tf)

	if err := re.CopyTargetToRepo(opts.FulcioTarget, targetName); err != nil {
		return fmt.Errorf("failed to copy target file: %w", err)
	}

	derBytes, err := sigstore.LoadDERBytes(opts.FulcioTarget)
	if err != nil {
		return fmt.Errorf("failed to load DER bytes: %w", err)
	}

	now := currentTimestamp()
	start, end := validForFromStatus(opts.FulcioStatus, now)

	var certs []*commonpb.X509Certificate
	for _, der := range derBytes {
		certs = append(certs, &commonpb.X509Certificate{RawBytes: der})
	}

	subject := sigstore.ExtractSubjectFromCert(opts.FulcioTarget)

	ca := &trustrootpb.CertificateAuthority{
		Subject: &subject,
		Uri:     opts.FulcioURI,
		CertChain: &commonpb.X509CertificateChain{
			Certificates: certs,
		},
		ValidFor: &commonpb.TimeRange{Start: start, End: end},
		Operator: opts.Operator,
	}

	if err := re.TrustBundle.SetCertificateAuthority(ca, sigstore.TargetCertificateAuthority); err != nil {
		return fmt.Errorf("failed to set certificate authority: %w", err)
	}

	validFor := &commonpb.TimeRange{Start: start, End: end}
	for _, oidcURI := range opts.OIDCURIs {
		if err := re.TrustBundle.AddOIDCURL(oidcURI, validFor, opts.Operator); err != nil {
			return fmt.Errorf("failed to add OIDC URL: %w", err)
		}
	}

	return nil
}

func (opts *Options) setCtlogTarget(re *Editor) error {
	if opts.CtlogTarget == "" {
		return nil
	}

	if !isValidStatus(opts.CtlogStatus) {
		return fmt.Errorf("invalid CTLog status: %q (must be Active or Expired)", opts.CtlogStatus)
	}

	targetName := filepath.Base(opts.CtlogTarget)
	tf, err := editor.BuildTargetFiles(opts.CtlogTarget, opts.HashAlgo)
	if err != nil {
		return fmt.Errorf("failed to build target metadata: %w", err)
	}
	if err := editor.SetTargetCustom(tf, map[string]interface{}{
		"sigstore": map[string]interface{}{
			"status": opts.CtlogStatus,
			"uri":    opts.CtlogURI,
			"usage":  "CTFE",
		},
	}); err != nil {
		return fmt.Errorf("failed to set custom metadata: %w", err)
	}
	re.AddTarget(targetName, tf)

	if err := re.CopyTargetToRepo(opts.CtlogTarget, targetName); err != nil {
		return fmt.Errorf("failed to copy target file: %w", err)
	}

	derBytes, err := sigstore.LoadDERBytes(opts.CtlogTarget)
	if err != nil {
		return fmt.Errorf("failed to load DER bytes: %w", err)
	}

	keyDetails, err := detectPublicKeyDetails(opts.CtlogTarget)
	if err != nil {
		return fmt.Errorf("failed to detect public key details: %w", err)
	}

	rawBytes := derBytes[0]
	keyID := sha256.Sum256(rawBytes)

	now := currentTimestamp()
	start, end := validForFromStatus(opts.CtlogStatus, now)

	log := &trustrootpb.TransparencyLogInstance{
		BaseUrl:       opts.CtlogURI,
		HashAlgorithm: commonpb.HashAlgorithm_SHA2_256,
		PublicKey: &commonpb.PublicKey{
			RawBytes:   rawBytes,
			KeyDetails: keyDetails,
			ValidFor:   &commonpb.TimeRange{Start: start, End: end},
		},
		LogId:    &commonpb.LogId{KeyId: keyID[:]},
		Operator: opts.Operator,
	}

	if err := re.TrustBundle.SetTransparencyLog(log, sigstore.TargetCtlog); err != nil {
		return fmt.Errorf("failed to set CTLog: %w", err)
	}

	return nil
}

func (opts *Options) setRekorTarget(re *Editor) error {
	if opts.RekorTarget == "" {
		return nil
	}

	if !isValidStatus(opts.RekorStatus) {
		return fmt.Errorf("invalid Rekor status: %q (must be Active or Expired)", opts.RekorStatus)
	}

	targetName := filepath.Base(opts.RekorTarget)
	tf, err := editor.BuildTargetFiles(opts.RekorTarget, opts.HashAlgo)
	if err != nil {
		return fmt.Errorf("failed to build target metadata: %w", err)
	}
	if err := editor.SetTargetCustom(tf, map[string]interface{}{
		"sigstore": map[string]interface{}{
			"status": opts.RekorStatus,
			"uri":    opts.RekorURI,
			"usage":  "Rekor",
		},
	}); err != nil {
		return fmt.Errorf("failed to set custom metadata: %w", err)
	}
	re.AddTarget(targetName, tf)

	if err := re.CopyTargetToRepo(opts.RekorTarget, targetName); err != nil {
		return fmt.Errorf("failed to copy target file: %w", err)
	}

	derBytes, err := sigstore.LoadDERBytes(opts.RekorTarget)
	if err != nil {
		return fmt.Errorf("failed to load DER bytes: %w", err)
	}

	keyDetails, err := detectPublicKeyDetails(opts.RekorTarget)
	if err != nil {
		return fmt.Errorf("failed to detect public key details: %w", err)
	}

	rawBytes := derBytes[0]
	keyID := sha256.Sum256(rawBytes)

	now := currentTimestamp()
	start, end := validForFromStatus(opts.RekorStatus, now)

	log := &trustrootpb.TransparencyLogInstance{
		BaseUrl:       opts.RekorURI,
		HashAlgorithm: commonpb.HashAlgorithm_SHA2_256,
		PublicKey: &commonpb.PublicKey{
			RawBytes:   rawBytes,
			KeyDetails: keyDetails,
			ValidFor:   &commonpb.TimeRange{Start: start, End: end},
		},
		LogId:    &commonpb.LogId{KeyId: keyID[:]},
		Operator: opts.Operator,
	}

	if err := re.TrustBundle.SetTransparencyLog(log, sigstore.TargetTlog); err != nil {
		return fmt.Errorf("failed to set Rekor: %w", err)
	}

	return nil
}

func (opts *Options) setTsaTarget(re *Editor) error {
	if opts.TsaTarget == "" {
		return nil
	}

	if !isValidStatus(opts.TsaStatus) {
		return fmt.Errorf("invalid TSA status: %q (must be Active or Expired)", opts.TsaStatus)
	}

	targetName := filepath.Base(opts.TsaTarget)
	tf, err := editor.BuildTargetFiles(opts.TsaTarget, opts.HashAlgo)
	if err != nil {
		return fmt.Errorf("failed to build target metadata: %w", err)
	}
	if err := editor.SetTargetCustom(tf, map[string]interface{}{
		"sigstore": map[string]interface{}{
			"status": opts.TsaStatus,
			"uri":    opts.TsaURI,
			"usage":  "TSA",
		},
	}); err != nil {
		return fmt.Errorf("failed to set custom metadata: %w", err)
	}
	re.AddTarget(targetName, tf)

	if err := re.CopyTargetToRepo(opts.TsaTarget, targetName); err != nil {
		return fmt.Errorf("failed to copy target file: %w", err)
	}

	derBytes, err := sigstore.LoadDERBytes(opts.TsaTarget)
	if err != nil {
		return fmt.Errorf("failed to load DER bytes: %w", err)
	}

	now := currentTimestamp()
	start, end := validForFromStatus(opts.TsaStatus, now)

	var certs []*commonpb.X509Certificate
	for _, der := range derBytes {
		certs = append(certs, &commonpb.X509Certificate{RawBytes: der})
	}

	subject := sigstore.ExtractSubjectFromCert(opts.TsaTarget)

	tsa := &trustrootpb.CertificateAuthority{
		Subject: &subject,
		Uri:     opts.TsaURI,
		CertChain: &commonpb.X509CertificateChain{
			Certificates: certs,
		},
		ValidFor: &commonpb.TimeRange{Start: start, End: end},
		Operator: opts.Operator,
	}

	if err := re.TrustBundle.SetCertificateAuthority(tsa, sigstore.TargetTimestampAuthority); err != nil {
		return fmt.Errorf("failed to set TSA: %w", err)
	}

	return nil
}

func addTrustBundleTargets(re *Editor, trustedRootPath, signingConfigPath, hashAlgo string) error {
	if utils.FileExists(trustedRootPath) {
		tf, err := editor.BuildTargetFiles(trustedRootPath, hashAlgo)
		if err != nil {
			return fmt.Errorf("failed to build trusted root target: %w", err)
		}
		re.AddTarget("trusted_root.json", tf)
	}

	if utils.FileExists(signingConfigPath) {
		tf, err := editor.BuildTargetFiles(signingConfigPath, hashAlgo)
		if err != nil {
			return fmt.Errorf("failed to build signing config target: %w", err)
		}
		re.AddTarget("signing_config.v0.2.json", tf)
	}

	return nil
}

func isValidStatus(status string) bool {
	return status == "Active" || status == "Expired"
}

func currentTimestamp() *timestamppb.Timestamp {
	now := time.Now().UTC().Truncate(time.Second)
	return timestamppb.New(now)
}

func validForFromStatus(status string, now *timestamppb.Timestamp) (*timestamppb.Timestamp, *timestamppb.Timestamp) {
	if status == "Expired" {
		return nil, now
	}
	return now, nil
}

func detectPublicKeyDetails(path string) (commonpb.PublicKeyDetails, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("failed to read key file %s: %w", path, err)
	}

	pub, err := cryptoutils.UnmarshalPEMToPublicKey(data)
	if err != nil {
		certs, certErr := cryptoutils.UnmarshalCertificatesFromPEM(data)
		if certErr != nil || len(certs) == 0 {
			return 0, fmt.Errorf("failed to parse public key or certificate from %s: %w", path, err)
		}
		pub = certs[0].PublicKey
	}

	details, err := sigstorepkg.GetDefaultPublicKeyDetails(pub)
	if err != nil {
		return 0, fmt.Errorf("failed to detect key details for %s: %w", path, err)
	}

	return details, nil
}
