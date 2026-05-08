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
	"strings"
	"time"

	"github.com/securesign/tufcli/internal/root"
	"github.com/securesign/tufcli/internal/schema"
	"github.com/spf13/cobra"
)

// rootMetadataCmd represents the root metadata command
var rootMetadataCmd = &cobra.Command{
	Use:   "root",
	Short: "Manipulate a root.json metadata file",
	Long:  `Commands for manipulating root.json metadata files in a TUF repository.`,
}

var (
	rootInitPath    string
	rootInitVersion uint64
)

var rootInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new root.json file",
	Long:  `Create a new root.json metadata file with default settings.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		log.Infof("Initializing root.json at %s...", rootInitPath)

		err := root.Init(root.InitOptions{
			Path:    rootInitPath,
			Version: rootInitVersion,
		})

		if err != nil {
			return fmt.Errorf("failed to initialize root.json: %w", err)
		}

		log.Infof("Successfully created root.json at %s", rootInitPath)
		log.Warnf("Default threshold is set to %d for all roles. You should update this before signing!", root.DefaultThreshold)
		return nil
	},
}

var (
	rootExpirePath string
	rootExpireTime string
)

var rootExpireCmd = &cobra.Command{
	Use:   "expire",
	Short: "Set the expiration date for root.json",
	Long:  `Set the expiration date for root.json. Time can be in RFC 3339 format or relative like "in 7 days".`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Parse the time
		expires, err := parseTime(rootExpireTime)
		if err != nil {
			return fmt.Errorf("failed to parse time: %w", err)
		}

		log.Infof("Setting root.json expiration to %s...", expires.Format(time.RFC3339))

		err = root.Expire(root.ExpireOptions{
			Path:    rootExpirePath,
			Expires: expires,
		})

		if err != nil {
			return fmt.Errorf("failed to set expiration: %w", err)
		}

		log.Infof("Successfully set expiration to %s", expires.Format(time.RFC3339))
		return nil
	},
}

var (
	rootSetThresholdPath      string
	rootSetThresholdRole      string
	rootSetThresholdThreshold uint64
)

var rootSetThresholdCmd = &cobra.Command{
	Use:   "set-threshold",
	Short: "Set the signature count threshold for a role",
	Long:  `Set the minimum number of signatures required for a role (root, snapshot, targets, or timestamp).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Parse role type
		roleType := schema.RoleType(rootSetThresholdRole)
		if !isValidRole(roleType) {
			return fmt.Errorf("invalid role: %s (must be root, snapshot, targets, or timestamp)", rootSetThresholdRole)
		}

		log.Infof("Setting threshold for role '%s' to %d...", rootSetThresholdRole, rootSetThresholdThreshold)

		err := root.SetThreshold(root.SetThresholdOptions{
			Path:      rootSetThresholdPath,
			Role:      roleType,
			Threshold: rootSetThresholdThreshold,
		})

		if err != nil {
			return fmt.Errorf("failed to set threshold: %w", err)
		}

		log.Infof("Successfully set threshold for role '%s' to %d", rootSetThresholdRole, rootSetThresholdThreshold)
		return nil
	},
}

var rootBumpVersionPath string

var rootBumpVersionCmd = &cobra.Command{
	Use:   "bump-version",
	Short: "Increment the version number",
	Long:  `Increment the version number of root.json by 1.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		log.Info("Incrementing version...")

		err := root.BumpVersion(root.BumpVersionOptions{
			Path: rootBumpVersionPath,
		})

		if err != nil {
			return fmt.Errorf("failed to bump version: %w", err)
		}

		log.Info("Successfully incremented version")
		return nil
	},
}

var (
	rootSetVersionPath    string
	rootSetVersionVersion uint64
)

var rootSetVersionCmd = &cobra.Command{
	Use:   "set-version",
	Short: "Set the version number",
	Long:  `Set a specific version number for root.json.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		log.Infof("Setting version to %d...", rootSetVersionVersion)

		err := root.SetVersion(root.SetVersionOptions{
			Path:    rootSetVersionPath,
			Version: rootSetVersionVersion,
		})

		if err != nil {
			return fmt.Errorf("failed to set version: %w", err)
		}

		log.Infof("Successfully set version to %d", rootSetVersionVersion)
		return nil
	},
}

var (
	rootRemoveKeyPath string
	rootRemoveKeyID   string
	rootRemoveKeyRole string
)

var rootRemoveKeyCmd = &cobra.Command{
	Use:   "remove-key",
	Short: "Remove a key from root.json",
	Long:  `Remove a key ID either entirely or from a single role. If no role is specified, the key is removed from all roles and the keys map.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var rolePtr *schema.RoleType
		if rootRemoveKeyRole != "" {
			roleType := schema.RoleType(rootRemoveKeyRole)
			if !isValidRole(roleType) {
				return fmt.Errorf("invalid role: %s (must be root, snapshot, targets, or timestamp)", rootRemoveKeyRole)
			}
			rolePtr = &roleType
		}

		if rolePtr != nil {
			log.Infof("Removing key %s from role '%s'...", rootRemoveKeyID, rootRemoveKeyRole)
		} else {
			log.Infof("Removing key %s from all roles...", rootRemoveKeyID)
		}

		err := root.RemoveKey(root.RemoveKeyOptions{
			Path:  rootRemoveKeyPath,
			KeyID: rootRemoveKeyID,
			Role:  rolePtr,
		})

		if err != nil {
			return fmt.Errorf("failed to remove key: %w", err)
		}

		log.Info("Successfully removed key")
		return nil
	},
}

var (
	rootAddKeyPath  string
	rootAddKeyKeys  []string
	rootAddKeyRoles []string
)

var rootAddKeyCmd = &cobra.Command{
	Use:   "add-key",
	Short: "Add one or more keys to root.json",
	Long:  `Add public or private keys to specified roles. Keys should be in PEM format (RSA, ECDSA, or ED25519).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(rootAddKeyKeys) == 0 {
			return fmt.Errorf("at least one key must be specified")
		}
		if len(rootAddKeyRoles) == 0 {
			return fmt.Errorf("at least one role must be specified")
		}

		// Parse roles
		roles := make([]schema.RoleType, 0, len(rootAddKeyRoles))
		for _, roleStr := range rootAddKeyRoles {
			roleType := schema.RoleType(roleStr)
			if !isValidRole(roleType) {
				return fmt.Errorf("invalid role: %s (must be root, snapshot, targets, or timestamp)", roleStr)
			}
			roles = append(roles, roleType)
		}

		log.Infof("Adding %d key(s) to roles: %v...", len(rootAddKeyKeys), rootAddKeyRoles)

		keyIDs, err := root.AddKey(root.AddKeyOptions{
			Path:     rootAddKeyPath,
			KeyPaths: rootAddKeyKeys,
			Roles:    roles,
		})

		if err != nil {
			return fmt.Errorf("failed to add key: %w", err)
		}

		for _, keyID := range keyIDs {
			log.Infof("Added key: %s", keyID)
		}

		return nil
	},
}

var (
	rootGenRsaKeyPath     string
	rootGenRsaKeyOutput   string
	rootGenRsaKeyBits     int
	rootGenRsaKeyExponent int
	rootGenRsaKeyRoles    []string
)

var rootGenRsaKeyCmd = &cobra.Command{
	Use:   "gen-rsa-key",
	Short: "Generate a new RSA key pair",
	Long:  `Generate a new RSA key pair using OpenSSL, add it to specified roles, and save it to a file.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(rootGenRsaKeyRoles) == 0 {
			return fmt.Errorf("at least one role must be specified")
		}

		// Parse roles
		roles := make([]schema.RoleType, 0, len(rootGenRsaKeyRoles))
		for _, roleStr := range rootGenRsaKeyRoles {
			roleType := schema.RoleType(roleStr)
			if !isValidRole(roleType) {
				return fmt.Errorf("invalid role: %s (must be root, snapshot, targets, or timestamp)", roleStr)
			}
			roles = append(roles, roleType)
		}

		log.Infof("Generating %d-bit RSA key...", rootGenRsaKeyBits)

		keyID, err := root.GenRsaKey(root.GenRsaKeyOptions{
			Path:     rootGenRsaKeyPath,
			KeyPath:  rootGenRsaKeyOutput,
			Bits:     rootGenRsaKeyBits,
			Exponent: rootGenRsaKeyExponent,
			Roles:    roles,
		})

		if err != nil {
			return fmt.Errorf("failed to generate RSA key: %w", err)
		}

		log.Infof("Generated key: %s", keyID)
		log.Infof("Saved key to: %s", rootGenRsaKeyOutput)

		return nil
	},
}

var (
	rootSignPath            string
	rootSignKeys            []string
	rootSignCrossSign       string
	rootSignIgnoreThreshold bool
)

var rootSignCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign root.json with private keys",
	Long:  `Sign root.json with one or more private keys. Supports cross-signing and threshold validation.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(rootSignKeys) == 0 {
			return fmt.Errorf("at least one key must be specified")
		}

		log.Infof("Signing root.json with %d key(s)...", len(rootSignKeys))

		err := root.Sign(root.SignOptions{
			Path:            rootSignPath,
			KeyPaths:        rootSignKeys,
			CrossSignPath:   rootSignCrossSign,
			IgnoreThreshold: rootSignIgnoreThreshold,
		})

		if err != nil {
			return fmt.Errorf("failed to sign root.json: %w", err)
		}

		log.Info("Successfully signed root.json")
		return nil
	},
}

func init() {
	// Add flags to init command
	rootInitCmd.Flags().StringVarP(&rootInitPath, "path", "p", "root.json", "Path to new root.json file")
	rootInitCmd.Flags().Uint64Var(&rootInitVersion, "version", 1, "Initial metadata file version")

	// Add flags to expire command
	rootExpireCmd.Flags().StringVarP(&rootExpirePath, "path", "p", "root.json", "Path to root.json file")
	rootExpireCmd.Flags().StringVarP(&rootExpireTime, "time", "t", "", "Expiration time (RFC 3339 format or relative like 'in 7 days')")
	rootExpireCmd.MarkFlagRequired("time")

	// Add flags to set-threshold command
	rootSetThresholdCmd.Flags().StringVarP(&rootSetThresholdPath, "path", "p", "root.json", "Path to root.json file")
	rootSetThresholdCmd.Flags().StringVarP(&rootSetThresholdRole, "role", "r", "", "Role name (root, snapshot, targets, or timestamp)")
	rootSetThresholdCmd.Flags().Uint64VarP(&rootSetThresholdThreshold, "threshold", "n", 0, "Signature threshold")
	rootSetThresholdCmd.MarkFlagRequired("role")
	rootSetThresholdCmd.MarkFlagRequired("threshold")

	// Add flags to bump-version command
	rootBumpVersionCmd.Flags().StringVarP(&rootBumpVersionPath, "path", "p", "root.json", "Path to root.json file")

	// Add flags to set-version command
	rootSetVersionCmd.Flags().StringVarP(&rootSetVersionPath, "path", "p", "root.json", "Path to root.json file")
	rootSetVersionCmd.Flags().Uint64VarP(&rootSetVersionVersion, "version", "n", 0, "Version number")
	rootSetVersionCmd.MarkFlagRequired("version")

	// Add flags to remove-key command
	rootRemoveKeyCmd.Flags().StringVarP(&rootRemoveKeyPath, "path", "p", "root.json", "Path to root.json file")
	rootRemoveKeyCmd.Flags().StringVar(&rootRemoveKeyID, "key-id", "", "Key ID to remove")
	rootRemoveKeyCmd.Flags().StringVarP(&rootRemoveKeyRole, "role", "r", "", "Role to remove key from (optional, if not specified removes from all roles)")
	rootRemoveKeyCmd.MarkFlagRequired("key-id")

	// Add flags to add-key command
	rootAddKeyCmd.Flags().StringVarP(&rootAddKeyPath, "path", "p", "root.json", "Path to root.json file")
	rootAddKeyCmd.Flags().StringSliceVarP(&rootAddKeyKeys, "key", "k", []string{}, "Path to key file (can be specified multiple times)")
	rootAddKeyCmd.Flags().StringSliceVarP(&rootAddKeyRoles, "role", "r", []string{}, "Role to add key to (can be specified multiple times)")
	rootAddKeyCmd.MarkFlagRequired("key")
	rootAddKeyCmd.MarkFlagRequired("role")

	// Add flags to gen-rsa-key command
	rootGenRsaKeyCmd.Flags().StringVarP(&rootGenRsaKeyPath, "path", "p", "root.json", "Path to root.json file")
	rootGenRsaKeyCmd.Flags().StringVarP(&rootGenRsaKeyOutput, "output", "o", "", "Path to save the generated key")
	rootGenRsaKeyCmd.Flags().IntVarP(&rootGenRsaKeyBits, "bits", "b", 2048, "Bit length of new key")
	rootGenRsaKeyCmd.Flags().IntVarP(&rootGenRsaKeyExponent, "exponent", "e", 65537, "Public exponent of new key")
	rootGenRsaKeyCmd.Flags().StringSliceVarP(&rootGenRsaKeyRoles, "role", "r", []string{}, "Role to add key to (can be specified multiple times)")
	rootGenRsaKeyCmd.MarkFlagRequired("output")
	rootGenRsaKeyCmd.MarkFlagRequired("role")

	// Add flags to sign command
	rootSignCmd.Flags().StringVarP(&rootSignPath, "path", "p", "root.json", "Path to root.json file")
	rootSignCmd.Flags().StringSliceVarP(&rootSignKeys, "key", "k", []string{}, "Path to private key file (can be specified multiple times)")
	rootSignCmd.Flags().StringVarP(&rootSignCrossSign, "cross-sign", "c", "", "Path to older root.json for cross-signing")
	rootSignCmd.Flags().BoolVarP(&rootSignIgnoreThreshold, "ignore-threshold", "i", false, "Ignore threshold when signing with fewer keys")
	rootSignCmd.MarkFlagRequired("key")

	// Add subcommands to root metadata command
	rootMetadataCmd.AddCommand(rootInitCmd)
	rootMetadataCmd.AddCommand(rootExpireCmd)
	rootMetadataCmd.AddCommand(rootSetThresholdCmd)
	rootMetadataCmd.AddCommand(rootBumpVersionCmd)
	rootMetadataCmd.AddCommand(rootSetVersionCmd)
	rootMetadataCmd.AddCommand(rootRemoveKeyCmd)
	rootMetadataCmd.AddCommand(rootAddKeyCmd)
	rootMetadataCmd.AddCommand(rootGenRsaKeyCmd)
	rootMetadataCmd.AddCommand(rootSignCmd)
}

// parseTime parses a time string in RFC 3339 format or relative format like "in 7 days"
func parseTime(timeStr string) (time.Time, error) {
	// Try RFC 3339 format first
	t, err := time.Parse(time.RFC3339, timeStr)
	if err == nil {
		return t, nil
	}

	// Try parsing relative time like "in 7 days"
	if strings.HasPrefix(timeStr, "in ") {
		return parseRelativeTime(timeStr)
	}

	return time.Time{}, fmt.Errorf("invalid time format: %s (expected RFC 3339 or 'in X days/hours/minutes')", timeStr)
}

// parseRelativeTime parses relative time strings like "in 7 days".
// Also accepts months/year for convenience, and bare Go duration strings (e.g. "2h30m").
func parseRelativeTime(timeStr string) (time.Time, error) {
	// Remove "in " prefix
	timeStr = strings.TrimPrefix(timeStr, "in ")
	timeStr = strings.TrimSpace(timeStr)

	// Parse duration
	if duration, err := time.ParseDuration(timeStr); err == nil {
		return schema.RoundTime(time.Now().UTC().Add(duration)), nil
	}

	var n int
	if _, err := fmt.Sscanf(timeStr, "%d", &n); err != nil {
		return time.Time{}, fmt.Errorf("failed to parse relative time: %s", timeStr)
	}

	switch {
	case strings.HasSuffix(timeStr, " hours") || strings.HasSuffix(timeStr, " hour"):
		return schema.RoundTime(time.Now().UTC().Add(time.Duration(n) * time.Hour)), nil
	case strings.HasSuffix(timeStr, " days") || strings.HasSuffix(timeStr, " day"):
		return schema.RoundTime(time.Now().UTC().AddDate(0, 0, n)), nil
	case strings.HasSuffix(timeStr, " weeks") || strings.HasSuffix(timeStr, " week"):
		return schema.RoundTime(time.Now().UTC().AddDate(0, 0, n*7)), nil
	case strings.HasSuffix(timeStr, " months") || strings.HasSuffix(timeStr, " month"):
		return schema.RoundTime(time.Now().UTC().AddDate(0, n, 0)), nil
	case strings.HasSuffix(timeStr, " years") || strings.HasSuffix(timeStr, " year"):
		return schema.RoundTime(time.Now().UTC().AddDate(n, 0, 0)), nil
	}

	return time.Time{}, fmt.Errorf("unsupported time unit in %q (use hours, days, weeks, months, or years)", timeStr)
}

// isValidRole checks if a role type is valid
func isValidRole(role schema.RoleType) bool {
	switch role {
	case schema.RoleTypeRoot, schema.RoleTypeSnapshot, schema.RoleTypeTargets, schema.RoleTypeTimestamp:
		return true
	default:
		return false
	}
}
