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
	"time"

	"github.com/securesign/tufcli/internal/signingconfig"
	"github.com/spf13/cobra"
)

// signingConfigCmd represents the signing-config command group
var signingConfigCmd = &cobra.Command{
	Use:   "signing-config",
	Short: "Manage Sigstore signing configuration files",
	Long:  "Commands for creating, modifying, and inspecting Sigstore signing config files (signing_config.v0.2.json).",
}

var (
	scCreateOutput       string
	scCreateBaseConfig   string
	scCreateWithDefaults bool
)

var scCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new signing config file",
	Long:  "Create a new Sigstore signing configuration file.",
	RunE: func(_ *cobra.Command, _ []string) error {
		log.Infof("Creating signing config at %s...", scCreateOutput)

		err := signingconfig.Create(signingconfig.CreateOptions{
			Output:              scCreateOutput,
			BaseConfig:          scCreateBaseConfig,
			WithDefaultServices: scCreateWithDefaults,
		})

		if err != nil {
			return fmt.Errorf("failed to create signing config: %w", err)
		}

		log.Infof("Successfully created signing config at %s", scCreateOutput)
		return nil
	},
}

var (
	scAddURLConfig     string
	scAddURLType       string
	scAddURLURL        string
	scAddURLAPIVersion uint32
	scAddURLOperator   string
	scAddURLStartTime  string
	scAddURLEndTime    string
	scAddURLOutput     string
)

var scAddURLCmd = &cobra.Command{
	Use:   "add-url",
	Short: "Add a service URL to a signing config",
	Long:  "Add a service URL to a Sigstore signing configuration file.",
	RunE: func(_ *cobra.Command, _ []string) error {
		startTime, err := parseTime(scAddURLStartTime)
		if err != nil {
			return fmt.Errorf("failed to parse start time: %w", err)
		}

		var endTime *time.Time
		if scAddURLEndTime != "" {
			t, err := parseTime(scAddURLEndTime)
			if err != nil {
				return fmt.Errorf("failed to parse end time: %w", err)
			}
			endTime = &t
		}

		log.Infof("Adding %s URL %s to signing config...", scAddURLType, scAddURLURL)

		err = signingconfig.AddURL(signingconfig.AddURLOptions{
			ConfigPath: scAddURLConfig,
			OutputPath: scAddURLOutput,
			Type:       scAddURLType,
			URL:        scAddURLURL,
			APIVersion: scAddURLAPIVersion,
			Operator:   scAddURLOperator,
			StartTime:  startTime,
			EndTime:    endTime,
		})

		if err != nil {
			return fmt.Errorf("failed to add URL: %w", err)
		}

		log.Infof("Successfully added %s URL %s", scAddURLType, scAddURLURL)
		return nil
	},
}

var (
	scRemoveURLConfig string
	scRemoveURLType   string
	scRemoveURLURL    string
	scRemoveURLOutput string
)

var scRemoveURLCmd = &cobra.Command{
	Use:   "remove-url",
	Short: "Remove a service URL from a signing config",
	Long:  "Remove a service URL from a Sigstore signing configuration file.",
	RunE: func(_ *cobra.Command, _ []string) error {
		log.Infof("Removing %s URL %s from signing config...", scRemoveURLType, scRemoveURLURL)

		err := signingconfig.RemoveURL(signingconfig.RemoveURLOptions{
			ConfigPath: scRemoveURLConfig,
			OutputPath: scRemoveURLOutput,
			Type:       scRemoveURLType,
			URL:        scRemoveURLURL,
		})

		if err != nil {
			return fmt.Errorf("failed to remove URL: %w", err)
		}

		log.Infof("Successfully removed %s URL %s", scRemoveURLType, scRemoveURLURL)
		return nil
	},
}

var (
	scSetConfigConfig   string
	scSetConfigType     string
	scSetConfigSelector string
	scSetConfigCount    uint32
	scSetConfigOutput   string
)

var scSetConfigCmd = &cobra.Command{
	Use:   "set-config",
	Short: "Set service selection configuration",
	Long:  "Set service selection configuration for a Sigstore signing configuration file.",
	RunE: func(_ *cobra.Command, _ []string) error {
		log.Infof("Setting %s config: selector=%s, count=%d...", scSetConfigType, scSetConfigSelector, scSetConfigCount)

		err := signingconfig.SetConfig(signingconfig.SetConfigOptions{
			ConfigPath: scSetConfigConfig,
			OutputPath: scSetConfigOutput,
			Type:       scSetConfigType,
			Selector:   scSetConfigSelector,
			Count:      scSetConfigCount,
		})

		if err != nil {
			return fmt.Errorf("failed to set config: %w", err)
		}

		log.Infof("Successfully set %s config", scSetConfigType)
		return nil
	},
}

var (
	scInspectConfig string
	scInspectFormat string
)

var scInspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "Inspect a signing config file",
	Long:  "Inspect a Sigstore signing configuration file and display its contents.",
	RunE: func(_ *cobra.Command, _ []string) error {
		result, err := signingconfig.Inspect(signingconfig.InspectOptions{
			ConfigPath: scInspectConfig,
			Format:     scInspectFormat,
		})

		if err != nil {
			return fmt.Errorf("failed to inspect signing config: %w", err)
		}

		fmt.Print(result)
		return nil
	},
}

func init() {
	// Add flags to create command
	scCreateCmd.Flags().StringVarP(&scCreateOutput, "output", "o", "signing_config.v0.2.json", "Path to output signing config file")
	scCreateCmd.Flags().StringVar(&scCreateBaseConfig, "base-config", "", "Path to base signing config to copy from")
	scCreateCmd.Flags().BoolVar(&scCreateWithDefaults, "with-default-services", false, "Fetch default services from the public Sigstore TUF repository")
	scCreateCmd.MarkFlagsMutuallyExclusive("base-config", "with-default-services")

	// Add flags to add-url command
	scAddURLCmd.Flags().StringVarP(&scAddURLConfig, "config", "c", "signing_config.v0.2.json", "Path to signing config file")
	scAddURLCmd.Flags().StringVarP(&scAddURLType, "type", "t", "", "Service type (ca, oidc, rekor, tsa)")
	scAddURLCmd.Flags().StringVarP(&scAddURLURL, "url", "u", "", "Service URL to add")
	scAddURLCmd.Flags().Uint32Var(&scAddURLAPIVersion, "api-version", 1, "Major API version")
	scAddURLCmd.Flags().StringVar(&scAddURLOperator, "operator", "sigstore.dev", "Service operator")
	scAddURLCmd.Flags().StringVar(&scAddURLStartTime, "start-time", "", "Start time (RFC 3339 format or relative like 'in 7 days')")
	scAddURLCmd.Flags().StringVar(&scAddURLEndTime, "end-time", "", "End time (RFC 3339 format or relative like 'in 7 days')")
	scAddURLCmd.Flags().StringVarP(&scAddURLOutput, "output", "o", "", "Path to output signing config file (defaults to input config)")
	scAddURLCmd.MarkFlagRequired("type")
	scAddURLCmd.MarkFlagRequired("url")
	scAddURLCmd.MarkFlagRequired("start-time")

	// Add flags to remove-url command
	scRemoveURLCmd.Flags().StringVarP(&scRemoveURLConfig, "config", "c", "signing_config.v0.2.json", "Path to signing config file")
	scRemoveURLCmd.Flags().StringVarP(&scRemoveURLType, "type", "t", "", "Service type (ca, oidc, rekor, tsa)")
	scRemoveURLCmd.Flags().StringVarP(&scRemoveURLURL, "url", "u", "", "Service URL to remove")
	scRemoveURLCmd.Flags().StringVarP(&scRemoveURLOutput, "output", "o", "", "Path to output signing config file (defaults to input config)")
	scRemoveURLCmd.MarkFlagRequired("type")
	scRemoveURLCmd.MarkFlagRequired("url")

	// Add flags to set-config command
	scSetConfigCmd.Flags().StringVarP(&scSetConfigConfig, "config", "c", "signing_config.v0.2.json", "Path to signing config file")
	scSetConfigCmd.Flags().StringVarP(&scSetConfigType, "type", "t", "", "Service type (rekor, tsa)")
	scSetConfigCmd.Flags().StringVarP(&scSetConfigSelector, "selector", "s", "", "Service selector (ALL, ANY, EXACT)")
	scSetConfigCmd.Flags().Uint32VarP(&scSetConfigCount, "count", "n", 0, "Service count (required for EXACT selector)")
	scSetConfigCmd.Flags().StringVarP(&scSetConfigOutput, "output", "o", "", "Path to output signing config file (defaults to input config)")
	scSetConfigCmd.MarkFlagRequired("type")
	scSetConfigCmd.MarkFlagRequired("selector")

	// Add flags to inspect command
	scInspectCmd.Flags().StringVarP(&scInspectConfig, "config", "c", "signing_config.v0.2.json", "Path to signing config file")
	scInspectCmd.Flags().StringVarP(&scInspectFormat, "format", "f", "text", "Output format (text, json)")

	// Add subcommands to signing-config command
	signingConfigCmd.AddCommand(scCreateCmd)
	signingConfigCmd.AddCommand(scAddURLCmd)
	signingConfigCmd.AddCommand(scRemoveURLCmd)
	signingConfigCmd.AddCommand(scSetConfigCmd)
	signingConfigCmd.AddCommand(scInspectCmd)
}
