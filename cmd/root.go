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
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	// SpecVersion represents the TUF specification version
	SpecVersion = "1.0.0"
	// Version represents the tufcli version
	Version = "0.1.0"
)

var (
	logLevel string
	log      = logrus.New()
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "tufcli",
	Short:   "A CLI tool for creating and managing TUF repositories",
	Long:    `tufcli is a command-line utility for creating and signing The Update Framework (TUF) repositories.`,
	Version: Version,
	PersistentPreRun: func(_ *cobra.Command, _ []string) {
		// Initialize logger
		level, err := logrus.ParseLevel(logLevel)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid log level: %s\n", logLevel)
			os.Exit(1)
		}
		log.SetLevel(level)
		log.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVarP(&logLevel, "log-level", "l", "info", "Set logging verbosity [trace|debug|info|warn|error]")

	// Add subcommands
	rootCmd.AddCommand(createCmd)
	rootCmd.AddCommand(cloneCmd)
	rootCmd.AddCommand(downloadCmd)
	rootCmd.AddCommand(updateCmd)
	rootCmd.AddCommand(delegationCmd)
	rootCmd.AddCommand(rootMetadataCmd)
	rootCmd.AddCommand(transferMetadataCmd)
	rootCmd.AddCommand(rhtasCmd)
}
