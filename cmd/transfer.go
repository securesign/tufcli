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

	"github.com/spf13/cobra"
)

// transferMetadataCmd represents the transfer-metadata command
var transferMetadataCmd = &cobra.Command{
	Use:   "transfer-metadata",
	Short: "Transfer a TUF repository's metadata from a previous root to a new root",
	Long:  `Transfer metadata from a previous root to a new root in a TUF repository.`,
	RunE: func(_ *cobra.Command, _ []string) error {
		log.Info("Transferring metadata...")
		return fmt.Errorf("transfer-metadata command not yet implemented")
	},
}

func init() {
	// Add flags for transfer-metadata command
	// TODO: Add flags for old root, new root, etc.
}
