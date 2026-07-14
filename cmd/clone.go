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

// cloneCmd represents the clone command
var cloneCmd = &cobra.Command{
	Use:   "clone",
	Short: "Clone a TUF repository",
	Long:  `Clone a TUF repository, including metadata and some or all targets.`,
	RunE: func(_ *cobra.Command, _ []string) error {
		log.Info("Cloning TUF repository...")
		return fmt.Errorf("clone command not yet implemented")
	},
}

func init() {
	// Add flags for clone command
	// TODO: Add flags for source URL, output directory, etc.
}
