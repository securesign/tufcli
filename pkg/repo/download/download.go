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

// Package download provides functions for downloading targets from
// TUF repositories with full metadata verification.
package download

import (
	"fmt"

	internal "github.com/securesign/tufcli/internal/download"
)

// Options contains all configuration for a download operation, including
// root trust anchor, remote URLs, output directory, and target selection.
type Options = internal.Options

// Download downloads targets from a TUF repository with full metadata verification.
// It refreshes the TUF metadata, resolves the requested targets, and downloads
// each one to the output directory with integrity checks.
func Download(opts *Options) error {
	if opts == nil {
		return fmt.Errorf("opts must not be nil")
	}
	return internal.Run(opts)
}
