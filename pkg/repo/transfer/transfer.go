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

// Package transfer provides functions for transferring TUF repository
// metadata from one root of trust to another, used during root key rotation.
package transfer

import (
	"fmt"

	internal "github.com/securesign/tufcli/internal/transfer"
)

// Options contains all configuration for a transfer-metadata operation,
// including current and new root paths, signing keys, remote URLs, metadata
// versions, and expirations.
type Options = internal.Options

// Transfer transfers TUF repository metadata from one root of trust to another.
// It loads the existing repository under the current root, creates fresh
// targets/snapshot/timestamp metadata under the new root, signs everything
// with the new root's authorized keys, and writes the result to the output
// directory.
func Transfer(opts *Options) error {
	if opts == nil {
		return fmt.Errorf("opts must not be nil")
	}
	return internal.Run(opts)
}
