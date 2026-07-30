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

// Package create provides functions for creating new TUF repositories.
// It initializes targets, snapshot, and timestamp metadata, adds target files,
// signs all metadata, and writes the repository to disk.
package create

import (
	"fmt"

	internal "github.com/securesign/tufcli/internal/create"
)

// Options contains all configuration for a create operation, including paths,
// signing keys, target directories, metadata versions, and expirations.
type Options = internal.Options

// Create creates a new TUF repository using the provided options. It validates
// inputs, walks the target directory, hashes and copies targets, then signs
// and writes all metadata to the output directory.
func Create(opts *Options) error {
	if opts == nil {
		return fmt.Errorf("opts must not be nil")
	}
	return internal.Run(opts)
}
