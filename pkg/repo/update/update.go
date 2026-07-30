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

// Package update provides functions for updating existing TUF repositories.
// It loads metadata from a repository, optionally adds targets, bumps versions,
// updates expirations, re-signs, and writes the updated repository.
package update

import (
	"fmt"

	internal "github.com/securesign/tufcli/internal/update"
)

// Options contains all configuration for an update operation, including
// metadata URL, signing keys, version overrides, expiration times, and
// delegated metadata settings.
type Options = internal.Options

// Update updates an existing TUF repository using the provided options. It
// loads the current metadata from the metadata URL, applies target additions,
// version bumps, and expiration changes, then re-signs and writes the
// updated repository.
func Update(opts *Options) error {
	if opts == nil {
		return fmt.Errorf("opts must not be nil")
	}
	return internal.Run(opts)
}
