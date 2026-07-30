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

// Package rhtas provides functions for managing RHTAS (Red Hat Trusted
// Artifact Signer) TUF repositories with Sigstore-specific targets including
// Fulcio, CTLog, Rekor, and TSA services.
package rhtas

import (
	"fmt"

	internal "github.com/securesign/tufcli/internal/rhtas"
)

// Options contains all configuration for an RHTAS operation, including service
// target paths and URIs, deletion lists, metadata versions and expirations,
// repository loading settings, and delegated metadata options.
type Options = internal.Options

// Run manages an RHTAS TUF repository. It loads the existing repository,
// applies service target additions and deletions for Fulcio, CTLog, Rekor,
// and TSA, updates the trust bundle and signing config, then signs and writes
// the updated repository.
func Run(opts *Options) error {
	if opts == nil {
		return fmt.Errorf("opts must not be nil")
	}
	return internal.Run(opts)
}
