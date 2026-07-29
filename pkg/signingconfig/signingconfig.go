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

// Package signingconfig provides functions for creating, modifying, and
// inspecting Sigstore signing configuration files (signing_config.v0.2.json).
//
// Signing configs define which Sigstore service endpoints (Fulcio, Rekor,
// OIDC, TSA) a client should use for signing operations, along with service
// selection policies. This package produces output byte-identical to
// cosign signing-config create.
//
// The package operates on files: each function reads a signing config from
// disk, applies a mutation, and writes it back. Use [Create] to start a new
// config, [AddURL] and [RemoveURL] to manage service endpoints, [SetConfig]
// to configure service selection policies, and [Inspect] to display contents.
package signingconfig

import (
	trustrootpb "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"

	internal "github.com/securesign/tufcli/internal/signingconfig"
)

// ServiceType identifies the kind of Sigstore service (ca, oidc, rekor, tsa).
type ServiceType = internal.ServiceType

const (
	// ServiceTypeCA represents a Fulcio certificate authority.
	ServiceTypeCA = internal.ServiceTypeCA
	// ServiceTypeOIDC represents an OIDC identity provider.
	ServiceTypeOIDC = internal.ServiceTypeOIDC
	// ServiceTypeRekor represents a Rekor transparency log.
	ServiceTypeRekor = internal.ServiceTypeRekor
	// ServiceTypeTSA represents a timestamp authority.
	ServiceTypeTSA = internal.ServiceTypeTSA
)

// CreateOptions configures the Create operation.
// Set Output to the destination file path. Optionally set BaseConfig to clone
// an existing signing config, or WithDefaultServices to fetch defaults from
// the public Sigstore TUF repository.
type CreateOptions = internal.CreateOptions

// AddURLOptions configures the AddURL operation.
// ConfigPath is the signing config to modify. Type is one of "ca", "oidc",
// "rekor", or "tsa". URL is the service endpoint. StartTime is required.
// If a service with the same URL already exists, it is replaced.
type AddURLOptions = internal.AddURLOptions

// RemoveURLOptions configures the RemoveURL operation.
// Removes a service entry by exact URL match. If no entry matches, the
// operation is a no-op.
type RemoveURLOptions = internal.RemoveURLOptions

// SetConfigOptions configures the SetConfig operation.
// Type must be "rekor" or "tsa". Selector is one of "ALL", "ANY", or "EXACT".
// Count is required when Selector is "EXACT" and must be 0 for "ALL"/"ANY".
type SetConfigOptions = internal.SetConfigOptions

// InspectOptions configures the Inspect operation.
// Format is "text" for human-readable output or "json" for indented protojson.
type InspectOptions = internal.InspectOptions

// Create creates a new signing config file. When BaseConfig is set, the
// existing config is cloned. When WithDefaultServices is set, defaults are
// fetched from the public Sigstore TUF repository. Otherwise an empty config
// with ANY selectors is created.
func Create(opts CreateOptions) error { return internal.Create(opts) }

// AddURL adds or replaces a service URL in a signing config file.
// StartTime is required on every service entry. If a service with the same
// URL already exists, it is replaced (not duplicated). EndTime is optional
// but must be after StartTime when provided.
func AddURL(opts AddURLOptions) error { return internal.AddURL(opts) }

// RemoveURL removes a service URL from a signing config file by exact URL
// match. If no entry matches, the config is saved unchanged.
func RemoveURL(opts RemoveURLOptions) error { return internal.RemoveURL(opts) }

// SetConfig sets the service selection configuration for Rekor or TSA.
// Selector must be "ALL", "ANY", or "EXACT". The "EXACT" selector requires
// Count > 0; "ALL" and "ANY" reject a non-zero Count.
func SetConfig(opts SetConfigOptions) error { return internal.SetConfig(opts) }

// Inspect reads a signing config and returns its contents as a string.
// Format "text" produces a human-readable summary; "json" produces indented
// protojson matching the on-disk format.
func Inspect(opts InspectOptions) (string, error) { return internal.Inspect(opts) }

// ParseServiceType parses a service type string (case-insensitive).
// Valid values: "ca", "oidc", "rekor", "tsa".
func ParseServiceType(s string) (ServiceType, error) {
	return internal.ParseServiceType(s)
}

// ParseSelector parses a service selector string (case-insensitive).
// Valid values: "ALL", "ANY", "EXACT".
func ParseSelector(s string) (trustrootpb.ServiceSelector, error) {
	return internal.ParseSelector(s)
}
