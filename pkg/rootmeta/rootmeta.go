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

// Package rootmeta provides functions for managing TUF root.json metadata files.
// It supports the full root.json lifecycle: initialization, key management, threshold
// configuration, expiration, versioning, and signing with cross-sign support.
package rootmeta

import (
	internal "github.com/securesign/tufcli/internal/root"
)

const (
	// DefaultVersion is the initial version for a new root.json.
	DefaultVersion = internal.DefaultVersion
	// DefaultThreshold is intentionally high to force operators to set a real value
	// before signing.
	DefaultThreshold = internal.DefaultThreshold
)

// InitOptions contains options for initializing a root.json file.
type InitOptions = internal.InitOptions

// ExpireOptions contains options for setting the expiration time on root.json.
type ExpireOptions = internal.ExpireOptions

// SetThresholdOptions contains options for setting a role's signature threshold.
type SetThresholdOptions = internal.SetThresholdOptions

// BumpVersionOptions contains options for incrementing the root.json version.
type BumpVersionOptions = internal.BumpVersionOptions

// SetVersionOptions contains options for setting a specific version on root.json.
type SetVersionOptions = internal.SetVersionOptions

// RemoveKeyOptions contains options for removing a key from root.json roles.
type RemoveKeyOptions = internal.RemoveKeyOptions

// AddKeyOptions contains options for adding public keys to root.json roles.
type AddKeyOptions = internal.AddKeyOptions

// GenRsaKeyOptions contains options for generating an RSA key pair and adding it
// to root.json roles.
type GenRsaKeyOptions = internal.GenRsaKeyOptions

// SignOptions contains options for signing root.json, including cross-sign support.
type SignOptions = internal.SignOptions

// Init creates a new root.json metadata file with default thresholds and the
// specified version. If Version is zero, the default version is used.
func Init(opts InitOptions) error { return internal.Init(opts) }

// Expire sets the expiration time on root.json and clears existing signatures.
func Expire(opts ExpireOptions) error { return internal.Expire(opts) }

// SetThreshold sets the signature threshold for a role in root.json.
// Threshold must be greater than zero.
func SetThreshold(opts SetThresholdOptions) error { return internal.SetThreshold(opts) }

// BumpVersion increments the root.json version by 1 and clears signatures.
func BumpVersion(opts BumpVersionOptions) error { return internal.BumpVersion(opts) }

// SetVersion sets a specific version number on root.json and clears signatures.
// Version must be greater than zero.
func SetVersion(opts SetVersionOptions) error { return internal.SetVersion(opts) }

// RemoveKey removes a key ID from a specific role or from all roles in root.json.
// When Role is nil the key is also deleted from the keys map.
func RemoveKey(opts RemoveKeyOptions) error { return internal.RemoveKey(opts) }

// AddKey adds one or more public keys to the specified roles in root.json.
// Returns the key IDs of the added keys.
func AddKey(opts AddKeyOptions) ([]string, error) { return internal.AddKey(opts) }

// GenRsaKey generates an RSA key pair, adds its public key to the specified roles,
// and saves the private key to KeyPath. Returns the key ID of the generated key.
func GenRsaKey(opts GenRsaKeyOptions) (string, error) { return internal.GenRsaKey(opts) }

// Sign signs root.json with the provided keys. Signing is incremental: an existing
// signature for the same key ID is replaced rather than duplicated. Cross-signing
// uses an older root to authorise keys.
func Sign(opts SignOptions) error { return internal.Sign(opts) }
