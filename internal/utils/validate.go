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

package utils

import (
	"fmt"
	"strings"
)

// ValidateTargetPathExists validates the TargetPathExists policy value.
// Returns "skip" when value is empty (default), or the value itself if valid.
func ValidateTargetPathExists(value string) (string, error) {
	if value == "" {
		return "skip", nil
	}
	switch value {
	case "skip", "replace", "fail":
		return value, nil
	default:
		return "", fmt.Errorf("invalid TargetPathExists value %q (must be skip, replace, or fail)", value)
	}
}

// ValidateURLScheme validates that a URL has a supported scheme (file://, http://, https://).
func ValidateURLScheme(url string) error {
	if strings.HasPrefix(url, "file://") ||
		strings.HasPrefix(url, "http://") ||
		strings.HasPrefix(url, "https://") {
		return nil
	}
	return fmt.Errorf("invalid metadata URL scheme (must be file://, http://, or https://)")
}

// ValidateForceVersion checks that explicit versions require ForceVersion=true.
func ValidateForceVersion(forceVersion bool, versions ...*int64) error {
	if forceVersion {
		return nil
	}
	for _, v := range versions {
		if v != nil {
			return fmt.Errorf("explicit version values require ForceVersion=true")
		}
	}
	return nil
}

// ValidateDelegationFlags checks that IncomingMetadata and DelegatedRole are set together.
func ValidateDelegationFlags(incomingMetadata, delegatedRole string) error {
	if (incomingMetadata != "") != (delegatedRole != "") {
		return fmt.Errorf("IncomingMetadata and DelegatedRole must be set together")
	}
	return nil
}

// ValidateHashAlgo checks that hashAlgo is "sha256" or "sha512".
func ValidateHashAlgo(hashAlgo string) error {
	if hashAlgo != "sha256" && hashAlgo != "sha512" {
		return fmt.Errorf("unsupported hash algorithm %q (must be sha256 or sha512)", hashAlgo)
	}
	return nil
}
