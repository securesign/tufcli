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

package root

import (
	"fmt"
	"time"

	"github.com/securesign/tufcli/internal/schema"
	"github.com/securesign/tufcli/internal/utils"
)

const (
	// DefaultVersion is the default version for a new root.json
	DefaultVersion = 1
	// DefaultThreshold is an absurdly high threshold to force users to set proper values
	// This matches the Rust implementation
	DefaultThreshold = 1507
)

// InitOptions contains options for initializing a root.json file
type InitOptions struct {
	Path    string
	Version uint64
}

// Init creates a new root.json metadata file
func Init(opts InitOptions) error {
	// Use default version if not specified
	version := opts.Version
	if version == 0 {
		version = DefaultVersion
	}

	// Create the root metadata structure
	root := schema.Root{
		Type:               "root",
		SpecVersion:        "1.0.0",
		ConsistentSnapshot: true,
		Version:            version,
		Expires:            schema.RoundTime(time.Now().UTC()),
		Keys:               make(map[string]schema.Key),
		Roles: map[schema.RoleType]schema.RoleKeys{
			schema.RoleTypeRoot: {
				KeyIDs:    []string{},
				Threshold: DefaultThreshold,
			},
			schema.RoleTypeSnapshot: {
				KeyIDs:    []string{},
				Threshold: DefaultThreshold,
			},
			schema.RoleTypeTargets: {
				KeyIDs:    []string{},
				Threshold: DefaultThreshold,
			},
			schema.RoleTypeTimestamp: {
				KeyIDs:    []string{},
				Threshold: DefaultThreshold,
			},
		},
	}

	// Wrap in signed structure with empty signatures
	signed := schema.Signed{
		Signed:     root,
		Signatures: []schema.Signature{},
	}

	// Write to file
	if err := utils.WriteJSONFile(opts.Path, signed); err != nil {
		return fmt.Errorf("failed to write root.json: %w", err)
	}

	return nil
}
