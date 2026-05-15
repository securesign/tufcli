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

	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/securesign/tufcli/internal/utils"
)

const (
	// DefaultVersion is the initial version for a new root.json.
	DefaultVersion = 1
	// DefaultThreshold is intentionally high to force operators to set a real value
	// before signing — matches the Rust tuftool behaviour.
	DefaultThreshold = 1507
)

// InitOptions contains options for initializing a root.json file.
type InitOptions struct {
	Path    string
	Version uint64
}

// Init creates a new root.json metadata file using go-tuf's canonical constructor.
func Init(opts InitOptions) error {
	expires := time.Now().UTC().Truncate(time.Second)
	md := tufmeta.Root(expires)

	// Override threshold for all four roles to the intentionally high sentinel value.
	for _, role := range []string{tufmeta.ROOT, tufmeta.SNAPSHOT, tufmeta.TARGETS, tufmeta.TIMESTAMP} {
		md.Signed.Roles[role].Threshold = DefaultThreshold
	}

	if opts.Version != 0 {
		md.Signed.Version = int64(opts.Version)
	}

	data, err := md.ToBytes(true)
	if err != nil {
		return fmt.Errorf("failed to serialize root.json: %w", err)
	}

	if err := utils.WriteFileAtomic(opts.Path, data); err != nil {
		return fmt.Errorf("failed to write root.json: %w", err)
	}

	return nil
}
