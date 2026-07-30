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

package rootmeta_test

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/securesign/tufcli/pkg/rootmeta"
)

func ExampleInit() {
	dir, err := os.MkdirTemp("", "rootmeta-example")
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}
	defer os.RemoveAll(dir)
	rootPath := filepath.Join(dir, "root.json")
	keyPath := filepath.Join(dir, "key.pem")

	// Initialize a new root.json
	if err := rootmeta.Init(rootmeta.InitOptions{Path: rootPath}); err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}

	// Set expiration
	expires := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := rootmeta.Expire(rootmeta.ExpireOptions{
		Path:    rootPath,
		Expires: expires,
	}); err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}

	// Set threshold for all roles
	for _, role := range []string{"root", "snapshot", "targets", "timestamp"} {
		if err := rootmeta.SetThreshold(rootmeta.SetThresholdOptions{
			Path:      rootPath,
			Role:      role,
			Threshold: 1,
		}); err != nil {
			fmt.Printf("error: %v\n", err)
			return
		}
	}

	// Generate a key pair and add to all roles
	keyID, err := rootmeta.GenRsaKey(rootmeta.GenRsaKeyOptions{
		Path:    rootPath,
		KeyPath: keyPath,
		Bits:    2048,
		Roles:   []string{"root", "snapshot", "targets", "timestamp"},
	})
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}

	// Sign root.json
	if err := rootmeta.Sign(rootmeta.SignOptions{
		Path:     rootPath,
		KeyPaths: []string{keyPath},
	}); err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}

	fmt.Printf("root.json initialized and signed with key %s\n", keyID[:8])
}
