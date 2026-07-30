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

package update_test

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/securesign/tufcli/pkg/repo/create"
	"github.com/securesign/tufcli/pkg/repo/update"
	"github.com/securesign/tufcli/pkg/rootmeta"
)

func ExampleUpdate() {
	dir, err := os.MkdirTemp("", "update-example")
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}
	defer os.RemoveAll(dir)

	rootPath := filepath.Join(dir, "root.json")
	keyPath := filepath.Join(dir, "key.pem")

	// Initialize root.json using the public rootmeta API
	if err := rootmeta.Init(rootmeta.InitOptions{Path: rootPath}); err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}
	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		if err := rootmeta.SetThreshold(rootmeta.SetThresholdOptions{Path: rootPath, Role: role, Threshold: 1}); err != nil {
			fmt.Printf("error: %v\n", err)
			return
		}
	}
	if _, err := rootmeta.GenRsaKey(rootmeta.GenRsaKeyOptions{
		Path: rootPath, KeyPath: keyPath, Bits: 2048,
		Roles: []string{"root", "targets", "snapshot", "timestamp"},
	}); err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}
	if err := rootmeta.Sign(rootmeta.SignOptions{Path: rootPath, KeyPaths: []string{keyPath}}); err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}

	// Create initial repo
	repoDir := filepath.Join(dir, "repo")
	inputDir := filepath.Join(dir, "input")
	if err := os.MkdirAll(inputDir, 0755); err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}
	if err := os.WriteFile(filepath.Join(inputDir, "v1.txt"), []byte("version 1"), 0600); err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}

	expires := time.Now().UTC().Truncate(time.Second).AddDate(1, 0, 0)
	if err := create.Create(&create.Options{
		RootPath:         rootPath,
		KeyPaths:         []string{keyPath},
		OutDir:           repoDir,
		AddTargetsDir:    inputDir,
		TargetsExpires:   expires,
		TargetsVersion:   1,
		SnapshotExpires:  expires,
		SnapshotVersion:  1,
		TimestampExpires: expires,
		TimestampVersion: 1,
	}); err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}

	// Update the repo with new targets
	updateInputDir := filepath.Join(dir, "update-input")
	if err := os.MkdirAll(updateInputDir, 0755); err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}
	if err := os.WriteFile(filepath.Join(updateInputDir, "v2.txt"), []byte("version 2"), 0600); err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}

	err = update.Update(&update.Options{
		RootPath:      rootPath,
		KeyPaths:      []string{keyPath},
		OutDir:        repoDir,
		MetadataURL:   "file:///" + repoDir,
		AddTargetsDir: updateInputDir,
	})
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}

	fmt.Println("repository updated")
	// Output:
	// repository updated
}
