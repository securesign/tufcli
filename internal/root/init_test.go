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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/securesign/tufcli/internal/schema"
)

func TestInit(t *testing.T) {
	// Create temp directory for test
	tmpDir, err := os.MkdirTemp("", "tufcli-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testPath := filepath.Join(tmpDir, "root.json")

	// Test with default version
	err = Init(InitOptions{
		Path:    testPath,
		Version: 0, // Should default to 1
	})
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(testPath); os.IsNotExist(err) {
		t.Fatal("root.json was not created")
	}

	// Read and parse the file
	data, err := os.ReadFile(testPath)
	if err != nil {
		t.Fatalf("failed to read root.json: %v", err)
	}

	var signed schema.Signed
	if err := json.Unmarshal(data, &signed); err != nil {
		t.Fatalf("failed to unmarshal root.json: %v", err)
	}

	// Verify structure
	if signed.Signed.Type != "root" {
		t.Errorf("expected _type 'root', got '%s'", signed.Signed.Type)
	}

	if signed.Signed.SpecVersion != "1.0.0" {
		t.Errorf("expected spec_version '1.0.0', got '%s'", signed.Signed.SpecVersion)
	}

	if signed.Signed.Version != 1 {
		t.Errorf("expected version 1, got %d", signed.Signed.Version)
	}

	if !signed.Signed.ConsistentSnapshot {
		t.Error("expected consistent_snapshot to be true")
	}

	// Verify all roles are present with correct threshold
	expectedRoles := []schema.RoleType{
		schema.RoleTypeRoot,
		schema.RoleTypeSnapshot,
		schema.RoleTypeTargets,
		schema.RoleTypeTimestamp,
	}

	for _, role := range expectedRoles {
		roleKeys, exists := signed.Signed.Roles[role]
		if !exists {
			t.Errorf("role %s not found", role)
			continue
		}

		if roleKeys.Threshold != DefaultThreshold {
			t.Errorf("role %s: expected threshold %d, got %d", role, DefaultThreshold, roleKeys.Threshold)
		}

		if len(roleKeys.KeyIDs) != 0 {
			t.Errorf("role %s: expected empty keyids, got %d keys", role, len(roleKeys.KeyIDs))
		}
	}

	// Verify empty keys
	if len(signed.Signed.Keys) != 0 {
		t.Errorf("expected empty keys, got %d keys", len(signed.Signed.Keys))
	}

	// Verify empty signatures
	if len(signed.Signatures) != 0 {
		t.Errorf("expected empty signatures, got %d signatures", len(signed.Signatures))
	}
}

func TestInitCustomVersion(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tufcli-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testPath := filepath.Join(tmpDir, "root.json")

	// Test with custom version
	customVersion := uint64(42)
	err = Init(InitOptions{
		Path:    testPath,
		Version: customVersion,
	})
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	data, err := os.ReadFile(testPath)
	if err != nil {
		t.Fatalf("failed to read root.json: %v", err)
	}

	var signed schema.Signed
	if err := json.Unmarshal(data, &signed); err != nil {
		t.Fatalf("failed to unmarshal root.json: %v", err)
	}

	if signed.Signed.Version != customVersion {
		t.Errorf("expected version %d, got %d", customVersion, signed.Signed.Version)
	}
}
