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

package signingconfig

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	trustrootpb "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
)

func TestPublicAPI_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "signing_config.v0.2.json")
	startTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	if err := Create(CreateOptions{Output: configPath}); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if err := AddURL(AddURLOptions{
		ConfigPath: configPath,
		Type:       "ca",
		URL:        "https://fulcio.example.com",
		APIVersion: 1,
		Operator:   "example.com",
		StartTime:  startTime,
	}); err != nil {
		t.Fatalf("AddURL ca failed: %v", err)
	}

	if err := AddURL(AddURLOptions{
		ConfigPath: configPath,
		Type:       "rekor",
		URL:        "https://rekor.example.com",
		APIVersion: 1,
		Operator:   "example.com",
		StartTime:  startTime,
	}); err != nil {
		t.Fatalf("AddURL rekor failed: %v", err)
	}

	if err := SetConfig(SetConfigOptions{
		ConfigPath: configPath,
		Type:       "rekor",
		Selector:   "ALL",
	}); err != nil {
		t.Fatalf("SetConfig failed: %v", err)
	}

	output, err := Inspect(InspectOptions{ConfigPath: configPath, Format: "text"})
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}
	if !strings.Contains(output, "https://fulcio.example.com") {
		t.Fatal("inspect output missing fulcio URL")
	}
	if !strings.Contains(output, "https://rekor.example.com") {
		t.Fatal("inspect output missing rekor URL")
	}

	if err := RemoveURL(RemoveURLOptions{
		ConfigPath: configPath,
		Type:       "ca",
		URL:        "https://fulcio.example.com",
	}); err != nil {
		t.Fatalf("RemoveURL failed: %v", err)
	}

	output, err = Inspect(InspectOptions{ConfigPath: configPath, Format: "text"})
	if err != nil {
		t.Fatalf("Inspect after remove failed: %v", err)
	}
	if strings.Contains(output, "https://fulcio.example.com") {
		t.Fatal("fulcio URL should have been removed")
	}
}

func TestPublicAPI_ParseServiceType(t *testing.T) {
	st, err := ParseServiceType("rekor")
	if err != nil {
		t.Fatalf("ParseServiceType failed: %v", err)
	}
	if st != ServiceTypeRekor {
		t.Fatalf("expected ServiceTypeRekor, got %v", st)
	}
}

func TestPublicAPI_ParseSelector(t *testing.T) {
	sel, err := ParseSelector("EXACT")
	if err != nil {
		t.Fatalf("ParseSelector failed: %v", err)
	}
	if sel != trustrootpb.ServiceSelector_EXACT {
		t.Fatalf("expected ServiceSelector_EXACT, got %v", sel)
	}
}
