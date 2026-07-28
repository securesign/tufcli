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

package signingconfig_test

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/securesign/tufcli/pkg/signingconfig"
)

func Example() {
	dir, _ := os.MkdirTemp("", "signingconfig-example")
	defer os.RemoveAll(dir)
	configPath := filepath.Join(dir, "signing_config.v0.2.json")
	startTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	// Create an empty signing config
	signingconfig.Create(signingconfig.CreateOptions{
		Output: configPath,
	})

	// Add service endpoints
	signingconfig.AddURL(signingconfig.AddURLOptions{
		ConfigPath: configPath,
		Type:       "ca",
		URL:        "https://fulcio.example.com",
		APIVersion: 1,
		Operator:   "example.com",
		StartTime:  startTime,
	})
	signingconfig.AddURL(signingconfig.AddURLOptions{
		ConfigPath: configPath,
		Type:       "rekor",
		URL:        "https://rekor.example.com",
		APIVersion: 1,
		Operator:   "example.com",
		StartTime:  startTime,
	})

	// Set service selection policy
	signingconfig.SetConfig(signingconfig.SetConfigOptions{
		ConfigPath: configPath,
		Type:       "rekor",
		Selector:   "ANY",
	})

	// Inspect the result
	output, _ := signingconfig.Inspect(signingconfig.InspectOptions{
		ConfigPath: configPath,
		Format:     "text",
	})
	fmt.Print(output)
	// Output:
	// Media Type: application/vnd.dev.sigstore.signingconfig.v0.2+json
	//
	// CA URLs:
	//   - https://fulcio.example.com (api=v1, operator=example.com)
	//     valid: 2025-01-01T00:00:00Z to (unset)
	//
	// OIDC URLs:
	//   (none)
	//
	// Rekor TLog URLs:
	//   - https://rekor.example.com (api=v1, operator=example.com)
	//     valid: 2025-01-01T00:00:00Z to (unset)
	//
	// TSA URLs:
	//   (none)
	//
	// Rekor TLog Config:
	//   selector: ANY, count: 0
	//
	// TSA Config:
	//   selector: ANY, count: 0
}

func ExampleCreate() {
	dir, _ := os.MkdirTemp("", "signingconfig-create")
	defer os.RemoveAll(dir)
	configPath := filepath.Join(dir, "signing_config.v0.2.json")

	err := signingconfig.Create(signingconfig.CreateOptions{
		Output: configPath,
	})
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}
	fmt.Println("signing config created")
	// Output:
	// signing config created
}

func ExampleCreate_fromBaseConfig() {
	dir, _ := os.MkdirTemp("", "signingconfig-clone")
	defer os.RemoveAll(dir)
	basePath := filepath.Join(dir, "base.json")
	clonePath := filepath.Join(dir, "clone.json")

	// Create a base config first
	signingconfig.Create(signingconfig.CreateOptions{Output: basePath})

	// Clone it
	err := signingconfig.Create(signingconfig.CreateOptions{
		Output:     clonePath,
		BaseConfig: basePath,
	})
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}
	fmt.Println("cloned signing config created")
	// Output:
	// cloned signing config created
}

func ExampleAddURL() {
	dir, _ := os.MkdirTemp("", "signingconfig-addurl")
	defer os.RemoveAll(dir)
	configPath := filepath.Join(dir, "signing_config.v0.2.json")
	signingconfig.Create(signingconfig.CreateOptions{Output: configPath})

	err := signingconfig.AddURL(signingconfig.AddURLOptions{
		ConfigPath: configPath,
		Type:       "ca",
		URL:        "https://fulcio.sigstore.dev",
		APIVersion: 1,
		Operator:   "sigstore.dev",
		StartTime:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}
	fmt.Println("URL added")
	// Output:
	// URL added
}

func ExampleInspect() {
	dir, _ := os.MkdirTemp("", "signingconfig-inspect")
	defer os.RemoveAll(dir)
	configPath := filepath.Join(dir, "signing_config.v0.2.json")
	signingconfig.Create(signingconfig.CreateOptions{Output: configPath})

	output, err := signingconfig.Inspect(signingconfig.InspectOptions{
		ConfigPath: configPath,
		Format:     "text",
	})
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}
	fmt.Print(output)
	// Output:
	// Media Type: application/vnd.dev.sigstore.signingconfig.v0.2+json
	//
	// CA URLs:
	//   (none)
	//
	// OIDC URLs:
	//   (none)
	//
	// Rekor TLog URLs:
	//   (none)
	//
	// TSA URLs:
	//   (none)
	//
	// Rekor TLog Config:
	//   selector: ANY, count: 0
	//
	// TSA Config:
	//   selector: ANY, count: 0
}
