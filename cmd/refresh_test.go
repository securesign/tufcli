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
package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/securesign/tufcli/internal/refresh"
)

func TestWriteRefreshResult(t *testing.T) {
	path := filepath.Join(t.TempDir(), "termination-log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	result := refresh.Failure("timestamp", errors.New(strings.Repeat("long error\n", 1000)))
	var out, warnings bytes.Buffer
	if err := writeRefreshResult(&out, &warnings, path, result); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > 4096 {
		t.Fatalf("termination log is %d bytes", len(data))
	}
	var logged, printed refresh.Result
	if err := json.Unmarshal(data, &logged); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out.Bytes(), &printed); err != nil {
		t.Fatal(err)
	}
	if logged.Result != result.Result || logged.Role != result.Role || logged.Error.Reason != result.Error.Reason {
		t.Fatalf("termination log lost the failure outcome: %s", data)
	}
	if printed.Error.Message != result.Error.Message || warnings.Len() != 0 {
		t.Fatal("expected complete stdout result without warnings")
	}
}
