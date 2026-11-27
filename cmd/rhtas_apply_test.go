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
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/securesign/tufcli/internal/rhtas"
)

func withTerminationLog(t *testing.T, create bool) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "termination-log")
	if create {
		if err := os.WriteFile(path, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	old := terminationLogPath
	terminationLogPath = path
	t.Cleanup(func() { terminationLogPath = old })
	return path
}

func TestRhtasApply_MissingKeysReportsFailure(t *testing.T) {
	path := withTerminationLog(t, true)
	var out bytes.Buffer
	c := &cobra.Command{Use: "apply", RunE: rhtasApplyCmd.RunE}
	c.SetArgs([]string{})
	c.SetOut(&out)
	c.SetErr(io.Discard)
	if err := c.Execute(); err == nil {
		t.Fatal("expected missing keys error")
	}
	logged, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != string(logged) {
		t.Fatalf("stdout %q and termination log %q differ", out.String(), logged)
	}
	var result rhtas.ApplyResult
	if err := json.Unmarshal(logged, &result); err != nil {
		t.Fatal(err)
	}
	if result.Result != rhtas.ResultFailed || result.Error == nil || result.Error.Reason != rhtas.ReasonFailed ||
		!strings.Contains(result.Error.Message, "--key or --vault-key") {
		t.Fatalf("unexpected result: %s", logged)
	}
}

func TestWriteApplyResult_StdoutAndTerminationLog(t *testing.T) {
	path := withTerminationLog(t, true)
	result := &rhtas.ApplyResult{APIVersion: "rhtas.tufcli/v1", Result: rhtas.ResultApplied, Targets: &rhtas.RoleResult{Version: 3}}

	var out bytes.Buffer
	if err := writeApplyResult(&out, io.Discard, result); err != nil {
		t.Fatal(err)
	}
	logged, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != string(logged) {
		t.Fatalf("stdout %q and termination log %q differ", out.String(), logged)
	}
	var back rhtas.ApplyResult
	if err := json.Unmarshal(logged, &back); err != nil || back.Result != rhtas.ResultApplied || back.Targets.Version != 3 {
		t.Fatalf("termination log = %s (%v)", logged, err)
	}
}

func TestWriteApplyResult_NoTerminationLogOutsideKubernetes(t *testing.T) {
	path := withTerminationLog(t, false)
	var out bytes.Buffer
	if err := writeApplyResult(&out, io.Discard, &rhtas.ApplyResult{Result: rhtas.ResultNoChange}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("termination log must not be created")
	}
}

func TestWriteApplyResult_TerminationLogWriteFailureWarns(t *testing.T) {
	path := withTerminationLog(t, false)
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	var out, warnings bytes.Buffer
	if err := writeApplyResult(&out, &warnings, &rhtas.ApplyResult{Result: rhtas.ResultApplied}); err != nil {
		t.Fatal(err)
	}
	var result rhtas.ApplyResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil || result.Result != rhtas.ResultApplied {
		t.Fatalf("stdout = %q (%v)", out.String(), err)
	}
	if !strings.Contains(warnings.String(), "WARNING: failed to write "+path) {
		t.Fatalf("missing termination log warning: %q", warnings.String())
	}
}

func TestWriteApplyResult_LongErrorStaysValidJSONWithinLimit(t *testing.T) {
	path := withTerminationLog(t, true)
	op := 7
	result := &rhtas.ApplyResult{Result: rhtas.ResultFailed, Error: &rhtas.ApplyError{
		Reason: "OperationRejected", Message: strings.Repeat("x", 10000), Operation: &op, Path: "/components/rekor/a",
	}}
	var out bytes.Buffer
	if err := writeApplyResult(&out, io.Discard, result); err != nil {
		t.Fatal(err)
	}
	logged, _ := os.ReadFile(path)
	if len(logged) > terminationLogLimit {
		t.Fatalf("termination log is %d bytes", len(logged))
	}
	var back rhtas.ApplyResult
	if err := json.Unmarshal(logged, &back); err != nil {
		t.Fatalf("termination log is not valid JSON: %v", err)
	}
	if back.Error.Reason != "OperationRejected" || *back.Error.Operation != 7 || !strings.HasSuffix(back.Error.Message, "...") {
		t.Fatalf("structure lost: %+v", back.Error)
	}
	if !strings.Contains(out.String(), strings.Repeat("x", 10000)) {
		t.Fatal("stdout must keep the full message")
	}
}

func TestFitTerminationLog_MultiByteAndHugePath(t *testing.T) {
	for name, e := range map[string]*rhtas.ApplyError{
		"multi-byte message": {Reason: "OperationRejected", Message: strings.Repeat("é", 5000), Path: "/components/rekor/a"},
		"huge path":          {Reason: "OperationRejected", Message: "short", Path: "/" + strings.Repeat("p", 6000)},
	} {
		result := &rhtas.ApplyResult{Result: rhtas.ResultFailed, Error: e}
		full, _ := json.Marshal(result)
		got := fitTerminationLog(result, full)
		if len(got) > terminationLogLimit {
			t.Fatalf("%s: %d bytes", name, len(got))
		}
		var back rhtas.ApplyResult
		if err := json.Unmarshal(got, &back); err != nil || back.Error.Reason != "OperationRejected" {
			t.Fatalf("%s: %s (%v)", name, got, err)
		}
		if strings.ContainsRune(back.Error.Message, '\uFFFD') {
			t.Fatalf("%s: message cut inside a character", name)
		}
	}
}
