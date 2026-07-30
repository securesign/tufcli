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
	"strings"
	"testing"
)

func TestValidateTargetPathExists(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"empty defaults to skip", "", "skip", false},
		{"skip", "skip", "skip", false},
		{"replace", "replace", "replace", false},
		{"fail", "fail", "fail", false},
		{"invalid", "bogus", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateTargetPathExists(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestValidateURLScheme(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"file://", "file:///tmp/repo", false},
		{"http://", "http://example.com", false},
		{"https://", "https://example.com", false},
		{"no scheme", "example.com", true},
		{"ftp://", "ftp://example.com", true},
		{"empty", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateURLScheme(tt.url)
			if tt.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateForceVersion(t *testing.T) {
	v1 := int64(1)

	tests := []struct {
		name         string
		forceVersion bool
		versions     []*int64
		wantErr      bool
	}{
		{"force true, versions set", true, []*int64{&v1}, false},
		{"force true, no versions", true, []*int64{nil}, false},
		{"force false, no versions", false, []*int64{nil, nil}, false},
		{"force false, version set", false, []*int64{&v1}, true},
		{"force false, mixed", false, []*int64{nil, &v1, nil}, true},
		{"force false, empty", false, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateForceVersion(tt.forceVersion, tt.versions...)
			if tt.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr && err != nil && !strings.Contains(err.Error(), "ForceVersion") {
				t.Fatalf("expected ForceVersion error, got: %v", err)
			}
		})
	}
}

func TestValidateDelegationFlags(t *testing.T) {
	tests := []struct {
		name             string
		incomingMetadata string
		delegatedRole    string
		wantErr          bool
	}{
		{"both empty", "", "", false},
		{"both set", "metadata.json", "role-name", false},
		{"only metadata", "metadata.json", "", true},
		{"only role", "", "role-name", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDelegationFlags(tt.incomingMetadata, tt.delegatedRole)
			if tt.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
