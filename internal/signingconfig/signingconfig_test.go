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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	trustrootpb "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"google.golang.org/protobuf/encoding/protojson"
)

// testStartTime is a fixed start time used across tests.
var testStartTime = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

// --- 1. Parser tests (table-driven) ---

func TestParseServiceType(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    ServiceType
		wantErr bool
	}{
		{"ca", "ca", ServiceTypeCA, false},
		{"oidc", "oidc", ServiceTypeOIDC, false},
		{"rekor", "rekor", ServiceTypeRekor, false},
		{"tsa", "tsa", ServiceTypeTSA, false},
		{"case insensitive CA", "CA", ServiceTypeCA, false},
		{"case insensitive Rekor", "Rekor", ServiceTypeRekor, false},
		{"invalid", "invalid", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseServiceType(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseServiceType(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseServiceType(%q) unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("ParseServiceType(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseSelector(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    trustrootpb.ServiceSelector
		wantErr bool
	}{
		{"ALL", "ALL", trustrootpb.ServiceSelector_ALL, false},
		{"ANY", "ANY", trustrootpb.ServiceSelector_ANY, false},
		{"EXACT", "EXACT", trustrootpb.ServiceSelector_EXACT, false},
		{"case insensitive all", "all", trustrootpb.ServiceSelector_ALL, false},
		{"case insensitive any", "any", trustrootpb.ServiceSelector_ANY, false},
		{"empty string", "", 0, true},
		{"bogus", "bogus", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSelector(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseSelector(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSelector(%q) unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("ParseSelector(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// --- 2. Create tests ---

func TestCreate_EmptyDefaults(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "signing_config.json")

	if err := Create(CreateOptions{Output: outPath}); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	sc, err := loadSigningConfig(outPath)
	if err != nil {
		t.Fatalf("loadSigningConfig failed: %v", err)
	}

	if len(sc.FulcioCertificateAuthorityURLs()) != 0 {
		t.Fatalf("expected empty CA URLs, got %d", len(sc.FulcioCertificateAuthorityURLs()))
	}
	if len(sc.OIDCProviderURLs()) != 0 {
		t.Fatalf("expected empty OIDC URLs, got %d", len(sc.OIDCProviderURLs()))
	}
	if len(sc.RekorLogURLs()) != 0 {
		t.Fatalf("expected empty Rekor URLs, got %d", len(sc.RekorLogURLs()))
	}
	if len(sc.TimestampAuthorityURLs()) != 0 {
		t.Fatalf("expected empty TSA URLs, got %d", len(sc.TimestampAuthorityURLs()))
	}

	rekorConfig := sc.RekorLogURLsConfig()
	if rekorConfig.Selector != trustrootpb.ServiceSelector_ANY {
		t.Fatalf("expected RekorTlogConfig selector ANY, got %v", rekorConfig.Selector)
	}
	if rekorConfig.Count != 0 {
		t.Fatalf("expected RekorTlogConfig count 0, got %d", rekorConfig.Count)
	}
	tsaConfig := sc.TimestampAuthorityURLsConfig()
	if tsaConfig.Selector != trustrootpb.ServiceSelector_ANY {
		t.Fatalf("expected TsaConfig selector ANY, got %v", tsaConfig.Selector)
	}
	if tsaConfig.Count != 0 {
		t.Fatalf("expected TsaConfig count 0, got %d", tsaConfig.Count)
	}
}

func TestCreate_FromBaseConfig(t *testing.T) {
	dir := t.TempDir()

	// Create a base config with services manually using protobuf
	baseSC := &trustrootpb.SigningConfig{
		MediaType: root.SigningConfigMediaType02,
		CaUrls: []*trustrootpb.Service{
			{Url: "https://fulcio.example.com", MajorApiVersion: 1, Operator: "example.com"},
		},
		OidcUrls: []*trustrootpb.Service{
			{Url: "https://oidc.example.com", MajorApiVersion: 1, Operator: "example.com"},
		},
		RekorTlogUrls: []*trustrootpb.Service{
			{Url: "https://rekor.example.com", MajorApiVersion: 1, Operator: "example.com"},
		},
		TsaUrls: []*trustrootpb.Service{
			{Url: "https://tsa.example.com", MajorApiVersion: 1, Operator: "example.com"},
		},
		RekorTlogConfig: &trustrootpb.ServiceConfiguration{
			Selector: trustrootpb.ServiceSelector_ALL,
			Count:    0,
		},
		TsaConfig: &trustrootpb.ServiceConfiguration{
			Selector: trustrootpb.ServiceSelector_EXACT,
			Count:    2,
		},
	}
	baseData, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(baseSC)
	if err != nil {
		t.Fatalf("failed to marshal base config: %v", err)
	}
	basePath := filepath.Join(dir, "base.json")
	if err := os.WriteFile(basePath, baseData, 0644); err != nil {
		t.Fatalf("failed to write base config: %v", err)
	}

	outPath := filepath.Join(dir, "output.json")
	if err := Create(CreateOptions{Output: outPath, BaseConfig: basePath}); err != nil {
		t.Fatalf("Create from base failed: %v", err)
	}

	sc, err := loadSigningConfig(outPath)
	if err != nil {
		t.Fatalf("loadSigningConfig failed: %v", err)
	}

	caURLs := sc.FulcioCertificateAuthorityURLs()
	if len(caURLs) != 1 {
		t.Fatalf("expected 1 CA URL, got %d", len(caURLs))
	}
	if caURLs[0].URL != "https://fulcio.example.com" {
		t.Fatalf("CA URL mismatch: %s", caURLs[0].URL)
	}
	if len(sc.OIDCProviderURLs()) != 1 {
		t.Fatalf("expected 1 OIDC URL, got %d", len(sc.OIDCProviderURLs()))
	}
	if len(sc.RekorLogURLs()) != 1 {
		t.Fatalf("expected 1 Rekor URL, got %d", len(sc.RekorLogURLs()))
	}
	if len(sc.TimestampAuthorityURLs()) != 1 {
		t.Fatalf("expected 1 TSA URL, got %d", len(sc.TimestampAuthorityURLs()))
	}
	if sc.RekorLogURLsConfig().Selector != trustrootpb.ServiceSelector_ALL {
		t.Fatalf("expected RekorTlogConfig selector ALL, got %v", sc.RekorLogURLsConfig().Selector)
	}
	if sc.TimestampAuthorityURLsConfig().Selector != trustrootpb.ServiceSelector_EXACT {
		t.Fatalf("expected TsaConfig selector EXACT, got %v", sc.TimestampAuthorityURLsConfig().Selector)
	}
	if sc.TimestampAuthorityURLsConfig().Count != 2 {
		t.Fatalf("expected TsaConfig count 2, got %d", sc.TimestampAuthorityURLsConfig().Count)
	}
}

func TestCreate_InvalidBaseConfig(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "output.json")

	err := Create(CreateOptions{
		Output:     outPath,
		BaseConfig: filepath.Join(dir, "nonexistent.json"),
	})
	if err == nil {
		t.Fatal("expected error for non-existent base config")
	}
}

func TestCreate_InvalidMediaType(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad_media.json")

	// Write JSON with a wrong mediaType
	badJSON := `{
  "mediaType": "application/vnd.dev.sigstore.signingconfig.v0.WRONG+json",
  "caUrls": [],
  "oidcUrls": [],
  "rekorTlogUrls": [],
  "tsaUrls": [],
  "rekorTlogConfig": {"selector": "ANY"},
  "tsaConfig": {"selector": "ANY"}
}`
	if err := os.WriteFile(cfgPath, []byte(badJSON), 0644); err != nil {
		t.Fatalf("failed to write bad config: %v", err)
	}

	// loadSigningConfig should fail because NewSigningConfigFromProtobuf rejects wrong mediaType
	_, err := loadSigningConfig(cfgPath)
	if err == nil {
		t.Fatal("expected error for invalid media type")
	}
	if !strings.Contains(err.Error(), "unsupported SigningConfig media type") {
		t.Fatalf("expected media type error, got: %v", err)
	}
}

// --- 3. AddURL tests ---

func TestAddURL_CA(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signing_config.json")

	if err := Create(CreateOptions{Output: cfgPath}); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if err := AddURL(AddURLOptions{
		ConfigPath: cfgPath,
		Type:       "ca",
		URL:        "https://fulcio.example.com",
		APIVersion: 1,
		Operator:   "example.com",
		StartTime:  testStartTime,
	}); err != nil {
		t.Fatalf("AddURL failed: %v", err)
	}

	// Verify via Inspect JSON
	output, err := Inspect(InspectOptions{ConfigPath: cfgPath, Format: "json"})
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}
	if !strings.Contains(output, "https://fulcio.example.com") {
		t.Fatalf("JSON output missing CA URL, got:\n%s", output)
	}
	if !strings.Contains(output, "validFor") {
		t.Fatalf("JSON output missing validFor, got:\n%s", output)
	}

	// Verify via loadSigningConfig
	sc, err := loadSigningConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadSigningConfig failed: %v", err)
	}
	caURLs := sc.FulcioCertificateAuthorityURLs()
	if len(caURLs) != 1 {
		t.Fatalf("expected 1 CA URL, got %d", len(caURLs))
	}
	if caURLs[0].URL != "https://fulcio.example.com" {
		t.Fatalf("URL mismatch: %s", caURLs[0].URL)
	}
	if caURLs[0].MajorAPIVersion != 1 {
		t.Fatalf("API version mismatch: %d", caURLs[0].MajorAPIVersion)
	}
	if caURLs[0].Operator != "example.com" {
		t.Fatalf("operator mismatch: %s", caURLs[0].Operator)
	}
}

func TestAddURL_OIDC(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signing_config.json")

	if err := Create(CreateOptions{Output: cfgPath}); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if err := AddURL(AddURLOptions{
		ConfigPath: cfgPath,
		Type:       "oidc",
		URL:        "https://oidc.example.com",
		APIVersion: 1,
		Operator:   "example.com",
		StartTime:  testStartTime,
	}); err != nil {
		t.Fatalf("AddURL failed: %v", err)
	}

	output, err := Inspect(InspectOptions{ConfigPath: cfgPath, Format: "json"})
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}
	if !strings.Contains(output, "https://oidc.example.com") {
		t.Fatalf("JSON output missing OIDC URL, got:\n%s", output)
	}

	sc, err := loadSigningConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadSigningConfig failed: %v", err)
	}
	oidcURLs := sc.OIDCProviderURLs()
	if len(oidcURLs) != 1 {
		t.Fatalf("expected 1 OIDC URL, got %d", len(oidcURLs))
	}
	if oidcURLs[0].URL != "https://oidc.example.com" {
		t.Fatalf("URL mismatch: %s", oidcURLs[0].URL)
	}
}

func TestAddURL_Rekor(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signing_config.json")

	if err := Create(CreateOptions{Output: cfgPath}); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if err := AddURL(AddURLOptions{
		ConfigPath: cfgPath,
		Type:       "rekor",
		URL:        "https://rekor.example.com",
		APIVersion: 1,
		Operator:   "example.com",
		StartTime:  testStartTime,
	}); err != nil {
		t.Fatalf("AddURL failed: %v", err)
	}

	output, err := Inspect(InspectOptions{ConfigPath: cfgPath, Format: "json"})
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}
	if !strings.Contains(output, "https://rekor.example.com") {
		t.Fatalf("JSON output missing Rekor URL, got:\n%s", output)
	}

	sc, err := loadSigningConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadSigningConfig failed: %v", err)
	}
	rekorURLs := sc.RekorLogURLs()
	if len(rekorURLs) != 1 {
		t.Fatalf("expected 1 Rekor URL, got %d", len(rekorURLs))
	}
	if rekorURLs[0].URL != "https://rekor.example.com" {
		t.Fatalf("URL mismatch: %s", rekorURLs[0].URL)
	}
}

func TestAddURL_TSA(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signing_config.json")

	if err := Create(CreateOptions{Output: cfgPath}); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if err := AddURL(AddURLOptions{
		ConfigPath: cfgPath,
		Type:       "tsa",
		URL:        "https://tsa.example.com",
		APIVersion: 1,
		Operator:   "example.com",
		StartTime:  testStartTime,
	}); err != nil {
		t.Fatalf("AddURL failed: %v", err)
	}

	output, err := Inspect(InspectOptions{ConfigPath: cfgPath, Format: "json"})
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}
	if !strings.Contains(output, "https://tsa.example.com") {
		t.Fatalf("JSON output missing TSA URL, got:\n%s", output)
	}

	sc, err := loadSigningConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadSigningConfig failed: %v", err)
	}
	tsaURLs := sc.TimestampAuthorityURLs()
	if len(tsaURLs) != 1 {
		t.Fatalf("expected 1 TSA URL, got %d", len(tsaURLs))
	}
	if tsaURLs[0].URL != "https://tsa.example.com" {
		t.Fatalf("URL mismatch: %s", tsaURLs[0].URL)
	}
}

func TestAddURL_ReplaceExisting(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signing_config.json")

	if err := Create(CreateOptions{Output: cfgPath}); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Add initial URL
	if err := AddURL(AddURLOptions{
		ConfigPath: cfgPath,
		Type:       "ca",
		URL:        "https://fulcio.example.com",
		APIVersion: 1,
		Operator:   "operator-v1",
		StartTime:  testStartTime,
	}); err != nil {
		t.Fatalf("AddURL (first) failed: %v", err)
	}

	// Add same URL with different operator
	if err := AddURL(AddURLOptions{
		ConfigPath: cfgPath,
		Type:       "ca",
		URL:        "https://fulcio.example.com",
		APIVersion: 2,
		Operator:   "operator-v2",
		StartTime:  testStartTime,
	}); err != nil {
		t.Fatalf("AddURL (replace) failed: %v", err)
	}

	sc, err := loadSigningConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadSigningConfig failed: %v", err)
	}
	caURLs := sc.FulcioCertificateAuthorityURLs()
	if len(caURLs) != 1 {
		t.Fatalf("expected 1 CA URL after replace, got %d", len(caURLs))
	}
	if caURLs[0].Operator != "operator-v2" {
		t.Fatalf("expected operator 'operator-v2', got %q", caURLs[0].Operator)
	}
}

func TestAddURL_WithValidityPeriod(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signing_config.json")

	if err := Create(CreateOptions{Output: cfgPath}); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	startTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	endTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	if err := AddURL(AddURLOptions{
		ConfigPath: cfgPath,
		Type:       "rekor",
		URL:        "https://rekor.example.com",
		APIVersion: 1,
		Operator:   "example.com",
		StartTime:  startTime,
		EndTime:    &endTime,
	}); err != nil {
		t.Fatalf("AddURL with validity period failed: %v", err)
	}

	// Verify both start and end are in JSON output
	output, err := Inspect(InspectOptions{ConfigPath: cfgPath, Format: "json"})
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}
	if !strings.Contains(output, "start") {
		t.Fatalf("JSON output missing validFor.start, got:\n%s", output)
	}
	if !strings.Contains(output, "end") {
		t.Fatalf("JSON output missing validFor.end, got:\n%s", output)
	}

	sc, err := loadSigningConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadSigningConfig failed: %v", err)
	}
	rekorURLs := sc.RekorLogURLs()
	if len(rekorURLs) != 1 {
		t.Fatalf("expected 1 Rekor URL, got %d", len(rekorURLs))
	}
	svc := rekorURLs[0]
	if svc.ValidityPeriodStart.IsZero() {
		t.Fatal("expected ValidityPeriodStart to be set")
	}
	if svc.ValidityPeriodEnd.IsZero() {
		t.Fatal("expected ValidityPeriodEnd to be set")
	}
	if !svc.ValidityPeriodStart.Equal(startTime) {
		t.Fatalf("start time mismatch: got %v, want %v", svc.ValidityPeriodStart, startTime)
	}
	if !svc.ValidityPeriodEnd.Equal(endTime) {
		t.Fatalf("end time mismatch: got %v, want %v", svc.ValidityPeriodEnd, endTime)
	}
}

func TestAddURL_InvalidType(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signing_config.json")

	if err := Create(CreateOptions{Output: cfgPath}); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	err := AddURL(AddURLOptions{
		ConfigPath: cfgPath,
		Type:       "invalid",
		URL:        "https://example.com",
		StartTime:  testStartTime,
	})
	if err == nil {
		t.Fatal("expected error for invalid service type")
	}
}

func TestAddURL_InvalidURL(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signing_config.json")

	if err := Create(CreateOptions{Output: cfgPath}); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	err := AddURL(AddURLOptions{
		ConfigPath: cfgPath,
		Type:       "ca",
		URL:        "not-a-url",
		StartTime:  testStartTime,
	})
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
	if !strings.Contains(err.Error(), "invalid URL") {
		t.Fatalf("expected 'invalid URL' error, got: %v", err)
	}
}

func TestAddURL_MissingStartTime(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signing_config.json")

	if err := Create(CreateOptions{Output: cfgPath}); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	err := AddURL(AddURLOptions{
		ConfigPath: cfgPath,
		Type:       "ca",
		URL:        "https://fulcio.example.com",
	})
	if err == nil {
		t.Fatal("expected error for missing start time")
	}
	if !strings.Contains(err.Error(), "start time is required") {
		t.Fatalf("expected 'start time is required' error, got: %v", err)
	}
}

// --- 4. RemoveURL tests ---

func TestRemoveURL_Existing(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signing_config.json")

	if err := Create(CreateOptions{Output: cfgPath}); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Add two URLs
	for _, u := range []string{"https://fulcio1.example.com", "https://fulcio2.example.com"} {
		if err := AddURL(AddURLOptions{
			ConfigPath: cfgPath,
			Type:       "ca",
			URL:        u,
			Operator:   "example.com",
			StartTime:  testStartTime,
		}); err != nil {
			t.Fatalf("AddURL(%s) failed: %v", u, err)
		}
	}

	// Remove the first one
	if err := RemoveURL(RemoveURLOptions{
		ConfigPath: cfgPath,
		Type:       "ca",
		URL:        "https://fulcio1.example.com",
	}); err != nil {
		t.Fatalf("RemoveURL failed: %v", err)
	}

	sc, err := loadSigningConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadSigningConfig failed: %v", err)
	}
	caURLs := sc.FulcioCertificateAuthorityURLs()
	if len(caURLs) != 1 {
		t.Fatalf("expected 1 CA URL after remove, got %d", len(caURLs))
	}
	if caURLs[0].URL != "https://fulcio2.example.com" {
		t.Fatalf("wrong URL remaining: %s", caURLs[0].URL)
	}
}

func TestRemoveURL_NonExistent(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signing_config.json")

	if err := Create(CreateOptions{Output: cfgPath}); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Add one URL
	if err := AddURL(AddURLOptions{
		ConfigPath: cfgPath,
		Type:       "ca",
		URL:        "https://fulcio.example.com",
		Operator:   "example.com",
		StartTime:  testStartTime,
	}); err != nil {
		t.Fatalf("AddURL failed: %v", err)
	}

	// Remove a URL that doesn't exist
	if err := RemoveURL(RemoveURLOptions{
		ConfigPath: cfgPath,
		Type:       "ca",
		URL:        "https://nonexistent.example.com",
	}); err != nil {
		t.Fatalf("RemoveURL for non-existent URL should not error: %v", err)
	}

	sc, err := loadSigningConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadSigningConfig failed: %v", err)
	}
	caURLs := sc.FulcioCertificateAuthorityURLs()
	if len(caURLs) != 1 {
		t.Fatalf("expected 1 CA URL unchanged, got %d", len(caURLs))
	}
	if caURLs[0].URL != "https://fulcio.example.com" {
		t.Fatalf("URL should be unchanged: %s", caURLs[0].URL)
	}
}

// --- 5. SetConfig tests ---

func TestSetConfig_RekorALL(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signing_config.json")

	if err := Create(CreateOptions{Output: cfgPath}); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if err := SetConfig(SetConfigOptions{
		ConfigPath: cfgPath,
		Type:       "rekor",
		Selector:   "ALL",
	}); err != nil {
		t.Fatalf("SetConfig failed: %v", err)
	}

	// Verify selector in inspect output
	output, err := Inspect(InspectOptions{ConfigPath: cfgPath, Format: "text"})
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}
	if !strings.Contains(output, "ALL") {
		t.Fatalf("text output missing ALL selector, got:\n%s", output)
	}

	sc, err := loadSigningConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadSigningConfig failed: %v", err)
	}
	if sc.RekorLogURLsConfig().Selector != trustrootpb.ServiceSelector_ALL {
		t.Fatalf("expected selector ALL, got %v", sc.RekorLogURLsConfig().Selector)
	}
}

func TestSetConfig_TsaEXACT(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signing_config.json")

	if err := Create(CreateOptions{Output: cfgPath}); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if err := SetConfig(SetConfigOptions{
		ConfigPath: cfgPath,
		Type:       "tsa",
		Selector:   "EXACT",
		Count:      2,
	}); err != nil {
		t.Fatalf("SetConfig failed: %v", err)
	}

	// Verify selector and count in inspect output
	output, err := Inspect(InspectOptions{ConfigPath: cfgPath, Format: "text"})
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}
	if !strings.Contains(output, "EXACT") {
		t.Fatalf("text output missing EXACT selector, got:\n%s", output)
	}
	if !strings.Contains(output, "count: 2") {
		t.Fatalf("text output missing count: 2, got:\n%s", output)
	}

	sc, err := loadSigningConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadSigningConfig failed: %v", err)
	}
	tsaConfig := sc.TimestampAuthorityURLsConfig()
	if tsaConfig.Selector != trustrootpb.ServiceSelector_EXACT {
		t.Fatalf("expected selector EXACT, got %v", tsaConfig.Selector)
	}
	if tsaConfig.Count != 2 {
		t.Fatalf("expected count 2, got %d", tsaConfig.Count)
	}
}

func TestSetConfig_InvalidType(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signing_config.json")

	if err := Create(CreateOptions{Output: cfgPath}); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	err := SetConfig(SetConfigOptions{
		ConfigPath: cfgPath,
		Type:       "ca",
		Selector:   "ALL",
	})
	if err == nil {
		t.Fatal("expected error for 'ca' type in SetConfig")
	}
}

func TestSetConfig_ExactZeroCount(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signing_config.json")

	if err := Create(CreateOptions{Output: cfgPath}); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	err := SetConfig(SetConfigOptions{
		ConfigPath: cfgPath,
		Type:       "rekor",
		Selector:   "EXACT",
		Count:      0,
	})
	if err == nil {
		t.Fatal("expected error for EXACT selector with count=0")
	}
}

func TestSetConfig_ANYWithCount(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signing_config.json")

	if err := Create(CreateOptions{Output: cfgPath}); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	err := SetConfig(SetConfigOptions{
		ConfigPath: cfgPath,
		Type:       "rekor",
		Selector:   "ANY",
		Count:      1,
	})
	if err == nil {
		t.Fatal("expected error for ANY selector with count > 0")
	}
	if !strings.Contains(err.Error(), "selector ANY does not accept a count") {
		t.Fatalf("expected 'selector ANY does not accept a count' error, got: %v", err)
	}
}

func TestSetConfig_ALLWithCount(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signing_config.json")

	if err := Create(CreateOptions{Output: cfgPath}); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	err := SetConfig(SetConfigOptions{
		ConfigPath: cfgPath,
		Type:       "rekor",
		Selector:   "ALL",
		Count:      1,
	})
	if err == nil {
		t.Fatal("expected error for ALL selector with count > 0")
	}
	if !strings.Contains(err.Error(), "selector ALL does not accept a count") {
		t.Fatalf("expected 'selector ALL does not accept a count' error, got: %v", err)
	}
}

// --- 6. Inspect tests ---

func TestInspect_TextFormat(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signing_config.json")

	if err := Create(CreateOptions{Output: cfgPath}); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if err := AddURL(AddURLOptions{
		ConfigPath: cfgPath,
		Type:       "ca",
		URL:        "https://fulcio.example.com",
		APIVersion: 1,
		Operator:   "example.com",
		StartTime:  testStartTime,
	}); err != nil {
		t.Fatalf("AddURL failed: %v", err)
	}

	if err := AddURL(AddURLOptions{
		ConfigPath: cfgPath,
		Type:       "rekor",
		URL:        "https://rekor.example.com",
		APIVersion: 1,
		Operator:   "example.com",
		StartTime:  testStartTime,
	}); err != nil {
		t.Fatalf("AddURL failed: %v", err)
	}

	output, err := Inspect(InspectOptions{ConfigPath: cfgPath, Format: "text"})
	if err != nil {
		t.Fatalf("Inspect text failed: %v", err)
	}

	if !strings.Contains(output, "https://fulcio.example.com") {
		t.Fatalf("text output missing CA URL, got:\n%s", output)
	}
	if !strings.Contains(output, "https://rekor.example.com") {
		t.Fatalf("text output missing Rekor URL, got:\n%s", output)
	}
	if !strings.Contains(output, "Media Type:") {
		t.Fatalf("text output missing Media Type header, got:\n%s", output)
	}
}

func TestInspect_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signing_config.json")

	if err := Create(CreateOptions{Output: cfgPath}); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if err := AddURL(AddURLOptions{
		ConfigPath: cfgPath,
		Type:       "ca",
		URL:        "https://fulcio.example.com",
		APIVersion: 1,
		Operator:   "example.com",
		StartTime:  testStartTime,
	}); err != nil {
		t.Fatalf("AddURL failed: %v", err)
	}

	output, err := Inspect(InspectOptions{ConfigPath: cfgPath, Format: "json"})
	if err != nil {
		t.Fatalf("Inspect json failed: %v", err)
	}

	if !json.Valid([]byte(output)) {
		t.Fatalf("inspect JSON output is not valid JSON:\n%s", output)
	}
	if !strings.Contains(output, root.SigningConfigMediaType02) {
		t.Fatalf("JSON output missing media type, got:\n%s", output)
	}
}

// --- 7. Additional coverage tests ---

func TestServiceType_String(t *testing.T) {
	tests := []struct {
		input ServiceType
		want  string
	}{
		{ServiceTypeCA, "ca"},
		{ServiceTypeOIDC, "oidc"},
		{ServiceTypeRekor, "rekor"},
		{ServiceTypeTSA, "tsa"},
		{ServiceType(99), "unknown"},
	}
	for _, tt := range tests {
		got := tt.input.String()
		if got != tt.want {
			t.Fatalf("ServiceType(%d).String() = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestRemoveURL_OIDC(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signing_config.json")

	Create(CreateOptions{Output: cfgPath})
	AddURL(AddURLOptions{ConfigPath: cfgPath, Type: "oidc", URL: "https://oidc1.example.com", Operator: "e", StartTime: testStartTime})
	AddURL(AddURLOptions{ConfigPath: cfgPath, Type: "oidc", URL: "https://oidc2.example.com", Operator: "e", StartTime: testStartTime})

	if err := RemoveURL(RemoveURLOptions{ConfigPath: cfgPath, Type: "oidc", URL: "https://oidc1.example.com"}); err != nil {
		t.Fatalf("RemoveURL oidc failed: %v", err)
	}
	sc, _ := loadSigningConfig(cfgPath)
	if len(sc.OIDCProviderURLs()) != 1 {
		t.Fatalf("expected 1 OIDC URL, got %d", len(sc.OIDCProviderURLs()))
	}
	if sc.OIDCProviderURLs()[0].URL != "https://oidc2.example.com" {
		t.Fatalf("wrong URL remaining: %s", sc.OIDCProviderURLs()[0].URL)
	}
}

func TestRemoveURL_Rekor(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signing_config.json")

	Create(CreateOptions{Output: cfgPath})
	AddURL(AddURLOptions{ConfigPath: cfgPath, Type: "rekor", URL: "https://rekor1.example.com", Operator: "e", StartTime: testStartTime})
	AddURL(AddURLOptions{ConfigPath: cfgPath, Type: "rekor", URL: "https://rekor2.example.com", Operator: "e", StartTime: testStartTime})

	if err := RemoveURL(RemoveURLOptions{ConfigPath: cfgPath, Type: "rekor", URL: "https://rekor1.example.com"}); err != nil {
		t.Fatalf("RemoveURL rekor failed: %v", err)
	}
	sc, _ := loadSigningConfig(cfgPath)
	if len(sc.RekorLogURLs()) != 1 {
		t.Fatalf("expected 1 Rekor URL, got %d", len(sc.RekorLogURLs()))
	}
	if sc.RekorLogURLs()[0].URL != "https://rekor2.example.com" {
		t.Fatalf("wrong URL remaining: %s", sc.RekorLogURLs()[0].URL)
	}
}

func TestRemoveURL_TSA(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signing_config.json")

	Create(CreateOptions{Output: cfgPath})
	AddURL(AddURLOptions{ConfigPath: cfgPath, Type: "tsa", URL: "https://tsa1.example.com", Operator: "e", StartTime: testStartTime})
	AddURL(AddURLOptions{ConfigPath: cfgPath, Type: "tsa", URL: "https://tsa2.example.com", Operator: "e", StartTime: testStartTime})

	if err := RemoveURL(RemoveURLOptions{ConfigPath: cfgPath, Type: "tsa", URL: "https://tsa1.example.com"}); err != nil {
		t.Fatalf("RemoveURL tsa failed: %v", err)
	}
	sc, _ := loadSigningConfig(cfgPath)
	if len(sc.TimestampAuthorityURLs()) != 1 {
		t.Fatalf("expected 1 TSA URL, got %d", len(sc.TimestampAuthorityURLs()))
	}
	if sc.TimestampAuthorityURLs()[0].URL != "https://tsa2.example.com" {
		t.Fatalf("wrong URL remaining: %s", sc.TimestampAuthorityURLs()[0].URL)
	}
}

func TestInspect_InvalidFormat(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signing_config.json")
	Create(CreateOptions{Output: cfgPath})

	_, err := Inspect(InspectOptions{ConfigPath: cfgPath, Format: "yaml"})
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
	if !strings.Contains(err.Error(), "unknown format") {
		t.Fatalf("expected 'unknown format' error, got: %v", err)
	}
}

func TestAddURL_OutputPath(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "input.json")
	outputPath := filepath.Join(dir, "output.json")

	Create(CreateOptions{Output: inputPath})

	if err := AddURL(AddURLOptions{
		ConfigPath: inputPath,
		OutputPath: outputPath,
		Type:       "ca",
		URL:        "https://fulcio.example.com",
		APIVersion: 1,
		Operator:   "example.com",
		StartTime:  testStartTime,
	}); err != nil {
		t.Fatalf("AddURL with OutputPath failed: %v", err)
	}

	// Output file should have the URL
	scOut, err := loadSigningConfig(outputPath)
	if err != nil {
		t.Fatalf("loadSigningConfig(output) failed: %v", err)
	}
	if len(scOut.FulcioCertificateAuthorityURLs()) != 1 {
		t.Fatalf("expected 1 CA URL in output, got %d", len(scOut.FulcioCertificateAuthorityURLs()))
	}

	// Input file should be unchanged (empty)
	scIn, err := loadSigningConfig(inputPath)
	if err != nil {
		t.Fatalf("loadSigningConfig(input) failed: %v", err)
	}
	if len(scIn.FulcioCertificateAuthorityURLs()) != 0 {
		t.Fatalf("expected 0 CA URLs in input (unchanged), got %d", len(scIn.FulcioCertificateAuthorityURLs()))
	}
}

func TestSavedFileFormat_CompactJSON(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signing_config.json")

	Create(CreateOptions{Output: cfgPath})
	AddURL(AddURLOptions{
		ConfigPath: cfgPath,
		Type:       "ca",
		URL:        "https://fulcio.example.com",
		APIVersion: 1,
		Operator:   "example.com",
		StartTime:  testStartTime,
	})

	// Read raw bytes from disk
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("failed to read config file: %v", err)
	}

	// Compact JSON should NOT contain newlines (single line)
	if strings.Contains(string(data), "\n") {
		t.Fatalf("saved file should be compact JSON (no newlines), got:\n%s", string(data))
	}

	// Should be valid JSON
	if !json.Valid(data) {
		t.Fatalf("saved file is not valid JSON")
	}

	// Should contain validFor (cosign parity)
	if !strings.Contains(string(data), "validFor") {
		t.Fatalf("saved file missing validFor field")
	}
}

func TestCosignOutputParity(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signing_config.json")
	startTime := time.Date(2026, 7, 28, 14, 12, 14, 0, time.UTC)

	Create(CreateOptions{Output: cfgPath})

	services := []struct {
		svcType  string
		url      string
		operator string
	}{
		{"ca", "https://fulcio.example.com", "rhtas.redhat.com"},
		{"oidc", "https://keycloak.example.com/realms/trusted-artifact-signer", "rhtas.redhat.com"},
		{"rekor", "https://rekor.example.com", "rhtas.redhat.com"},
		{"tsa", "https://tsa.example.com/api/v1/timestamp", "rhtas.redhat.com"},
	}
	for _, s := range services {
		AddURL(AddURLOptions{
			ConfigPath: cfgPath,
			Type:       s.svcType,
			URL:        s.url,
			APIVersion: 1,
			Operator:   s.operator,
			StartTime:  startTime,
		})
	}
	SetConfig(SetConfigOptions{ConfigPath: cfgPath, Type: "rekor", Selector: "ANY"})
	SetConfig(SetConfigOptions{ConfigPath: cfgPath, Type: "tsa", Selector: "ANY"})

	// Read raw saved file
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("failed to read config: %v", err)
	}

	// Parse and verify structure matches cosign's output format
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	// Media type
	if parsed["mediaType"] != root.SigningConfigMediaType02 {
		t.Fatalf("wrong media type: %v", parsed["mediaType"])
	}

	// Every service list should have entries with validFor.start
	for _, field := range []string{"caUrls", "oidcUrls", "rekorTlogUrls", "tsaUrls"} {
		list, ok := parsed[field].([]interface{})
		if !ok || len(list) == 0 {
			t.Fatalf("expected non-empty %s", field)
		}
		entry := list[0].(map[string]interface{})
		validFor, ok := entry["validFor"].(map[string]interface{})
		if !ok {
			t.Fatalf("%s[0] missing validFor", field)
		}
		if _, ok := validFor["start"]; !ok {
			t.Fatalf("%s[0].validFor missing start", field)
		}
	}

	// Rekor/TSA configs should have selector
	for _, field := range []string{"rekorTlogConfig", "tsaConfig"} {
		cfg, ok := parsed[field].(map[string]interface{})
		if !ok {
			t.Fatalf("missing %s", field)
		}
		if _, ok := cfg["selector"]; !ok {
			t.Fatalf("%s missing selector", field)
		}
	}
}

func TestClusterConfigRoundtrip(t *testing.T) {
	dir := t.TempDir()
	startTime := time.Date(2026, 7, 28, 14, 12, 14, 0, time.UTC)

	// Simulate a cluster-deployed config (pretty-printed, like rhtas produces)
	clusterJSON := `{
  "mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json",
  "caUrls": [
    {
      "url": "https://fulcio.cluster.example.com",
      "majorApiVersion": 1,
      "validFor": {
        "start": "2026-07-28T14:12:14Z"
      },
      "operator": "rhtas.redhat.com"
    }
  ],
  "oidcUrls": [
    {
      "url": "https://keycloak.cluster.example.com/realms/trusted-artifact-signer",
      "majorApiVersion": 1,
      "validFor": {
        "start": "2026-07-28T14:12:14Z"
      },
      "operator": "rhtas.redhat.com"
    }
  ],
  "rekorTlogUrls": [
    {
      "url": "https://rekor.cluster.example.com",
      "majorApiVersion": 1,
      "validFor": {
        "start": "2026-07-28T14:12:14Z"
      },
      "operator": "rhtas.redhat.com"
    }
  ],
  "rekorTlogConfig": {
    "selector": "ANY"
  },
  "tsaUrls": [
    {
      "url": "https://tsa.cluster.example.com/api/v1/timestamp",
      "majorApiVersion": 1,
      "validFor": {
        "start": "2026-07-28T14:12:14Z"
      },
      "operator": "rhtas.redhat.com"
    }
  ],
  "tsaConfig": {
    "selector": "ANY"
  }
}`
	clusterPath := filepath.Join(dir, "cluster.json")
	os.WriteFile(clusterPath, []byte(clusterJSON), 0644)

	// Clone it
	clonePath := filepath.Join(dir, "cloned.json")
	if err := Create(CreateOptions{Output: clonePath, BaseConfig: clusterPath}); err != nil {
		t.Fatalf("Create from cluster config failed: %v", err)
	}

	// Modify: add a second OIDC provider
	if err := AddURL(AddURLOptions{
		ConfigPath: clonePath,
		Type:       "oidc",
		URL:        "https://accounts.google.com",
		APIVersion: 1,
		Operator:   "google.com",
		StartTime:  startTime,
	}); err != nil {
		t.Fatalf("AddURL oidc failed: %v", err)
	}

	// Verify original services survived the roundtrip
	sc, err := loadSigningConfig(clonePath)
	if err != nil {
		t.Fatalf("loadSigningConfig failed: %v", err)
	}

	if len(sc.FulcioCertificateAuthorityURLs()) != 1 {
		t.Fatalf("expected 1 CA URL preserved, got %d", len(sc.FulcioCertificateAuthorityURLs()))
	}
	if sc.FulcioCertificateAuthorityURLs()[0].URL != "https://fulcio.cluster.example.com" {
		t.Fatalf("CA URL not preserved: %s", sc.FulcioCertificateAuthorityURLs()[0].URL)
	}
	if len(sc.OIDCProviderURLs()) != 2 {
		t.Fatalf("expected 2 OIDC URLs (1 original + 1 added), got %d", len(sc.OIDCProviderURLs()))
	}
	if len(sc.RekorLogURLs()) != 1 {
		t.Fatalf("expected 1 Rekor URL preserved, got %d", len(sc.RekorLogURLs()))
	}
	if len(sc.TimestampAuthorityURLs()) != 1 {
		t.Fatalf("expected 1 TSA URL preserved, got %d", len(sc.TimestampAuthorityURLs()))
	}
	if sc.RekorLogURLsConfig().Selector != trustrootpb.ServiceSelector_ANY {
		t.Fatalf("Rekor config not preserved, got %v", sc.RekorLogURLsConfig().Selector)
	}

	// Remove the added OIDC and verify we're back to original count
	if err := RemoveURL(RemoveURLOptions{
		ConfigPath: clonePath,
		Type:       "oidc",
		URL:        "https://accounts.google.com",
	}); err != nil {
		t.Fatalf("RemoveURL oidc failed: %v", err)
	}
	sc, _ = loadSigningConfig(clonePath)
	if len(sc.OIDCProviderURLs()) != 1 {
		t.Fatalf("expected 1 OIDC URL after remove, got %d", len(sc.OIDCProviderURLs()))
	}
}

func TestAddURL_EndTimeBeforeStartTime(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signing_config.json")
	Create(CreateOptions{Output: cfgPath})

	startTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	endTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	err := AddURL(AddURLOptions{
		ConfigPath: cfgPath,
		Type:       "ca",
		URL:        "https://fulcio.example.com",
		StartTime:  startTime,
		EndTime:    &endTime,
	})
	if err == nil {
		t.Fatal("expected error for end time before start time")
	}
	if !strings.Contains(err.Error(), "end time must be after start time") {
		t.Fatalf("expected 'end time must be after start time' error, got: %v", err)
	}
}

func TestAddURL_EndTimeEqualStartTime(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signing_config.json")
	Create(CreateOptions{Output: cfgPath})

	sameTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	err := AddURL(AddURLOptions{
		ConfigPath: cfgPath,
		Type:       "ca",
		URL:        "https://fulcio.example.com",
		StartTime:  sameTime,
		EndTime:    &sameTime,
	})
	if err == nil {
		t.Fatal("expected error for end time equal to start time")
	}
}

func TestSaveSigningConfig_NestedOutputPath(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signing_config.json")
	Create(CreateOptions{Output: cfgPath})

	nestedOutput := filepath.Join(dir, "nested", "deep", "output.json")

	err := AddURL(AddURLOptions{
		ConfigPath: cfgPath,
		OutputPath: nestedOutput,
		Type:       "ca",
		URL:        "https://fulcio.example.com",
		APIVersion: 1,
		Operator:   "example.com",
		StartTime:  testStartTime,
	})
	if err != nil {
		t.Fatalf("AddURL to nested output path failed: %v", err)
	}

	sc, err := loadSigningConfig(nestedOutput)
	if err != nil {
		t.Fatalf("loadSigningConfig from nested path failed: %v", err)
	}
	if len(sc.FulcioCertificateAuthorityURLs()) != 1 {
		t.Fatalf("expected 1 CA URL in nested output, got %d", len(sc.FulcioCertificateAuthorityURLs()))
	}
}

func TestEnsureConfigDefaults_NilConfigs(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "minimal.json")

	// Write JSON with valid media type but missing rekorTlogConfig and tsaConfig
	minimalJSON := `{"mediaType":"application/vnd.dev.sigstore.signingconfig.v0.2+json"}`
	os.WriteFile(cfgPath, []byte(minimalJSON), 0644)

	sc, err := loadSigningConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadSigningConfig failed: %v", err)
	}

	// ensureConfigDefaults should have initialized the nil configs
	rekorCfg := sc.RekorLogURLsConfig()
	if rekorCfg.Selector != trustrootpb.ServiceSelector_ANY {
		t.Fatalf("expected RekorTlogConfig selector ANY, got %v", rekorCfg.Selector)
	}
	tsaCfg := sc.TimestampAuthorityURLsConfig()
	if tsaCfg.Selector != trustrootpb.ServiceSelector_ANY {
		t.Fatalf("expected TsaConfig selector ANY, got %v", tsaCfg.Selector)
	}
}

func TestLoadSigningConfig_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad.json")
	os.WriteFile(cfgPath, []byte(`{not valid json`), 0644)

	_, err := loadSigningConfig(cfgPath)
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if !strings.Contains(err.Error(), "failed to parse") {
		t.Fatalf("expected parse error, got: %v", err)
	}
}

func TestLoadSigningConfig_FileNotFound(t *testing.T) {
	_, err := loadSigningConfig("/nonexistent/path/config.json")
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
	if !strings.Contains(err.Error(), "failed to read") {
		t.Fatalf("expected read error, got: %v", err)
	}
}

func TestRemoveURL_LoadError(t *testing.T) {
	err := RemoveURL(RemoveURLOptions{
		ConfigPath: "/nonexistent/config.json",
		Type:       "ca",
		URL:        "https://example.com",
	})
	if err == nil {
		t.Fatal("expected error for non-existent config")
	}
}

func TestRemoveURL_InvalidType(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signing_config.json")
	Create(CreateOptions{Output: cfgPath})

	err := RemoveURL(RemoveURLOptions{
		ConfigPath: cfgPath,
		Type:       "bogus",
		URL:        "https://example.com",
	})
	if err == nil {
		t.Fatal("expected error for invalid type")
	}
}

func TestSetConfig_LoadError(t *testing.T) {
	err := SetConfig(SetConfigOptions{
		ConfigPath: "/nonexistent/config.json",
		Type:       "rekor",
		Selector:   "ANY",
	})
	if err == nil {
		t.Fatal("expected error for non-existent config")
	}
}

func TestSetConfig_InvalidSelector(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signing_config.json")
	Create(CreateOptions{Output: cfgPath})

	err := SetConfig(SetConfigOptions{
		ConfigPath: cfgPath,
		Type:       "rekor",
		Selector:   "BOGUS",
	})
	if err == nil {
		t.Fatal("expected error for invalid selector")
	}
}

func TestInspect_LoadError(t *testing.T) {
	_, err := Inspect(InspectOptions{
		ConfigPath: "/nonexistent/config.json",
		Format:     "text",
	})
	if err == nil {
		t.Fatal("expected error for non-existent config")
	}
}

func TestInspect_TextWithEndTime(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signing_config.json")
	Create(CreateOptions{Output: cfgPath})

	startTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	endTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	AddURL(AddURLOptions{
		ConfigPath: cfgPath,
		Type:       "ca",
		URL:        "https://fulcio.example.com",
		APIVersion: 1,
		Operator:   "example.com",
		StartTime:  startTime,
		EndTime:    &endTime,
	})

	output, err := Inspect(InspectOptions{ConfigPath: cfgPath, Format: "text"})
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}
	if !strings.Contains(output, "2025-01-01T00:00:00Z") {
		t.Fatalf("text output missing start time, got:\n%s", output)
	}
	if !strings.Contains(output, "2026-01-01T00:00:00Z") {
		t.Fatalf("text output missing end time, got:\n%s", output)
	}
}

func TestAddURL_LoadError(t *testing.T) {
	err := AddURL(AddURLOptions{
		ConfigPath: "/nonexistent/config.json",
		Type:       "ca",
		URL:        "https://example.com",
		StartTime:  testStartTime,
	})
	if err == nil {
		t.Fatal("expected error for non-existent config")
	}
}

// --- 8. Roundtrip test ---

func TestFullWorkflow(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signing_config.json")

	// Step 1: Create
	if err := Create(CreateOptions{Output: cfgPath}); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Step 2: Add URLs for all 4 types
	urls := []struct {
		svcType  string
		url      string
		operator string
	}{
		{"ca", "https://fulcio.example.com", "example.com"},
		{"oidc", "https://oidc.example.com", "example.com"},
		{"rekor", "https://rekor.example.com", "example.com"},
		{"tsa", "https://tsa.example.com", "example.com"},
	}
	for _, u := range urls {
		if err := AddURL(AddURLOptions{
			ConfigPath: cfgPath,
			Type:       u.svcType,
			URL:        u.url,
			APIVersion: 1,
			Operator:   u.operator,
			StartTime:  testStartTime,
		}); err != nil {
			t.Fatalf("AddURL(%s) failed: %v", u.svcType, err)
		}
	}

	// Step 3: Set config for rekor=ALL and tsa=EXACT:2
	if err := SetConfig(SetConfigOptions{
		ConfigPath: cfgPath,
		Type:       "rekor",
		Selector:   "ALL",
	}); err != nil {
		t.Fatalf("SetConfig rekor failed: %v", err)
	}
	if err := SetConfig(SetConfigOptions{
		ConfigPath: cfgPath,
		Type:       "tsa",
		Selector:   "EXACT",
		Count:      2,
	}); err != nil {
		t.Fatalf("SetConfig tsa failed: %v", err)
	}

	// Step 4: Inspect text - verify all URLs present
	textOutput, err := Inspect(InspectOptions{ConfigPath: cfgPath, Format: "text"})
	if err != nil {
		t.Fatalf("Inspect text failed: %v", err)
	}
	for _, u := range urls {
		if !strings.Contains(textOutput, u.url) {
			t.Fatalf("text output missing %s URL %s", u.svcType, u.url)
		}
	}

	// Step 5: Inspect JSON - verify valid JSON
	jsonOutput, err := Inspect(InspectOptions{ConfigPath: cfgPath, Format: "json"})
	if err != nil {
		t.Fatalf("Inspect json failed: %v", err)
	}
	if !json.Valid([]byte(jsonOutput)) {
		t.Fatalf("JSON output is not valid JSON")
	}

	// Step 6: Remove CA URL and verify
	if err := RemoveURL(RemoveURLOptions{
		ConfigPath: cfgPath,
		Type:       "ca",
		URL:        "https://fulcio.example.com",
	}); err != nil {
		t.Fatalf("RemoveURL failed: %v", err)
	}

	sc, err := loadSigningConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadSigningConfig failed: %v", err)
	}
	if len(sc.FulcioCertificateAuthorityURLs()) != 0 {
		t.Fatalf("expected 0 CA URLs after remove, got %d", len(sc.FulcioCertificateAuthorityURLs()))
	}
	if len(sc.OIDCProviderURLs()) != 1 {
		t.Fatalf("expected 1 OIDC URL, got %d", len(sc.OIDCProviderURLs()))
	}
	if len(sc.RekorLogURLs()) != 1 {
		t.Fatalf("expected 1 Rekor URL, got %d", len(sc.RekorLogURLs()))
	}
	if len(sc.TimestampAuthorityURLs()) != 1 {
		t.Fatalf("expected 1 TSA URL, got %d", len(sc.TimestampAuthorityURLs()))
	}
	if sc.RekorLogURLsConfig().Selector != trustrootpb.ServiceSelector_ALL {
		t.Fatalf("expected RekorTlogConfig selector ALL, got %v", sc.RekorLogURLsConfig().Selector)
	}
	if sc.TimestampAuthorityURLsConfig().Selector != trustrootpb.ServiceSelector_EXACT {
		t.Fatalf("expected TsaConfig selector EXACT, got %v", sc.TimestampAuthorityURLsConfig().Selector)
	}
	if sc.TimestampAuthorityURLsConfig().Count != 2 {
		t.Fatalf("expected TsaConfig count 2, got %d", sc.TimestampAuthorityURLsConfig().Count)
	}
}
