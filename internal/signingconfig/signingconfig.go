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
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	trustrootpb "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/securesign/tufcli/internal/utils"
)

type ServiceType int

const (
	ServiceTypeCA ServiceType = iota
	ServiceTypeOIDC
	ServiceTypeRekor
	ServiceTypeTSA
)

func (t ServiceType) String() string {
	switch t {
	case ServiceTypeCA:
		return "ca"
	case ServiceTypeOIDC:
		return "oidc"
	case ServiceTypeRekor:
		return "rekor"
	case ServiceTypeTSA:
		return "tsa"
	default:
		return "unknown"
	}
}

func ParseServiceType(s string) (ServiceType, error) {
	switch strings.ToLower(s) {
	case "ca":
		return ServiceTypeCA, nil
	case "oidc":
		return ServiceTypeOIDC, nil
	case "rekor":
		return ServiceTypeRekor, nil
	case "tsa":
		return ServiceTypeTSA, nil
	default:
		return 0, fmt.Errorf("unknown service type %q: must be one of ca, oidc, rekor, tsa", s)
	}
}

func ParseSelector(s string) (trustrootpb.ServiceSelector, error) {
	switch strings.ToUpper(s) {
	case "ALL":
		return trustrootpb.ServiceSelector_ALL, nil
	case "ANY":
		return trustrootpb.ServiceSelector_ANY, nil
	case "EXACT":
		return trustrootpb.ServiceSelector_EXACT, nil
	default:
		return 0, fmt.Errorf("unknown selector %q: must be one of ALL, ANY, EXACT", s)
	}
}

func ensureConfigDefaults(sc *trustrootpb.SigningConfig) {
	if sc.CaUrls == nil {
		sc.CaUrls = []*trustrootpb.Service{}
	}
	if sc.OidcUrls == nil {
		sc.OidcUrls = []*trustrootpb.Service{}
	}
	if sc.RekorTlogUrls == nil {
		sc.RekorTlogUrls = []*trustrootpb.Service{}
	}
	if sc.TsaUrls == nil {
		sc.TsaUrls = []*trustrootpb.Service{}
	}
	if sc.RekorTlogConfig == nil {
		sc.RekorTlogConfig = &trustrootpb.ServiceConfiguration{
			Selector: trustrootpb.ServiceSelector_ANY,
			Count:    0,
		}
	}
	if sc.TsaConfig == nil {
		sc.TsaConfig = &trustrootpb.ServiceConfiguration{
			Selector: trustrootpb.ServiceSelector_ANY,
			Count:    0,
		}
	}
}

func loadSigningConfig(path string) (*root.SigningConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read signing config from %s: %w", path, err)
	}
	pbsc := &trustrootpb.SigningConfig{}
	if err := protojson.Unmarshal(data, pbsc); err != nil {
		return nil, fmt.Errorf("failed to parse signing config from %s: %w", path, err)
	}
	ensureConfigDefaults(pbsc)
	return root.NewSigningConfigFromProtobuf(pbsc)
}

func saveSigningConfig(sc *root.SigningConfig, path string) error {
	data, err := sc.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal signing config: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create parent directory: %w", err)
	}
	return utils.WriteFileAtomic(path, data)
}

func replaceOrAppendService(services []root.Service, newService root.Service) []root.Service {
	result := make([]root.Service, 0, len(services))
	for _, svc := range services {
		if svc.URL != newService.URL {
			result = append(result, svc)
		}
	}
	return append(result, newService)
}

func filterServicesByURL(services []root.Service, serviceURL string) []root.Service {
	result := make([]root.Service, 0, len(services))
	for _, svc := range services {
		if svc.URL != serviceURL {
			result = append(result, svc)
		}
	}
	return result
}

type CreateOptions struct {
	Output              string
	BaseConfig          string
	WithDefaultServices bool
}

func Create(opts CreateOptions) error {
	var sc *root.SigningConfig
	var err error

	switch {
	case opts.BaseConfig != "":
		sc, err = loadSigningConfig(opts.BaseConfig)
		if err != nil {
			return err
		}
	case opts.WithDefaultServices:
		sc, err = root.FetchSigningConfig()
		if err != nil {
			return err
		}
	default:
		sc, err = root.NewSigningConfig(
			root.SigningConfigMediaType02,
			nil,
			nil,
			nil,
			root.ServiceConfiguration{Selector: trustrootpb.ServiceSelector_ANY},
			nil,
			root.ServiceConfiguration{Selector: trustrootpb.ServiceSelector_ANY},
		)
		if err != nil {
			return err
		}
	}
	return saveSigningConfig(sc, opts.Output)
}

type AddURLOptions struct {
	ConfigPath string
	OutputPath string
	Type       string
	URL        string
	APIVersion uint32
	Operator   string
	StartTime  time.Time
	EndTime    *time.Time
}

func AddURL(opts AddURLOptions) error {
	sc, err := loadSigningConfig(opts.ConfigPath)
	if err != nil {
		return err
	}

	svcType, err := ParseServiceType(opts.Type)
	if err != nil {
		return err
	}

	// Validate URL
	u, err := url.Parse(opts.URL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid URL %q: must have a scheme and host", opts.URL)
	}

	// Validate start time
	if opts.StartTime.IsZero() {
		return fmt.Errorf("start time is required")
	}

	service := root.Service{
		URL:                 opts.URL,
		MajorAPIVersion:     opts.APIVersion,
		Operator:            opts.Operator,
		ValidityPeriodStart: opts.StartTime,
	}

	if opts.EndTime != nil {
		if !opts.EndTime.After(opts.StartTime) {
			return fmt.Errorf("end time must be after start time")
		}
		service.ValidityPeriodEnd = *opts.EndTime
	}

	switch svcType {
	case ServiceTypeCA:
		services := replaceOrAppendService(sc.FulcioCertificateAuthorityURLs(), service)
		sc = sc.WithFulcioCertificateAuthorityURLs(services...)
	case ServiceTypeOIDC:
		services := replaceOrAppendService(sc.OIDCProviderURLs(), service)
		sc = sc.WithOIDCProviderURLs(services...)
	case ServiceTypeRekor:
		services := replaceOrAppendService(sc.RekorLogURLs(), service)
		sc = sc.WithRekorLogURLs(services...)
	case ServiceTypeTSA:
		services := replaceOrAppendService(sc.TimestampAuthorityURLs(), service)
		sc = sc.WithTimestampAuthorityURLs(services...)
	}

	output := opts.OutputPath
	if output == "" {
		output = opts.ConfigPath
	}
	return saveSigningConfig(sc, output)
}

type RemoveURLOptions struct {
	ConfigPath string
	OutputPath string
	Type       string
	URL        string
}

func RemoveURL(opts RemoveURLOptions) error {
	sc, err := loadSigningConfig(opts.ConfigPath)
	if err != nil {
		return err
	}

	svcType, err := ParseServiceType(opts.Type)
	if err != nil {
		return err
	}

	switch svcType {
	case ServiceTypeCA:
		services := filterServicesByURL(sc.FulcioCertificateAuthorityURLs(), opts.URL)
		sc = sc.WithFulcioCertificateAuthorityURLs(services...)
	case ServiceTypeOIDC:
		services := filterServicesByURL(sc.OIDCProviderURLs(), opts.URL)
		sc = sc.WithOIDCProviderURLs(services...)
	case ServiceTypeRekor:
		services := filterServicesByURL(sc.RekorLogURLs(), opts.URL)
		sc = sc.WithRekorLogURLs(services...)
	case ServiceTypeTSA:
		services := filterServicesByURL(sc.TimestampAuthorityURLs(), opts.URL)
		sc = sc.WithTimestampAuthorityURLs(services...)
	}

	output := opts.OutputPath
	if output == "" {
		output = opts.ConfigPath
	}
	return saveSigningConfig(sc, output)
}

type SetConfigOptions struct {
	ConfigPath string
	OutputPath string
	Type       string
	Selector   string
	Count      uint32
}

func SetConfig(opts SetConfigOptions) error {
	sc, err := loadSigningConfig(opts.ConfigPath)
	if err != nil {
		return err
	}

	svcType, err := ParseServiceType(opts.Type)
	if err != nil {
		return err
	}
	if svcType != ServiceTypeRekor && svcType != ServiceTypeTSA {
		return fmt.Errorf("service configuration only applies to rekor and tsa, got %q", opts.Type)
	}

	selector, err := ParseSelector(opts.Selector)
	if err != nil {
		return err
	}

	if selector == trustrootpb.ServiceSelector_ANY && opts.Count > 0 {
		return fmt.Errorf("selector ANY does not accept a count")
	}
	if selector == trustrootpb.ServiceSelector_ALL && opts.Count > 0 {
		return fmt.Errorf("selector ALL does not accept a count")
	}
	if selector == trustrootpb.ServiceSelector_EXACT && opts.Count == 0 {
		return fmt.Errorf("EXACT selector requires count > 0")
	}

	switch svcType {
	case ServiceTypeRekor:
		sc = sc.WithRekorTlogConfig(selector, opts.Count)
	case ServiceTypeTSA:
		sc = sc.WithTsaConfig(selector, opts.Count)
	}

	output := opts.OutputPath
	if output == "" {
		output = opts.ConfigPath
	}
	return saveSigningConfig(sc, output)
}

type InspectOptions struct {
	ConfigPath string
	Format     string
}

func Inspect(opts InspectOptions) (string, error) {
	sc, err := loadSigningConfig(opts.ConfigPath)
	if err != nil {
		return "", err
	}

	switch opts.Format {
	case "json":
		data, err := sc.MarshalJSON()
		if err != nil {
			return "", fmt.Errorf("failed to marshal signing config: %w", err)
		}
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, data, "", "  "); err != nil {
			return "", fmt.Errorf("failed to format JSON: %w", err)
		}
		return pretty.String(), nil
	case "text":
		return formatText(sc), nil
	default:
		return "", fmt.Errorf("unknown format %q: must be json or text", opts.Format)
	}
}

func formatText(sc *root.SigningConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Media Type: %s\n", root.SigningConfigMediaType02)

	printServices := func(label string, services []root.Service) {
		fmt.Fprintf(&b, "\n%s:\n", label)
		if len(services) == 0 {
			fmt.Fprintf(&b, "  (none)\n")
			return
		}
		for _, svc := range services {
			fmt.Fprintf(&b, "  - %s (api=v%d, operator=%s)\n", svc.URL, svc.MajorAPIVersion, svc.Operator)
			if !svc.ValidityPeriodStart.IsZero() || !svc.ValidityPeriodEnd.IsZero() {
				start := "(unset)"
				if !svc.ValidityPeriodStart.IsZero() {
					start = svc.ValidityPeriodStart.UTC().Format(time.RFC3339)
				}
				end := "(unset)"
				if !svc.ValidityPeriodEnd.IsZero() {
					end = svc.ValidityPeriodEnd.UTC().Format(time.RFC3339)
				}
				fmt.Fprintf(&b, "    valid: %s to %s\n", start, end)
			}
		}
	}

	printServices("CA URLs", sc.FulcioCertificateAuthorityURLs())
	printServices("OIDC URLs", sc.OIDCProviderURLs())
	printServices("Rekor TLog URLs", sc.RekorLogURLs())
	printServices("TSA URLs", sc.TimestampAuthorityURLs())

	printConfig := func(label string, cfg root.ServiceConfiguration) {
		fmt.Fprintf(&b, "\n%s:\n", label)
		fmt.Fprintf(&b, "  selector: %s, count: %d\n", cfg.Selector.String(), cfg.Count)
	}

	printConfig("Rekor TLog Config", sc.RekorLogURLsConfig())
	printConfig("TSA Config", sc.TimestampAuthorityURLsConfig())

	return b.String()
}
