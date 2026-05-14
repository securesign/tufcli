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

package sigstore

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	commonpb "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	trustrootpb "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/securesign/tufcli/internal/utils"
)

// TargetKind identifies the type of RHTAS target.
type TargetKind int

const (
	TargetCertificateAuthority TargetKind = iota
	TargetTimestampAuthority
	TargetCtlog
	TargetTlog
)

var protojsonMarshaler = protojson.MarshalOptions{
	Multiline: true,
	Indent:    "  ",
}

// TrustBundle manages the TrustedRoot and SigningConfig for a Sigstore/RHTAS repository.
type TrustBundle struct {
	TrustedRoot   *trustrootpb.TrustedRoot
	SigningConfig *trustrootpb.SigningConfig
}

// NewTrustBundle creates a new TrustBundle with empty defaults.
func NewTrustBundle() *TrustBundle {
	return &TrustBundle{
		TrustedRoot: &trustrootpb.TrustedRoot{
			MediaType:              root.TrustedRootMediaType01,
			Tlogs:                  []*trustrootpb.TransparencyLogInstance{},
			CertificateAuthorities: []*trustrootpb.CertificateAuthority{},
			Ctlogs:                 []*trustrootpb.TransparencyLogInstance{},
			TimestampAuthorities:   []*trustrootpb.CertificateAuthority{},
		},
		SigningConfig: &trustrootpb.SigningConfig{
			MediaType:     root.SigningConfigMediaType02,
			CaUrls:        []*trustrootpb.Service{},
			OidcUrls:      []*trustrootpb.Service{},
			RekorTlogUrls: []*trustrootpb.Service{},
			TsaUrls:       []*trustrootpb.Service{},
			RekorTlogConfig: &trustrootpb.ServiceConfiguration{
				Selector: trustrootpb.ServiceSelector_ANY,
				Count:    0,
			},
			TsaConfig: &trustrootpb.ServiceConfiguration{
				Selector: trustrootpb.ServiceSelector_ANY,
				Count:    0,
			},
		},
	}
}

// LoadTrustBundle loads a TrustBundle from existing files, or creates a new one if files don't exist.
func LoadTrustBundle(trustedRootPath, signingConfigPath string) (*TrustBundle, error) {
	tb := NewTrustBundle()

	if utils.FileExists(trustedRootPath) {
		data, err := os.ReadFile(trustedRootPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read trusted root from %s: %w", trustedRootPath, err)
		}
		if err := protojson.Unmarshal(data, tb.TrustedRoot); err != nil {
			return nil, fmt.Errorf("failed to parse trusted root from %s: %w", trustedRootPath, err)
		}
	}

	if utils.FileExists(signingConfigPath) {
		data, err := os.ReadFile(signingConfigPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read signing config from %s: %w", signingConfigPath, err)
		}
		if err := protojson.Unmarshal(data, tb.SigningConfig); err != nil {
			return nil, fmt.Errorf("failed to parse signing config from %s: %w", signingConfigPath, err)
		}
	}

	return tb, nil
}

// SaveTrustedRoot writes the TrustedRoot to the given path.
func (tb *TrustBundle) SaveTrustedRoot(path string) error {
	data, err := protojsonMarshaler.Marshal(tb.TrustedRoot)
	if err != nil {
		return fmt.Errorf("failed to marshal trusted root: %w", err)
	}
	return utils.WriteFileAtomic(path, data)
}

// SaveSigningConfig writes the SigningConfig to the given path.
func (tb *TrustBundle) SaveSigningConfig(path string) error {
	if tb.SigningConfig == nil {
		return fmt.Errorf("no signing config available to save")
	}
	data, err := protojsonMarshaler.Marshal(tb.SigningConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal signing config: %w", err)
	}
	return utils.WriteFileAtomic(path, data)
}

// SetCertificateAuthority adds or updates a certificate authority (Fulcio or TSA) in the TrustedRoot.
// For new entries, the previous entry's end time is set to the new entry's start time.
// Also updates the corresponding SigningConfig URLs.
func (tb *TrustBundle) SetCertificateAuthority(ca *trustrootpb.CertificateAuthority, kind TargetKind) error {
	var authorities *[]*trustrootpb.CertificateAuthority
	switch kind {
	case TargetCertificateAuthority:
		authorities = &tb.TrustedRoot.CertificateAuthorities
	case TargetTimestampAuthority:
		authorities = &tb.TrustedRoot.TimestampAuthorities
	default:
		return fmt.Errorf("invalid kind for certificate authority: expected CertificateAuthority or TimestampAuthority")
	}

	cleanCertAuthorities(authorities)

	existingIdx := -1
	for i, existing := range *authorities {
		if certChainsEqual(existing.CertChain, ca.CertChain) {
			existingIdx = i
			break
		}
	}

	if existingIdx >= 0 {
		if ca.ValidFor != nil && ca.ValidFor.Start == nil {
			if (*authorities)[existingIdx].ValidFor != nil {
				ca.ValidFor.Start = (*authorities)[existingIdx].ValidFor.Start
			}
		}
		(*authorities)[existingIdx] = ca
	} else {
		if len(*authorities) > 0 {
			last := (*authorities)[len(*authorities)-1]
			if last.ValidFor != nil && last.ValidFor.End == nil && ca.ValidFor != nil {
				last.ValidFor.End = ca.ValidFor.Start
			}
		}
		*authorities = append(*authorities, ca)
	}

	tb.ensureSigningConfig()
	operator := ca.Operator
	if operator == "" {
		operator = "sigstore.dev"
	}
	service := &trustrootpb.Service{
		Url:             ca.Uri,
		MajorApiVersion: 1,
		ValidFor:        ca.ValidFor,
		Operator:        operator,
	}

	switch kind {
	case TargetCertificateAuthority:
		tb.SigningConfig.CaUrls = replaceOrAppendService(tb.SigningConfig.CaUrls, service)
	case TargetTimestampAuthority:
		tb.SigningConfig.TsaUrls = replaceOrAppendService(tb.SigningConfig.TsaUrls, service)
	}

	return nil
}

// SetTransparencyLog adds or updates a transparency log (CTLog or Rekor) in the TrustedRoot.
func (tb *TrustBundle) SetTransparencyLog(log *trustrootpb.TransparencyLogInstance, kind TargetKind) error {
	var logs *[]*trustrootpb.TransparencyLogInstance
	switch kind {
	case TargetCtlog:
		logs = &tb.TrustedRoot.Ctlogs
	case TargetTlog:
		logs = &tb.TrustedRoot.Tlogs
	default:
		return fmt.Errorf("invalid kind for transparency log: expected Ctlog or Tlog")
	}

	cleanTransparencyLogs(logs)

	existingIdx := -1
	for i, existing := range *logs {
		if logIDsEqual(existing.LogId, log.LogId) || publicKeysEqual(existing.PublicKey, log.PublicKey) {
			existingIdx = i
			break
		}
	}

	if existingIdx >= 0 {
		if log.PublicKey != nil && log.PublicKey.ValidFor != nil && log.PublicKey.ValidFor.Start == nil {
			existingPK := (*logs)[existingIdx].PublicKey
			if existingPK != nil && existingPK.ValidFor != nil {
				log.PublicKey.ValidFor.Start = existingPK.ValidFor.Start
			}
		}
		(*logs)[existingIdx] = log
	} else {
		if len(*logs) > 0 {
			last := (*logs)[len(*logs)-1]
			if last.PublicKey != nil && last.PublicKey.ValidFor != nil && last.PublicKey.ValidFor.End == nil {
				if log.PublicKey != nil && log.PublicKey.ValidFor != nil {
					last.PublicKey.ValidFor.End = log.PublicKey.ValidFor.Start
				}
			}
		}
		*logs = append(*logs, log)
	}

	if kind == TargetTlog {
		tb.ensureSigningConfig()
		operator := log.Operator
		if operator == "" {
			operator = "sigstore.dev"
		}
		var validFor *commonpb.TimeRange
		if log.PublicKey != nil {
			validFor = log.PublicKey.ValidFor
		}
		service := &trustrootpb.Service{
			Url:             log.BaseUrl,
			MajorApiVersion: 1,
			ValidFor:        validFor,
			Operator:        operator,
		}
		tb.SigningConfig.RekorTlogUrls = replaceOrAppendService(tb.SigningConfig.RekorTlogUrls, service)
	}

	return nil
}

// DeleteTarget removes a target from the TrustedRoot by its identifier (DER bytes).
func (tb *TrustBundle) DeleteTarget(kind TargetKind, identifier []byte) error {
	switch kind {
	case TargetCertificateAuthority:
		cleanCertAuthorities(&tb.TrustedRoot.CertificateAuthorities)
		tb.TrustedRoot.CertificateAuthorities = filterCertAuthorities(
			tb.TrustedRoot.CertificateAuthorities, identifier,
		)
	case TargetTimestampAuthority:
		cleanCertAuthorities(&tb.TrustedRoot.TimestampAuthorities)
		tb.TrustedRoot.TimestampAuthorities = filterCertAuthorities(
			tb.TrustedRoot.TimestampAuthorities, identifier,
		)
	case TargetCtlog:
		cleanTransparencyLogs(&tb.TrustedRoot.Ctlogs)
		tb.TrustedRoot.Ctlogs = filterTransparencyLogs(tb.TrustedRoot.Ctlogs, identifier)
	case TargetTlog:
		cleanTransparencyLogs(&tb.TrustedRoot.Tlogs)
		tb.TrustedRoot.Tlogs = filterTransparencyLogs(tb.TrustedRoot.Tlogs, identifier)
	}
	return nil
}

// DeleteSigningConfigTarget removes a target from the SigningConfig by its URI.
func (tb *TrustBundle) DeleteSigningConfigTarget(kind TargetKind, uri string) error {
	if tb.SigningConfig == nil {
		return nil
	}
	switch kind {
	case TargetCertificateAuthority:
		tb.SigningConfig.CaUrls = filterServicesByURL(tb.SigningConfig.CaUrls, uri)
		tb.SigningConfig.OidcUrls = filterServicesByURL(tb.SigningConfig.OidcUrls, uri)
	case TargetTlog:
		tb.SigningConfig.RekorTlogUrls = filterServicesByURL(tb.SigningConfig.RekorTlogUrls, uri)
	case TargetTimestampAuthority:
		tb.SigningConfig.TsaUrls = filterServicesByURL(tb.SigningConfig.TsaUrls, uri)
	case TargetCtlog:
		// SigningConfig doesn't include CTlog entries
	}
	return nil
}

// GetURIForTarget returns the URI associated with a target identifier in the TrustedRoot.
func (tb *TrustBundle) GetURIForTarget(kind TargetKind, identifier []byte) string {
	switch kind {
	case TargetCertificateAuthority:
		for _, ca := range tb.TrustedRoot.CertificateAuthorities {
			if ca.CertChain != nil {
				for _, cert := range ca.CertChain.Certificates {
					if bytes.Equal(cert.RawBytes, identifier) && ca.Uri != "" {
						return ca.Uri
					}
				}
			}
		}
	case TargetTlog:
		for _, tlog := range tb.TrustedRoot.Tlogs {
			if tlog.PublicKey != nil && bytes.Equal(tlog.PublicKey.RawBytes, identifier) && tlog.BaseUrl != "" {
				return tlog.BaseUrl
			}
		}
	case TargetTimestampAuthority:
		for _, tsa := range tb.TrustedRoot.TimestampAuthorities {
			if tsa.CertChain != nil {
				for _, cert := range tsa.CertChain.Certificates {
					if bytes.Equal(cert.RawBytes, identifier) && tsa.Uri != "" {
						return tsa.Uri
					}
				}
			}
		}
	case TargetCtlog:
		// SigningConfig doesn't contain CT logs
	}
	return ""
}

// AddOIDCURL adds an OIDC URL to the SigningConfig.
func (tb *TrustBundle) AddOIDCURL(url string, validFor *commonpb.TimeRange, operator string) error {
	if tb.SigningConfig == nil {
		return fmt.Errorf("cannot add OIDC URL: signing config does not exist")
	}
	if operator == "" {
		operator = "sigstore.dev"
	}
	service := &trustrootpb.Service{
		Url:             url,
		MajorApiVersion: 1,
		ValidFor:        validFor,
		Operator:        operator,
	}
	tb.SigningConfig.OidcUrls = replaceOrAppendService(tb.SigningConfig.OidcUrls, service)
	return nil
}

func (tb *TrustBundle) ensureSigningConfig() {
	if tb.SigningConfig == nil {
		tb.SigningConfig = &trustrootpb.SigningConfig{
			MediaType:     root.SigningConfigMediaType02,
			CaUrls:        []*trustrootpb.Service{},
			OidcUrls:      []*trustrootpb.Service{},
			RekorTlogUrls: []*trustrootpb.Service{},
			TsaUrls:       []*trustrootpb.Service{},
			RekorTlogConfig: &trustrootpb.ServiceConfiguration{
				Selector: trustrootpb.ServiceSelector_ANY,
				Count:    0,
			},
			TsaConfig: &trustrootpb.ServiceConfiguration{
				Selector: trustrootpb.ServiceSelector_ANY,
				Count:    0,
			},
		}
	}
}

func isCorruptedRawBytes(rawBytes []byte) bool {
	if text := string(rawBytes); strings.Contains(text, "-----BEGIN") {
		return true
	}
	return false
}

func cleanCertAuthorities(authorities *[]*trustrootpb.CertificateAuthority) {
	result := make([]*trustrootpb.CertificateAuthority, 0, len(*authorities))
	for _, ca := range *authorities {
		if ca.CertChain == nil {
			result = append(result, ca)
			continue
		}
		clean := make([]*commonpb.X509Certificate, 0, len(ca.CertChain.Certificates))
		for _, cert := range ca.CertChain.Certificates {
			if !isCorruptedRawBytes(cert.RawBytes) {
				clean = append(clean, cert)
			}
		}
		if len(clean) > 0 {
			ca.CertChain.Certificates = clean
			result = append(result, ca)
		}
	}
	*authorities = result
}

func cleanTransparencyLogs(logs *[]*trustrootpb.TransparencyLogInstance) {
	result := make([]*trustrootpb.TransparencyLogInstance, 0, len(*logs))
	for _, log := range *logs {
		if log.PublicKey != nil && isCorruptedRawBytes(log.PublicKey.RawBytes) {
			continue
		}
		result = append(result, log)
	}
	*logs = result
}

func certChainsEqual(a, b *commonpb.X509CertificateChain) bool {
	if a == nil || b == nil {
		return a == b
	}
	if len(a.Certificates) != len(b.Certificates) {
		return false
	}
	for i := range a.Certificates {
		if !bytes.Equal(a.Certificates[i].RawBytes, b.Certificates[i].RawBytes) {
			return false
		}
	}
	return true
}

func logIDsEqual(a, b *commonpb.LogId) bool {
	if a == nil || b == nil {
		return false
	}
	return bytes.Equal(a.KeyId, b.KeyId)
}

func publicKeysEqual(a, b *commonpb.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	return bytes.Equal(a.RawBytes, b.RawBytes)
}

func filterCertAuthorities(authorities []*trustrootpb.CertificateAuthority, identifier []byte) []*trustrootpb.CertificateAuthority {
	result := make([]*trustrootpb.CertificateAuthority, 0, len(authorities))
	for _, ca := range authorities {
		if ca.CertChain != nil {
			match := false
			for _, cert := range ca.CertChain.Certificates {
				if bytes.Equal(cert.RawBytes, identifier) {
					match = true
					break
				}
			}
			if match {
				continue
			}
		}
		result = append(result, ca)
	}
	return result
}

func filterTransparencyLogs(logs []*trustrootpb.TransparencyLogInstance, identifier []byte) []*trustrootpb.TransparencyLogInstance {
	result := make([]*trustrootpb.TransparencyLogInstance, 0, len(logs))
	for _, log := range logs {
		if log.PublicKey != nil && bytes.Equal(log.PublicKey.RawBytes, identifier) {
			continue
		}
		result = append(result, log)
	}
	return result
}

func filterServicesByURL(services []*trustrootpb.Service, url string) []*trustrootpb.Service {
	result := make([]*trustrootpb.Service, 0, len(services))
	for _, svc := range services {
		if svc.Url != url {
			result = append(result, svc)
		}
	}
	return result
}

func replaceOrAppendService(services []*trustrootpb.Service, newService *trustrootpb.Service) []*trustrootpb.Service {
	result := make([]*trustrootpb.Service, 0, len(services))
	for _, svc := range services {
		if svc.Url != newService.Url {
			result = append(result, svc)
		}
	}
	return append(result, newService)
}
