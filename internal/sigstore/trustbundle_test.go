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
	"path/filepath"
	"testing"

	commonpb "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	trustrootpb "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestNewTrustBundle(t *testing.T) {
	tb := NewTrustBundle()

	if tb.TrustedRoot == nil {
		t.Fatal("TrustedRoot is nil")
	}
	if tb.SigningConfig == nil {
		t.Fatal("SigningConfig is nil")
	}
	if tb.TrustedRoot.MediaType != root.TrustedRootMediaType01 {
		t.Fatalf("unexpected TrustedRoot media type: %s", tb.TrustedRoot.MediaType)
	}
	if tb.SigningConfig.MediaType != root.SigningConfigMediaType02 {
		t.Fatalf("unexpected SigningConfig media type: %s", tb.SigningConfig.MediaType)
	}
	if len(tb.TrustedRoot.CertificateAuthorities) != 0 {
		t.Fatal("expected empty CertificateAuthorities")
	}
	if len(tb.TrustedRoot.Tlogs) != 0 {
		t.Fatal("expected empty Tlogs")
	}
}

func TestSetCertificateAuthority_New(t *testing.T) {
	tb := NewTrustBundle()

	ca := &trustrootpb.CertificateAuthority{
		Subject: &commonpb.DistinguishedName{
			Organization: "test.dev",
			CommonName:   "test",
		},
		Uri: "https://fulcio.test.dev",
		CertChain: &commonpb.X509CertificateChain{
			Certificates: []*commonpb.X509Certificate{
				{RawBytes: []byte("test-cert-bytes")},
			},
		},
		ValidFor: &commonpb.TimeRange{
			Start: &timestamppb.Timestamp{Seconds: 1000, Nanos: 0},
		},
		Operator: "test.dev",
	}

	if err := tb.SetCertificateAuthority(ca, TargetCertificateAuthority); err != nil {
		t.Fatalf("SetCertificateAuthority failed: %v", err)
	}

	if len(tb.TrustedRoot.CertificateAuthorities) != 1 {
		t.Fatalf("expected 1 CA, got %d", len(tb.TrustedRoot.CertificateAuthorities))
	}
	if tb.TrustedRoot.CertificateAuthorities[0].Uri != "https://fulcio.test.dev" {
		t.Fatal("CA URI mismatch")
	}

	// SigningConfig should have the CA URL
	if len(tb.SigningConfig.CaUrls) != 1 {
		t.Fatalf("expected 1 CA URL in signing config, got %d", len(tb.SigningConfig.CaUrls))
	}
	if tb.SigningConfig.CaUrls[0].Url != "https://fulcio.test.dev" {
		t.Fatal("signing config CA URL mismatch")
	}
}

func TestSetCertificateAuthority_ExpiresPrevious(t *testing.T) {
	tb := NewTrustBundle()

	ca1 := &trustrootpb.CertificateAuthority{
		Uri: "https://fulcio1.test.dev",
		CertChain: &commonpb.X509CertificateChain{
			Certificates: []*commonpb.X509Certificate{{RawBytes: []byte("cert1")}},
		},
		ValidFor: &commonpb.TimeRange{
			Start: &timestamppb.Timestamp{Seconds: 1000},
		},
	}
	tb.SetCertificateAuthority(ca1, TargetCertificateAuthority)

	ca2 := &trustrootpb.CertificateAuthority{
		Uri: "https://fulcio2.test.dev",
		CertChain: &commonpb.X509CertificateChain{
			Certificates: []*commonpb.X509Certificate{{RawBytes: []byte("cert2")}},
		},
		ValidFor: &commonpb.TimeRange{
			Start: &timestamppb.Timestamp{Seconds: 2000},
		},
	}
	tb.SetCertificateAuthority(ca2, TargetCertificateAuthority)

	if len(tb.TrustedRoot.CertificateAuthorities) != 2 {
		t.Fatalf("expected 2 CAs, got %d", len(tb.TrustedRoot.CertificateAuthorities))
	}

	// Previous CA should have end time set to new CA's start time
	prev := tb.TrustedRoot.CertificateAuthorities[0]
	if prev.ValidFor.End == nil {
		t.Fatal("previous CA should have end time set")
	}
	if prev.ValidFor.End.Seconds != 2000 {
		t.Fatalf("previous CA end should be 2000, got %d", prev.ValidFor.End.Seconds)
	}
}

func TestSetCertificateAuthority_Update(t *testing.T) {
	tb := NewTrustBundle()

	certBytes := []byte("same-cert")
	ca := &trustrootpb.CertificateAuthority{
		Uri: "https://fulcio.test.dev",
		CertChain: &commonpb.X509CertificateChain{
			Certificates: []*commonpb.X509Certificate{{RawBytes: certBytes}},
		},
		ValidFor: &commonpb.TimeRange{
			Start: &timestamppb.Timestamp{Seconds: 1000},
		},
	}
	tb.SetCertificateAuthority(ca, TargetCertificateAuthority)

	// Update same CA (same cert chain) with new subject
	updated := &trustrootpb.CertificateAuthority{
		Subject: &commonpb.DistinguishedName{Organization: "updated"},
		Uri:     "https://fulcio-updated.test.dev",
		CertChain: &commonpb.X509CertificateChain{
			Certificates: []*commonpb.X509Certificate{{RawBytes: certBytes}},
		},
		ValidFor: &commonpb.TimeRange{
			Start: &timestamppb.Timestamp{Seconds: 2000},
		},
	}
	tb.SetCertificateAuthority(updated, TargetCertificateAuthority)

	if len(tb.TrustedRoot.CertificateAuthorities) != 1 {
		t.Fatalf("expected 1 CA after update, got %d", len(tb.TrustedRoot.CertificateAuthorities))
	}
	if tb.TrustedRoot.CertificateAuthorities[0].Subject.Organization != "updated" {
		t.Fatal("CA was not updated")
	}
}

func TestSetTransparencyLog_New(t *testing.T) {
	tb := NewTrustBundle()

	log := &trustrootpb.TransparencyLogInstance{
		BaseUrl:       "https://rekor.test.dev",
		HashAlgorithm: commonpb.HashAlgorithm_SHA2_256,
		PublicKey: &commonpb.PublicKey{
			RawBytes:   []byte("rekor-key"),
			KeyDetails: commonpb.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
			ValidFor: &commonpb.TimeRange{
				Start: &timestamppb.Timestamp{Seconds: 1000},
			},
		},
		LogId:    &commonpb.LogId{KeyId: []byte("log-id-1")},
		Operator: "test.dev",
	}

	if err := tb.SetTransparencyLog(log, TargetTlog); err != nil {
		t.Fatalf("SetTransparencyLog failed: %v", err)
	}

	if len(tb.TrustedRoot.Tlogs) != 1 {
		t.Fatalf("expected 1 tlog, got %d", len(tb.TrustedRoot.Tlogs))
	}

	// Rekor URLs should be in signing config
	if len(tb.SigningConfig.RekorTlogUrls) != 1 {
		t.Fatalf("expected 1 rekor URL, got %d", len(tb.SigningConfig.RekorTlogUrls))
	}
}

func TestSetTransparencyLog_CtlogNotInSigningConfig(t *testing.T) {
	tb := NewTrustBundle()

	log := &trustrootpb.TransparencyLogInstance{
		BaseUrl:       "https://ctlog.test.dev",
		HashAlgorithm: commonpb.HashAlgorithm_SHA2_256,
		PublicKey: &commonpb.PublicKey{
			RawBytes:   []byte("ctlog-key"),
			KeyDetails: commonpb.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
			ValidFor:   &commonpb.TimeRange{Start: &timestamppb.Timestamp{Seconds: 1000}},
		},
		LogId: &commonpb.LogId{KeyId: []byte("ctlog-id")},
	}

	tb.SetTransparencyLog(log, TargetCtlog)

	if len(tb.TrustedRoot.Ctlogs) != 1 {
		t.Fatalf("expected 1 ctlog, got %d", len(tb.TrustedRoot.Ctlogs))
	}
	// CTLog should NOT appear in signing config
	if len(tb.SigningConfig.RekorTlogUrls) != 0 {
		t.Fatal("CTLog should not be added to rekor_tlog_urls")
	}
}

func TestDeleteTarget_CertificateAuthority(t *testing.T) {
	tb := NewTrustBundle()

	certBytes := []byte("cert-to-delete")
	ca := &trustrootpb.CertificateAuthority{
		Uri: "https://fulcio.test.dev",
		CertChain: &commonpb.X509CertificateChain{
			Certificates: []*commonpb.X509Certificate{{RawBytes: certBytes}},
		},
		ValidFor: &commonpb.TimeRange{Start: &timestamppb.Timestamp{Seconds: 1000}},
	}
	tb.SetCertificateAuthority(ca, TargetCertificateAuthority)

	if len(tb.TrustedRoot.CertificateAuthorities) != 1 {
		t.Fatal("CA should exist before deletion")
	}

	tb.DeleteTarget(TargetCertificateAuthority, certBytes)

	if len(tb.TrustedRoot.CertificateAuthorities) != 0 {
		t.Fatal("CA should be deleted")
	}
}

func TestDeleteTarget_TransparencyLog(t *testing.T) {
	tb := NewTrustBundle()

	keyBytes := []byte("key-to-delete")
	log := &trustrootpb.TransparencyLogInstance{
		BaseUrl: "https://rekor.test.dev",
		PublicKey: &commonpb.PublicKey{
			RawBytes: keyBytes,
			ValidFor: &commonpb.TimeRange{Start: &timestamppb.Timestamp{Seconds: 1000}},
		},
		LogId: &commonpb.LogId{KeyId: []byte("log-id")},
	}
	tb.SetTransparencyLog(log, TargetTlog)

	tb.DeleteTarget(TargetTlog, keyBytes)

	if len(tb.TrustedRoot.Tlogs) != 0 {
		t.Fatal("tlog should be deleted")
	}
}

func TestDeleteSigningConfigTarget(t *testing.T) {
	tb := NewTrustBundle()

	ca := &trustrootpb.CertificateAuthority{
		Uri: "https://fulcio.test.dev",
		CertChain: &commonpb.X509CertificateChain{
			Certificates: []*commonpb.X509Certificate{{RawBytes: []byte("cert")}},
		},
		ValidFor: &commonpb.TimeRange{Start: &timestamppb.Timestamp{Seconds: 1000}},
	}
	tb.SetCertificateAuthority(ca, TargetCertificateAuthority)

	if len(tb.SigningConfig.CaUrls) != 1 {
		t.Fatal("signing config should have CA URL")
	}

	tb.DeleteSigningConfigTarget(TargetCertificateAuthority, "https://fulcio.test.dev")

	if len(tb.SigningConfig.CaUrls) != 0 {
		t.Fatal("CA URL should be deleted from signing config")
	}
}

func TestGetURIForTarget(t *testing.T) {
	tb := NewTrustBundle()

	certBytes := []byte("lookup-cert")
	ca := &trustrootpb.CertificateAuthority{
		Uri: "https://fulcio.test.dev",
		CertChain: &commonpb.X509CertificateChain{
			Certificates: []*commonpb.X509Certificate{{RawBytes: certBytes}},
		},
		ValidFor: &commonpb.TimeRange{Start: &timestamppb.Timestamp{Seconds: 1000}},
	}
	tb.SetCertificateAuthority(ca, TargetCertificateAuthority)

	uri := tb.GetURIForTarget(TargetCertificateAuthority, certBytes)
	if uri != "https://fulcio.test.dev" {
		t.Fatalf("expected URI 'https://fulcio.test.dev', got %q", uri)
	}

	uri = tb.GetURIForTarget(TargetCertificateAuthority, []byte("nonexistent"))
	if uri != "" {
		t.Fatalf("expected empty URI for nonexistent target, got %q", uri)
	}
}

func TestAddOIDCURL(t *testing.T) {
	tb := NewTrustBundle()

	err := tb.AddOIDCURL("https://oidc.test.dev", nil, "test.dev")
	if err != nil {
		t.Fatalf("AddOIDCURL failed: %v", err)
	}

	if len(tb.SigningConfig.OidcUrls) != 1 {
		t.Fatalf("expected 1 OIDC URL, got %d", len(tb.SigningConfig.OidcUrls))
	}
	if tb.SigningConfig.OidcUrls[0].Url != "https://oidc.test.dev" {
		t.Fatal("OIDC URL mismatch")
	}

	// Adding same URL should replace, not duplicate
	tb.AddOIDCURL("https://oidc.test.dev", nil, "test2.dev")
	if len(tb.SigningConfig.OidcUrls) != 1 {
		t.Fatalf("expected 1 OIDC URL after replace, got %d", len(tb.SigningConfig.OidcUrls))
	}
	if tb.SigningConfig.OidcUrls[0].Operator != "test2.dev" {
		t.Fatal("OIDC URL operator should be updated")
	}
}

func TestSaveTrustedRoot(t *testing.T) {
	dir := t.TempDir()
	tb := NewTrustBundle()

	ca := &trustrootpb.CertificateAuthority{
		Uri: "https://fulcio.test.dev",
		CertChain: &commonpb.X509CertificateChain{
			Certificates: []*commonpb.X509Certificate{{RawBytes: []byte("cert")}},
		},
	}
	tb.SetCertificateAuthority(ca, TargetCertificateAuthority)

	path := filepath.Join(dir, "trusted_root.json")
	if err := tb.SaveTrustedRoot(path); err != nil {
		t.Fatalf("SaveTrustedRoot failed: %v", err)
	}

	// Load it back
	loaded, err := LoadTrustBundle(path, filepath.Join(dir, "nonexistent.json"))
	if err != nil {
		t.Fatalf("LoadTrustBundle failed: %v", err)
	}
	if len(loaded.TrustedRoot.CertificateAuthorities) != 1 {
		t.Fatal("loaded TrustedRoot should have 1 CA")
	}
}

func TestSaveSigningConfig(t *testing.T) {
	dir := t.TempDir()
	tb := NewTrustBundle()

	tb.AddOIDCURL("https://oidc.test.dev", nil, "test.dev")

	path := filepath.Join(dir, "signing_config.json")
	if err := tb.SaveSigningConfig(path); err != nil {
		t.Fatalf("SaveSigningConfig failed: %v", err)
	}

	// Load it back
	loaded, err := LoadTrustBundle(filepath.Join(dir, "nonexistent.json"), path)
	if err != nil {
		t.Fatalf("LoadTrustBundle failed: %v", err)
	}
	if len(loaded.SigningConfig.OidcUrls) != 1 {
		t.Fatal("loaded SigningConfig should have 1 OIDC URL")
	}
}

func TestCorruptedRawBytesCleanup(t *testing.T) {
	tb := NewTrustBundle()

	// Add a corrupted CA (PEM text in raw_bytes)
	tb.TrustedRoot.CertificateAuthorities = append(tb.TrustedRoot.CertificateAuthorities,
		&trustrootpb.CertificateAuthority{
			Uri: "https://corrupt.dev",
			CertChain: &commonpb.X509CertificateChain{
				Certificates: []*commonpb.X509Certificate{
					{RawBytes: []byte("-----BEGIN CERTIFICATE-----\ndata\n-----END CERTIFICATE-----")},
				},
			},
		},
	)

	// Add a valid CA
	validCA := &trustrootpb.CertificateAuthority{
		Uri: "https://valid.dev",
		CertChain: &commonpb.X509CertificateChain{
			Certificates: []*commonpb.X509Certificate{{RawBytes: []byte("valid-der-bytes")}},
		},
		ValidFor: &commonpb.TimeRange{Start: &timestamppb.Timestamp{Seconds: 1000}},
	}
	tb.SetCertificateAuthority(validCA, TargetCertificateAuthority)

	// The corrupted entry should have been cleaned during SetCertificateAuthority
	for _, ca := range tb.TrustedRoot.CertificateAuthorities {
		if ca.Uri == "https://corrupt.dev" {
			t.Fatal("corrupted CA should have been removed")
		}
	}
}

func TestSetTimestampAuthority(t *testing.T) {
	tb := NewTrustBundle()

	tsa := &trustrootpb.CertificateAuthority{
		Uri: "https://tsa.test.dev",
		CertChain: &commonpb.X509CertificateChain{
			Certificates: []*commonpb.X509Certificate{{RawBytes: []byte("tsa-cert")}},
		},
		ValidFor: &commonpb.TimeRange{Start: &timestamppb.Timestamp{Seconds: 1000}},
	}

	if err := tb.SetCertificateAuthority(tsa, TargetTimestampAuthority); err != nil {
		t.Fatalf("SetCertificateAuthority for TSA failed: %v", err)
	}

	if len(tb.TrustedRoot.TimestampAuthorities) != 1 {
		t.Fatalf("expected 1 TSA, got %d", len(tb.TrustedRoot.TimestampAuthorities))
	}
	if len(tb.SigningConfig.TsaUrls) != 1 {
		t.Fatalf("expected 1 TSA URL in signing config, got %d", len(tb.SigningConfig.TsaUrls))
	}
}

func TestSetTransparencyLog_Rotation(t *testing.T) {
	tb := NewTrustBundle()

	log1 := &trustrootpb.TransparencyLogInstance{
		BaseUrl: "https://rekor.test.dev",
		LogId:   &commonpb.LogId{KeyId: []byte("logid-1")},
		PublicKey: &commonpb.PublicKey{
			RawBytes: []byte("pubkey-1"),
			ValidFor: &commonpb.TimeRange{Start: &timestamppb.Timestamp{Seconds: 1000}},
		},
	}
	tb.SetTransparencyLog(log1, TargetTlog)

	log2 := &trustrootpb.TransparencyLogInstance{
		BaseUrl: "https://rekor-new.test.dev",
		LogId:   &commonpb.LogId{KeyId: []byte("logid-2")},
		PublicKey: &commonpb.PublicKey{
			RawBytes: []byte("pubkey-2"),
			ValidFor: &commonpb.TimeRange{Start: &timestamppb.Timestamp{Seconds: 2000}},
		},
	}
	tb.SetTransparencyLog(log2, TargetTlog)

	if len(tb.TrustedRoot.Tlogs) != 2 {
		t.Fatalf("expected 2 tlogs, got %d", len(tb.TrustedRoot.Tlogs))
	}
	if tb.TrustedRoot.Tlogs[0].PublicKey.ValidFor.End == nil {
		t.Fatal("expected previous tlog's ValidFor.End to be set")
	}
}

func TestSetTransparencyLog_UpdateExistingByLogID(t *testing.T) {
	tb := NewTrustBundle()

	log1 := &trustrootpb.TransparencyLogInstance{
		BaseUrl: "https://rekor.test.dev",
		LogId:   &commonpb.LogId{KeyId: []byte("logid-1")},
		PublicKey: &commonpb.PublicKey{
			RawBytes: []byte("pubkey-1"),
			ValidFor: &commonpb.TimeRange{Start: &timestamppb.Timestamp{Seconds: 1000}},
		},
	}
	tb.SetTransparencyLog(log1, TargetTlog)

	log1Updated := &trustrootpb.TransparencyLogInstance{
		BaseUrl: "https://rekor-updated.test.dev",
		LogId:   &commonpb.LogId{KeyId: []byte("logid-1")},
		PublicKey: &commonpb.PublicKey{
			RawBytes: []byte("pubkey-1-new"),
			ValidFor: &commonpb.TimeRange{},
		},
	}
	tb.SetTransparencyLog(log1Updated, TargetTlog)

	if len(tb.TrustedRoot.Tlogs) != 1 {
		t.Fatalf("expected 1 tlog (updated), got %d", len(tb.TrustedRoot.Tlogs))
	}
	if tb.TrustedRoot.Tlogs[0].BaseUrl != "https://rekor-updated.test.dev" {
		t.Fatalf("expected updated URL, got %s", tb.TrustedRoot.Tlogs[0].BaseUrl)
	}
}

func TestSetTransparencyLog_UpdateExistingByPublicKey(t *testing.T) {
	tb := NewTrustBundle()

	log1 := &trustrootpb.TransparencyLogInstance{
		BaseUrl: "https://rekor.test.dev",
		LogId:   &commonpb.LogId{KeyId: []byte("logid-1")},
		PublicKey: &commonpb.PublicKey{
			RawBytes: []byte("same-pubkey"),
			ValidFor: &commonpb.TimeRange{Start: &timestamppb.Timestamp{Seconds: 1000}},
		},
	}
	tb.SetTransparencyLog(log1, TargetTlog)

	log2 := &trustrootpb.TransparencyLogInstance{
		BaseUrl: "https://rekor-v2.test.dev",
		LogId:   &commonpb.LogId{KeyId: []byte("logid-different")},
		PublicKey: &commonpb.PublicKey{
			RawBytes: []byte("same-pubkey"),
			ValidFor: &commonpb.TimeRange{},
		},
	}
	tb.SetTransparencyLog(log2, TargetTlog)

	if len(tb.TrustedRoot.Tlogs) != 1 {
		t.Fatalf("expected 1 tlog (matched by pubkey), got %d", len(tb.TrustedRoot.Tlogs))
	}
}

func TestSetTransparencyLog_InvalidKind(t *testing.T) {
	tb := NewTrustBundle()
	log1 := &trustrootpb.TransparencyLogInstance{BaseUrl: "https://test.dev"}
	err := tb.SetTransparencyLog(log1, TargetCertificateAuthority)
	if err == nil {
		t.Fatal("expected error for invalid kind")
	}
}

func TestDeleteTarget_CtlogAndTlog(t *testing.T) {
	tb := NewTrustBundle()

	ctlog := &trustrootpb.TransparencyLogInstance{
		BaseUrl:   "https://ctlog.test.dev",
		PublicKey: &commonpb.PublicKey{RawBytes: []byte("ctlog-key")},
	}
	tb.SetTransparencyLog(ctlog, TargetCtlog)

	tlog := &trustrootpb.TransparencyLogInstance{
		BaseUrl:   "https://rekor.test.dev",
		PublicKey: &commonpb.PublicKey{RawBytes: []byte("tlog-key")},
	}
	tb.SetTransparencyLog(tlog, TargetTlog)

	tb.DeleteTarget(TargetCtlog, []byte("ctlog-key"))
	if len(tb.TrustedRoot.Ctlogs) != 0 {
		t.Fatalf("expected 0 ctlogs after delete, got %d", len(tb.TrustedRoot.Ctlogs))
	}

	tb.DeleteTarget(TargetTlog, []byte("tlog-key"))
	if len(tb.TrustedRoot.Tlogs) != 0 {
		t.Fatalf("expected 0 tlogs after delete, got %d", len(tb.TrustedRoot.Tlogs))
	}
}

func TestDeleteTarget_TimestampAuthority(t *testing.T) {
	tb := NewTrustBundle()

	tsa := &trustrootpb.CertificateAuthority{
		Uri: "https://tsa.test.dev",
		CertChain: &commonpb.X509CertificateChain{
			Certificates: []*commonpb.X509Certificate{{RawBytes: []byte("tsa-cert")}},
		},
		ValidFor: &commonpb.TimeRange{Start: &timestamppb.Timestamp{Seconds: 1000}},
	}
	tb.SetCertificateAuthority(tsa, TargetTimestampAuthority)

	tb.DeleteTarget(TargetTimestampAuthority, []byte("tsa-cert"))
	if len(tb.TrustedRoot.TimestampAuthorities) != 0 {
		t.Fatalf("expected 0 TSAs after delete, got %d", len(tb.TrustedRoot.TimestampAuthorities))
	}
}

func TestDeleteSigningConfigTarget_Tlog(t *testing.T) {
	tb := NewTrustBundle()

	tlog := &trustrootpb.TransparencyLogInstance{
		BaseUrl:   "https://rekor.test.dev",
		PublicKey: &commonpb.PublicKey{RawBytes: []byte("tlog-key")},
	}
	tb.SetTransparencyLog(tlog, TargetTlog)

	tb.DeleteSigningConfigTarget(TargetTlog, "https://rekor.test.dev")
	if len(tb.SigningConfig.RekorTlogUrls) != 0 {
		t.Fatalf("expected 0 rekor URLs after delete, got %d", len(tb.SigningConfig.RekorTlogUrls))
	}
}

func TestDeleteSigningConfigTarget_TSA(t *testing.T) {
	tb := NewTrustBundle()

	tsa := &trustrootpb.CertificateAuthority{
		Uri: "https://tsa.test.dev",
		CertChain: &commonpb.X509CertificateChain{
			Certificates: []*commonpb.X509Certificate{{RawBytes: []byte("tsa-cert")}},
		},
		ValidFor: &commonpb.TimeRange{Start: &timestamppb.Timestamp{Seconds: 1000}},
	}
	tb.SetCertificateAuthority(tsa, TargetTimestampAuthority)

	tb.DeleteSigningConfigTarget(TargetTimestampAuthority, "https://tsa.test.dev")
	if len(tb.SigningConfig.TsaUrls) != 0 {
		t.Fatalf("expected 0 TSA URLs after delete, got %d", len(tb.SigningConfig.TsaUrls))
	}
}

func TestDeleteSigningConfigTarget_Ctlog(t *testing.T) {
	tb := NewTrustBundle()
	err := tb.DeleteSigningConfigTarget(TargetCtlog, "https://ctlog.test.dev")
	if err != nil {
		t.Fatalf("DeleteSigningConfigTarget for CTLog should be no-op: %v", err)
	}
}

func TestDeleteSigningConfigTarget_NilConfig(t *testing.T) {
	tb := NewTrustBundle()
	tb.SigningConfig = nil
	err := tb.DeleteSigningConfigTarget(TargetTlog, "https://rekor.test.dev")
	if err != nil {
		t.Fatalf("DeleteSigningConfigTarget with nil config should succeed: %v", err)
	}
}

func TestGetURIForTarget_Tlog(t *testing.T) {
	tb := NewTrustBundle()

	tlog := &trustrootpb.TransparencyLogInstance{
		BaseUrl:   "https://rekor.test.dev",
		PublicKey: &commonpb.PublicKey{RawBytes: []byte("tlog-key")},
	}
	tb.SetTransparencyLog(tlog, TargetTlog)

	uri := tb.GetURIForTarget(TargetTlog, []byte("tlog-key"))
	if uri != "https://rekor.test.dev" {
		t.Fatalf("expected 'https://rekor.test.dev', got %q", uri)
	}
}

func TestGetURIForTarget_TSA(t *testing.T) {
	tb := NewTrustBundle()

	tsa := &trustrootpb.CertificateAuthority{
		Uri: "https://tsa.test.dev",
		CertChain: &commonpb.X509CertificateChain{
			Certificates: []*commonpb.X509Certificate{{RawBytes: []byte("tsa-cert")}},
		},
		ValidFor: &commonpb.TimeRange{Start: &timestamppb.Timestamp{Seconds: 1000}},
	}
	tb.SetCertificateAuthority(tsa, TargetTimestampAuthority)

	uri := tb.GetURIForTarget(TargetTimestampAuthority, []byte("tsa-cert"))
	if uri != "https://tsa.test.dev" {
		t.Fatalf("expected 'https://tsa.test.dev', got %q", uri)
	}
}

func TestGetURIForTarget_Ctlog(t *testing.T) {
	tb := NewTrustBundle()
	uri := tb.GetURIForTarget(TargetCtlog, []byte("anything"))
	if uri != "" {
		t.Fatalf("expected empty string for CTLog, got %q", uri)
	}
}

func TestGetURIForTarget_NotFound(t *testing.T) {
	tb := NewTrustBundle()
	uri := tb.GetURIForTarget(TargetCertificateAuthority, []byte("nonexistent"))
	if uri != "" {
		t.Fatalf("expected empty string for nonexistent target, got %q", uri)
	}
}

func TestLoadTrustBundle_NonexistentFiles(t *testing.T) {
	tb, err := LoadTrustBundle("/nonexistent/trusted_root.json", "/nonexistent/signing_config.json")
	if err != nil {
		t.Fatalf("LoadTrustBundle should not error on missing files: %v", err)
	}
	if tb == nil {
		t.Fatal("expected non-nil TrustBundle")
	}
}

func TestSaveTrustedRoot_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	tb := NewTrustBundle()

	ca := &trustrootpb.CertificateAuthority{
		Uri: "https://fulcio.test.dev",
		CertChain: &commonpb.X509CertificateChain{
			Certificates: []*commonpb.X509Certificate{{RawBytes: []byte("cert-data")}},
		},
		ValidFor: &commonpb.TimeRange{Start: &timestamppb.Timestamp{Seconds: 1000}},
	}
	tb.SetCertificateAuthority(ca, TargetCertificateAuthority)

	trPath := filepath.Join(dir, "trusted_root.json")
	scPath := filepath.Join(dir, "signing_config.json")
	tb.SaveTrustedRoot(trPath)
	tb.SaveSigningConfig(scPath)

	tb2, err := LoadTrustBundle(trPath, scPath)
	if err != nil {
		t.Fatalf("LoadTrustBundle after save failed: %v", err)
	}
	if len(tb2.TrustedRoot.CertificateAuthorities) != 1 {
		t.Fatalf("expected 1 CA after roundtrip, got %d", len(tb2.TrustedRoot.CertificateAuthorities))
	}
	if len(tb2.SigningConfig.CaUrls) != 1 {
		t.Fatalf("expected 1 CA URL after roundtrip, got %d", len(tb2.SigningConfig.CaUrls))
	}
}

func TestAddOIDCURL_NilSigningConfig(t *testing.T) {
	tb := NewTrustBundle()
	tb.SigningConfig = nil

	err := tb.AddOIDCURL("https://oidc.test.dev", nil, "test.dev")
	if err == nil {
		t.Fatal("expected error when signing config is nil")
	}
}

func TestAddOIDCURL_DefaultOperator(t *testing.T) {
	tb := NewTrustBundle()
	tb.AddOIDCURL("https://oidc.test.dev", nil, "")

	if len(tb.SigningConfig.OidcUrls) != 1 {
		t.Fatalf("expected 1 OIDC URL, got %d", len(tb.SigningConfig.OidcUrls))
	}
	if tb.SigningConfig.OidcUrls[0].Operator != "sigstore.dev" {
		t.Fatalf("expected default operator 'sigstore.dev', got %q", tb.SigningConfig.OidcUrls[0].Operator)
	}
}

func TestAddOIDCURL_ReplaceExisting(t *testing.T) {
	tb := NewTrustBundle()
	tb.AddOIDCURL("https://oidc.test.dev", nil, "op1")
	tb.AddOIDCURL("https://oidc.test.dev", nil, "op2")

	if len(tb.SigningConfig.OidcUrls) != 1 {
		t.Fatalf("expected 1 OIDC URL (replaced), got %d", len(tb.SigningConfig.OidcUrls))
	}
	if tb.SigningConfig.OidcUrls[0].Operator != "op2" {
		t.Fatalf("expected operator 'op2', got %q", tb.SigningConfig.OidcUrls[0].Operator)
	}
}

func TestSetCertificateAuthority_InvalidKind(t *testing.T) {
	tb := NewTrustBundle()
	ca := &trustrootpb.CertificateAuthority{Uri: "https://test.dev"}
	err := tb.SetCertificateAuthority(ca, TargetCtlog)
	if err == nil {
		t.Fatal("expected error for invalid kind")
	}
}

func TestLogIDsEqual(t *testing.T) {
	tests := []struct {
		name string
		a, b *commonpb.LogId
		want bool
	}{
		{"both nil", nil, nil, false},
		{"a nil", nil, &commonpb.LogId{KeyId: []byte{1}}, false},
		{"b nil", &commonpb.LogId{KeyId: []byte{1}}, nil, false},
		{"same", &commonpb.LogId{KeyId: []byte{1, 2}}, &commonpb.LogId{KeyId: []byte{1, 2}}, true},
		{"different", &commonpb.LogId{KeyId: []byte{1}}, &commonpb.LogId{KeyId: []byte{2}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := logIDsEqual(tt.a, tt.b); got != tt.want {
				t.Fatalf("logIDsEqual = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPublicKeysEqual(t *testing.T) {
	tests := []struct {
		name string
		a, b *commonpb.PublicKey
		want bool
	}{
		{"both nil", nil, nil, false},
		{"a nil", nil, &commonpb.PublicKey{RawBytes: []byte{1}}, false},
		{"b nil", &commonpb.PublicKey{RawBytes: []byte{1}}, nil, false},
		{"same", &commonpb.PublicKey{RawBytes: []byte{3, 4}}, &commonpb.PublicKey{RawBytes: []byte{3, 4}}, true},
		{"different", &commonpb.PublicKey{RawBytes: []byte{3}}, &commonpb.PublicKey{RawBytes: []byte{5}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := publicKeysEqual(tt.a, tt.b); got != tt.want {
				t.Fatalf("publicKeysEqual = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEnsureSigningConfig(t *testing.T) {
	t.Run("nil initializes defaults", func(t *testing.T) {
		tb := NewTrustBundle()
		tb.SigningConfig = nil

		tb.ensureSigningConfig()

		if tb.SigningConfig == nil {
			t.Fatal("SigningConfig should not be nil after ensureSigningConfig")
		}
		if tb.SigningConfig.MediaType != root.SigningConfigMediaType02 {
			t.Fatalf("expected media type %q, got %q", root.SigningConfigMediaType02, tb.SigningConfig.MediaType)
		}
		if tb.SigningConfig.CaUrls == nil || tb.SigningConfig.OidcUrls == nil ||
			tb.SigningConfig.RekorTlogUrls == nil || tb.SigningConfig.TsaUrls == nil {
			t.Fatal("expected non-nil slice fields")
		}
		if tb.SigningConfig.RekorTlogConfig == nil || tb.SigningConfig.TsaConfig == nil {
			t.Fatal("expected non-nil service configs")
		}
		if tb.SigningConfig.RekorTlogConfig.Selector != trustrootpb.ServiceSelector_ANY {
			t.Fatalf("expected ANY selector, got %v", tb.SigningConfig.RekorTlogConfig.Selector)
		}
	})

	t.Run("non-nil unchanged", func(t *testing.T) {
		tb := NewTrustBundle()
		original := tb.SigningConfig

		tb.ensureSigningConfig()

		if tb.SigningConfig != original {
			t.Fatal("ensureSigningConfig should not replace existing config")
		}
	})
}
