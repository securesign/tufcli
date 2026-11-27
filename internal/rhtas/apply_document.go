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

package rhtas

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	commonpb "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	trustrootpb "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	sigstorepkg "github.com/sigstore/sigstore/pkg/signature"
	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/securesign/tufcli/internal/rhtas/document"
	"github.com/securesign/tufcli/internal/sigstore"
	"github.com/securesign/tufcli/internal/utils"
)

// ErrInconsistentRepository is returned when the repository's per-key targets
// and trusted_root.json do not agree, so the document cannot be built.
var ErrInconsistentRepository = errors.New("repository is inconsistent")

// usage values of the "sigstore" custom target metadata, per component.
var componentUsage = map[document.Component]string{
	document.Ctlog:  "CTFE",
	document.Fulcio: "Fulcio",
	document.Rekor:  "Rekor",
	document.Tsa:    "TSA",
}

// targetRef links a document target to what represents it in the repository.
type targetRef struct {
	files     *tufmeta.TargetFiles
	authority *trustrootpb.CertificateAuthority    // Fulcio, TSA
	log       *trustrootpb.TransparencyLogInstance // CTlog, Rekor
}

type refKey struct {
	component document.Component
	name      string
}

// repositoryDocument is the document built from a repository, with the
// repository objects behind each target.
type repositoryDocument struct {
	doc  document.Document
	refs map[refKey]targetRef
	// otherTargets are targets that are not per-key RHTAS targets (including
	// the generated trust bundle files); their names cannot be used.
	otherTargets map[string]bool
}

// buildDocument rebuilds the document from the repository: every target whose
// "sigstore" custom metadata names an RHTAS usage is a per-key target, mapped
// to its trusted_root.json entry by key material.
func buildDocument(re *Editor) (*repositoryDocument, error) {
	rd := &repositoryDocument{doc: document.New(), refs: map[refKey]targetRef{}, otherTargets: map[string]bool{}}
	tr := re.TrustBundle.TrustedRoot
	used := map[any]string{}

	for _, name := range sortedTargetNames(re.Targets().Signed.Targets) {
		tf := re.Targets().Signed.Targets[name]
		component, ok := targetComponent(tf)
		if !ok {
			rd.otherTargets[name] = true
			continue
		}
		inconsistent := func(format string, args ...any) error {
			return fmt.Errorf("%w: %s target %q: %s", ErrInconsistentRepository, component, name, fmt.Sprintf(format, args...))
		}
		hash, err := utils.PreferredHash(tf.Hashes)
		if err != nil {
			return nil, inconsistent("%v", err)
		}
		data, err := os.ReadFile(filepath.Join(re.OutDir(), "targets", hash+"."+name))
		if err != nil {
			return nil, inconsistent("cannot read target file: %v", err)
		}
		if err := tf.VerifyLengthHashes(data); err != nil {
			return nil, inconsistent("target file does not match targets.json: %v", err)
		}
		m, err := document.ParseMaterial(component, string(data))
		if err != nil {
			return nil, inconsistent("%v", err)
		}

		ref := targetRef{files: tf}
		var validFor *commonpb.TimeRange
		var uri string
		switch component {
		case document.Fulcio, document.Tsa:
			list := tr.CertificateAuthorities
			if component == document.Tsa {
				list = tr.TimestampAuthorities
			}
			for _, ca := range list {
				if ca != nil && chainMatches(ca.CertChain, m.DER) {
					ref.authority = ca
					validFor, uri = ca.ValidFor, ca.Uri
					break
				}
			}
		case document.Ctlog, document.Rekor:
			list := tr.Ctlogs
			if component == document.Rekor {
				list = tr.Tlogs
			}
			for _, l := range list {
				if l != nil && l.PublicKey != nil && bytes.Equal(l.PublicKey.RawBytes, m.DER[0]) {
					ref.log = l
					uri = l.BaseUrl
					validFor = l.PublicKey.ValidFor
					break
				}
			}
		}
		var entry any = ref.authority
		if ref.log != nil {
			entry = ref.log
		}
		if ref.authority == nil && ref.log == nil {
			return nil, inconsistent("no trusted_root.json entry has its key material")
		}
		if other, dup := used[entry]; dup {
			return nil, inconsistent("same trusted_root.json entry as target %q", other)
		}
		used[entry] = name

		t := document.Target{
			URI:         uri,
			OIDCIssuers: []string{},
			ValidFor:    validForFromProto(validFor),
			Material:    string(data),
		}
		if component == document.Fulcio {
			t.OIDCIssuers = fulcioIssuers(tf, ref.authority, re.TrustBundle.SigningConfig)
		}
		rd.doc.Targets(component)[name] = t
		rd.refs[refKey{component, name}] = ref
	}

	// Not validated as a whole: a patch only has to make the targets it
	// touches valid (document.Apply), so an odd published entry never blocks
	// every later change, including the one that repairs it.
	return rd, nil
}

// targetComponent reads the component of a per-key target from its
// "sigstore" custom metadata.
func targetComponent(tf *tufmeta.TargetFiles) (document.Component, bool) {
	custom := customMap(tf)
	sig, _ := custom["sigstore"].(map[string]any)
	usage, _ := sig["usage"].(string)
	for c, u := range componentUsage {
		if u == usage {
			return c, true
		}
	}
	return "", false
}

func customMap(tf *tufmeta.TargetFiles) map[string]any {
	custom := map[string]any{}
	if tf != nil && tf.Custom != nil {
		_ = json.Unmarshal(*tf.Custom, &custom)
	}
	return custom
}

// fulcioIssuers returns the OIDC issuers of a Fulcio target. tufcli records
// them in the target's "rhtas" custom metadata; repositories written before
// that only have them in signing_config.v0.2.json, as OIDC services created
// together with the Fulcio entry (see legacyIssuerOf).
func fulcioIssuers(tf *tufmeta.TargetFiles, ca *trustrootpb.CertificateAuthority, sc *trustrootpb.SigningConfig) []string {
	issuers := []string{}
	if rh, ok := customMap(tf)["rhtas"].(map[string]any); ok {
		if list, ok := rh["oidcIssuers"].([]any); ok {
			for _, v := range list {
				if s, ok := v.(string); ok {
					issuers = append(issuers, s)
				}
			}
			return issuers
		}
	}
	if sc == nil || ca == nil {
		return issuers
	}
	for _, svc := range sc.OidcUrls {
		if svc != nil && !slices.Contains(issuers, svc.Url) && legacyIssuerOf(svc, ca) {
			issuers = append(issuers, svc.Url)
		}
	}
	return issuers
}

// legacyIssuerOf reports whether an OIDC service was published together with
// a Fulcio entry by the flag-based command: same operator and the same window,
// or the window that command leaves after a rotation (the Fulcio window closed,
// the issuer's still open from the same start). An issuer with an end of its
// own is configured independently and does not belong to the entry.
func legacyIssuerOf(svc *trustrootpb.Service, ca *trustrootpb.CertificateAuthority) bool {
	if operatorOrDefault(svc.Operator) != operatorOrDefault(ca.Operator) {
		return false
	}
	if proto.Equal(svc.GetValidFor(), ca.GetValidFor()) {
		return true
	}
	return proto.Equal(svc.GetValidFor().GetStart(), ca.GetValidFor().GetStart()) &&
		svc.GetValidFor().GetEnd() == nil && ca.GetValidFor().GetEnd() != nil
}

func operatorOrDefault(op string) string {
	if op == "" {
		return "sigstore.dev"
	}
	return op
}

func chainMatches(chain *commonpb.X509CertificateChain, der [][]byte) bool {
	if chain == nil || len(chain.Certificates) != len(der) {
		return false
	}
	for i, cert := range chain.Certificates {
		if cert == nil || !bytes.Equal(cert.RawBytes, der[i]) {
			return false
		}
	}
	return true
}

func validForFromProto(tr *commonpb.TimeRange) document.ValidFor {
	var v document.ValidFor
	if tr == nil {
		return v
	}
	if tr.Start != nil {
		t := tr.Start.AsTime().UTC()
		v.Start = &t
	}
	if tr.End != nil {
		t := tr.End.AsTime().UTC()
		v.End = &t
	}
	return v
}

func validForToProto(v document.ValidFor) *commonpb.TimeRange {
	tr := &commonpb.TimeRange{}
	if v.Start != nil {
		tr.Start = timestamppb.New(*v.Start)
	}
	if v.End != nil {
		tr.End = timestamppb.New(*v.End)
	}
	return tr
}

func sortedTargetNames(targets map[string]*tufmeta.TargetFiles) []string {
	names := make([]string, 0, len(targets))
	for name := range targets {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// stagedTarget is the content of a new per-key target, to be written to
// targets/<name> before signing.
type stagedTarget struct {
	name string
	data []byte
}

// renderDocument changes the repository in memory so that it describes next:
// per-key targets and their custom metadata, trusted_root.json entries with
// the exact windows of the document, and signing_config.v0.2.json services
// rebuilt from the open-ended entries. Targets that did not change keep their
// metadata and trusted_root.json entry untouched. It returns the files of the
// new targets; nothing is written.
func renderDocument(re *Editor, current *repositoryDocument, next document.Document, operator, hashAlgo string) ([]stagedTarget, error) {
	tr := re.TrustBundle.TrustedRoot
	var staged []stagedTarget
	at := now()

	// All removals first: a name can leave one component and, in a later
	// patch, be used again by another.
	for _, c := range document.Components {
		cur, nxt := current.doc.Targets(c), next.Targets(c)
		for _, name := range document.SortedNames(cur) {
			if _, keep := nxt[name]; keep {
				continue
			}
			ref := current.refs[refKey{c, name}]
			if err := re.RemoveTarget(name); err != nil {
				return nil, err
			}
			removeEntry(tr, c, ref)
		}
	}

	for _, c := range document.Components {
		cur, nxt := current.doc.Targets(c), next.Targets(c)
		for _, name := range document.SortedNames(nxt) {
			t := nxt[name]
			old, exists := cur[name]
			if exists && document.Equal(c, old, t) {
				// Untouched: its metadata, trusted_root.json entry and
				// signing services stay exactly as published.
				continue
			}
			if current.otherTargets[name] {
				return nil, fmt.Errorf("%w: %s", document.ErrNameUnavailable, name)
			}
			if exists {
				ref := current.refs[refKey{c, name}]
				updateEntry(ref, t)
				if err := setPerKeyCustom(ref.files, c, t); err != nil {
					return nil, err
				}
				continue
			}
			m, err := document.ParseMaterial(c, t.Material)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", document.Pointer(c, name, "material"), err)
			}
			data := m.PEM()
			tf, err := tufmeta.TargetFile().FromBytes(name, data, hashAlgo)
			if err != nil {
				return nil, fmt.Errorf("failed to build target metadata for %q: %w", name, err)
			}
			if err := setPerKeyCustom(tf, c, t); err != nil {
				return nil, err
			}
			re.AddTarget(name, tf)
			if err := addEntry(tr, c, m, t, operator); err != nil {
				return nil, fmt.Errorf("%s: %w", document.Pointer(c, name), err)
			}
			staged = append(staged, stagedTarget{name: name, data: data})
		}
	}

	renderSigningConfig(re.TrustBundle, managedURLs(current.doc, next), deriveServices(re.TrustBundle, next, at))
	return staged, nil
}

// setPerKeyCustom writes the custom metadata of a per-key target, keeping
// keys tufcli does not own.
func setPerKeyCustom(tf *tufmeta.TargetFiles, c document.Component, t document.Target) error {
	custom := customMap(tf)
	sig, _ := custom["sigstore"].(map[string]any)
	if sig == nil {
		sig = map[string]any{}
	}
	status := "Active"
	if t.ValidFor.End != nil && !t.ValidFor.End.After(now()) {
		status = "Expired"
	}
	sig["status"] = status
	sig["uri"] = t.URI
	sig["usage"] = componentUsage[c]
	custom["sigstore"] = sig
	if c == document.Fulcio {
		setIssuers(custom, t.OIDCIssuers)
	}
	return writeCustom(tf, custom)
}

func setIssuers(custom map[string]any, issuers []string) {
	rh, _ := custom["rhtas"].(map[string]any)
	if rh == nil {
		rh = map[string]any{}
	}
	if issuers == nil {
		issuers = []string{}
	}
	rh["oidcIssuers"] = issuers
	custom["rhtas"] = rh
}

func writeCustom(tf *tufmeta.TargetFiles, custom map[string]any) error {
	data, err := json.Marshal(custom)
	if err != nil {
		return fmt.Errorf("failed to marshal custom metadata: %w", err)
	}
	raw := json.RawMessage(data)
	tf.Custom = &raw
	return nil
}

func updateEntry(ref targetRef, t document.Target) {
	if ref.authority != nil {
		ref.authority.Uri = t.URI
		ref.authority.ValidFor = validForToProto(t.ValidFor)
	}
	if ref.log != nil {
		ref.log.BaseUrl = t.URI
		ref.log.PublicKey.ValidFor = validForToProto(t.ValidFor)
	}
}

func removeEntry(tr *trustrootpb.TrustedRoot, c document.Component, ref targetRef) {
	switch c {
	case document.Fulcio:
		tr.CertificateAuthorities = slices.DeleteFunc(tr.CertificateAuthorities, func(e *trustrootpb.CertificateAuthority) bool { return e == ref.authority })
	case document.Tsa:
		tr.TimestampAuthorities = slices.DeleteFunc(tr.TimestampAuthorities, func(e *trustrootpb.CertificateAuthority) bool { return e == ref.authority })
	case document.Ctlog:
		tr.Ctlogs = slices.DeleteFunc(tr.Ctlogs, func(e *trustrootpb.TransparencyLogInstance) bool { return e == ref.log })
	case document.Rekor:
		tr.Tlogs = slices.DeleteFunc(tr.Tlogs, func(e *trustrootpb.TransparencyLogInstance) bool { return e == ref.log })
	}
}

func addEntry(tr *trustrootpb.TrustedRoot, c document.Component, m *document.Material, t document.Target, operator string) error {
	if c.UsesCertificates() {
		var certs []*commonpb.X509Certificate
		for _, der := range m.DER {
			certs = append(certs, &commonpb.X509Certificate{RawBytes: der})
		}
		subject := &commonpb.DistinguishedName{CommonName: m.Certificates[0].Subject.CommonName}
		if len(m.Certificates[0].Subject.Organization) > 0 {
			subject.Organization = m.Certificates[0].Subject.Organization[0]
		}
		ca := &trustrootpb.CertificateAuthority{
			Subject:   subject,
			Uri:       t.URI,
			CertChain: &commonpb.X509CertificateChain{Certificates: certs},
			ValidFor:  validForToProto(t.ValidFor),
			Operator:  operator,
		}
		if c == document.Fulcio {
			tr.CertificateAuthorities = append(tr.CertificateAuthorities, ca)
		} else {
			tr.TimestampAuthorities = append(tr.TimestampAuthorities, ca)
		}
		return nil
	}

	details, err := sigstorepkg.GetDefaultPublicKeyDetails(m.PublicKey)
	if err != nil {
		return fmt.Errorf("unsupported public key: %w", err)
	}
	keyID := sha256.Sum256(m.DER[0])
	l := &trustrootpb.TransparencyLogInstance{
		BaseUrl:       t.URI,
		HashAlgorithm: commonpb.HashAlgorithm_SHA2_256,
		PublicKey: &commonpb.PublicKey{
			RawBytes:   m.DER[0],
			KeyDetails: details,
			ValidFor:   validForToProto(t.ValidFor),
		},
		LogId:    &commonpb.LogId{KeyId: keyID[:]},
		Operator: operator,
	}
	if c == document.Ctlog {
		tr.Ctlogs = append(tr.Ctlogs, l)
	} else {
		tr.Tlogs = append(tr.Tlogs, l)
	}
	return nil
}

// signingServices are the signing config services that targets of a document
// account for.
type signingServices struct {
	ca, oidc, rekor, tsa []*trustrootpb.Service
}

// deriveServices returns the Fulcio, OIDC, Rekor and TSA services of the
// targets of doc whose window has not ended at the given time, each with its
// window, in trusted_root.json order. Targets sharing a URL (a key rotation)
// stay separate services, so clients always find one whose window covers the
// current time.
func deriveServices(tb *sigstore.TrustBundle, doc document.Document, at time.Time) signingServices {
	tr := tb.TrustedRoot
	type active struct {
		uri      string
		validFor *commonpb.TimeRange
		operator string
		issuers  []string
	}
	collect := func(c document.Component, entries func(yield func(der [][]byte, op string) bool)) []active {
		byDigest := map[string]document.Target{}
		for _, t := range doc.Targets(c) {
			if (t.ValidFor.End != nil && !t.ValidFor.End.After(at)) || t.URI == "" {
				continue
			}
			if m, err := document.ParseMaterial(c, t.Material); err == nil {
				byDigest[m.Digest] = t
			}
		}
		var out []active
		for der, op := range entries {
			h := sha256.New()
			for _, b := range der {
				h.Write(b)
			}
			t, ok := byDigest[fmt.Sprintf("sha256:%x", h.Sum(nil))]
			if !ok {
				continue
			}
			out = append(out, active{uri: t.URI, validFor: validForToProto(t.ValidFor), operator: operatorOrDefault(op), issuers: t.OIDCIssuers})
		}
		return out
	}
	authorities := func(list []*trustrootpb.CertificateAuthority) func(func([][]byte, string) bool) {
		return func(yield func([][]byte, string) bool) {
			for _, ca := range list {
				if ca == nil || ca.CertChain == nil {
					continue
				}
				var der [][]byte
				for _, cert := range ca.CertChain.Certificates {
					der = append(der, cert.GetRawBytes())
				}
				if !yield(der, ca.Operator) {
					return
				}
			}
		}
	}
	logs := func(list []*trustrootpb.TransparencyLogInstance) func(func([][]byte, string) bool) {
		return func(yield func([][]byte, string) bool) {
			for _, l := range list {
				if l == nil || l.PublicKey == nil {
					continue
				}
				if !yield([][]byte{l.PublicKey.RawBytes}, l.Operator) {
					return
				}
			}
		}
	}
	services := func(entries []active) []*trustrootpb.Service {
		var out []*trustrootpb.Service
		for _, e := range entries {
			out = appendService(out, newSigningService(e.uri, e.validFor, e.operator))
		}
		return out
	}

	fulcio := collect(document.Fulcio, authorities(tr.CertificateAuthorities))
	var oidc []active
	for _, f := range fulcio {
		for _, issuer := range f.issuers {
			oidc = append(oidc, active{uri: issuer, validFor: f.validFor, operator: f.operator})
		}
	}
	return signingServices{
		ca:    services(fulcio),
		oidc:  services(oidc),
		rekor: services(collect(document.Rekor, logs(tr.Tlogs))),
		tsa:   services(collect(document.Tsa, authorities(tr.TimestampAuthorities))),
	}
}

// managedURLs returns, per signing config list, the URLs of the targets a
// patch adds, changes or removes (on either side, whatever their windows),
// and for Fulcio targets their OIDC issuers. tufcli owns every service at
// these URLs: services published earlier for them may carry other windows
// (an older tufcli kept a service open after closing the key, or the window
// has ended since), so ownership cannot be decided by comparing services.
func managedURLs(current, next document.Document) signingURLs {
	urls := signingURLs{ca: map[string]bool{}, oidc: map[string]bool{}, rekor: map[string]bool{}, tsa: map[string]bool{}}
	add := func(c document.Component, t document.Target) {
		switch c {
		case document.Fulcio:
			urls.ca[t.URI] = true
			for _, issuer := range t.OIDCIssuers {
				urls.oidc[issuer] = true
			}
		case document.Rekor:
			urls.rekor[t.URI] = true
		case document.Tsa:
			urls.tsa[t.URI] = true
		}
	}
	for _, c := range document.Components {
		cur, nxt := current.Targets(c), next.Targets(c)
		for name, old := range cur {
			if t, ok := nxt[name]; !ok || !document.Equal(c, old, t) {
				add(c, old)
			}
		}
		for name, t := range nxt {
			if old, ok := cur[name]; !ok || !document.Equal(c, old, t) {
				add(c, t)
			}
		}
	}
	for _, m := range []map[string]bool{urls.ca, urls.oidc, urls.rekor, urls.tsa} {
		delete(m, "")
	}
	return urls
}

type signingURLs struct {
	ca, oidc, rekor, tsa map[string]bool
}

// renderSigningConfig replaces the services at the managed URLs with the ones
// the new document gives (targets whose window has not ended, each with its
// window). Services at other URLs are outside the patch and kept as they are,
// including independently configured ones (for example an OIDC issuer added
// with `tufcli signing-config`).
func renderSigningConfig(tb *sigstore.TrustBundle, managed signingURLs, after signingServices) {
	if tb.SigningConfig == nil {
		tb.SigningConfig = sigstore.NewTrustBundle().SigningConfig
	}
	sc := tb.SigningConfig
	update := func(list *[]*trustrootpb.Service, managed map[string]bool, after []*trustrootpb.Service) {
		out := []*trustrootpb.Service{}
		previous := map[string][]*trustrootpb.Service{}
		for _, s := range *list {
			if s != nil && managed[s.Url] {
				previous[s.Url] = append(previous[s.Url], s)
				continue
			}
			out = append(out, s)
		}
		for _, s := range after {
			if managed[s.Url] {
				keepAPIVersion(s, previous[s.Url])
				out = appendService(out, s)
			}
		}
		*list = out
	}
	update(&sc.CaUrls, managed.ca, after.ca)
	update(&sc.OidcUrls, managed.oidc, after.oidc)
	update(&sc.RekorTlogUrls, managed.rekor, after.rekor)
	update(&sc.TsaUrls, managed.tsa, after.tsa)
}

// keepAPIVersion gives a regenerated service the API version that was
// configured for its URL (for example Rekor v2 set with
// `tufcli signing-config add-url --api-version 2`): from a previous service
// with the same start if there is one, else from the one with the latest start
// (no start counts as the earliest). Among equal candidates the highest
// version wins, whatever the file order. The document does not carry API
// versions, so a URL seen for the first time gets version 1.
func keepAPIVersion(s *trustrootpb.Service, previous []*trustrootpb.Service) {
	var same, latest *trustrootpb.Service
	start := func(p *trustrootpb.Service) time.Time {
		if ts := p.GetValidFor().GetStart(); ts != nil {
			return ts.AsTime()
		}
		return time.Time{}
	}
	better := func(a, b *trustrootpb.Service) bool { // a preferred over b
		if b == nil {
			return true
		}
		if !start(a).Equal(start(b)) {
			return start(a).After(start(b))
		}
		return a.MajorApiVersion > b.MajorApiVersion
	}
	for _, p := range previous {
		if proto.Equal(p.GetValidFor().GetStart(), s.GetValidFor().GetStart()) &&
			(same == nil || p.MajorApiVersion > same.MajorApiVersion) {
			same = p
		}
		if better(p, latest) {
			latest = p
		}
	}
	chosen := same
	if chosen == nil {
		chosen = latest
	}
	if chosen != nil && chosen.MajorApiVersion > 0 {
		s.MajorApiVersion = chosen.MajorApiVersion
	}
}

func containsService(list []*trustrootpb.Service, s *trustrootpb.Service) bool {
	return slices.ContainsFunc(list, func(o *trustrootpb.Service) bool { return proto.Equal(o, s) })
}

func appendService(list []*trustrootpb.Service, s *trustrootpb.Service) []*trustrootpb.Service {
	if containsService(list, s) {
		return list
	}
	return append(list, s)
}

func newSigningService(uri string, validFor *commonpb.TimeRange, operator string) *trustrootpb.Service {
	return &trustrootpb.Service{Url: uri, MajorApiVersion: 1, ValidFor: validFor, Operator: operator}
}

// now is the clock used to decide which windows have ended; variable for tests.
var now = func() time.Time { return time.Now().UTC() }
