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

// Package document defines the versioned JSON document that describes the
// RHTAS targets of a TUF repository, and applies RFC 6902 JSON Patches to it.
//
// The document is what `tufcli rhtas apply` patches. tufcli rebuilds it from
// the repository on every run; callers never send a whole document, only a
// patch over it. Every field is always present: a missing window end is
// `null`, a target without OIDC issuers has `[]`.
//
//	{
//	  "apiVersion": "rhtas.tufcli/v1",
//	  "components": {
//	    "ctlog":  {},
//	    "fulcio": {"fulcio.crt.pem": {"uri": "https://fulcio.example.com",
//	               "oidcIssuers": ["https://oidc.example.com"],
//	               "validFor": {"start": "2025-01-01T00:00:00Z", "end": null},
//	               "material": "-----BEGIN CERTIFICATE-----\n..."}},
//	    "rekor":  {},
//	    "tsa":    {}
//	  }
//	}
package document

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
)

// APIVersion is the only document version this tufcli understands. Patches
// must start with a "test" operation on /apiVersion carrying this value.
const APIVersion = "rhtas.tufcli/v1"

// Component is one kind of RHTAS service whose key material is published.
type Component string

const (
	Ctlog  Component = "ctlog"
	Fulcio Component = "fulcio"
	Rekor  Component = "rekor"
	Tsa    Component = "tsa"
)

// Components lists every component in a fixed order.
var Components = []Component{Ctlog, Fulcio, Rekor, Tsa}

// UsesCertificates reports whether the component's material is a certificate
// chain (Fulcio, TSA) rather than a single public key (CTlog, Rekor).
func (c Component) UsesCertificates() bool {
	return c == Fulcio || c == Tsa
}

// Document is the RHTAS targets document.
type Document struct {
	APIVersion string           `json:"apiVersion"`
	Components ComponentTargets `json:"components"`
}

// ComponentTargets holds the targets of each component, keyed by target name.
type ComponentTargets struct {
	Ctlog  map[string]Target `json:"ctlog"`
	Fulcio map[string]Target `json:"fulcio"`
	Rekor  map[string]Target `json:"rekor"`
	Tsa    map[string]Target `json:"tsa"`
}

// Target is one published key or certificate chain.
type Target struct {
	// URI is the service endpoint (Fulcio/TSA URI, Rekor/CTlog base URL).
	URI string `json:"uri"`
	// OIDCIssuers are the OIDC issuers published with a Fulcio target; always
	// empty for other components.
	OIDCIssuers []string `json:"oidcIssuers"`
	// ValidFor is the window during which the material is trusted.
	ValidFor ValidFor `json:"validFor"`
	// Material is the key (CTlog, Rekor) or certificate chain (Fulcio, TSA),
	// as PEM. Patches may also carry base64-encoded DER.
	Material string `json:"material"`
}

// ValidFor is a validity window. A nil End means the window is open.
type ValidFor struct {
	Start *time.Time `json:"start"`
	End   *time.Time `json:"end"`
}

// New returns an empty document of the current version.
func New() Document {
	return Document{
		APIVersion: APIVersion,
		Components: ComponentTargets{
			Ctlog:  map[string]Target{},
			Fulcio: map[string]Target{},
			Rekor:  map[string]Target{},
			Tsa:    map[string]Target{},
		},
	}
}

// Normalized returns a copy with nil maps and slices replaced by empty ones,
// so that it encodes with every field present.
func (d Document) Normalized() Document {
	out := Document{APIVersion: d.APIVersion}
	maps := []*map[string]Target{&out.Components.Ctlog, &out.Components.Fulcio, &out.Components.Rekor, &out.Components.Tsa}
	for i, c := range Components {
		*maps[i] = map[string]Target{}
		for name, t := range d.Targets(c) {
			if t.OIDCIssuers == nil {
				t.OIDCIssuers = []string{}
			}
			(*maps[i])[name] = t
		}
	}
	return out
}

// Targets returns the target map of component c (nil for an unknown one).
func (d *Document) Targets(c Component) map[string]Target {
	switch c {
	case Ctlog:
		return d.Components.Ctlog
	case Fulcio:
		return d.Components.Fulcio
	case Rekor:
		return d.Components.Rekor
	case Tsa:
		return d.Components.Tsa
	}
	return nil
}

// ValidationError describes why a document is invalid. Path is the JSON
// pointer of the offending value.
type ValidationError struct {
	Path    string
	Message string
}

func (e *ValidationError) Error() string {
	if e.Path == "" {
		return e.Message
	}
	return fmt.Sprintf("%s: %s", e.Path, e.Message)
}

func invalid(path, format string, args ...any) error {
	return &ValidationError{Path: path, Message: fmt.Sprintf(format, args...)}
}

// Pointer returns the JSON pointer of a target, or of a field below it.
func Pointer(c Component, name string, fields ...string) string {
	parts := append([]string{"", "components", string(c), escapePointer(name)}, fields...)
	return strings.Join(parts, "/")
}

func escapePointer(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

// Parse decodes and validates a document. Unknown and missing fields are
// errors: every field is always present.
func Parse(data []byte) (Document, error) {
	doc, err := decode(data)
	if err != nil {
		return Document{}, err
	}
	if err := doc.Validate(); err != nil {
		return Document{}, err
	}
	return doc, nil
}

// decode checks the shape of a document and decodes it, without validating
// the targets.
func decode(data []byte) (Document, error) {
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return Document{}, invalid("", "not valid JSON: %v", err)
	}
	if err := checkShape(raw); err != nil {
		return Document{}, err
	}
	var doc Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return Document{}, invalid("", "%v", err)
	}
	return doc, nil
}

// checkShape checks that every object has exactly the expected keys, so that
// a patch cannot drop a field or smuggle in one tufcli would ignore.
func checkShape(raw any) error {
	top, err := objectWithKeys(raw, "", "apiVersion", "components")
	if err != nil {
		return err
	}
	componentNames := make([]string, len(Components))
	for i, c := range Components {
		componentNames[i] = string(c)
	}
	comps, err := objectWithKeys(top["components"], "/components", componentNames...)
	if err != nil {
		return err
	}
	for _, c := range Components {
		targets, ok := comps[string(c)].(map[string]any)
		if !ok {
			return invalid("/components/"+string(c), "must be an object of targets")
		}
		for name, t := range targets {
			fields, err := objectWithKeys(t, Pointer(c, name), "uri", "oidcIssuers", "validFor", "material")
			if err != nil {
				return err
			}
			if _, ok := fields["uri"].(string); !ok {
				return invalid(Pointer(c, name, "uri"), "must be a string")
			}
			if _, err := objectWithKeys(fields["validFor"], Pointer(c, name, "validFor"), "start", "end"); err != nil {
				return err
			}
			if fields["oidcIssuers"] == nil {
				return invalid(Pointer(c, name, "oidcIssuers"), "must be an array (use [] for none)")
			}
		}
	}
	return nil
}

func objectWithKeys(v any, path string, keys ...string) (map[string]any, error) {
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, invalid(path, "must be an object")
	}
	for _, k := range keys {
		if _, ok := obj[k]; !ok {
			return nil, invalid(path+"/"+k, "is required")
		}
	}
	for k := range obj {
		if !slices.Contains(keys, k) {
			return nil, invalid(path+"/"+escapePointer(k), "unknown field")
		}
	}
	return obj, nil
}

// Validate checks the rules every document must satisfy.
func (d *Document) Validate() error {
	return d.validate(nil)
}

// ValidateChanges checks the same rules as Validate, but only for the targets
// that are new or differ from base. Targets the patch did not touch are taken
// as published, so a repository with an odd entry (for example a window that
// another tool closed before it opened) can still be patched, including to
// repair that entry.
func (d *Document) ValidateChanges(base Document) error {
	return d.validate(&base)
}

func (d *Document) validate(base *Document) error {
	if d.APIVersion != APIVersion {
		return invalid("/apiVersion", "unsupported version %q (this tufcli supports %q)", d.APIVersion, APIVersion)
	}
	type key struct {
		c    Component
		name string
	}
	touched := map[key]bool{}
	owners := map[string][]Component{}
	digests := map[Component]map[string][]string{}
	for _, c := range Components {
		targets := d.Targets(c)
		if targets == nil {
			return invalid("/components/"+string(c), "must be an object of targets")
		}
		digests[c] = map[string][]string{}
		for _, name := range SortedNames(targets) {
			t := targets[name]
			changed := true
			if base != nil {
				old, ok := base.Targets(c)[name]
				changed = !ok || !Equal(c, old, t)
			}
			touched[key{c, name}] = changed
			owners[name] = append(owners[name], c)
			if m, err := ParseMaterial(c, t.Material); err == nil {
				digests[c][m.Digest] = append(digests[c][m.Digest], name)
			} else if changed {
				return invalid(Pointer(c, name, "material"), "%v", err)
			}
		}
	}

	for _, c := range Components {
		targets := d.Targets(c)
		for _, name := range SortedNames(targets) {
			if !touched[key{c, name}] {
				continue
			}
			t := targets[name]
			if err := ValidateTargetName(name); err != nil {
				return invalid(Pointer(c, name), "%v", err)
			}
			// targets.json has one namespace: a name belongs to one component.
			for _, other := range owners[name] {
				if other != c {
					return invalid(Pointer(c, name), "target name %q is also used by a %s target", name, other)
				}
			}
			m, _ := ParseMaterial(c, t.Material)
			for _, other := range digests[c][m.Digest] {
				if other != name {
					return invalid(Pointer(c, name, "material"), "same material as target %q", other)
				}
			}
			if t.URI != "" {
				if err := validateURL(t.URI); err != nil {
					return invalid(Pointer(c, name, "uri"), "%v", err)
				}
			}
			if c != Fulcio && len(t.OIDCIssuers) > 0 {
				return invalid(Pointer(c, name, "oidcIssuers"), "only Fulcio targets have OIDC issuers")
			}
			for i, issuer := range t.OIDCIssuers {
				if err := validateURL(issuer); err != nil {
					return invalid(Pointer(c, name, "oidcIssuers", fmt.Sprint(i)), "%v", err)
				}
				if slices.Index(t.OIDCIssuers, issuer) != i {
					return invalid(Pointer(c, name, "oidcIssuers", fmt.Sprint(i)), "duplicate issuer %q", issuer)
				}
			}
			if s, e := t.ValidFor.Start, t.ValidFor.End; s != nil && e != nil && e.Before(*s) {
				return invalid(Pointer(c, name, "validFor"), "end is before start")
			}
		}
	}
	return nil
}

// reservedTargetNames are targets tufcli generates; they cannot be per-key targets.
var reservedTargetNames = []string{"trusted_root.json", "signing_config.v0.2.json"}

// ValidateTargetName checks that name is usable as a top-level target file name.
func ValidateTargetName(name string) error {
	switch {
	case name == "":
		return errors.New("target name is empty")
	case name == "." || name == "..":
		return fmt.Errorf("target name %q is not a file name", name)
	case strings.ContainsAny(name, "/\\~") || strings.ContainsFunc(name, func(r rune) bool { return r < 0x20 || r == 0x7f }):
		return fmt.Errorf("target name %q must not contain '/', '\\', '~' or control characters", name)
	case slices.Contains(reservedTargetNames, name):
		return fmt.Errorf("target name %q is reserved", name)
	}
	return nil
}

func validateURL(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %v", s, err)
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("invalid URL %q: must be an absolute http(s) URL", s)
	}
	return nil
}

// SortedNames returns the keys of targets in sorted order.
func SortedNames(targets map[string]Target) []string {
	names := make([]string, 0, len(targets))
	for name := range targets {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// Material is parsed key material.
type Material struct {
	// DER holds one block per certificate (chain order) or the single public key.
	DER [][]byte
	// Certificates is set for Fulcio and TSA material.
	Certificates []*x509.Certificate
	// PublicKey is set for CTlog and Rekor material.
	PublicKey crypto.PublicKey
	// Digest identifies the material whatever its encoding: "sha256:" and the
	// hex SHA-256 of the DER blocks concatenated (DER is self-delimiting).
	Digest string
}

// ParseMaterial decodes material for component c. It accepts PEM (CERTIFICATE
// blocks for Fulcio and TSA, one PUBLIC KEY block for CTlog and Rekor) or the
// same DER encoded as base64.
func ParseMaterial(c Component, s string) (*Material, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("material is empty")
	}
	var blocks [][]byte
	if strings.Contains(s, "-----BEGIN") {
		wantType := "PUBLIC KEY"
		if c.UsesCertificates() {
			wantType = "CERTIFICATE"
		}
		rest := []byte(s)
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != wantType {
				return nil, fmt.Errorf("PEM block %q found, %s material needs %q", block.Type, c, wantType)
			}
			blocks = append(blocks, block.Bytes)
		}
		if len(blocks) == 0 || len(bytes.TrimSpace(rest)) != 0 {
			return nil, errors.New("material is not valid PEM")
		}
	} else {
		der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
		if err != nil {
			return nil, errors.New("material is neither PEM nor base64-encoded DER")
		}
		if c.UsesCertificates() {
			certs, err := x509.ParseCertificates(der)
			if err != nil {
				return nil, fmt.Errorf("base64 material is not a DER certificate chain: %v", err)
			}
			for _, cert := range certs {
				blocks = append(blocks, cert.Raw)
			}
		} else {
			blocks = [][]byte{der}
		}
	}

	m := &Material{DER: blocks}
	if c.UsesCertificates() {
		for _, der := range blocks {
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, fmt.Errorf("invalid certificate: %v", err)
			}
			m.Certificates = append(m.Certificates, cert)
		}
	} else {
		if len(blocks) != 1 {
			return nil, fmt.Errorf("%s material must be exactly one public key, found %d blocks", c, len(blocks))
		}
		pub, err := x509.ParsePKIXPublicKey(blocks[0])
		if err != nil {
			return nil, fmt.Errorf("invalid public key: %v", err)
		}
		if _, err := signature.GetDefaultPublicKeyDetails(pub); err != nil {
			return nil, fmt.Errorf("unsupported public key: %v", err)
		}
		m.PublicKey = pub
	}
	h := sha256.New()
	for _, der := range blocks {
		h.Write(der)
	}
	m.Digest = "sha256:" + hex.EncodeToString(h.Sum(nil))
	return m, nil
}

// PEM returns the canonical PEM encoding of the material.
func (m *Material) PEM() []byte {
	blockType := "PUBLIC KEY"
	if m.Certificates != nil {
		blockType = "CERTIFICATE"
	}
	var buf bytes.Buffer
	for _, der := range m.DER {
		_ = pem.Encode(&buf, &pem.Block{Type: blockType, Bytes: der})
	}
	return buf.Bytes()
}

// Equal reports whether two targets of component c describe the same thing.
// Material is compared by digest, windows by instant, so encodings do not
// matter. Both targets must hold valid material.
func Equal(c Component, a, b Target) bool {
	if a.URI != b.URI || !slices.Equal(a.OIDCIssuers, b.OIDCIssuers) ||
		!timesEqual(a.ValidFor.Start, b.ValidFor.Start) || !timesEqual(a.ValidFor.End, b.ValidFor.End) {
		return false
	}
	ma, errA := ParseMaterial(c, a.Material)
	mb, errB := ParseMaterial(c, b.Material)
	return errA == nil && errB == nil && ma.Digest == mb.Digest
}

func timesEqual(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

// DocumentsEqual reports whether two valid documents describe the same targets.
func DocumentsEqual(a, b Document) bool {
	if a.APIVersion != b.APIVersion {
		return false
	}
	for _, c := range Components {
		ta, tb := a.Targets(c), b.Targets(c)
		if len(ta) != len(tb) {
			return false
		}
		for name, t := range ta {
			other, ok := tb[name]
			if !ok || !Equal(c, t, other) {
				return false
			}
		}
	}
	return true
}
