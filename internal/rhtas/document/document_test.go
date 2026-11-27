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

package document

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"
)

func testPublicKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func testCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"Org"}, CommonName: "CN"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func pemToBase64(t *testing.T, s string) string {
	t.Helper()
	var der []byte
	rest := []byte(s)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		der = append(der, b.Bytes...)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func ts(s string) *time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return &t
}

func testDocument(t *testing.T) (Document, string) {
	t.Helper()
	doc := New()
	rekor := testPublicKeyPEM(t)
	doc.Components.Rekor["rekor.pub"] = Target{
		URI:         "https://rekor.example.com",
		OIDCIssuers: []string{},
		ValidFor:    ValidFor{Start: ts("2025-01-01T00:00:00Z")},
		Material:    rekor,
	}
	doc.Components.Fulcio["fulcio.pem"] = Target{
		URI:         "https://fulcio.example.com",
		OIDCIssuers: []string{"https://oidc.example.com"},
		ValidFor:    ValidFor{Start: ts("2025-01-01T00:00:00Z")},
		Material:    testCertPEM(t),
	}
	if err := doc.Validate(); err != nil {
		t.Fatalf("test document invalid: %v", err)
	}
	return doc, rekor
}

const versionTest = `{"op":"test","path":"/apiVersion","value":"rhtas.tufcli/v1"}`

func patchOf(ops ...string) []byte {
	return []byte("[" + strings.Join(append([]string{versionTest}, ops...), ",") + "]")
}

func targetJSON(t *testing.T, target Target) string {
	t.Helper()
	if target.OIDCIssuers == nil {
		target.OIDCIssuers = []string{}
	}
	return string(mustJSON(t, target))
}

func applyPatch(d Document, patch []byte) (Document, error) {
	return Apply(d, patch, nil)
}

func requirePatchError(t *testing.T, err error, reason string, index int) *PatchError {
	t.Helper()
	var pe *PatchError
	if !errors.As(err, &pe) {
		t.Fatalf("expected PatchError %s, got %v", reason, err)
	}
	if pe.Reason != reason || pe.Index != index {
		t.Fatalf("expected %s at operation %d, got %s at %d: %v", reason, index, pe.Reason, pe.Index, err)
	}
	return pe
}

func TestParseMaterial_PEMAndBase64HaveSameDigest(t *testing.T) {
	for _, tc := range []struct {
		component Component
		pem       string
	}{
		{Rekor, testPublicKeyPEM(t)},
		{Ctlog, testPublicKeyPEM(t)},
		{Fulcio, testCertPEM(t) + testCertPEM(t)},
		{Tsa, testCertPEM(t)},
	} {
		fromPEM, err := ParseMaterial(tc.component, tc.pem)
		if err != nil {
			t.Fatalf("%s PEM: %v", tc.component, err)
		}
		fromB64, err := ParseMaterial(tc.component, pemToBase64(t, tc.pem))
		if err != nil {
			t.Fatalf("%s base64: %v", tc.component, err)
		}
		if fromPEM.Digest != fromB64.Digest || !strings.HasPrefix(fromPEM.Digest, "sha256:") {
			t.Fatalf("%s: digests differ: %s vs %s", tc.component, fromPEM.Digest, fromB64.Digest)
		}
		if string(fromB64.PEM()) != strings.TrimSpace(tc.pem)+"\n" {
			t.Fatalf("%s: canonical PEM differs from input", tc.component)
		}
	}
}

func TestParseMaterial_Rejects(t *testing.T) {
	key, cert := testPublicKeyPEM(t), testCertPEM(t)
	for name, tc := range map[string]struct {
		component Component
		material  string
	}{
		"empty":                {Rekor, "  "},
		"cert for rekor":       {Rekor, cert},
		"key for fulcio":       {Fulcio, key},
		"two keys":             {Ctlog, key + key},
		"not base64":           {Rekor, "not material!"},
		"garbage after PEM":    {Rekor, key + "trailing"},
		"base64 of non-key":    {Rekor, base64.StdEncoding.EncodeToString([]byte("hello"))},
		"base64 of non-cert":   {Tsa, base64.StdEncoding.EncodeToString([]byte("hello"))},
		"truncated PEM header": {Rekor, "-----BEGIN PUBLIC KEY-----\nAAAA"},
	} {
		if _, err := ParseMaterial(tc.component, tc.material); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestParse_RequiresEveryFieldAndNoUnknownOnes(t *testing.T) {
	doc, _ := testDocument(t)
	good, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(good); err != nil {
		t.Fatalf("valid document rejected: %v", err)
	}

	for name, mutate := range map[string]func(m map[string]any){
		"missing end":       func(m map[string]any) { delete(rekorOf(m)["validFor"].(map[string]any), "end") },
		"missing material":  func(m map[string]any) { delete(rekorOf(m), "material") },
		"null oidcIssuers":  func(m map[string]any) { rekorOf(m)["oidcIssuers"] = nil },
		"unknown field":     func(m map[string]any) { rekorOf(m)["status"] = "Active" },
		"unknown component": func(m map[string]any) { m["components"].(map[string]any)["oidc"] = map[string]any{} },
		"missing component": func(m map[string]any) { delete(m["components"].(map[string]any), "tsa") },
		"wrong version":     func(m map[string]any) { m["apiVersion"] = "v2" },
	} {
		var m map[string]any
		if err := json.Unmarshal(good, &m); err != nil {
			t.Fatal(err)
		}
		mutate(m)
		data, _ := json.Marshal(m)
		var ve *ValidationError
		if _, err := Parse(data); !errors.As(err, &ve) {
			t.Errorf("%s: expected a ValidationError, got %v", name, err)
		}
	}
}

func rekorOf(m map[string]any) map[string]any {
	return m["components"].(map[string]any)["rekor"].(map[string]any)["rekor.pub"].(map[string]any)
}

func TestValidate_Rules(t *testing.T) {
	for name, mutate := range map[string]func(d *Document){
		"end before start": func(d *Document) { setRekor(d, func(t *Target) { t.ValidFor.End = ts("2024-01-01T00:00:00Z") }) },
		"issuers on rekor": func(d *Document) {
			setRekor(d, func(t *Target) { t.OIDCIssuers = []string{"https://oidc.example.com"} })
		},
		"relative uri":           func(d *Document) { setRekor(d, func(t *Target) { t.URI = "rekor.example.com" }) },
		"slash in name":          func(d *Document) { d.Components.Rekor["a/b"] = d.Components.Rekor["rekor.pub"] },
		"reserved name":          func(d *Document) { d.Components.Rekor["trusted_root.json"] = d.Components.Rekor["rekor.pub"] },
		"same material twice":    func(d *Document) { d.Components.Rekor["copy.pub"] = d.Components.Rekor["rekor.pub"] },
		"name in two components": func(d *Document) { d.Components.Ctlog["rekor.pub"] = d.Components.Rekor["rekor.pub"] },
		"duplicate issuer": func(d *Document) {
			setFulcio(d, func(t *Target) { t.OIDCIssuers = append(t.OIDCIssuers, t.OIDCIssuers[0]) })
		},
		"issuer not a URL": func(d *Document) { setFulcio(d, func(t *Target) { t.OIDCIssuers = []string{"oidc"} }) },
		"material of wrong type": func(d *Document) {
			setFulcio(d, func(t *Target) { t.Material = d.Components.Rekor["rekor.pub"].Material })
		},
		"tilde in name (pointers)": func(d *Document) { d.Components.Rekor["a~b"] = d.Components.Rekor["rekor.pub"] },
	} {
		doc, _ := testDocument(t)
		mutate(&doc)
		if err := doc.Validate(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}

	doc, _ := testDocument(t)
	setRekor(&doc, func(t *Target) { t.URI = "" })
	if err := doc.Validate(); err != nil {
		t.Errorf("empty URI must be accepted (existing repositories may have one): %v", err)
	}
}

func setRekor(d *Document, f func(t *Target)) {
	t := d.Components.Rekor["rekor.pub"]
	f(&t)
	d.Components.Rekor["rekor.pub"] = t
}

func setFulcio(d *Document, f func(t *Target)) {
	t := d.Components.Fulcio["fulcio.pem"]
	f(&t)
	d.Components.Fulcio["fulcio.pem"] = t
}

func TestApply_VersionTestRequired(t *testing.T) {
	doc, _ := testDocument(t)
	for name, tc := range map[string]struct {
		patch  string
		reason string
	}{
		"not JSON":          {`{`, ReasonInvalidPatch},
		"not an array":      {`{"op":"test"}`, ReasonInvalidPatch},
		"empty":             {`[]`, ReasonUnsupportedVersion},
		"no version test":   {`[{"op":"remove","path":"/components/rekor/rekor.pub"}]`, ReasonUnsupportedVersion},
		"other version":     {`[{"op":"test","path":"/apiVersion","value":"rhtas.tufcli/v2"}]`, ReasonUnsupportedVersion},
		"version not first": {`[{"op":"test","path":"/components/rekor/rekor.pub/uri","value":"https://rekor.example.com"},` + versionTest + `]`, ReasonUnsupportedVersion},
	} {
		_, err := applyPatch(doc, []byte(tc.patch))
		var pe *PatchError
		if !errors.As(err, &pe) || pe.Reason != tc.reason {
			t.Errorf("%s: expected %s, got %v", name, tc.reason, err)
		}
	}
}

func TestApply_OnlyTestAddReplaceRemove(t *testing.T) {
	doc, _ := testDocument(t)
	for _, op := range []string{
		`{"op":"move","from":"/components/rekor/rekor.pub","path":"/components/rekor/other.pub"}`,
		`{"op":"copy","from":"/components/rekor/rekor.pub","path":"/components/rekor/other.pub"}`,
		`{"path":"/components/rekor/rekor.pub"}`,
	} {
		_, err := applyPatch(doc, patchOf(op))
		requirePatchError(t, err, ReasonInvalidPatch, 1)
	}
}

func TestApply_ContractRows(t *testing.T) {
	doc, rekor := testDocument(t)
	newKey := testPublicKeyPEM(t)
	existing := doc.Components.Rekor["rekor.pub"]

	t.Run("add creates a target", func(t *testing.T) {
		added := Target{URI: "https://rekor2.example.com", ValidFor: ValidFor{Start: ts("2025-06-01T00:00:00Z")}, Material: newKey}
		got, err := applyPatch(doc, patchOf(`{"op":"add","path":"/components/rekor/rekor2.pub","value":`+targetJSON(t, added)+`}`))
		if err != nil {
			t.Fatal(err)
		}
		if !Equal(Rekor, got.Components.Rekor["rekor2.pub"], Target{URI: added.URI, OIDCIssuers: []string{}, ValidFor: added.ValidFor, Material: newKey}) {
			t.Fatalf("added target not in result: %+v", got.Components.Rekor)
		}
	})

	t.Run("add over an existing target with the same material updates its fields", func(t *testing.T) {
		updated := existing
		updated.Material = pemToBase64(t, rekor) // same material, other encoding
		updated.ValidFor.End = ts("2025-06-01T00:00:00Z")
		got, err := applyPatch(doc, patchOf(`{"op":"add","path":"/components/rekor/rekor.pub","value":`+targetJSON(t, updated)+`}`))
		if err != nil {
			t.Fatal(err)
		}
		if !got.Components.Rekor["rekor.pub"].ValidFor.End.Equal(*updated.ValidFor.End) {
			t.Fatalf("window not updated: %+v", got.Components.Rekor["rekor.pub"])
		}
	})

	t.Run("add over an existing target with other material is rejected", func(t *testing.T) {
		other := existing
		other.Material = newKey
		_, err := applyPatch(doc, patchOf(`{"op":"add","path":"/components/rekor/rekor.pub","value":`+targetJSON(t, other)+`}`))
		pe := requirePatchError(t, err, ReasonOperationRejected, 1)
		if !errors.Is(pe, ErrMaterialChanged) {
			t.Fatalf("expected ErrMaterialChanged, got %v", err)
		}
	})

	t.Run("replace of material is rejected", func(t *testing.T) {
		v, _ := json.Marshal(newKey)
		_, err := applyPatch(doc, patchOf(`{"op":"replace","path":"/components/rekor/rekor.pub/material","value":`+string(v)+`}`))
		if pe := requirePatchError(t, err, ReasonOperationRejected, 1); !errors.Is(pe, ErrMaterialChanged) {
			t.Fatalf("expected ErrMaterialChanged, got %v", err)
		}
	})

	t.Run("remove then add under the same name with other material is rejected", func(t *testing.T) {
		other := existing
		other.Material = newKey
		_, err := applyPatch(doc, patchOf(
			`{"op":"remove","path":"/components/rekor/rekor.pub"}`,
			`{"op":"add","path":"/components/rekor/rekor.pub","value":`+targetJSON(t, other)+`}`))
		requirePatchError(t, err, ReasonOperationRejected, 2)
	})

	t.Run("replace updates and can reopen a window", func(t *testing.T) {
		closed, err := applyPatch(doc, patchOf(`{"op":"replace","path":"/components/rekor/rekor.pub/validFor/end","value":"2025-06-01T00:00:00Z"}`))
		if err != nil {
			t.Fatal(err)
		}
		reopened, err := applyPatch(closed, patchOf(`{"op":"replace","path":"/components/rekor/rekor.pub/validFor/end","value":null}`))
		if err != nil {
			t.Fatal(err)
		}
		if reopened.Components.Rekor["rekor.pub"].ValidFor.End != nil {
			t.Fatal("window not reopened")
		}
		if !DocumentsEqual(doc, reopened) {
			t.Fatal("reopened document differs from the original")
		}
	})

	t.Run("replace of a missing target fails", func(t *testing.T) {
		_, err := applyPatch(doc, patchOf(`{"op":"replace","path":"/components/rekor/missing.pub/uri","value":"https://x.example.com"}`))
		requirePatchError(t, err, ReasonOperationRejected, 1)
	})

	t.Run("URI must be a string, including for an empty URL", func(t *testing.T) {
		const path = "/components/rekor/rekor.pub/uri"
		_, err := applyPatch(doc, patchOf(`{"op":"replace","path":"`+path+`","value":null}`))
		if pe := requirePatchError(t, err, ReasonOperationRejected, 1); pe.Path != path {
			t.Fatalf("rejected path = %q, want %q", pe.Path, path)
		}
		got, err := applyPatch(doc, patchOf(`{"op":"replace","path":"`+path+`","value":""}`))
		if err != nil {
			t.Fatal(err)
		}
		if got.Components.Rekor["rekor.pub"].URI != "" {
			t.Fatal("URI was not cleared")
		}
	})

	t.Run("remove deletes a target", func(t *testing.T) {
		got, err := applyPatch(doc, patchOf(`{"op":"remove","path":"/components/rekor/rekor.pub"}`))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := got.Components.Rekor["rekor.pub"]; ok {
			t.Fatal("target not removed")
		}
	})

	t.Run("remove of a missing target is a no-op", func(t *testing.T) {
		got, err := applyPatch(doc, patchOf(`{"op":"remove","path":"/components/rekor/missing.pub"}`))
		if err != nil {
			t.Fatal(err)
		}
		if !DocumentsEqual(doc, got) {
			t.Fatal("document changed")
		}
	})

	t.Run("removing a required field is rejected", func(t *testing.T) {
		_, err := applyPatch(doc, patchOf(`{"op":"remove","path":"/components/rekor/rekor.pub/validFor/end"}`))
		requirePatchError(t, err, ReasonOperationRejected, 1)
	})

	t.Run("entries not in the patch are untouched", func(t *testing.T) {
		got, err := applyPatch(doc, patchOf(`{"op":"replace","path":"/components/rekor/rekor.pub/uri","value":"https://rekor.other.example.com"}`))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got.Components.Fulcio, doc.Components.Fulcio) {
			t.Fatal("fulcio targets changed")
		}
	})
}

func TestApply_IdempotentReapplication(t *testing.T) {
	doc, _ := testDocument(t)
	added := Target{URI: "https://rekor.example.com", ValidFor: ValidFor{Start: ts("2025-06-01T00:00:00Z")}, Material: testPublicKeyPEM(t)}
	patch := patchOf(
		`{"op":"replace","path":"/components/rekor/rekor.pub/validFor/end","value":"2025-06-01T00:00:00Z"}`,
		`{"op":"add","path":"/components/rekor/rekor2.pub","value":`+targetJSON(t, added)+`}`,
		`{"op":"remove","path":"/components/fulcio/fulcio.pem"}`,
	)
	once, err := applyPatch(doc, patch)
	if err != nil {
		t.Fatal(err)
	}
	twice, err := applyPatch(once, patch)
	if err != nil {
		t.Fatal(err)
	}
	if DocumentsEqual(doc, once) || !DocumentsEqual(once, twice) {
		t.Fatal("second application must change nothing")
	}
}

func TestApply_AllOrNothing(t *testing.T) {
	doc, _ := testDocument(t)
	before, _ := json.Marshal(doc)
	_, err := applyPatch(doc, patchOf(
		`{"op":"remove","path":"/components/fulcio/fulcio.pem"}`,
		`{"op":"replace","path":"/components/rekor/missing.pub/uri","value":"https://x.example.com"}`,
	))
	requirePatchError(t, err, ReasonOperationRejected, 2)
	after, _ := json.Marshal(doc)
	if string(before) != string(after) {
		t.Fatal("input document was modified by a rejected patch")
	}
}

func TestDocumentsEqual_IgnoresEncodings(t *testing.T) {
	a, rekor := testDocument(t)
	b, _ := Parse(mustJSON(t, a))
	setRekor(&b, func(tg *Target) {
		tg.Material = pemToBase64(t, rekor)
		start := tg.ValidFor.Start.In(time.FixedZone("x", 3600))
		tg.ValidFor.Start = &start
	})
	if !DocumentsEqual(a, b) {
		t.Fatal("same targets in other encodings must be equal")
	}
	setRekor(&b, func(tg *Target) { tg.URI = "https://other.example.com" })
	if DocumentsEqual(a, b) {
		t.Fatal("different URIs must differ")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestApply_IssuerElementEditsRejected(t *testing.T) {
	doc, _ := testDocument(t)
	for _, op := range []string{
		`{"op":"add","path":"/components/fulcio/fulcio.pem/oidcIssuers/-","value":"https://other.example.com"}`,
		`{"op":"add","path":"/components/fulcio/fulcio.pem/oidcIssuers/0","value":"https://other.example.com"}`,
		`{"op":"remove","path":"/components/fulcio/fulcio.pem/oidcIssuers/0"}`,
		`{"op":"replace","path":"/components/fulcio/fulcio.pem/oidcIssuers/0","value":"https://other.example.com"}`,
	} {
		_, err := applyPatch(doc, patchOf(op))
		requirePatchError(t, err, ReasonInvalidPatch, 1)
	}
	// Whole-list replacement is idempotent.
	patch := patchOf(`{"op":"replace","path":"/components/fulcio/fulcio.pem/oidcIssuers","value":["https://oidc.example.com","https://other.example.com"]}`)
	once, err := applyPatch(doc, patch)
	if err != nil {
		t.Fatal(err)
	}
	twice, err := applyPatch(once, patch)
	if err != nil || !DocumentsEqual(once, twice) {
		t.Fatalf("replaying a list replacement: %v", err)
	}
	// Testing an element is harmless and allowed.
	if _, err := applyPatch(doc, patchOf(`{"op":"test","path":"/components/fulcio/fulcio.pem/oidcIssuers/0","value":"https://oidc.example.com"}`)); err != nil {
		t.Fatal(err)
	}
}

func TestApply_ValueRequiredButNullAccepted(t *testing.T) {
	doc, _ := testDocument(t)
	for _, op := range []string{
		`{"op":"test","path":"/components/rekor/rekor.pub/validFor/end"}`,
		`{"op":"replace","path":"/components/rekor/rekor.pub/validFor/end"}`,
		`{"op":"add","path":"/components/rekor/rekor.pub/validFor/end"}`,
	} {
		_, err := applyPatch(doc, patchOf(op))
		requirePatchError(t, err, ReasonInvalidPatch, 1)
	}
	if _, err := applyPatch(doc, patchOf(`{"op":"test","path":"/components/rekor/rekor.pub/validFor/end","value":null}`)); err != nil {
		t.Fatalf("explicit null must be accepted: %v", err)
	}
	_, err := applyPatch(doc, patchOf(`{"op":"test","path":"/components/rekor/rekor.pub/validFor/start","value":null}`))
	requirePatchError(t, err, ReasonOperationRejected, 1)
}

func TestApply_GuardedPatchIsReplaySafe(t *testing.T) {
	doc, _ := testDocument(t)
	patch := patchOf(
		`{"op":"test","path":"/components/rekor/rekor.pub/uri","value":"https://rekor.example.com"}`,
		`{"op":"replace","path":"/components/rekor/rekor.pub/uri","value":"https://rekor2.example.com"}`)
	once, err := applyPatch(doc, patch)
	if err != nil {
		t.Fatal(err)
	}
	// Retry: the guard no longer holds, but the change is already in place.
	twice, err := applyPatch(once, patch)
	if err != nil || !DocumentsEqual(once, twice) {
		t.Fatalf("retry of an applied guarded patch: %v", err)
	}
	// Another writer set a third value: the guard rejection stands.
	other, err := applyPatch(doc, patchOf(`{"op":"replace","path":"/components/rekor/rekor.pub/uri","value":"https://rekor3.example.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	_, err = applyPatch(other, patch)
	requirePatchError(t, err, ReasonOperationRejected, 1)
	// A guard on a removed target, retried after the removal.
	removal := patchOf(
		`{"op":"test","path":"/components/rekor/rekor.pub/uri","value":"https://rekor.example.com"}`,
		`{"op":"remove","path":"/components/rekor/rekor.pub"}`)
	gone, err := applyPatch(doc, removal)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := applyPatch(gone, removal); err != nil || !DocumentsEqual(gone, again) {
		t.Fatalf("retry of an applied guarded removal: %v", err)
	}
}
