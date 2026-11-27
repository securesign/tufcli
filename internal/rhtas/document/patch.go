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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	jsonpatch "github.com/evanphx/json-patch/v5"
)

// Reasons a patch is refused. They are part of the machine-readable result.
const (
	// ReasonInvalidPatch: the patch is not a JSON array of RFC 6902 operations.
	ReasonInvalidPatch = "InvalidPatch"
	// ReasonUnsupportedVersion: the patch does not start with a "test" of
	// /apiVersion, or tests a version this tufcli does not support.
	ReasonUnsupportedVersion = "UnsupportedVersion"
	// ReasonOperationRejected: one operation failed or broke a document rule.
	ReasonOperationRejected = "OperationRejected"
)

// PatchError reports a refused patch. Index is the zero-based position of the
// operation at fault (-1 when the patch as a whole is at fault).
type PatchError struct {
	Reason string
	Index  int
	Op     string
	Path   string
	Err    error
}

func (e *PatchError) Error() string {
	if e.Index < 0 {
		return fmt.Sprintf("%s: %v", e.Reason, e.Err)
	}
	return fmt.Sprintf("%s: operation %d (%s %s): %v", e.Reason, e.Index, e.Op, e.Path, e.Err)
}

func (e *PatchError) Unwrap() error { return e.Err }

// ErrMaterialChanged is returned when a patch would give an existing target
// name different key material. A key change is a new target.
var ErrMaterialChanged = errors.New("an existing target name cannot get other key material or move to another component; publish the new material under a new target name")

// ErrNameUnavailable is returned when a patch gives a new target the name of a
// repository target that is not an RHTAS key.
var ErrNameUnavailable = errors.New("target name is used by a repository target that is not an RHTAS key")

var allowedOps = map[string]bool{"test": true, "add": true, "replace": true, "remove": true}

type operationHeader struct {
	Op    string           `json:"op"`
	Path  *string          `json:"path"`
	Value *json.RawMessage `json:"value"`
}

// Apply applies an RFC 6902 JSON Patch to current, which must be valid, and
// returns the result. It is all or nothing: on error current is unchanged and
// no result is returned.
//
// On top of RFC 6902:
//   - the first operation must be {"op":"test","path":"/apiVersion","value":APIVersion};
//   - only test, add, replace and remove are accepted;
//   - remove of a missing path is a no-op (so removing a target is idempotent);
//   - after every operation the document must be valid, and a target that
//     exists in current must keep its key material (compared by digest).
//
// So "add" of a whole target creates it, or updates its other fields when it
// exists with the same material; "replace" fails when the path is missing.
//
// unavailable names targets of the repository that are not RHTAS keys; a patch
// cannot give their names to a new target.
func Apply(current Document, patch []byte, unavailable map[string]bool) (Document, error) {
	result, err := apply(current, patch, unavailable)
	var pe *PatchError
	if err == nil || !errors.As(err, &pe) || pe.Op != "test" || pe.Index < 1 ||
		(!errors.Is(err, jsonpatch.ErrTestFailed) && !errors.Is(err, jsonpatch.ErrMissing)) {
		return result, err
	}
	// A guard ("test" after the version test) no longer holds. That is what
	// a retry of a published patch sees: the guarded value already has its new
	// value. If the patch without its guards changes nothing, it is already
	// applied: report the current document (NoChange). Otherwise the state
	// changed in another way and the guard rejection stands.
	// A patch made only of tests is an assertion: its failure stands.
	unguarded, ok := withoutGuards(patch)
	if !ok {
		return result, err
	}
	if again, err2 := apply(current, unguarded, unavailable); err2 == nil && DocumentsEqual(current, again) {
		return current, nil
	}
	return result, err
}

// withoutGuards returns the patch without its "test" operations, except the
// leading version test.
func withoutGuards(patch []byte) ([]byte, bool) {
	var ops []json.RawMessage
	if json.Unmarshal(patch, &ops) != nil || len(ops) == 0 {
		return nil, false
	}
	kept := []json.RawMessage{ops[0]}
	for _, raw := range ops[1:] {
		var h operationHeader
		if json.Unmarshal(raw, &h) != nil {
			return nil, false
		}
		if h.Op != "test" {
			kept = append(kept, raw)
		}
	}
	if len(kept) == 1 {
		return nil, false
	}
	out, err := json.Marshal(kept)
	return out, err == nil
}

func apply(current Document, patch []byte, unavailable map[string]bool) (Document, error) {
	var rawOps []json.RawMessage
	if err := json.Unmarshal(patch, &rawOps); err != nil {
		return Document{}, &PatchError{Reason: ReasonInvalidPatch, Index: -1, Err: fmt.Errorf("patch must be a JSON array of operations: %v", err)}
	}
	if len(rawOps) == 0 {
		return Document{}, &PatchError{Reason: ReasonUnsupportedVersion, Index: -1, Err: fmt.Errorf("patch is empty; it must start with a test of /apiVersion")}
	}

	headers := make([]operationHeader, len(rawOps))
	for i, raw := range rawOps {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &headers[i]); err != nil || headers[i].Path == nil || json.Unmarshal(raw, &fields) != nil {
			return Document{}, &PatchError{Reason: ReasonInvalidPatch, Index: i, Err: fmt.Errorf("not an RFC 6902 operation with op and path")}
		}
		h := headers[i]
		invalidOp := func(format string, args ...any) error {
			return &PatchError{Reason: ReasonInvalidPatch, Index: i, Op: h.Op, Path: *h.Path, Err: fmt.Errorf(format, args...)}
		}
		if !allowedOps[h.Op] {
			return Document{}, invalidOp("operation %q is not supported (use test, add, replace or remove)", h.Op)
		}
		// RFC 6902 requires "value" for these; a missing one must not be
		// read as null (a test of an open window would then pass).
		if _, ok := fields["value"]; !ok && h.Op != "remove" {
			return Document{}, invalidOp("%q operation needs a value (use null for an open window)", h.Op)
		}
		// oidcIssuers is the only array: edits of single elements (appending
		// with "-", removing by index) do something else when the patch is
		// applied again, so a retry after a published run would fail or
		// change the list twice. The whole list is replaced instead.
		if h.Op != "test" && isArrayElementPath(*h.Path) {
			return Document{}, invalidOp("oidcIssuers elements cannot be edited one by one; replace the whole list")
		}
	}

	first := headers[0]
	var testedVersion string
	if first.Op != "test" || *first.Path != "/apiVersion" || first.Value == nil || json.Unmarshal(*first.Value, &testedVersion) != nil {
		return Document{}, &PatchError{Reason: ReasonUnsupportedVersion, Index: 0, Op: first.Op, Path: *first.Path,
			Err: fmt.Errorf("the first operation must be {\"op\":\"test\",\"path\":\"/apiVersion\",\"value\":%q}", APIVersion)}
	}
	if testedVersion != current.APIVersion {
		return Document{}, &PatchError{Reason: ReasonUnsupportedVersion, Index: 0, Op: first.Op, Path: *first.Path,
			Err: fmt.Errorf("patch is for document version %q, this tufcli supports %q", testedVersion, current.APIVersion)}
	}

	// Existing target names keep their component and their material.
	type existing struct {
		component Component
		digest    string
	}
	original := map[string]existing{}
	for _, c := range Components {
		for name, t := range current.Targets(c) {
			m, err := ParseMaterial(c, t.Material)
			if err != nil {
				return Document{}, fmt.Errorf("current document is invalid: %s: %w", Pointer(c, name, "material"), err)
			}
			original[name] = existing{c, m.Digest}
		}
	}

	doc, err := json.Marshal(current.Normalized())
	if err != nil {
		return Document{}, fmt.Errorf("failed to encode current document: %w", err)
	}
	options := jsonpatch.NewApplyOptions()
	options.AllowMissingPathOnRemove = true
	options.SupportNegativeIndices = false
	options.EscapeHTML = false

	var result Document
	for i, raw := range rawOps {
		h := headers[i]
		rejected := func(err error) error {
			return &PatchError{Reason: ReasonOperationRejected, Index: i, Op: h.Op, Path: *h.Path, Err: err}
		}
		op, err := jsonpatch.DecodePatch(append(append([]byte("["), raw...), ']'))
		if err != nil {
			return Document{}, &PatchError{Reason: ReasonInvalidPatch, Index: i, Op: h.Op, Path: *h.Path, Err: err}
		}
		doc, err = op.ApplyWithOptions(doc, options)
		if err != nil {
			return Document{}, rejected(err)
		}
		result, err = decode(doc)
		if err != nil {
			return Document{}, rejected(err)
		}
		if err := result.ValidateChanges(current); err != nil {
			return Document{}, rejected(err)
		}
		for _, c := range Components {
			for name, t := range result.Targets(c) {
				was, existed := original[name]
				if !existed {
					if unavailable[name] {
						return Document{}, rejected(fmt.Errorf("%s: %w", Pointer(c, name), ErrNameUnavailable))
					}
					continue
				}
				m, err := ParseMaterial(c, t.Material)
				if err != nil || was.component != c || m.Digest != was.digest {
					return Document{}, rejected(fmt.Errorf("%s: %w", Pointer(c, name), ErrMaterialChanged))
				}
			}
		}
	}
	return result, nil
}

// isArrayElementPath reports whether path points below a target's
// oidcIssuers list (/components/<component>/<name>/oidcIssuers/<index>).
func isArrayElementPath(path string) bool {
	tokens := strings.Split(path, "/")
	return len(tokens) > 5 && tokens[1] == "components" && tokens[4] == "oidcIssuers"
}

// Encode returns the document as indented JSON.
func (d Document) Encode() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(d); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
