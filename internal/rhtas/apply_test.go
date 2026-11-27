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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	commonpb "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	trustrootpb "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/securesign/tufcli/internal/editor"
	"github.com/securesign/tufcli/internal/rhtas/document"
	"github.com/securesign/tufcli/internal/sigstore"
	"github.com/securesign/tufcli/internal/utils"
)

// applyRepo is a repository built the way rhtas/tuf-repo-init.sh builds one:
// one `tufcli rhtas` run per service, plus a second Rekor key added by hand.
type applyRepo struct {
	dir, rootPath, outDir, keyPath string
	material                       map[string]string // target name -> PEM
}

func setupApplyRepo(t *testing.T) *applyRepo {
	t.Helper()
	dir, rootPath, outDir := setupTestRepo(t)
	r := &applyRepo{dir: dir, rootPath: rootPath, outDir: outDir, keyPath: filepath.Join(dir, "key.pem"), material: map[string]string{}}
	run := func(o Options) {
		t.Helper()
		o.RootPath, o.OutDir, o.KeyPaths, o.Operator = rootPath, outDir, []string{r.keyPath}, "rhtas"
		if err := Run(&o); err != nil {
			t.Fatalf("rhtas run failed: %v", err)
		}
	}
	read := func(path string) string {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		r.material[filepath.Base(path)] = string(data)
		return path
	}
	run(Options{FulcioTarget: read(generateTestCert(t, dir, "fulcio.crt.pem")), FulcioURI: "https://fulcio.example.com", OIDCURIs: []string{"https://oidc.example.com"}})
	run(Options{TsaTarget: read(generateTestCert(t, dir, "tsa.certchain.pem")), TsaURI: "https://tsa.example.com"})
	run(Options{CtlogTarget: read(generateTestPublicKey(t, dir, "ctfe.pub")), CtlogURI: "https://ctfe.example.com"})
	run(Options{RekorTarget: read(generateTestPublicKey(t, dir, "rekor.pub")), RekorURI: "https://rekor.example.com"})
	// Hand-added later: tufcli closes the previous Rekor window automatically.
	time.Sleep(1100 * time.Millisecond)
	run(Options{RekorTarget: read(generateTestPublicKey(t, dir, "rekor-2.pub")), RekorURI: "https://rekor.example.com"})
	return r
}

func (r *applyRepo) apply(t *testing.T, ops ...string) (*ApplyResult, error) {
	t.Helper()
	patch := "[" + strings.Join(append([]string{`{"op":"test","path":"/apiVersion","value":"rhtas.tufcli/v1"}`}, ops...), ",") + "]"
	return Apply(&ApplyOptions{RootPath: r.rootPath, OutDir: r.outDir, KeyPaths: []string{r.keyPath}, Patch: []byte(patch), Operator: "rhtas"})
}

func (r *applyRepo) document(t *testing.T) document.Document {
	t.Helper()
	re := r.load(t)
	rd, err := buildDocument(re)
	if err != nil {
		t.Fatalf("buildDocument: %v", err)
	}
	return rd.doc
}

func (r *applyRepo) load(t *testing.T) *Editor {
	t.Helper()
	re, err := LoadRepository(editor.LoadOptions{RootPath: r.rootPath, OutDir: r.outDir})
	if err != nil {
		t.Fatal(err)
	}
	return re
}

// snapshotFiles returns the content digest of every file in the repository.
func snapshotFiles(t *testing.T, dir string) map[string][32]byte {
	t.Helper()
	files := map[string][32]byte{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() == ".tufcli.lock" {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		files[rel] = sha256.Sum256(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func requireSameFiles(t *testing.T, before, after map[string][32]byte) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatalf("repository files changed: %d before, %d after", len(before), len(after))
	}
	for name, sum := range before {
		if after[name] != sum {
			t.Fatalf("repository file %s changed", name)
		}
	}
}

func targetValue(t *testing.T, target document.Target) string {
	t.Helper()
	if target.OIDCIssuers == nil {
		target.OIDCIssuers = []string{}
	}
	data, err := json.Marshal(target)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func publishedTrustBundle(t *testing.T, outDir string) *sigstore.TrustBundle {
	t.Helper()
	re, err := LoadRepository(editor.LoadOptions{RootPath: filepath.Join(outDir, "root.json"), OutDir: outDir})
	if err != nil {
		t.Fatal(err)
	}
	return re.TrustBundle
}

func publishedTargetPath(t *testing.T, outDir, name string) string {
	t.Helper()
	md := &tufmeta.Metadata[tufmeta.TargetsType]{}
	path, _, err := editor.FindLatestVersionedFile(outDir, "targets.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := md.FromFile(path); err != nil {
		t.Fatal(err)
	}
	tf, ok := md.Signed.Targets[name]
	if !ok {
		t.Fatalf("target %s not published", name)
	}
	hash, err := utils.PreferredHash(tf.Hashes)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(outDir, "targets", hash+"."+name)
}

// publishSigningConfig publishes a hand-edited signing config, as
// `tufcli signing-config` followed by `tufcli update` would.
func (r *applyRepo) publishSigningConfig(t *testing.T, edit func(sc *trustrootpb.SigningConfig)) {
	t.Helper()
	re := r.load(t)
	edit(re.TrustBundle.SigningConfig)
	re.BumpTargetsVersion()
	re.BumpSnapshotVersion()
	re.BumpTimestampVersion()
	scPath := filepath.Join(r.outDir, "targets", "signing_config.v0.2.json")
	if err := re.TrustBundle.SaveSigningConfig(scPath); err != nil {
		t.Fatal(err)
	}
	tf, err := tufmeta.TargetFile().FromFile(scPath, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	re.AddTarget("signing_config.v0.2.json", tf)
	if err := re.SignAndWrite(editor.SignAndWriteOptions{KeyPaths: []string{r.keyPath}, OutDir: r.outDir, HashAlgo: "sha256"}); err != nil {
		t.Fatal(err)
	}
}

func TestBuildDocument_FromRhtasRepository(t *testing.T) {
	r := setupApplyRepo(t)
	doc := r.document(t)

	want := map[document.Component][]string{
		document.Fulcio: {"fulcio.crt.pem"},
		document.Tsa:    {"tsa.certchain.pem"},
		document.Ctlog:  {"ctfe.pub"},
		document.Rekor:  {"rekor-2.pub", "rekor.pub"},
	}
	for c, names := range want {
		if got := document.SortedNames(doc.Targets(c)); strings.Join(got, ",") != strings.Join(names, ",") {
			t.Fatalf("%s targets = %v, want %v", c, got, names)
		}
		for _, name := range names {
			if doc.Targets(c)[name].Material != r.material[name] {
				t.Fatalf("%s/%s: material is not the target file", c, name)
			}
		}
	}
	fulcio := doc.Components.Fulcio["fulcio.crt.pem"]
	if fulcio.URI != "https://fulcio.example.com" || strings.Join(fulcio.OIDCIssuers, ",") != "https://oidc.example.com" {
		t.Fatalf("fulcio target = %+v", fulcio)
	}
	if fulcio.ValidFor.Start == nil || fulcio.ValidFor.End != nil {
		t.Fatalf("fulcio window = %+v", fulcio.ValidFor)
	}
	old, current := doc.Components.Rekor["rekor.pub"], doc.Components.Rekor["rekor-2.pub"]
	if old.ValidFor.End == nil || current.ValidFor.Start == nil || !old.ValidFor.End.Equal(*current.ValidFor.Start) {
		t.Fatalf("hand-added Rekor key: windows %+v and %+v", old.ValidFor, current.ValidFor)
	}
	if len(doc.Components.Rekor["rekor.pub"].OIDCIssuers) != 0 {
		t.Fatal("non-Fulcio targets have no issuers")
	}
}

func TestApply_NoChangePublishesNothing(t *testing.T) {
	r := setupApplyRepo(t)
	before := snapshotFiles(t, r.outDir)
	re := r.load(t)

	result, err := r.apply(t)
	if err != nil {
		t.Fatal(err)
	}
	if result.Result != ResultNoChange || result.Targets.Version != re.Targets().Signed.Version {
		t.Fatalf("result = %+v", result)
	}
	requireSameFiles(t, before, snapshotFiles(t, r.outDir))
}

func TestApply_RotationWithExactWindowsIsIdempotent(t *testing.T) {
	r := setupApplyRepo(t)
	re := r.load(t)
	version := re.Targets().Signed.Version
	start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	newKey := string(mustRead(t, generateTestPublicKey(t, r.dir, "rekor-3.pub")))
	ops := []string{
		fmt.Sprintf(`{"op":"replace","path":"/components/rekor/rekor-2.pub/validFor/end","value":%q}`, start.Format(time.RFC3339)),
		`{"op":"add","path":"/components/rekor/rekor-3.pub","value":` + targetValue(t, document.Target{
			URI: "https://rekor.example.com", ValidFor: document.ValidFor{Start: &start}, Material: newKey}) + `}`,
	}

	result, err := r.apply(t, ops...)
	if err != nil {
		t.Fatal(err)
	}
	if result.Result != ResultApplied || result.Targets.Version != version+1 ||
		result.Snapshot.Version != re.Snapshot().Signed.Version+1 || result.Timestamp.Version != re.Timestamp().Signed.Version+1 {
		t.Fatalf("result = %+v", result)
	}

	// Exact windows, not "now" and no automatic rollover.
	tb := publishedTrustBundle(t, r.outDir)
	var windows []string
	for _, l := range tb.TrustedRoot.Tlogs {
		vf := l.PublicKey.ValidFor
		end := "open"
		if vf.End != nil {
			end = vf.End.AsTime().Format(time.RFC3339)
		}
		windows = append(windows, vf.Start.AsTime().Format(time.RFC3339)+"/"+end)
	}
	doc := r.document(t)
	wantOld := doc.Components.Rekor["rekor.pub"].ValidFor
	want := []string{
		wantOld.Start.Format(time.RFC3339) + "/" + wantOld.End.Format(time.RFC3339),
		doc.Components.Rekor["rekor-2.pub"].ValidFor.Start.Format(time.RFC3339) + "/" + start.Format(time.RFC3339),
		start.Format(time.RFC3339) + "/open",
	}
	if strings.Join(windows, " ") != strings.Join(want, " ") {
		t.Fatalf("tlog windows = %v, want %v", windows, want)
	}
	// Both the current and the next key are signing services until the switch.
	var services []string
	for _, s := range tb.SigningConfig.RekorTlogUrls {
		services = append(services, s.Url)
	}
	if len(services) != 2 {
		t.Fatalf("rekor services = %v, want the current and the next key", services)
	}
	// Clients can load what was published.
	if _, err := root.NewTrustedRootFromJSON(mustRead(t, publishedTargetPath(t, r.outDir, "trusted_root.json"))); err != nil {
		t.Fatalf("published trusted_root.json does not load: %v", err)
	}
	if _, err := root.NewSigningConfigFromJSON(mustRead(t, publishedTargetPath(t, r.outDir, "signing_config.v0.2.json"))); err != nil {
		t.Fatalf("published signing config does not load: %v", err)
	}
	custom := customMap(r.load(t).Targets().Signed.Targets["rekor-2.pub"])
	// The window ends in an hour: still Active until then.
	if custom["sigstore"].(map[string]any)["status"] != "Active" {
		t.Fatalf("closed target custom metadata = %v", custom)
	}

	before := snapshotFiles(t, r.outDir)
	again, err := r.apply(t, ops...)
	if err != nil {
		t.Fatal(err)
	}
	if again.Result != ResultNoChange || again.Targets.Version != version+1 {
		t.Fatalf("second application = %+v", again)
	}
	requireSameFiles(t, before, snapshotFiles(t, r.outDir))
}

func TestApply_InlineBase64MaterialWithoutFiles(t *testing.T) {
	r := setupApplyRepo(t)
	keyPath := generateTestPublicKey(t, r.dir, "ctfe-2.pub")
	pemData := mustRead(t, keyPath)
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemData)
	value := fmt.Sprintf(`{"uri":"https://ctfe.example.com","oidcIssuers":[],"validFor":{"start":"2025-01-01T00:00:00Z","end":null},"material":%q}`,
		base64.StdEncoding.EncodeToString(block.Bytes))

	if _, err := r.apply(t, `{"op":"add","path":"/components/ctlog/ctfe-2.pub","value":`+value+`}`); err != nil {
		t.Fatal(err)
	}
	published := mustRead(t, publishedTargetPath(t, r.outDir, "ctfe-2.pub"))
	if string(published) != string(pemData) {
		t.Fatalf("published target is not the canonical PEM:\n%s", published)
	}
	if utils.FileExists(filepath.Join(r.outDir, "targets", "ctfe-2.pub")) {
		t.Fatal("staging copy left behind")
	}
}

func TestApply_RejectedPatchPublishesNothing(t *testing.T) {
	r := setupApplyRepo(t)
	before := snapshotFiles(t, r.outDir)
	other := string(mustRead(t, generateTestPublicKey(t, r.dir, "other.pub")))

	_, err := r.apply(t,
		`{"op":"remove","path":"/components/ctlog/ctfe.pub"}`,
		fmt.Sprintf(`{"op":"replace","path":"/components/rekor/rekor.pub/material","value":%q}`, other))
	ae := ClassifyError(err)
	if ae.Reason != document.ReasonOperationRejected || ae.Operation == nil || *ae.Operation != 2 || ae.Path != "/components/rekor/rekor.pub/material" {
		t.Fatalf("error = %+v", ae)
	}
	if !errors.Is(err, document.ErrMaterialChanged) {
		t.Fatalf("expected ErrMaterialChanged, got %v", err)
	}
	requireSameFiles(t, before, snapshotFiles(t, r.outDir))
}

func TestApply_UnauthorizedSignerPublishesNothing(t *testing.T) {
	r := setupApplyRepo(t)
	before := snapshotFiles(t, r.outDir)
	otherKey := generateTestKey(t, t.TempDir())

	_, err := Apply(&ApplyOptions{
		RootPath: r.rootPath, OutDir: r.outDir, KeyPaths: []string{otherKey},
		Patch: []byte(`[{"op":"test","path":"/apiVersion","value":"rhtas.tufcli/v1"},{"op":"remove","path":"/components/ctlog/ctfe.pub"}]`),
	})
	ae := ClassifyError(err)
	if ae.Reason != ReasonSignerNotAuthorized || ae.Role != "targets" {
		t.Fatalf("error = %+v (%v)", ae, err)
	}
	requireSameFiles(t, before, snapshotFiles(t, r.outDir))
}

func TestApply_RemoveKeepsFileForGraceAndIsIdempotent(t *testing.T) {
	r := setupApplyRepo(t)
	filePath := publishedTargetPath(t, r.outDir, "ctfe.pub")

	if _, err := r.apply(t, `{"op":"remove","path":"/components/ctlog/ctfe.pub"}`); err != nil {
		t.Fatal(err)
	}
	re := r.load(t)
	if _, ok := re.Targets().Signed.Targets["ctfe.pub"]; ok {
		t.Fatal("target still in targets.json")
	}
	if len(re.TrustBundle.TrustedRoot.Ctlogs) != 0 {
		t.Fatal("ctlog still in trusted_root.json")
	}
	if !utils.FileExists(filePath) {
		t.Fatal("removed target file must stay for the grace period")
	}

	result, err := r.apply(t, `{"op":"remove","path":"/components/ctlog/ctfe.pub"}`)
	if err != nil || result.Result != ResultNoChange {
		t.Fatalf("second removal: %+v, %v", result, err)
	}
}

func TestApply_FulcioIssuersRecordedAndPublished(t *testing.T) {
	r := setupApplyRepo(t)
	if _, err := r.apply(t, `{"op":"replace","path":"/components/fulcio/fulcio.crt.pem/oidcIssuers","value":["https://a.example.com","https://b.example.com"]}`); err != nil {
		t.Fatal(err)
	}
	custom := customMap(r.load(t).Targets().Signed.Targets["fulcio.crt.pem"])
	if fmt.Sprint(custom["rhtas"]) != "map[oidcIssuers:[https://a.example.com https://b.example.com]]" {
		t.Fatalf("custom metadata = %v", custom)
	}
	var oidc []string
	for _, s := range publishedTrustBundle(t, r.outDir).SigningConfig.OidcUrls {
		oidc = append(oidc, s.Url)
	}
	if strings.Join(oidc, ",") != "https://a.example.com,https://b.example.com" {
		t.Fatalf("oidc services = %v", oidc)
	}
	if got := r.document(t).Components.Fulcio["fulcio.crt.pem"].OIDCIssuers; strings.Join(got, ",") != strings.Join(oidc, ",") {
		t.Fatalf("rebuilt issuers = %v", got)
	}
}

func TestApply_TargetNameOfAnotherKindRefused(t *testing.T) {
	r := setupApplyRepo(t)
	value := targetValue(t, document.Target{URI: "https://rekor.example.com", Material: string(mustRead(t, generateTestPublicKey(t, r.dir, "x.pub")))})
	// A Rekor key cannot take the name of the existing CTlog target.
	_, err := r.apply(t, `{"op":"add","path":"/components/rekor/ctfe.pub","value":`+value+`}`)
	if err == nil || !strings.Contains(err.Error(), "ctfe.pub") {
		t.Fatalf("expected the name clash to be refused, got %v", err)
	}
}

func TestApply_NameCannotMoveToAnotherComponent(t *testing.T) {
	r := setupApplyRepo(t)
	before := snapshotFiles(t, r.outDir)
	value := targetValue(t, document.Target{URI: "https://ctfe.example.com", Material: string(mustRead(t, generateTestPublicKey(t, r.dir, "n.pub")))})

	_, err := r.apply(t,
		`{"op":"remove","path":"/components/rekor/rekor.pub"}`,
		`{"op":"add","path":"/components/ctlog/rekor.pub","value":`+value+`}`)
	if ae := ClassifyError(err); ae.Reason != document.ReasonOperationRejected || ae.Operation == nil || *ae.Operation != 2 {
		t.Fatalf("error = %+v", ae)
	}
	requireSameFiles(t, before, snapshotFiles(t, r.outDir))
}

func TestApply_OddPublishedEntryDoesNotBlockLaterPatches(t *testing.T) {
	r := setupApplyRepo(t)
	start := time.Now().UTC().Add(2 * time.Hour).Truncate(time.Second)
	value := targetValue(t, document.Target{URI: "https://rekor.example.com", ValidFor: document.ValidFor{Start: &start},
		Material: string(mustRead(t, generateTestPublicKey(t, r.dir, "future.pub")))})
	if _, err := r.apply(t, `{"op":"add","path":"/components/rekor/future.pub","value":`+value+`}`); err != nil {
		t.Fatal(err)
	}
	// The flag-based command's rollover closes the future key's window now,
	// before it opens.
	if err := Run(&Options{RootPath: r.rootPath, OutDir: r.outDir, KeyPaths: []string{r.keyPath},
		RekorTarget: generateTestPublicKey(t, r.dir, "later.pub"), RekorURI: "https://rekor.example.com"}); err != nil {
		t.Fatal(err)
	}
	if odd := r.document(t).Components.Rekor["future.pub"].ValidFor; odd.End == nil || !odd.End.Before(*odd.Start) {
		t.Fatalf("setup: expected end before start, got %+v", odd)
	}

	if _, err := r.apply(t, `{"op":"replace","path":"/components/ctlog/ctfe.pub/uri","value":"https://ctfe2.example.com"}`); err != nil {
		t.Fatalf("unrelated patch blocked: %v", err)
	}
	if _, err := r.apply(t, `{"op":"replace","path":"/components/rekor/future.pub/validFor/end","value":null}`); err != nil {
		t.Fatalf("repair blocked: %v", err)
	}
	if _, err := r.apply(t, fmt.Sprintf(`{"op":"replace","path":"/components/rekor/future.pub/validFor/start","value":%q}`,
		start.Add(time.Hour).Format(time.RFC3339))); err != nil {
		t.Fatal(err)
	}
	// Touching it while still invalid is refused.
	if _, err := r.apply(t, fmt.Sprintf(`{"op":"replace","path":"/components/rekor/future.pub/validFor/end","value":%q}`,
		start.Format(time.RFC3339))); err == nil {
		t.Fatal("an invalid window on a touched target must be refused")
	}
}

func TestApply_NameOfPlainTargetRefusedWithOperation(t *testing.T) {
	r := setupApplyRepo(t)
	re := r.load(t)
	plain := []byte("not a key")
	tf, err := tufmeta.TargetFile().FromBytes("notes.txt", plain, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	re.AddTarget("notes.txt", tf)
	re.BumpTargetsVersion()
	re.BumpSnapshotVersion()
	re.BumpTimestampVersion()
	if err := os.WriteFile(filepath.Join(r.outDir, "targets", "notes.txt"), plain, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := re.SignAndWrite(editor.SignAndWriteOptions{KeyPaths: []string{r.keyPath}, OutDir: r.outDir, HashAlgo: "sha256"}); err != nil {
		t.Fatal(err)
	}

	value := targetValue(t, document.Target{URI: "https://rekor.example.com", Material: string(mustRead(t, generateTestPublicKey(t, r.dir, "p.pub")))})
	_, err = r.apply(t, `{"op":"add","path":"/components/rekor/notes.txt","value":`+value+`}`)
	ae := ClassifyError(err)
	if ae.Reason != document.ReasonOperationRejected || ae.Operation == nil || *ae.Operation != 1 || !errors.Is(err, document.ErrNameUnavailable) {
		t.Fatalf("error = %+v (%v)", ae, err)
	}
	// The plain target is not part of the document and survives other patches.
	if _, err := r.apply(t, `{"op":"remove","path":"/components/ctlog/ctfe.pub"}`); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.load(t).Targets().Signed.Targets["notes.txt"]; !ok {
		t.Fatal("plain target removed")
	}
}

func TestApply_UnrelatedPatchLeavesLegacyFulcioUntouched(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	r := &applyRepo{dir: dir, rootPath: rootPath, outDir: outDir, keyPath: filepath.Join(dir, "key.pem")}
	// An Expired Fulcio target added by the flag-based command: its issuer is
	// only in the signing config, with an ended window.
	if err := Run(&Options{RootPath: rootPath, OutDir: outDir, KeyPaths: []string{r.keyPath},
		FulcioTarget: generateTestCert(t, dir, "fulcio.pem"), FulcioURI: "https://fulcio.example.com",
		FulcioStatus: "Expired", OIDCURIs: []string{"https://oidc.example.com"}}); err != nil {
		t.Fatal(err)
	}
	if err := Run(&Options{RootPath: rootPath, OutDir: outDir, KeyPaths: []string{r.keyPath},
		RekorTarget: generateTestPublicKey(t, dir, "rekor.pub"), RekorURI: "https://rekor.example.com"}); err != nil {
		t.Fatal(err)
	}
	if got := r.document(t).Components.Fulcio["fulcio.pem"].OIDCIssuers; len(got) != 1 {
		t.Fatalf("setup: recovered issuers = %v", got)
	}
	fulcioBefore, _ := json.Marshal(r.load(t).Targets().Signed.Targets["fulcio.pem"])
	oidcBefore := publishedTrustBundle(t, outDir).SigningConfig.OidcUrls

	if _, err := r.apply(t, `{"op":"replace","path":"/components/rekor/rekor.pub/uri","value":"https://rekor2.example.com"}`); err != nil {
		t.Fatal(err)
	}
	if fulcioAfter, _ := json.Marshal(r.load(t).Targets().Signed.Targets["fulcio.pem"]); string(fulcioAfter) != string(fulcioBefore) {
		t.Fatalf("untouched Fulcio target metadata changed:\n%s\n%s", fulcioBefore, fulcioAfter)
	}
	oidcAfter := publishedTrustBundle(t, outDir).SigningConfig.OidcUrls
	if len(oidcAfter) != len(oidcBefore) || !proto.Equal(oidcAfter[0], oidcBefore[0]) {
		t.Fatalf("untouched OIDC service changed: %v -> %v", oidcBefore, oidcAfter)
	}
	if got := r.document(t).Components.Fulcio["fulcio.pem"].OIDCIssuers; strings.Join(got, ",") != "https://oidc.example.com" {
		t.Fatalf("issuers after an unrelated apply = %v", got)
	}
}

func TestApply_RemovingLegacyRotatedFulcioDropsItsIssuer(t *testing.T) {
	r := setupApplyRepo(t)
	// Independently configured issuers: kept throughout. One shares the
	// Fulcio entry's start and operator but has an end of its own.
	ca := r.load(t).TrustBundle.TrustedRoot.CertificateAuthorities[0]
	ownEnd := timestamppb.New(time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second))
	r.publishSigningConfig(t, func(sc *trustrootpb.SigningConfig) {
		sc.OidcUrls = append(sc.OidcUrls,
			newSigningService("https://independent.example.com", &commonpb.TimeRange{Start: timestamppb.Now()}, "other"),
			newSigningService("https://same-start.example.com", &commonpb.TimeRange{Start: ca.ValidFor.Start, End: ownEnd}, ca.Operator))
	})
	// Flag-based rotation to another Fulcio URL, certificate and issuer: the
	// old CA window is closed, its OIDC service stays open.
	time.Sleep(1100 * time.Millisecond)
	if err := Run(&Options{RootPath: r.rootPath, OutDir: r.outDir, KeyPaths: []string{r.keyPath}, Operator: "rhtas",
		FulcioTarget: generateTestCert(t, r.dir, "fulcio-b.crt.pem"), FulcioURI: "https://fulcio-b.example.com",
		OIDCURIs: []string{"https://oidc-b.example.com"}}); err != nil {
		t.Fatal(err)
	}
	doc := r.document(t)
	if got := doc.Components.Fulcio["fulcio.crt.pem"].OIDCIssuers; strings.Join(got, ",") != "https://oidc.example.com" {
		t.Fatalf("setup: issuers of the rotated-out certificate = %v", got)
	}

	if _, err := r.apply(t, `{"op":"remove","path":"/components/fulcio/fulcio.crt.pem"}`); err != nil {
		t.Fatal(err)
	}
	var oidc []string
	for _, s := range publishedTrustBundle(t, r.outDir).SigningConfig.OidcUrls {
		oidc = append(oidc, s.Url)
	}
	if strings.Join(oidc, ",") != "https://independent.example.com,https://same-start.example.com,https://oidc-b.example.com" {
		t.Fatalf("oidc services after removing the old certificate = %v", oidc)
	}
}

func TestApply_APIVersionFromLatestStartWhateverTheOrder(t *testing.T) {
	r := setupApplyRepo(t)
	target := r.document(t).Components.Rekor["rekor-2.pub"]
	older := timestamppb.New(target.ValidFor.Start.Add(-time.Hour))
	newer := timestamppb.New(target.ValidFor.Start.Add(-time.Minute))
	// Same URL, neither start matches the target: v2 (newer start) first,
	// v1 (older start) last in the file.
	r.publishSigningConfig(t, func(sc *trustrootpb.SigningConfig) {
		sc.RekorTlogUrls = []*trustrootpb.Service{
			{Url: "https://rekor.example.com", MajorApiVersion: 2, ValidFor: &commonpb.TimeRange{Start: newer}, Operator: "rhtas"},
			{Url: "https://rekor.example.com", MajorApiVersion: 1, ValidFor: &commonpb.TimeRange{Start: older}, Operator: "rhtas"},
		}
	})
	end := time.Now().UTC().Add(5 * 24 * time.Hour).Truncate(time.Second)
	if _, err := r.apply(t, fmt.Sprintf(`{"op":"replace","path":"/components/rekor/rekor-2.pub/validFor/end","value":%q}`, end.Format(time.RFC3339))); err != nil {
		t.Fatal(err)
	}
	services := publishedTrustBundle(t, r.outDir).SigningConfig.RekorTlogUrls
	if len(services) != 1 || services[0].MajorApiVersion != 2 {
		t.Fatalf("rekor services = %v", services)
	}
}

func TestApply_GuardedPatchRetryIsNoChange(t *testing.T) {
	r := setupApplyRepo(t)
	guarded := []string{
		`{"op":"test","path":"/components/rekor/rekor-2.pub/uri","value":"https://rekor.example.com"}`,
		`{"op":"replace","path":"/components/rekor/rekor-2.pub/uri","value":"https://rekor2.example.com"}`,
	}
	if result, err := r.apply(t, guarded...); err != nil || result.Result != ResultApplied {
		t.Fatalf("%+v, %v", result, err)
	}
	before := snapshotFiles(t, r.outDir)
	result, err := r.apply(t, guarded...)
	if err != nil || result.Result != ResultNoChange {
		t.Fatalf("retry = %+v, %v", result, err)
	}
	requireSameFiles(t, before, snapshotFiles(t, r.outDir))
}

func TestApply_NoChangeStillCollectsRemovedTargetFiles(t *testing.T) {
	r := setupApplyRepo(t)
	old := deletedTargetGrace
	deletedTargetGrace = time.Second
	t.Cleanup(func() { deletedTargetGrace = old })
	filePath := publishedTargetPath(t, r.outDir, "ctfe.pub")

	// The removing run keeps the file for the grace period.
	if _, err := r.apply(t, `{"op":"remove","path":"/components/ctlog/ctfe.pub"}`); err != nil {
		t.Fatal(err)
	}
	if !utils.FileExists(filePath) {
		t.Fatal("setup: file already collected by the removing run")
	}
	time.Sleep(1100 * time.Millisecond)
	result, err := r.apply(t, `{"op":"remove","path":"/components/ctlog/ctfe.pub"}`)
	if err != nil || result.Result != ResultNoChange {
		t.Fatalf("%+v, %v", result, err)
	}
	if utils.FileExists(filePath) {
		t.Fatal("file of the removed target not collected after its grace period")
	}
}

func TestApply_KeepsSigningServicesOutsideThePatch(t *testing.T) {
	r := setupApplyRepo(t)
	// Re-running the flag-based command on the same Fulcio certificate with
	// another issuer moves the CA window to now and publishes the new issuer
	// with it; the first issuer keeps its older window, matching no target.
	time.Sleep(1100 * time.Millisecond)
	if err := Run(&Options{RootPath: r.rootPath, OutDir: r.outDir, KeyPaths: []string{r.keyPath}, Operator: "rhtas",
		FulcioTarget: filepath.Join(r.dir, "fulcio.crt.pem"), FulcioURI: "https://fulcio.example.com",
		OIDCURIs: []string{"https://second.example.com"}}); err != nil {
		t.Fatal(err)
	}
	oidcURLs := func() []string {
		var urls []string
		for _, s := range publishedTrustBundle(t, r.outDir).SigningConfig.OidcUrls {
			urls = append(urls, s.Url)
		}
		return urls
	}
	before := oidcURLs()
	if len(before) != 2 {
		t.Fatalf("setup: oidc services = %v", before)
	}

	if _, err := r.apply(t, `{"op":"replace","path":"/components/rekor/rekor-2.pub/uri","value":"https://rekor2.example.com"}`); err != nil {
		t.Fatal(err)
	}
	if after := oidcURLs(); strings.Join(after, ",") != strings.Join(before, ",") {
		t.Fatalf("a Rekor-only patch changed the OIDC services: %v -> %v", before, after)
	}
	var rekor []string
	for _, s := range publishedTrustBundle(t, r.outDir).SigningConfig.RekorTlogUrls {
		rekor = append(rekor, s.Url)
	}
	if strings.Join(rekor, ",") != "https://rekor2.example.com" {
		t.Fatalf("rekor services = %v", rekor)
	}
}

func rekorServiceURLs(t *testing.T, outDir string) []string {
	t.Helper()
	var urls []string
	for _, s := range publishedTrustBundle(t, outDir).SigningConfig.RekorTlogUrls {
		urls = append(urls, s.Url)
	}
	return urls
}

func TestApply_RemovingLegacyRotatedTargetDropsItsService(t *testing.T) {
	r := setupApplyRepo(t)
	// Flag-based rotation to another URL: the old key's window is closed in
	// trusted_root.json, but its signing service stays open.
	time.Sleep(1100 * time.Millisecond)
	if err := Run(&Options{RootPath: r.rootPath, OutDir: r.outDir, KeyPaths: []string{r.keyPath}, Operator: "rhtas",
		RekorTarget: generateTestPublicKey(t, r.dir, "rekor-b.pub"), RekorURI: "https://rekor-b.example.com"}); err != nil {
		t.Fatal(err)
	}
	if got := rekorServiceURLs(t, r.outDir); strings.Join(got, ",") != "https://rekor.example.com,https://rekor-b.example.com" {
		t.Fatalf("setup: rekor services = %v", got)
	}

	if _, err := r.apply(t, `{"op":"remove","path":"/components/rekor/rekor-2.pub"}`); err != nil {
		t.Fatal(err)
	}
	if got := rekorServiceURLs(t, r.outDir); strings.Join(got, ",") != "https://rekor-b.example.com" {
		t.Fatalf("service of the removed key's URL still published: %v", got)
	}
}

func TestApply_RemovingTargetAfterScheduledCutoffDropsItsService(t *testing.T) {
	r := setupApplyRepo(t)
	cutoff := time.Now().UTC().Add(2 * time.Second).Truncate(time.Second)
	value := targetValue(t, document.Target{URI: "https://rekor-b.example.com", ValidFor: document.ValidFor{Start: &cutoff},
		Material: string(mustRead(t, generateTestPublicKey(t, r.dir, "rekor-b.pub")))})
	if _, err := r.apply(t,
		fmt.Sprintf(`{"op":"replace","path":"/components/rekor/rekor-2.pub/validFor/end","value":%q}`, cutoff.Format(time.RFC3339)),
		`{"op":"add","path":"/components/rekor/rekor-b.pub","value":`+value+`}`); err != nil {
		t.Fatal(err)
	}
	if got := rekorServiceURLs(t, r.outDir); len(got) != 2 {
		t.Fatalf("before the cutoff both keys are services: %v", got)
	}
	time.Sleep(time.Until(cutoff) + 100*time.Millisecond)

	if _, err := r.apply(t, `{"op":"remove","path":"/components/rekor/rekor-2.pub"}`); err != nil {
		t.Fatal(err)
	}
	if got := rekorServiceURLs(t, r.outDir); strings.Join(got, ",") != "https://rekor-b.example.com" {
		t.Fatalf("ended service of the removed key still published: %v", got)
	}
}

func TestApply_KeepsDefaultOperatorForExistingServices(t *testing.T) {
	dir, rootPath, outDir := setupTestRepo(t)
	r := &applyRepo{rootPath: rootPath, outDir: outDir, keyPath: filepath.Join(dir, "key.pem")}
	if err := Run(&Options{RootPath: rootPath, OutDir: outDir, KeyPaths: []string{r.keyPath},
		FulcioTarget: generateTestCert(t, dir, "fulcio.crt.pem"), FulcioURI: "https://fulcio.example.com",
		OIDCURIs: []string{"https://oidc.example.com"}}); err != nil {
		t.Fatal(err)
	}
	re := r.load(t)
	re.TrustBundle.TrustedRoot.CertificateAuthorities[0].Operator = ""
	path := filepath.Join(r.outDir, "targets", "trusted_root.json")
	if err := re.TrustBundle.SaveTrustedRoot(path); err != nil {
		t.Fatal(err)
	}
	if err := addTrustBundleTargets(re, path, "", "sha256"); err != nil {
		t.Fatal(err)
	}
	re.BumpTargetsVersion()
	re.BumpSnapshotVersion()
	re.BumpTimestampVersion()
	if err := re.SignAndWrite(editor.SignAndWriteOptions{KeyPaths: []string{r.keyPath}, OutDir: r.outDir, HashAlgo: "sha256"}); err != nil {
		t.Fatal(err)
	}

	// r.apply sets a custom operator. It applies only to new entries.
	if _, err := r.apply(t, `{"op":"replace","path":"/components/fulcio/fulcio.crt.pem/uri","value":"https://new-fulcio.example.com"}`); err != nil {
		t.Fatal(err)
	}
	bundle := publishedTrustBundle(t, r.outDir)
	if bundle.TrustedRoot.CertificateAuthorities[0].Operator != "" {
		t.Fatal("existing trusted-root operator changed")
	}
	ca := bundle.SigningConfig.GetCaUrls()
	if len(ca) != 1 || ca[0].Url != "https://new-fulcio.example.com" || ca[0].Operator != "sigstore.dev" {
		t.Fatalf("unexpected Fulcio services: %v", ca)
	}
	oidc := bundle.SigningConfig.GetOidcUrls()
	if len(oidc) != 1 || oidc[0].Url != "https://oidc.example.com" || oidc[0].Operator != "sigstore.dev" {
		t.Fatalf("unexpected OIDC services: %v", oidc)
	}
}

func TestApply_KeepsConfiguredServiceAPIVersion(t *testing.T) {
	r := setupApplyRepo(t)
	// Mark the published Rekor service as API v2, as
	// `tufcli signing-config add-url --api-version 2` would.
	r.publishSigningConfig(t, func(sc *trustrootpb.SigningConfig) {
		for _, s := range sc.RekorTlogUrls {
			s.MajorApiVersion = 2
		}
	})

	end := time.Now().UTC().Add(5 * 24 * time.Hour).Truncate(time.Second)
	if _, err := r.apply(t, fmt.Sprintf(`{"op":"replace","path":"/components/rekor/rekor-2.pub/validFor/end","value":%q}`, end.Format(time.RFC3339))); err != nil {
		t.Fatal(err)
	}
	services := publishedTrustBundle(t, r.outDir).SigningConfig.RekorTlogUrls
	if len(services) != 1 || services[0].MajorApiVersion != 2 || services[0].ValidFor.End == nil {
		t.Fatalf("rekor services after a window-only patch = %v", services)
	}
	if _, err := root.NewSigningConfigFromJSON(mustRead(t, publishedTargetPath(t, r.outDir, "signing_config.v0.2.json"))); err != nil {
		t.Fatal(err)
	}
	// A new key at a new URL has no configured version: v1.
	value := targetValue(t, document.Target{URI: "https://rekor-new.example.com", ValidFor: document.ValidFor{Start: &end},
		Material: string(mustRead(t, generateTestPublicKey(t, r.dir, "rekor-new.pub")))})
	if _, err := r.apply(t, `{"op":"add","path":"/components/rekor/rekor-new.pub","value":`+value+`}`); err != nil {
		t.Fatal(err)
	}
	for _, s := range publishedTrustBundle(t, r.outDir).SigningConfig.RekorTlogUrls {
		if want := map[string]uint32{"https://rekor.example.com": 2, "https://rekor-new.example.com": 1}[s.Url]; s.MajorApiVersion != want {
			t.Fatalf("%s: API version %d, want %d", s.Url, s.MajorApiVersion, want)
		}
	}
}

func TestClassifyError(t *testing.T) {
	for err, reason := range map[error]string{
		editor.ErrNotConsistentSnapshot:                     ReasonNotConsistentSnapshot,
		fmt.Errorf("x: %w", editor.ErrLiveTimestampChanged): ReasonConcurrentUpdate,
		fmt.Errorf("x: %w", editor.ErrRollback):             ReasonRollback,
		fmt.Errorf("%w: y", ErrInconsistentRepository):      ReasonInconsistentRepository,
		errors.New("boom"):                                  ReasonFailed,
	} {
		if got := ClassifyError(err); got.Reason != reason || got.Message != err.Error() {
			t.Errorf("%v: got %+v, want %s", err, got, reason)
		}
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
