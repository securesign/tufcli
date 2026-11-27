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
package refresh

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/securesign/tufcli/internal/editor"
	"github.com/securesign/tufcli/internal/keys"
	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"
)

func createRepository(t *testing.T, expiry time.Time) (Options, map[string]string) {
	t.Helper()
	dir := t.TempDir()
	opts := Options{
		OutDir: dir, RootPath: filepath.Join(dir, "root.json"),
		ExpirationPolicy: 96 * time.Hour, RefreshInterval: 72 * time.Hour, Output: io.Discard,
	}
	root := tufmeta.Root(time.Now().AddDate(1, 0, 0))
	roleKeys := make(map[string]string)
	var online []string
	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		mustSucceed(t, err)
		der, err := x509.MarshalECPrivateKey(key)
		mustSucceed(t, err)
		path := filepath.Join(t.TempDir(), role+".pem")
		mustSucceed(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600))
		roleKeys[role] = path
		_, pub, keyID, err := keys.LoadSigner(path, nil)
		mustSucceed(t, err)
		root.Signed.Keys[keyID] = pub
		root.Signed.Roles[role] = &tufmeta.Role{KeyIDs: []string{keyID}, Threshold: 1}
		if role != "root" {
			online = append(online, path)
		}
	}
	rootSigners, err := keys.LoadSignerSet([]string{roleKeys["root"]}, nil)
	mustSucceed(t, err)
	mustSucceed(t, keys.SignForRole(rootSigners, root, "root", root.Signed.Roles["root"].KeyIDs, 1))
	mustSucceed(t, rootSigners.Close())
	mustSucceed(t, root.ToFile(opts.RootPath, false))
	ed, err := editor.LoadRepository(editor.LoadOptions{RootPath: opts.RootPath, OutDir: opts.OutDir})
	mustSucceed(t, err)
	ed.SetTargetsExpires(expiry)
	ed.SetSnapshotExpires(expiry)
	ed.SetTimestampExpires(expiry)
	mustSucceed(t, ed.SignAndWrite(editor.SignAndWriteOptions{KeyPaths: online, HashAlgo: "sha512", OutDir: opts.OutDir}))
	return opts, roleKeys
}

func TestRefreshChecksSuppliedRootAgainstPublishedRoot(t *testing.T) {
	opts, keyPaths := createRepository(t, time.Now().Add(time.Hour))
	opts.Role = "timestamp"
	opts.KeyPaths = []string{keyPaths["timestamp"]}

	published := &tufmeta.Metadata[tufmeta.RootType]{}
	_, err := published.FromFile(opts.RootPath)
	mustSucceed(t, err)
	externalPath := filepath.Join(t.TempDir(), "root.json")
	opts.RootPath = externalPath

	// A root from another initialized repository has the same version and
	// different role keys. It must fail the match before signing or publishing.
	other, _ := createRepository(t, time.Now().Add(time.Hour))
	alternate := &tufmeta.Metadata[tufmeta.RootType]{}
	_, err = alternate.FromFile(other.RootPath)
	mustSucceed(t, err)
	assertEqual(t, published.Signed.Version, alternate.Signed.Version)
	mustSucceed(t, alternate.ToFile(externalPath, true))
	_, err = Run(opts)
	if !errors.Is(err, editor.ErrInconsistentRepository) || !strings.Contains(err.Error(), "differs from published root") {
		t.Fatalf("expected a root mismatch error, got %v", err)
	}
	live, err := editor.LoadLiveRepository(filepath.Join(opts.OutDir, "root.json"), opts.OutDir, io.Discard)
	mustSucceed(t, err)
	assertEqual(t, int64(1), live.Timestamp().Signed.Version)

	// A differently formatted copy of the published root is valid.
	mustSucceed(t, published.ToFile(externalPath, true))
	result, err := Run(opts)
	mustSucceed(t, err)
	assertEqual(t, ResultRefreshed, result.Result)
}

func TestRefreshRejectsUnresolvableRootPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows normalizes path traversal before resolving components")
	}
	opts, keyPaths := createRepository(t, time.Now().Add(time.Hour))
	opts.Role = "timestamp"
	opts.KeyPaths = []string{keyPaths["timestamp"]}
	sep := string(os.PathSeparator)
	opts.RootPath = opts.OutDir + sep + "missing" + sep + ".." + sep + "root.json"

	_, err := Run(opts)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected the supplied path to fail resolution, got %v", err)
	}
}

func TestRefreshRoleChain(t *testing.T) {
	for _, role := range []string{"timestamp", "snapshot", "targets"} {
		t.Run(role, func(t *testing.T) {
			expiry := time.Now().UTC().Add(time.Hour)
			opts, keyPaths := createRepository(t, expiry)
			opts.Role = role
			opts.KeyPaths = []string{keyPaths["timestamp"]}
			if role != "timestamp" {
				opts.KeyPaths = append(opts.KeyPaths, keyPaths["snapshot"])
			}
			if role == "targets" {
				opts.KeyPaths = append(opts.KeyPaths, keyPaths["targets"])
			}

			result, err := Run(opts)
			mustSucceed(t, err)
			assertEqual(t, ResultRefreshed, result.Result)
			assertEqual(t, role, result.Role)
			live, err := editor.LoadLiveRepository(opts.RootPath, opts.OutDir, io.Discard)
			mustSucceed(t, err)
			assertEqual(t, int64(2), live.Timestamp().Signed.Version)
			assertEqual(t, int64(2), result.Timestamp.Version)
			if live.Timestamp().Signed.Meta["snapshot.json"].Hashes["sha512"] == nil ||
				live.Snapshot().Signed.Meta["targets.json"].Hashes["sha512"] == nil {
				t.Fatal("refresh dropped the existing SHA-512 metadata references")
			}
			if role != "timestamp" {
				assertEqual(t, int64(2), live.Snapshot().Signed.Version)
				assertEqual(t, int64(2), result.Snapshot.Version)
				assertEqual(t, expiry, live.Timestamp().Signed.Expires)
			} else {
				assertEqual(t, int64(1), live.Snapshot().Signed.Version)
				assertEqual(t, (*RoleResult)(nil), result.Snapshot)
			}
			if role == "targets" {
				assertEqual(t, int64(2), live.Targets().Signed.Version)
				assertEqual(t, int64(2), result.Targets.Version)
				assertEqual(t, expiry, live.Snapshot().Signed.Expires)
			} else {
				assertEqual(t, int64(1), live.Targets().Signed.Version)
				assertEqual(t, (*RoleResult)(nil), result.Targets)
			}

			opts.KeyPaths = nil
			again, err := Run(opts)
			mustSucceed(t, err)
			assertEqual(t, ResultNotDue, again.Result)
			assertEqual(t, *map[string]*RoleResult{"targets": result.Targets, "snapshot": result.Snapshot, "timestamp": result.Timestamp}[role],
				*map[string]*RoleResult{"targets": again.Targets, "snapshot": again.Snapshot, "timestamp": again.Timestamp}[role])
		})
	}
}

func TestRefreshExpiredRepository(t *testing.T) {
	opts, keyPaths := createRepository(t, time.Now().Add(-time.Hour))
	opts.Role = "targets"
	opts.KeyPaths = []string{keyPaths["targets"], keyPaths["snapshot"], keyPaths["timestamp"]}
	_, err := Run(opts)
	if !errors.Is(err, editor.ErrExpiredRepository) {
		t.Fatalf("expected expired repository error, got %v", err)
	}

	opts.AllowExpiredRepo = true
	opts.SnapshotPolicy = 48 * time.Hour
	opts.TimestampPolicy = 24 * time.Hour
	result, err := Run(opts)
	mustSucceed(t, err)
	assertEqual(t, ResultRefreshed, result.Result)
	assertEqual(t, 48*time.Hour, result.Targets.Expires.Sub(result.Snapshot.Expires))
	assertEqual(t, 24*time.Hour, result.Snapshot.Expires.Sub(result.Timestamp.Expires))
	live, err := editor.LoadLiveRepository(opts.RootPath, opts.OutDir, io.Discard)
	mustSucceed(t, err)
	mustSucceed(t, live.CheckExpiration(false))
}

func TestRefreshReportsOnlineRolesStillExpired(t *testing.T) {
	opts, keyPaths := createRepository(t, time.Now().Add(-time.Hour))
	opts.AllowExpiredRepo = true
	for _, tc := range []struct {
		role    string
		keys    []string
		expired []string
	}{
		{"timestamp", []string{keyPaths["timestamp"]}, []string{"targets", "snapshot"}},
		{"snapshot", []string{keyPaths["snapshot"], keyPaths["timestamp"]}, []string{"targets"}},
		{"targets", []string{keyPaths["targets"], keyPaths["snapshot"], keyPaths["timestamp"]}, nil},
	} {
		t.Run(tc.role, func(t *testing.T) {
			opts.Role = tc.role
			opts.KeyPaths = tc.keys
			result, err := Run(opts)
			mustSucceed(t, err)
			assertEqual(t, ResultRefreshed, result.Result)
			if !slices.Equal(tc.expired, result.ExpiredRoles) {
				t.Fatalf("Refreshed expiredRoles = %v, want %v", result.ExpiredRoles, tc.expired)
			}
			opts.KeyPaths = nil
			result, err = Run(opts)
			mustSucceed(t, err)
			assertEqual(t, ResultNotDue, result.Result)
			if !slices.Equal(tc.expired, result.ExpiredRoles) {
				t.Fatalf("NotDue expiredRoles = %v, want %v", result.ExpiredRoles, tc.expired)
			}
		})
	}
}

func TestRefreshRejectsWrongSignerWithoutPublication(t *testing.T) {
	opts, keyPaths := createRepository(t, time.Now().Add(time.Hour))
	opts.Role = "snapshot"
	opts.KeyPaths = []string{keyPaths["snapshot"]}
	_, err := Run(opts)
	if err == nil {
		t.Fatal("expected a signer error")
	}
	assertEqual(t, "SignerNotAuthorized", Failure(opts.Role, err).Error.Reason)
	assertEqual(t, "timestamp", Failure(opts.Role, err).Error.Role)
	if _, err := os.Stat(filepath.Join(opts.OutDir, "2.snapshot.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("snapshot was staged before detecting signer error: %v", err)
	}
	live, err := editor.LoadLiveRepository(opts.RootPath, opts.OutDir, io.Discard)
	mustSucceed(t, err)
	assertEqual(t, int64(1), live.Timestamp().Signed.Version)
}

func TestRefreshUsesLiveChainAndSerializesRetries(t *testing.T) {
	opts, keyPaths := createRepository(t, time.Now().Add(time.Hour))
	opts.Role = "snapshot"
	opts.KeyPaths = []string{keyPaths["snapshot"], keyPaths["timestamp"]}
	orphan := filepath.Join(opts.OutDir, "99.snapshot.json")
	mustSucceed(t, os.WriteFile(orphan, []byte("abandoned publication"), 0o600))

	type runResult struct {
		result Result
		err    error
	}
	runs := make(chan runResult, 2)
	for range 2 {
		go func() {
			result, err := Run(opts)
			runs <- runResult{result, err}
		}()
	}
	outcomes := map[string]int{}
	for range 2 {
		run := <-runs
		mustSucceed(t, run.err)
		outcomes[run.result.Result]++
		assertEqual(t, int64(2), run.result.Snapshot.Version)
	}
	assertEqual(t, 1, outcomes[ResultRefreshed])
	assertEqual(t, 1, outcomes[ResultNotDue])

	mustSucceed(t, os.Remove(filepath.Join(opts.OutDir, "2.snapshot.json")))
	_, err := Run(opts)
	if !errors.Is(err, editor.ErrInconsistentRepository) {
		t.Fatalf("expected a broken live chain error, got %v", err)
	}
}

func TestDue(t *testing.T) {
	now := time.Date(2026, time.November, 27, 12, 0, 0, 0, time.UTC)
	policy, interval := 96*time.Hour, 72*time.Hour
	assertEqual(t, true, due(now.Add(23*time.Hour), now, policy, interval))
	assertEqual(t, false, due(now.Add(24*time.Hour), now, policy, interval))
	assertEqual(t, false, due(now.Add(policy), now, policy, interval))
	assertEqual(t, true, due(now.Add(policy+time.Second), now, policy, interval))
}

func mustSucceed(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func assertEqual[T comparable](t *testing.T, want, got T) {
	t.Helper()
	if want != got {
		t.Fatalf("want %v, got %v", want, got)
	}
}
