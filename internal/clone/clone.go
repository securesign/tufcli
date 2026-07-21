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

package clone

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"

	"github.com/securesign/tufcli/internal/utils"
)

// Options contains all configuration for a clone operation.
type Options struct {
	Root              string
	MetadataURL       string
	TargetsURL        string
	MetadataDir       string
	TargetsDir        string
	TargetNames       []string
	RootVersion       int64
	MetadataOnly      bool
	AllowExpiredRepo  bool
	AllowRootDownload bool
}

// Run executes the clone command.
func Run(opts *Options) error {
	rootBytes, err := obtainRoot(opts)
	if err != nil {
		return err
	}

	metadataURL := strings.TrimRight(opts.MetadataURL, "/")

	targetsURL := metadataURL
	if opts.TargetsURL != "" {
		targetsURL = strings.TrimRight(opts.TargetsURL, "/")
	}

	tmpDir, err := os.MkdirTemp("", "tufcli-clone-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg, err := config.New(metadataURL, rootBytes)
	if err != nil {
		return fmt.Errorf("failed to create updater config: %w", err)
	}
	cfg.LocalMetadataDir = tmpDir
	cfg.LocalTargetsDir = filepath.Join(tmpDir, "targets")
	cfg.RemoteTargetsURL = targetsURL
	cfg.PrefixTargetsWithHash = true
	cfg.DisableLocalCache = true
	cfg.Fetcher = &localFetcher{httpFetcher: cfg.Fetcher}

	up, err := updater.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create TUF updater: %w", err)
	}

	if opts.AllowExpiredRepo {
		fmt.Fprintf(os.Stderr, "=================================================================\n")
		fmt.Fprintf(os.Stderr, "WARNING: --allow-expired-repo was passed; this is unsafe and\n")
		fmt.Fprintf(os.Stderr, "will not establish trust, use only for testing!\n")
		fmt.Fprintf(os.Stderr, "=================================================================\n")
		up.UnsafeSetRefTime(time.Time{})
	}

	if err := up.Refresh(); err != nil {
		return fmt.Errorf("failed to refresh TUF metadata: %w", err)
	}

	if err := os.MkdirAll(opts.MetadataDir, 0755); err != nil {
		return fmt.Errorf("failed to create metadata directory: %w", err)
	}

	if err := cacheMetadata(up, opts.MetadataDir); err != nil {
		return fmt.Errorf("failed to cache metadata: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Cloned repository metadata to %q\n", opts.MetadataDir)

	if opts.MetadataOnly {
		return nil
	}

	targets, err := resolveTargets(up, opts.TargetNames)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(opts.TargetsDir, 0755); err != nil {
		return fmt.Errorf("failed to create targets directory: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Downloading targets to %q\n", opts.TargetsDir)
	for name, tf := range targets {
		fmt.Fprintf(os.Stderr, "\t-> %s\n", name)
		destPath := filepath.Join(opts.TargetsDir, name)

		if err := validateTargetPath(opts.TargetsDir, destPath); err != nil {
			return err
		}

		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return fmt.Errorf("failed to create directory for target %q: %w", name, err)
		}

		_, data, err := up.DownloadTarget(tf, destPath, "")
		if err != nil {
			return fmt.Errorf("failed to download target %q: %w", name, err)
		}

		if err := utils.WriteFileAtomic(destPath, data); err != nil {
			return fmt.Errorf("failed to write target %q: %w", name, err)
		}
	}

	return nil
}

// cacheMetadata serializes the verified metadata from the updater and writes
// both versioned and unversioned copies to the output directory.
func cacheMetadata(up *updater.Updater, metadataDir string) error {
	trusted := up.GetTrustedMetadataSet()

	// root.json — versioned + unversioned
	rootData, err := trusted.Root.ToBytes(false)
	if err != nil {
		return fmt.Errorf("failed to serialize root.json: %w", err)
	}
	if err := utils.WriteFileAtomic(filepath.Join(metadataDir, "root.json"), rootData); err != nil {
		return err
	}
	if err := utils.WriteFileAtomic(filepath.Join(metadataDir, fmt.Sprintf("%d.root.json", trusted.Root.Signed.Version)), rootData); err != nil {
		return err
	}

	// timestamp.json — unversioned only (per TUF spec)
	timestampData, err := trusted.Timestamp.ToBytes(false)
	if err != nil {
		return fmt.Errorf("failed to serialize timestamp.json: %w", err)
	}
	if err := utils.WriteFileAtomic(filepath.Join(metadataDir, "timestamp.json"), timestampData); err != nil {
		return err
	}

	// snapshot.json — versioned
	snapshotData, err := trusted.Snapshot.ToBytes(false)
	if err != nil {
		return fmt.Errorf("failed to serialize snapshot.json: %w", err)
	}
	if err := utils.WriteFileAtomic(filepath.Join(metadataDir, fmt.Sprintf("%d.snapshot.json", trusted.Snapshot.Signed.Version)), snapshotData); err != nil {
		return err
	}

	// targets.json — versioned
	if topTargets, ok := trusted.Targets["targets"]; ok {
		targetsData, err := topTargets.ToBytes(false)
		if err != nil {
			return fmt.Errorf("failed to serialize targets.json: %w", err)
		}
		if err := utils.WriteFileAtomic(filepath.Join(metadataDir, fmt.Sprintf("%d.targets.json", topTargets.Signed.Version)), targetsData); err != nil {
			return err
		}
	}

	return nil
}

func obtainRoot(opts *Options) ([]byte, error) {
	if opts.Root != "" {
		data, err := os.ReadFile(opts.Root)
		if err != nil {
			return nil, fmt.Errorf("failed to read root.json from %s: %w", opts.Root, err)
		}
		return data, nil
	}

	if opts.AllowRootDownload {
		return downloadRoot(opts.MetadataURL, opts.RootVersion)
	}

	return nil, fmt.Errorf("no root.json available; provide --root or use --allow-root-download")
}

func downloadRoot(metadataURL string, version int64) ([]byte, error) {
	if version < 1 {
		return nil, fmt.Errorf("invalid root version %d (must be >= 1)", version)
	}
	metadataURL = strings.TrimRight(metadataURL, "/")
	rootURL := fmt.Sprintf("%s/%d.root.json", metadataURL, version)

	fmt.Fprintf(os.Stderr, "=================================================================\n")
	fmt.Fprintf(os.Stderr, "WARNING: Downloading root.json from %s\n", rootURL)
	fmt.Fprintf(os.Stderr, "This is unsafe and will not establish trust, use only for testing\n")
	fmt.Fprintf(os.Stderr, "=================================================================\n")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(rootURL) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("failed to download root.json: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download root.json: HTTP %d", resp.StatusCode)
	}

	const maxRootBytes = 10 << 20
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxRootBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read root.json response: %w", err)
	}
	if len(data) > maxRootBytes {
		return nil, fmt.Errorf("root.json response too large: exceeded %d bytes", maxRootBytes)
	}

	return data, nil
}

func resolveTargets(up *updater.Updater, names []string) (map[string]*metadata.TargetFiles, error) {
	if len(names) == 0 {
		targets := up.GetTopLevelTargets()
		if len(targets) == 0 {
			return nil, fmt.Errorf("no targets found in repository")
		}
		return targets, nil
	}

	targets := make(map[string]*metadata.TargetFiles, len(names))
	for _, name := range names {
		tf, err := up.GetTargetInfo(name)
		if err != nil {
			return nil, fmt.Errorf("target %q not found: %w", name, err)
		}
		targets[name] = tf
	}
	return targets, nil
}

func validateTargetPath(outDir, targetPath string) error {
	absOut, err := filepath.Abs(outDir)
	if err != nil {
		return fmt.Errorf("failed to resolve output directory: %w", err)
	}
	absTarget, err := filepath.Abs(targetPath)
	if err != nil {
		return fmt.Errorf("failed to resolve target path: %w", err)
	}
	rel, err := filepath.Rel(absOut, absTarget)
	if err != nil {
		return fmt.Errorf("failed to compute relative path: %w", err)
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("target path %q escapes output directory %q", targetPath, outDir)
	}
	return nil
}

// localFetcher wraps go-tuf's Fetcher to add file:// URL support.
type localFetcher struct {
	httpFetcher fetcher.Fetcher
}

func (f *localFetcher) DownloadFile(urlPath string, maxLength int64, timeout time.Duration) ([]byte, error) {
	u, err := url.Parse(urlPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL %q: %w", urlPath, err)
	}

	if u.Scheme != "file" {
		return f.httpFetcher.DownloadFile(urlPath, maxLength, timeout)
	}

	data, err := os.ReadFile(u.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, &metadata.ErrDownloadHTTP{StatusCode: http.StatusNotFound, URL: urlPath}
		}
		return nil, fmt.Errorf("failed to read %s: %w", u.Path, err)
	}

	if maxLength > 0 && int64(len(data)) > maxLength {
		return nil, fmt.Errorf("file %s is %d bytes, exceeds maximum %d", u.Path, len(data), maxLength)
	}

	return data, nil
}
