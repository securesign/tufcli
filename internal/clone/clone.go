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
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"

	"github.com/securesign/tufcli/internal/tufclient"
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
	Output            io.Writer
}

// Run executes the clone command.
func Run(opts *Options) error {
	output := utils.SafeWriter(opts.Output)

	if _, err := os.Stat(opts.MetadataDir); err == nil {
		return fmt.Errorf("metadata directory %q already exists", opts.MetadataDir)
	}
	if !opts.MetadataOnly && opts.TargetsDir != "" {
		if _, err := os.Stat(opts.TargetsDir); err == nil {
			return fmt.Errorf("targets directory %q already exists", opts.TargetsDir)
		}
	}

	rootBytes, err := tufclient.ObtainRoot(opts.Root, opts.AllowRootDownload, opts.MetadataURL, opts.RootVersion, output)
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
	cfg.Fetcher = tufclient.NewLocalFetcher(cfg.Fetcher)

	up, err := updater.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create TUF updater: %w", err)
	}

	if opts.AllowExpiredRepo {
		fmt.Fprintf(output, "=================================================================\n")
		fmt.Fprintf(output, "WARNING: AllowExpiredRepo is set; this is unsafe and\n")
		fmt.Fprintf(output, "will not establish trust, use only for testing!\n")
		fmt.Fprintf(output, "=================================================================\n")
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

	fmt.Fprintf(output, "Cloned repository metadata to %q\n", opts.MetadataDir)

	if opts.MetadataOnly {
		return nil
	}

	targets, err := tufclient.ResolveTargets(up, opts.TargetNames)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(opts.TargetsDir, 0755); err != nil {
		return fmt.Errorf("failed to create targets directory: %w", err)
	}

	fmt.Fprintf(output, "Downloading targets to %q\n", opts.TargetsDir)
	for name, tf := range targets {
		fmt.Fprintf(output, "\t-> %s\n", name)
		destPath := filepath.Join(opts.TargetsDir, name)

		if err := tufclient.ValidateTargetPath(opts.TargetsDir, destPath); err != nil {
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
