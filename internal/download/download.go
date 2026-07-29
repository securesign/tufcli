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

package download

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"

	"github.com/securesign/tufcli/internal/tufclient"
	"github.com/securesign/tufcli/internal/utils"
)

type Options struct {
	Root              string
	MetadataURL       string
	TargetsURL        string
	OutDir            string
	TargetNames       []string
	RootVersion       int64
	AllowExpiredRepo  bool
	AllowRootDownload bool
}

func Run(opts *Options) error {
	if _, err := os.Stat(opts.OutDir); err == nil {
		return fmt.Errorf("output directory %q already exists", opts.OutDir)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to check output directory %q: %w", opts.OutDir, err)
	}

	rootBytes, err := tufclient.ObtainRoot(opts.Root, opts.AllowRootDownload, opts.MetadataURL, opts.RootVersion)
	if err != nil {
		return err
	}

	metadataURL := strings.TrimRight(opts.MetadataURL, "/")
	targetsURL := strings.TrimRight(opts.TargetsURL, "/")

	tmpDir, err := os.MkdirTemp("", "tufcli-download-*")
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
		fmt.Fprintf(os.Stderr, "=================================================================\n")
		fmt.Fprintf(os.Stderr, "Downloading repo to %s\n", opts.OutDir)
		fmt.Fprintf(os.Stderr, "WARNING: --allow-expired-repo was passed; this is unsafe and\n")
		fmt.Fprintf(os.Stderr, "will not establish trust, use only for testing!\n")
		fmt.Fprintf(os.Stderr, "=================================================================\n")
		up.UnsafeSetRefTime(time.Time{})
	}

	if err := up.Refresh(); err != nil {
		return fmt.Errorf("failed to refresh TUF metadata: %w", err)
	}

	targets, err := tufclient.ResolveTargets(up, opts.TargetNames)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(opts.OutDir), 0755); err != nil {
		return fmt.Errorf("failed to create parent directory: %w", err)
	}
	if err := os.Mkdir(opts.OutDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Downloading targets to %q\n", opts.OutDir)
	for name, tf := range targets {
		fmt.Fprintf(os.Stderr, "\t-> %s\n", name)
		destPath := filepath.Join(opts.OutDir, name)

		if err := tufclient.ValidateTargetPath(opts.OutDir, destPath); err != nil {
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
