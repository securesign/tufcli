package targetscan

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"
)

// Target contains immutable staged bytes and metadata calculated from them.
type Target struct {
	Path string
	Name string
	Meta *tufmeta.TargetFiles
}

// Scan discovers files below root, copies each source into a private staging
// directory, and calculates metadata from the staged copy. cleanup removes
// the staging directory and is safe to call once.
func Scan(root string, follow bool, hashAlgo string) (targets []Target, cleanup func(), err error) {
	stageDir, err := os.MkdirTemp("", "tufcli-targets-")
	if err != nil {
		return nil, func() {}, fmt.Errorf("failed to create target staging directory: %w", err)
	}
	cleaned := false
	cleanup = func() {
		if !cleaned {
			cleaned = true
			_ = os.RemoveAll(stageDir)
		}
	}

	paths, err := discover(root, follow)
	if err != nil {
		cleanup()
		return nil, func() {}, err
	}

	for _, source := range paths {
		stagedPath := filepath.Join(stageDir, source.Name)
		if err := os.MkdirAll(filepath.Dir(stagedPath), 0755); err != nil {
			cleanup()
			return nil, func() {}, fmt.Errorf("failed to create staging directory for %s: %w", source.Name, err)
		}
		data, err := os.ReadFile(source.Path)
		if err != nil {
			cleanup()
			return nil, func() {}, fmt.Errorf("failed to read target %s: %w", source.Name, err)
		}
		if err := os.WriteFile(stagedPath, data, 0600); err != nil {
			cleanup()
			return nil, func() {}, fmt.Errorf("failed to stage target %s: %w", source.Name, err)
		}
		meta, err := tufmeta.TargetFile().FromFile(stagedPath, hashAlgo)
		if err != nil {
			cleanup()
			return nil, func() {}, fmt.Errorf("failed to hash target %s: %w", source.Name, err)
		}
		targets = append(targets, Target{Path: stagedPath, Name: source.Name, Meta: meta})
	}
	return targets, cleanup, nil
}

type discovered struct {
	Path string
	Name string
}

func discover(root string, follow bool) ([]discovered, error) {
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 {
		if !follow {
			return []discovered{}, nil
		}
		rootInfo, err = os.Stat(root)
		if err != nil {
			return nil, err
		}
	}
	if !rootInfo.IsDir() {
		return nil, fmt.Errorf("target root %s is not a directory", root)
	}

	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	visited := map[string]bool{rootReal: true}
	var out []discovered
	var walk func(string, string) error
	walk = func(dir, relDir string) error {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			path := filepath.Join(dir, entry.Name())
			rel := filepath.Join(relDir, entry.Name())
			if entry.Type()&fs.ModeSymlink != 0 {
				if !follow {
					continue
				}
				info, err := os.Stat(path)
				if err != nil {
					return fmt.Errorf("failed to resolve symlink %s: %w", path, err)
				}
				if info.IsDir() {
					id, err := filepath.EvalSymlinks(path)
					if err != nil {
						return err
					}
					if visited[id] {
						continue
					}
					visited[id] = true
					err = walk(path, rel)
					delete(visited, id)
					if err != nil {
						return err
					}
					continue
				}
				out = append(out, discovered{Path: path, Name: rel})
				continue
			}
			if entry.IsDir() {
				id, err := filepath.EvalSymlinks(path)
				if err != nil {
					return err
				}
				if visited[id] {
					continue
				}
				visited[id] = true
				err = walk(path, rel)
				delete(visited, id)
				if err != nil {
					return err
				}
				continue
			}
			out = append(out, discovered{Path: path, Name: rel})
		}
		return nil
	}
	if err := walk(root, ""); err != nil {
		return nil, err
	}
	return out, nil
}
