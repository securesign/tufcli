package targetscan

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"
)

// Target is a source file and its computed TUF metadata.
type Target struct {
	Path string
	Name string
	Meta *tufmeta.TargetFiles
}

// Scan discovers files below root and hashes them. Directory
// symlinks are followed when follow is true; visited directories are tracked
// by file identity to prevent symlink cycles.
func Scan(root string, follow bool, hashAlgo string) ([]Target, error) {
	paths, err := discover(root, follow)
	if err != nil {
		return nil, err
	}

	targets := make([]Target, 0, len(paths))
	for _, path := range paths {
		meta, err := tufmeta.TargetFile().FromFile(path.Path, hashAlgo)
		if err != nil {
			return nil, fmt.Errorf("failed to hash target %s: %w", path.Name, err)
		}
		targets = append(targets, Target{Path: path.Path, Name: path.Name, Meta: meta})
	}
	return targets, nil
}

type discovered struct {
	Path string
	Name string
}

func discover(root string, follow bool) ([]discovered, error) {
	rootInfo, err := os.Stat(root)
	if err != nil {
		return nil, err
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
					if err := walk(path, rel); err != nil {
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
				if err := walk(path, rel); err != nil {
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
