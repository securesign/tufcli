//go:build !windows

package utils

import "os"

func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	err = d.Sync()
	d.Close()
	return err
}
