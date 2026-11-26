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

// retryableRenameError: on Unix a rename onto a file that is open elsewhere
// just works, so a failure is never worth retrying.
func retryableRenameError(error) bool { return false }
