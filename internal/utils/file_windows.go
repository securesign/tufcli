package utils

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

func syncDir(_ string) error {
	return nil
}

// retryableRenameError reports the failures Windows gives when the target of a
// rename is open in another process without FILE_SHARE_DELETE; they clear when
// that reader closes the file.
func retryableRenameError(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	return errno == windows.ERROR_ACCESS_DENIED || errno == windows.ERROR_SHARING_VIOLATION
}
