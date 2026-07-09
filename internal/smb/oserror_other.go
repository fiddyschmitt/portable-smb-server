//go:build !windows

package smb

import (
	"errors"
	"syscall"
)

// osErrorStatus maps OS-specific errors (that errors.Is against the portable os
// sentinels misses) to an NTSTATUS.
func osErrorStatus(err error) (uint32, bool) {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.ENOTEMPTY:
			return statusDirectoryNotEmpty, true
		case syscall.EROFS:
			return statusMediaWriteProtected, true
		case syscall.ENOSYS:
			return statusNotSupported, true
		}
	}
	return 0, false
}
