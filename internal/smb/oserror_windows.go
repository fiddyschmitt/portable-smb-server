package smb

import (
	"errors"
	"syscall"
)

// Windows error codes that are not surfaced through the portable os sentinels.
const (
	errnoWriteProtect     syscall.Errno = 19  // ERROR_WRITE_PROTECT
	errnoSharingViolation syscall.Errno = 32  // ERROR_SHARING_VIOLATION
	errnoLockViolation    syscall.Errno = 33  // ERROR_LOCK_VIOLATION
	errnoDirNotEmpty      syscall.Errno = 145 // ERROR_DIR_NOT_EMPTY
)

// osErrorStatus maps OS-specific errors (that errors.Is against the portable os
// sentinels misses) to an NTSTATUS. A file another process holds open is the
// common one when serving a live Windows volume.
func osErrorStatus(err error) (uint32, bool) {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case errnoSharingViolation, errnoLockViolation:
			return statusSharingViolation, true
		case errnoDirNotEmpty:
			return statusDirectoryNotEmpty, true
		case errnoWriteProtect:
			return statusMediaWriteProtected, true
		}
	}
	return 0, false
}
