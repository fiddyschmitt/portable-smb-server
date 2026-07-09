//go:build windows

package localfs

import (
	"os"
	"syscall"
)

// openOSFile opens path like os.OpenFile but with FILE_SHARE_DELETE in the
// share mode. SMB rename and delete requests arrive while our own handle to
// the file is still open; without FILE_SHARE_DELETE that handle would make
// os.Rename/os.Remove fail with ERROR_SHARING_VIOLATION.
func openOSFile(path string, flag int, perm os.FileMode) (*os.File, error) {
	pathp, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}

	var access uint32
	switch flag & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR) {
	case os.O_RDONLY:
		access = syscall.GENERIC_READ
	case os.O_WRONLY:
		access = syscall.GENERIC_WRITE
	case os.O_RDWR:
		access = syscall.GENERIC_READ | syscall.GENERIC_WRITE
	}
	if flag&os.O_TRUNC != 0 {
		access |= syscall.GENERIC_WRITE
	}
	if flag&os.O_APPEND != 0 {
		// The SMB layer writes at explicit offsets and never passes
		// O_APPEND, but map it faithfully anyway.
		access &^= syscall.GENERIC_WRITE
		access |= FILE_APPEND_DATA
	}

	shareMode := uint32(syscall.FILE_SHARE_READ | syscall.FILE_SHARE_WRITE | syscall.FILE_SHARE_DELETE)

	var disposition uint32
	switch {
	case flag&(os.O_CREATE|os.O_EXCL) == os.O_CREATE|os.O_EXCL:
		disposition = syscall.CREATE_NEW
	case flag&(os.O_CREATE|os.O_TRUNC) == os.O_CREATE|os.O_TRUNC:
		disposition = syscall.CREATE_ALWAYS
	case flag&os.O_CREATE == os.O_CREATE:
		disposition = syscall.OPEN_ALWAYS
	case flag&os.O_TRUNC == os.O_TRUNC:
		disposition = syscall.TRUNCATE_EXISTING
	default:
		disposition = syscall.OPEN_EXISTING
	}

	attrs := uint32(syscall.FILE_ATTRIBUTE_NORMAL)
	if perm&0o200 == 0 {
		attrs = syscall.FILE_ATTRIBUTE_READONLY
	}

	h, err := syscall.CreateFile(pathp, access, shareMode, nil, disposition, attrs, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}

const FILE_APPEND_DATA = 0x0004
