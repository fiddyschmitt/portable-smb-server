// Package fsx defines the filesystem interface the SMB server serves. It sits
// between the protocol code (internal/smb) and the backend (internal/localfs)
// so neither has to import the other.
package fsx

import (
	"io"
	"os"
	"time"
)

// FileSystem is the filesystem behind one share. Paths are share-relative,
// forward-slash separated, with no leading slash; "" is the share root.
type FileSystem interface {
	Stat(path string) (os.FileInfo, error)
	OpenFile(path string, flag int, perm os.FileMode) (File, error)
	Mkdir(path string, perm os.FileMode) error
	ReadDir(path string) ([]os.FileInfo, error)
	Rename(oldPath, newPath string) error
	Remove(path string) error // file or empty directory
	Truncate(path string, size int64) error
	Chtimes(path string, mtime time.Time) error
	Statfs() (total, free int64, err error)
	CaseInsensitive() bool
}

// File is one open file handle. *os.File satisfies File.
type File interface {
	io.ReaderAt
	io.WriterAt
	io.Closer
	Truncate(size int64) error
	Sync() error
	Stat() (os.FileInfo, error)
}
