// Package localfs exposes a directory on the local filesystem to the SMB
// server. Paths handed to it are share-relative, forward-slash separated,
// with no leading slash; "" means the share root.
package localfs

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"portable-smb-server/internal/fsx"
)

// FS serves files beneath a single root directory.
type FS struct {
	root string // absolute, clean
}

// New returns an FS rooted at dir, which must be an existing directory.
func New(dir string) (*FS, error) {
	root, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%s: not a directory", root)
	}
	return &FS{root: root}, nil
}

// Root returns the absolute path of the directory being served.
func (f *FS) Root() string {
	return f.root
}

// resolve converts a share-relative path to an absolute local path,
// guaranteeing the result stays inside the root. The SMB layer already
// cleans names, so this is defence in depth.
func (f *FS) resolve(p string) (string, error) {
	if p == "" {
		return f.root, nil
	}
	clean := path.Clean("/" + p) // anchored: no ".." survives
	full := filepath.Join(f.root, filepath.FromSlash(clean))
	rel, err := filepath.Rel(f.root, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", os.ErrPermission
	}
	return full, nil
}

func (f *FS) Stat(p string) (os.FileInfo, error) {
	full, err := f.resolve(p)
	if err != nil {
		return nil, err
	}
	return os.Stat(full)
}

func (f *FS) OpenFile(p string, flag int, perm os.FileMode) (fsx.File, error) {
	full, err := f.resolve(p)
	if err != nil {
		return nil, err
	}
	h, err := openOSFile(full, flag, perm)
	if err != nil {
		return nil, err // explicit nil so the interface isn't a typed-nil *os.File
	}
	return h, nil
}

func (f *FS) Mkdir(p string, perm os.FileMode) error {
	full, err := f.resolve(p)
	if err != nil {
		return err
	}
	return os.Mkdir(full, perm)
}

func (f *FS) ReadDir(p string) ([]os.FileInfo, error) {
	full, err := f.resolve(p)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(full)
	if err != nil {
		return nil, err
	}
	infos := make([]os.FileInfo, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			// Entry disappeared between listing and stat - skip it.
			continue
		}
		infos = append(infos, info)
	}
	return infos, nil
}

func (f *FS) Rename(oldPath, newPath string) error {
	oldFull, err := f.resolve(oldPath)
	if err != nil {
		return err
	}
	newFull, err := f.resolve(newPath)
	if err != nil {
		return err
	}
	return os.Rename(oldFull, newFull)
}

func (f *FS) Remove(p string) error {
	full, err := f.resolve(p)
	if err != nil {
		return err
	}
	return os.Remove(full)
}

func (f *FS) Truncate(p string, size int64) error {
	full, err := f.resolve(p)
	if err != nil {
		return err
	}
	return os.Truncate(full, size)
}

func (f *FS) Chtimes(p string, mtime time.Time) error {
	full, err := f.resolve(p)
	if err != nil {
		return err
	}
	return os.Chtimes(full, mtime, mtime)
}

func (f *FS) Statfs() (total, free int64, err error) {
	return statfs(f.root)
}

func (f *FS) CaseInsensitive() bool {
	return runtime.GOOS == "windows" || runtime.GOOS == "darwin"
}
