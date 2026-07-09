//go:build !windows

package localfs

import "os"

func openOSFile(path string, flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(path, flag, perm)
}
