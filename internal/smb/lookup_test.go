package smb

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"portable-smb-server/internal/fsx"
	"portable-smb-server/internal/localfs"
)

// countingFS counts the backend calls a request makes.
type countingFS struct {
	fsx.FileSystem
	readDirs atomic.Int64
	stats    atomic.Int64
}

func (f *countingFS) ReadDir(path string) ([]os.FileInfo, error) {
	f.readDirs.Add(1)
	return f.FileSystem.ReadDir(path)
}

func (f *countingFS) Stat(path string) (os.FileInfo, error) {
	f.stats.Add(1)
	return f.FileSystem.Stat(path)
}

// TestQueryDirByNameIsOneStat checks that a QUERY_DIRECTORY whose pattern is a
// plain name (how macOS resolves every entry, how Windows resolves a path) is
// answered with one stat of that name and no listing of the folder, that the
// entry is right, and that a name that does not exist ends the enumeration.
func TestQueryDirByNameIsOneStat(t *testing.T) {
	dir := t.TempDir()
	const n = 2000
	for i := 0; i < n; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("file%04d.txt", i)), []byte("xy"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	local, err := localfs.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	counting := &countingFS{FileSystem: local}
	s, err := NewServer(Options{ListenAddr: "127.0.0.1:0", Shares: []ShareDef{{Name: "data", FS: counting}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Shutdown() })
	c := newConn(s, nil)

	query := func(pattern string, flags byte) (uint32, []byte) {
		of := dirHandle(c, "")
		of.fileID[1] = byte(len(pattern))
		c.handles[of.fileID] = of
		p := stringToUTF16le(pattern)
		body := make([]byte, 32+len(p))
		body[2] = 0x25
		body[3] = flags
		copy(body[8:24], of.fileID[:])
		le.PutUint16(body[24:26], smb2HeaderSize+32)
		le.PutUint16(body[26:28], uint16(len(p)))
		le.PutUint32(body[28:32], 1<<16)
		copy(body[32:], p)
		return c.handleQueryDirectory(header{}, body)
	}

	status, resp := query("file1234.txt", 0x03)
	if status != statusSuccess {
		t.Fatalf("lookup: status 0x%08x", status)
	}
	if counting.readDirs.Load() != 0 || counting.stats.Load() != 1 {
		t.Fatalf("a lookup by name did %d ReadDir and %d Stat calls, want 0 and 1", counting.readDirs.Load(), counting.stats.Load())
	}
	e := resp[8:]
	if name := utf16leToString(e[104 : 104+le.Uint32(e[60:64])]); name != "file1234.txt" || le.Uint64(e[40:48]) != 2 {
		t.Fatalf("entry %q size %d", name, le.Uint64(e[40:48]))
	}
	if got, want := le.Uint64(e[96:104]), pathFileID("data", "file1234.txt"); got != want {
		t.Fatalf("FileId %#x, want %#x", got, want)
	}

	if status, _ := query("nothere.txt", 0x03); status != statusNoMoreFiles {
		t.Fatalf("a missing name: status 0x%08x, want NO_MORE_FILES", status)
	}
	if counting.readDirs.Load() != 0 {
		t.Fatalf("a missing name listed the folder")
	}

	// a wildcard pattern still lists and filters
	status, resp = query("file12*", 0x01)
	if status != statusSuccess || counting.readDirs.Load() != 1 {
		t.Fatalf("wildcard: status 0x%08x, ReadDir calls %d", status, counting.readDirs.Load())
	}
	matched := 0
	for off := 0; ; {
		matched++
		next := int(le.Uint32(resp[8+off : 8+off+4]))
		if next == 0 {
			break
		}
		off += next
	}
	if matched != 100 {
		t.Fatalf("file12* matched %d entries, want 100", matched)
	}
}
