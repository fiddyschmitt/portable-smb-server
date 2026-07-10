package httpvfs

import (
	"errors"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"portable-smb-server/internal/fsx"
	"portable-smb-server/internal/localfs"
	"portable-smb-server/internal/vfsprovider"
)

// newPair starts a reference provider over dir and returns an FS client on it.
func newPair(t *testing.T, dir string, opt vfsprovider.Options) *FS {
	t.Helper()
	lfs, err := localfs.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(vfsprovider.Handler(lfs, opt))
	t.Cleanup(srv.Close)
	f, err := New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

var _ fsx.FileSystem = (*FS)(nil) // FS must satisfy the SMB layer's interface

func TestCapabilities(t *testing.T) {
	f := newPair(t, t.TempDir(), vfsprovider.Options{Name: "cloud", ReadOnly: true})
	if f.Name() != "cloud" || !f.ReadOnly() {
		t.Errorf("capabilities not honoured: name=%q readOnly=%v", f.Name(), f.ReadOnly())
	}
}

func TestNoCapabilitiesEndpoint(t *testing.T) {
	// A provider without /capabilities must be assumed writable.
	srv := httptest.NewServer(nil) // 404 for everything
	defer srv.Close()
	f, err := New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if f.ReadOnly() || f.Name() != "" {
		t.Errorf("defaults wrong: name=%q readOnly=%v", f.Name(), f.ReadOnly())
	}
}

func TestStatListRead(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hello world"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	f := newPair(t, dir, vfsprovider.Options{})

	fi, err := f.Stat("hello.txt")
	if err != nil || fi.Size() != 11 || fi.IsDir() {
		t.Fatalf("stat: %+v, %v", fi, err)
	}
	if _, err := f.Stat("nope.txt"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stat missing: %v, want ErrNotExist", err)
	}

	entries, err := f.ReadDir("")
	if err != nil || len(entries) != 2 {
		t.Fatalf("readdir: %d entries, %v", len(entries), err)
	}

	h, err := f.OpenFile("hello.txt", os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	// Full read.
	buf := make([]byte, 11)
	if n, err := h.ReadAt(buf, 0); n != 11 || (err != nil && err != io.EOF) {
		t.Fatalf("read: n=%d err=%v", n, err)
	}
	if string(buf) != "hello world" {
		t.Errorf("read %q", buf)
	}
	// Sub-file window.
	win := make([]byte, 5)
	if n, err := h.ReadAt(win, 6); n != 5 || (err != nil && err != io.EOF) || string(win) != "world" {
		t.Errorf("ranged read: n=%d err=%v data=%q", n, err, win)
	}
	// Past EOF -> 0, io.EOF.
	if n, err := h.ReadAt(win, 100); n != 0 || err != io.EOF {
		t.Errorf("read past EOF: n=%d err=%v, want 0/io.EOF", n, err)
	}
}

func TestWriteLifecycle(t *testing.T) {
	dir := t.TempDir()
	f := newPair(t, dir, vfsprovider.Options{})

	h, err := f.OpenFile("new.txt", os.O_RDWR|os.O_CREATE, 0o666)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.WriteAt([]byte("written data"), 0); err != nil {
		t.Fatal(err)
	}
	if fi, err := h.Stat(); err != nil || fi.Size() != 12 {
		t.Fatalf("stat after write: %v, %v", fi, err)
	}
	if err := h.Truncate(7); err != nil {
		t.Fatal(err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}

	// Bytes must land in the backing store.
	if got, _ := os.ReadFile(filepath.Join(dir, "new.txt")); string(got) != "written" {
		t.Errorf("backing store %q", got)
	}

	// O_EXCL on an existing file -> ErrExist.
	if _, err := f.OpenFile("new.txt", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o666); !errors.Is(err, os.ErrExist) {
		t.Errorf("exclusive create on existing: %v, want ErrExist", err)
	}

	if err := f.Mkdir("sub", 0o777); err != nil {
		t.Fatal(err)
	}
	if err := f.Rename("new.txt", "sub/moved.txt"); err != nil {
		t.Fatal(err)
	}
	if err := f.Chtimes("sub/moved.txt", time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	fi, err := f.Stat("sub/moved.txt")
	if err != nil || !fi.ModTime().Equal(time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)) {
		t.Errorf("chtimes: %v, %v", fi.ModTime(), err)
	}

	// Removing a non-empty dir -> ErrNotEmpty.
	if err := f.Remove("sub"); !errors.Is(err, fsx.ErrNotEmpty) {
		t.Errorf("remove non-empty dir: %v, want ErrNotEmpty", err)
	}
	if err := f.Remove("sub/moved.txt"); err != nil {
		t.Fatal(err)
	}
	if err := f.Remove("sub"); err != nil {
		t.Fatal(err)
	}
}

func TestReadOnlyProvider(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := newPair(t, dir, vfsprovider.Options{ReadOnly: true})

	// Reads work.
	if _, err := f.Stat("f.txt"); err != nil {
		t.Fatal(err)
	}
	// Every mutation is refused with ErrReadOnly.
	if _, err := f.OpenFile("new.txt", os.O_RDWR|os.O_CREATE, 0o666); !errors.Is(err, fsx.ErrReadOnly) {
		t.Errorf("create: %v, want ErrReadOnly", err)
	}
	if err := f.Mkdir("d", 0o777); !errors.Is(err, fsx.ErrReadOnly) {
		t.Errorf("mkdir: %v, want ErrReadOnly", err)
	}
	if err := f.Remove("f.txt"); !errors.Is(err, fsx.ErrReadOnly) {
		t.Errorf("remove: %v, want ErrReadOnly", err)
	}
	if err := f.Rename("f.txt", "g.txt"); !errors.Is(err, fsx.ErrReadOnly) {
		t.Errorf("rename: %v, want ErrReadOnly", err)
	}
}

func TestStatfs(t *testing.T) {
	f := newPair(t, t.TempDir(), vfsprovider.Options{})
	total, free, err := f.Statfs()
	if err != nil || total <= 0 || free <= 0 {
		t.Errorf("statfs: total=%d free=%d err=%v", total, free, err)
	}
}
