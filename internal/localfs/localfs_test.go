package localfs

import (
	"os"
	"path/filepath"
	"testing"
)

func newTestFS(t *testing.T) *FS {
	t.Helper()
	f, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestResolveContainment(t *testing.T) {
	f := newTestFS(t)
	for _, p := range []string{"..", "../x", "a/../../x", "....//..../../../x"} {
		full, err := f.resolve(p)
		if err != nil {
			continue // rejected, fine
		}
		rel, err := filepath.Rel(f.root, full)
		if err != nil || rel == ".." || filepath.IsAbs(rel) {
			t.Errorf("resolve(%q) escaped root: %q", p, full)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	f := newTestFS(t)

	h, err := f.OpenFile("hello.txt", os.O_RDWR|os.O_CREATE, 0o666)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.WriteAt([]byte("hello world"), 0); err != nil {
		t.Fatal(err)
	}

	// Rename and delete while our own handle is still open - this is what
	// SMB clients do, and requires FILE_SHARE_DELETE on Windows.
	if err := f.Rename("hello.txt", "renamed.txt"); err != nil {
		t.Fatalf("rename with open handle: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}

	fi, err := f.Stat("renamed.txt")
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != 11 {
		t.Errorf("size = %d, want 11", fi.Size())
	}

	h2, err := f.OpenFile("renamed.txt", os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Remove("renamed.txt"); err != nil {
		t.Fatalf("remove with open read handle: %v", err)
	}
	h2.Close()

	if _, err := f.Stat("renamed.txt"); !os.IsNotExist(err) {
		t.Errorf("stat after remove: %v, want not-exist", err)
	}
}

func TestDirOps(t *testing.T) {
	f := newTestFS(t)
	if err := f.Mkdir("sub", 0o777); err != nil {
		t.Fatal(err)
	}
	h, err := f.OpenFile("sub/a.txt", os.O_WRONLY|os.O_CREATE, 0o666)
	if err != nil {
		t.Fatal(err)
	}
	h.Close()

	infos, err := f.ReadDir("sub")
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 || infos[0].Name() != "a.txt" {
		t.Errorf("ReadDir = %v", infos)
	}

	if err := f.Remove("sub"); err == nil {
		t.Error("removing non-empty dir succeeded, want error")
	}
	if err := f.Remove("sub/a.txt"); err != nil {
		t.Fatal(err)
	}
	if err := f.Remove("sub"); err != nil {
		t.Fatal(err)
	}
}

func TestStatfs(t *testing.T) {
	f := newTestFS(t)
	total, free, err := f.Statfs()
	if err != nil {
		t.Fatal(err)
	}
	if total <= 0 || free <= 0 || free > total {
		t.Errorf("statfs total=%d free=%d", total, free)
	}
}

// TestRemoveWhileHandleOpen deletes a file while a handle to it is still open and then, WITHOUT
// closing that handle, checks the name is already gone. This is what a client that caches file
// handles (macOS smbfs) does: it deletes and immediately expects the entry gone, POSIX-style.
// Classic Windows DeleteFile only marks the file delete-pending until the last handle closes, so
// the name lingers and a Windows-hosted server disagrees with its Linux/macOS peers; Remove must
// unlink immediately even with the handle open.
func TestRemoveWhileHandleOpen(t *testing.T) {
	f := newTestFS(t)
	h, err := f.OpenFile("gone.txt", os.O_RDWR|os.O_CREATE, 0o666)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if _, err := h.WriteAt([]byte("data"), 0); err != nil {
		t.Fatal(err)
	}
	if err := f.Remove("gone.txt"); err != nil {
		t.Fatalf("remove with an open handle: %v", err)
	}
	if _, err := f.Stat("gone.txt"); !os.IsNotExist(err) {
		t.Errorf("stat right after remove (handle still open): %v, want not-exist", err)
	}
	if infos, err := f.ReadDir("."); err == nil {
		for _, fi := range infos {
			if fi.Name() == "gone.txt" {
				t.Errorf("gone.txt still listed in the directory after remove")
			}
		}
	}
}
