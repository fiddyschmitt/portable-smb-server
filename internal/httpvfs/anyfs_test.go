package httpvfs

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"portable-smb-server/internal/localfs"
	"portable-smb-server/internal/vfsprovider"
)

// The -vfs-token header: a provider started with a token refuses everything else.
func TestTokenRequired(t *testing.T) {
	lfs, err := localfs.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(vfsprovider.Handler(lfs, vfsprovider.Options{Token: "s3cret"}))
	defer srv.Close()
	if _, err := New(srv.URL); err == nil {
		t.Fatal("connected without the token")
	}
	if _, err := NewWithOptions(srv.URL, Options{Token: "wrong"}); err == nil {
		t.Fatal("connected with the wrong token")
	}
	f, err := NewWithOptions(srv.URL, Options{Token: "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Stat(""); err != nil {
		t.Fatalf("stat with the token: %v", err)
	}
	if _, err := f.ReadDir(""); err != nil {
		t.Fatalf("list with the token: %v", err)
	}
}

// A provider's per-file readOnly arrives as a mode without write bits, which
// is what the SMB layer keys FILE_ATTRIBUTE_READONLY and STATUS_ACCESS_DENIED on.
func TestReadOnlyFileHasNoWriteBits(t *testing.T) {
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked.txt")
	if err := os.WriteFile(locked, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o644) })
	if err := os.WriteFile(filepath.Join(dir, "open.txt"), []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := newPair(t, dir, vfsprovider.Options{})
	fi, err := f.Stat("locked.txt")
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o222 != 0 {
		t.Errorf("locked.txt: mode %v still has write bits", fi.Mode())
	}
	fi, err = f.Stat("open.txt")
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o222 == 0 {
		t.Errorf("open.txt: mode %v lost its write bits", fi.Mode())
	}
	infos, err := f.ReadDir("")
	if err != nil {
		t.Fatal(err)
	}
	for _, info := range infos {
		if info.Name() == "locked.txt" && info.Mode().Perm()&0o222 != 0 {
			t.Errorf("listing: locked.txt has write bits")
		}
	}
}

// Small sequential reads are served from a read-ahead window: one /read per
// window, not one per client read; a write through the handle drops the window.
func TestReadAheadCoalescesSequentialReads(t *testing.T) {
	dir := t.TempDir()
	data := make([]byte, 300*1024)
	for i := range data {
		data[i] = byte(i * 7)
	}
	if err := os.WriteFile(filepath.Join(dir, "big.bin"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	lfs, err := localfs.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	var reads atomic.Int32
	inner := vfsprovider.Handler(lfs, vfsprovider.Options{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/read" {
			reads.Add(1)
		}
		inner.ServeHTTP(w, r)
	}))
	defer srv.Close()
	f, err := NewWithOptions(srv.URL, Options{ReadAhead: 64 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	h, err := f.OpenFile("big.bin", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	got := make([]byte, 0, len(data))
	buf := make([]byte, 4096)
	for off := int64(0); ; {
		n, err := h.ReadAt(buf, off)
		got = append(got, buf[:n]...)
		off += int64(n)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("read back %d bytes, differ from the %d written", len(got), len(data))
	}
	if n := reads.Load(); n > 6 {
		t.Errorf("%d /read requests for 300 KiB in 4 KiB reads with a 64 KiB window; want about 5", n)
	}

	if _, err := h.WriteAt([]byte("ZZZZ"), 0); err != nil {
		t.Fatal(err)
	}
	if n, err := h.ReadAt(buf[:4], 0); err != nil || n != 4 || string(buf[:4]) != "ZZZZ" {
		t.Errorf("after a write the window must be refreshed: n=%d err=%v got %q", n, err, buf[:4])
	}

	before := reads.Load()
	big := make([]byte, 128*1024)
	if _, err := h.ReadAt(big, 0); err != nil {
		t.Fatal(err)
	}
	if reads.Load() != before+1 {
		t.Errorf("a read larger than the window goes straight through: %d requests", reads.Load()-before)
	}

	// read-ahead off: every read is a request
	plain, err := NewWithOptions(srv.URL, Options{ReadAhead: 0})
	if err != nil {
		t.Fatal(err)
	}
	ph, _ := plain.OpenFile("big.bin", os.O_RDONLY, 0)
	before = reads.Load()
	for i := 0; i < 3; i++ {
		if _, err := ph.ReadAt(buf, int64(i*4096)); err != nil {
			t.Fatal(err)
		}
	}
	if reads.Load() != before+3 {
		t.Errorf("with read-ahead off, 3 reads made %d requests", reads.Load()-before)
	}
}
