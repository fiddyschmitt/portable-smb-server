package e2e

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestHighCountFolder lists a 5,000-entry folder (the lab's fixture size) in one
// enumeration and then looks 300 of its names up one by one, the way a
// macOS client without Apple's extensions does for every entry: both have to
// finish in seconds against a local folder, or a client over a LAN never sees
// the folder at all.
func TestHighCountFolder(t *testing.T) {
	dir := t.TempDir()
	const n = 5000
	many := filepath.Join(dir, "many")
	if err := os.Mkdir(many, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := os.WriteFile(filepath.Join(many, fmt.Sprintf("file-%05d.txt", i)), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	addr := startServer(t, "-folder", dir, "-share", "data")
	share := dial(t, addr, "user", "password", "data")

	start := time.Now()
	entries, err := share.ReadDir("many")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != n {
		t.Fatalf("listed %d entries, want %d", len(entries), n)
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Fatalf("listing %d entries took %s", n, d)
	}

	start = time.Now()
	for i := 0; i < 300; i++ {
		name := fmt.Sprintf("many/file-%05d.txt", (i*17)%n)
		fi, err := share.Stat(name)
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if fi.Size() != 1 {
			t.Fatalf("stat %s: size %d", name, fi.Size())
		}
	}
	if d := time.Since(start); d > 30*time.Second {
		t.Fatalf("300 lookups by name in the %d-entry folder took %s", n, d)
	}
}

// TestConcurrentReaders has eight sessions read the same 8 MiB file at once and
// compares every copy with the original: the server's handle table and its
// per-connection state must keep the readers apart.
func TestConcurrentReaders(t *testing.T) {
	dir := t.TempDir()
	data := make([]byte, 8<<20)
	for i := range data {
		data[i] = byte(i*7 + i>>12)
	}
	if err := os.WriteFile(filepath.Join(dir, "big.bin"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(data)
	addr := startServer(t, "-folder", dir, "-share", "data")

	const readers = 8
	var wg sync.WaitGroup
	errs := make(chan error, readers)
	for i := 0; i < readers; i++ {
		share, err := tryDial(t, addr, "user", "password", "data", 0, false)
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got, err := share.ReadFile("big.bin")
			if err != nil {
				errs <- fmt.Errorf("reader %d: %v", i, err)
				return
			}
			if sum := sha256.Sum256(got); !bytes.Equal(sum[:], want[:]) {
				errs <- fmt.Errorf("reader %d: %d bytes, wrong hash", i, len(got))
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
