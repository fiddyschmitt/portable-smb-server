package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// startProvider launches the localvfs provider (built in TestMain) over dir
// and returns its URL.
func startProvider(t *testing.T, dir string, extra ...string) string {
	t.Helper()
	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	args := append([]string{"-addr", addr, "-folder", dir}, extra...)
	cmd := exec.Command(providerExe, args...)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	waitListening(t, addr)
	return "http://" + addr
}

// TestVFSRoundTrip drives the whole BYO-VFS chain: SMB client -> SMB server
// -> HTTP VFS contract -> provider -> disk.
func TestVFSRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("from the provider"), 0o644); err != nil {
		t.Fatal(err)
	}
	providerURL := startProvider(t, dir, "-name", "cloud")
	addr := startServer(t, "-vfs", providerURL)

	// The share name comes from the provider's /capabilities.
	share := dial(t, addr, "user", "password", "cloud")

	// Read what the provider had.
	data, err := share.ReadFile("hello.txt")
	if err != nil || string(data) != "from the provider" {
		t.Fatalf("read: %q, %v", data, err)
	}

	// Full write lifecycle through the chain.
	if err := share.WriteFile("new.txt", []byte("written via smb+vfs"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "new.txt")); string(got) != "written via smb+vfs" {
		t.Fatalf("backing store: %q", got)
	}
	if err := share.Mkdir("sub", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := share.Rename("new.txt", "sub/moved.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "sub", "moved.txt")); err != nil {
		t.Fatalf("rename didn't land: %v", err)
	}
	if err := share.Remove("sub/moved.txt"); err != nil {
		t.Fatal(err)
	}
	if err := share.Remove("sub"); err != nil {
		t.Fatal(err)
	}

	entries, err := share.ReadDir(".")
	if err != nil || len(entries) != 1 || entries[0].Name() != "hello.txt" {
		t.Fatalf("final listing: %v, %v", entries, err)
	}
}

// TestVFSReadOnlyProvider checks that a provider declaring readOnly results
// in a share that reads fine and refuses writes.
func TestVFSReadOnlyProvider(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("look only"), 0o644); err != nil {
		t.Fatal(err)
	}
	providerURL := startProvider(t, dir, "-name", "ro", "-readonly")
	addr := startServer(t, "-vfs", providerURL)
	share := dial(t, addr, "user", "password", "ro")

	data, err := share.ReadFile("f.txt")
	if err != nil || string(data) != "look only" {
		t.Fatalf("read: %q, %v", data, err)
	}
	if err := share.WriteFile("no.txt", []byte("x"), 0o644); err == nil {
		t.Error("write on read-only provider share must fail")
	}
	if err := share.Remove("f.txt"); err == nil {
		t.Error("delete on read-only provider share must fail")
	}
	if _, err := os.Stat(filepath.Join(dir, "f.txt")); err != nil {
		t.Errorf("backing file damaged: %v", err)
	}
}

// TestVFSAndFolderMixed serves one local folder and one provider share from
// the same server.
func TestVFSAndFolderMixed(t *testing.T) {
	localDir, vfsDir := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(localDir, "local.txt"), []byte("l"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vfsDir, "remote.txt"), []byte("r"), 0o644); err != nil {
		t.Fatal(err)
	}
	providerURL := startProvider(t, vfsDir, "-name", "cloud")
	addr := startServer(t, "-folder", localDir, "-share", "local", "-vfs", providerURL)

	local := dial(t, addr, "user", "password", "local")
	cloud := dial(t, addr, "user", "password", "cloud")

	if _, err := local.Stat("local.txt"); err != nil {
		t.Errorf("local share: %v", err)
	}
	if _, err := cloud.Stat("remote.txt"); err != nil {
		t.Errorf("vfs share: %v", err)
	}
	if _, err := local.Stat("remote.txt"); err == nil {
		t.Error("shares must be isolated")
	}
}
