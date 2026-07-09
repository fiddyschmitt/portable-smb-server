// Package e2e drives the built portable-smb-server executable with a real
// SMB2 client (the same client library rclone's own SMB server tests use).
// It lives in its own module so the product module keeps zero dependencies.
package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	smb2 "github.com/cloudsoda/go-smb2"
)

var serverExe string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "psmb-e2e")
	if err != nil {
		panic(err)
	}
	serverExe = filepath.Join(dir, "portable-smb-server")
	if runtime.GOOS == "windows" {
		serverExe += ".exe"
	}
	build := exec.Command("go", "build", "-o", serverExe, ".")
	build.Dir = ".."
	if out, err := build.CombinedOutput(); err != nil {
		panic(fmt.Sprintf("building server: %v\n%s", err, out))
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// freePort reserves a loopback port and releases it for the server to use.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

// startServer launches the server exe with the given extra args and waits for
// it to accept connections. It returns the address to dial.
func startServer(t *testing.T, args ...string) string {
	t.Helper()
	port := freePort(t)
	args = append([]string{"-ip", "127.0.0.1", "-port", fmt.Sprint(port)}, args...)
	cmd := exec.Command(serverExe, args...)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		nc, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = nc.Close()
			return addr
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server did not start listening on %s", addr)
	return ""
}

// dial connects with the given credentials and mounts the named share.
func dial(t *testing.T, addr, user, pass, shareName string) *smb2.Share {
	t.Helper()
	share, err := tryDial(t, addr, user, pass, shareName, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	return share
}

func tryDial(t *testing.T, addr, user, pass, shareName string, dialect uint16, requireSigning bool) (*smb2.Share, error) {
	t.Helper()
	nc, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	d := &smb2.Dialer{
		Negotiator: smb2.Negotiator{RequireMessageSigning: requireSigning, SpecifiedDialect: dialect},
		Initiator:  &smb2.NTLMInitiator{User: user, Password: pass},
	}
	session, err := d.DialConn(context.Background(), nc, addr)
	if err != nil {
		_ = nc.Close()
		return nil, err
	}
	share, err := session.Mount(shareName)
	if err != nil {
		_ = session.Logoff()
		return nil, err
	}
	t.Cleanup(func() {
		_ = share.Umount()
		_ = session.Logoff()
	})
	return share, nil
}

// TestRoundTrip covers write, read-back, stat, rename and delete with NTLM
// authentication and default credentials.
func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	addr := startServer(t, "-folder", dir, "-share", "data")
	share := dial(t, addr, "user", "password", "data")

	if err := share.WriteFile("new.txt", []byte("written data"), 0o644); err != nil {
		t.Fatal(err)
	}
	data, err := share.ReadFile("new.txt")
	if err != nil || string(data) != "written data" {
		t.Fatalf("read back %q, %v", data, err)
	}
	// The bytes must land in the backing store.
	backing, err := os.ReadFile(filepath.Join(dir, "new.txt"))
	if err != nil || string(backing) != "written data" {
		t.Fatalf("backing store %q, %v", backing, err)
	}

	if err := share.Mkdir("sub", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := share.WriteFile("sub/inner.txt", []byte("inner"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := share.Rename("new.txt", "renamed.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := share.Stat("new.txt"); err == nil {
		t.Fatal("stat of renamed-away file must fail")
	}
	if err := share.Remove("renamed.txt"); err != nil {
		t.Fatal(err)
	}
	if err := share.Remove("sub/inner.txt"); err != nil {
		t.Fatal(err)
	}
	if err := share.Remove("sub"); err != nil {
		t.Fatal(err)
	}
	entries, err := share.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("share should be empty, has %d entries", len(entries))
	}
}

// TestAuth checks NTLM success, wrong password and wrong user.
func TestAuth(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("top secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	addr := startServer(t, "-folder", dir, "-share", "data", "-user", "alice", "-pass", "s3cret")

	share, err := tryDial(t, addr, "alice", "s3cret", "data", 0, false)
	if err != nil {
		t.Fatal(err)
	}
	data, err := share.ReadFile("secret.txt")
	if err != nil || string(data) != "top secret" {
		t.Fatalf("read %q, %v", data, err)
	}

	if _, err := tryDial(t, addr, "alice", "wrong", "data", 0, false); err == nil {
		t.Fatal("wrong password must fail session setup")
	}
	if _, err := tryDial(t, addr, "bob", "s3cret", "data", 0, false); err == nil {
		t.Fatal("wrong user must fail session setup")
	}
}

// TestGuest checks that -guest allows an unauthenticated session.
func TestGuest(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("guest ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	addr := startServer(t, "-folder", dir, "-share", "data", "-guest")
	share := dial(t, addr, "anyone", "", "data")
	data, err := share.ReadFile("f.txt")
	if err != nil || string(data) != "guest ok" {
		t.Fatalf("read %q, %v", data, err)
	}
}

// TestMultipleShares checks that two -folder/-share pairs are both served and
// isolated from each other.
func TestMultipleShares(t *testing.T) {
	dir1, dir2 := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(dir1, "one.txt"), []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir2, "two.txt"), []byte("2"), 0o644); err != nil {
		t.Fatal(err)
	}
	addr := startServer(t, "-folder", dir1, "-share", "first", "-folder", dir2, "-share", "second")

	first := dial(t, addr, "user", "password", "first")
	second := dial(t, addr, "user", "password", "second")

	if _, err := first.Stat("one.txt"); err != nil {
		t.Errorf("first share: %v", err)
	}
	if _, err := first.Stat("two.txt"); err == nil {
		t.Error("first share must not expose second share's files")
	}
	if _, err := second.Stat("two.txt"); err != nil {
		t.Errorf("second share: %v", err)
	}
}

// TestSignedDialects checks message signing on the SMB2 (HMAC-SHA256) and
// SMB3 (AES-CMAC) paths with signing required by the client.
func TestSignedDialects(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("signed"), 0o644); err != nil {
		t.Fatal(err)
	}
	addr := startServer(t, "-folder", dir, "-share", "data")
	for _, dialect := range []uint16{0x0202, 0x0210, 0x0300, 0x0302} {
		share, err := tryDial(t, addr, "user", "password", "data", dialect, true)
		if err != nil {
			t.Errorf("dialect 0x%04x: %v", dialect, err)
			continue
		}
		data, err := share.ReadFile("f.txt")
		if err != nil || string(data) != "signed" {
			t.Errorf("dialect 0x%04x: read %q, %v", dialect, data, err)
		}
	}
}

// TestLargeFile round-trips a 10 MiB random file (many READ/WRITE PDUs).
func TestLargeFile(t *testing.T) {
	dir := t.TempDir()
	addr := startServer(t, "-folder", dir, "-share", "data")
	share := dial(t, addr, "user", "password", "data")

	payload := make([]byte, 10<<20)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	if err := share.WriteFile("big.bin", payload, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := share.ReadFile("big.bin")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("large file corrupted over SMB")
	}
	backing, err := os.ReadFile(filepath.Join(dir, "big.bin"))
	if err != nil || !bytes.Equal(backing, payload) {
		t.Fatalf("backing store mismatch: %v", err)
	}
}

// TestManyFiles lists a directory too large for one QUERY_DIRECTORY response.
func TestManyFiles(t *testing.T) {
	dir := t.TempDir()
	const n = 500
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("file-%03d-with-a-reasonably-long-name.txt", i)
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	addr := startServer(t, "-folder", dir, "-share", "data")
	share := dial(t, addr, "user", "password", "data")
	entries, err := share.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != n {
		t.Fatalf("listed %d entries, want %d", len(entries), n)
	}
}

// TestEmptyFile round-trips a zero-byte file.
func TestEmptyFile(t *testing.T) {
	dir := t.TempDir()
	addr := startServer(t, "-folder", dir, "-share", "data")
	share := dial(t, addr, "user", "password", "data")
	if err := share.WriteFile("empty.txt", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	data, err := share.ReadFile("empty.txt")
	if err != nil || len(data) != 0 {
		t.Fatalf("empty file read %d bytes, %v", len(data), err)
	}
}

// TestSpecialFilenames exercises non-ASCII and awkward (but legal) names.
func TestSpecialFilenames(t *testing.T) {
	dir := t.TempDir()
	addr := startServer(t, "-folder", dir, "-share", "data")
	share := dial(t, addr, "user", "password", "data")
	names := []string{
		"ünïcödé.txt",
		"日本語ファイル.txt",
		"name with spaces.txt",
		"dots.in.name.txt",
		"emoji-😀.txt",
	}
	for _, name := range names {
		if err := share.WriteFile(name, []byte(name), 0o644); err != nil {
			t.Errorf("write %q: %v", name, err)
			continue
		}
		data, err := share.ReadFile(name)
		if err != nil || string(data) != name {
			t.Errorf("read %q: got %q, %v", name, data, err)
		}
	}
	entries, err := share.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(names) {
		t.Errorf("listed %d entries, want %d", len(entries), len(names))
	}
}
