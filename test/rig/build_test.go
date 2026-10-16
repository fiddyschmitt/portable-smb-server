package rig

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// The binaries under test, built by TestMain for every OS the rig has: the server, the localvfs
// example provider (for the VFS shares) and the psmbstress load generator (test/rig/worker).
var binaries = map[OS]map[string]string{}

// Binary is the local path of a built binary for an OS.
func Binary(o OS, name string) string { return binaries[o][name] }

// targets maps each rig OS to the GOOS/GOARCH its machines run: amd64 VirtualBox VMs, and Apple
// silicon Macs.
var targets = map[OS][2]string{
	Linux:   {"linux", "amd64"},
	Windows: {"windows", "amd64"},
	MacOS:   {"darwin", "arm64"},
}

func TestMain(m *testing.M) {
	if _, err := Load(); err != nil {
		// No rig: every test skips with the reason. Nothing to build.
		fmt.Fprintf(os.Stderr, "rig: %v (the rig tests skip)\n", err)
		os.Exit(m.Run())
	}
	dir, err := os.MkdirTemp("", "psmb-rig-bin")
	if err != nil {
		panic(err)
	}
	_, file, _, _ := runtime.Caller(0)
	testDir := filepath.Dir(filepath.Dir(file)) // test/
	repo := filepath.Dir(testDir)
	for o, tgt := range targets {
		binaries[o] = map[string]string{}
		for name, build := range map[string]struct{ dir, pkg string }{
			serverImage:   {repo, "."},
			providerImage: {repo, "./examples/localvfs"},
			workerImage:   {testDir, "./rig/worker"},
		} {
			out := filepath.Join(dir, string(o), image(o, name))
			cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", out, build.pkg)
			cmd.Dir = build.dir
			cmd.Env = append(os.Environ(), "GOOS="+tgt[0], "GOARCH="+tgt[1], "CGO_ENABLED=0")
			if bout, err := cmd.CombinedOutput(); err != nil {
				panic(fmt.Sprintf("building %s for %s: %v\n%s", name, o, err, bout))
			}
			binaries[o][name] = out
		}
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// unreachable remembers the machines that couldn't be reached in this run (name -> reason), so a
// later pair that needs the same machine skips at once instead of waiting out another connect.
var unreachable sync.Map

// requireRig returns the rig's settings, or skips the test when there is no rig to be found.
func requireRig(t testing.TB) *Settings {
	t.Helper()
	s, err := Load()
	if err != nil {
		t.Skipf("no test rig: %v (set %s to the provisioning folder)", err, DirVariable)
	}
	return s
}

// connect opens a host, or skips the test when the machine can't be reached (it isn't up, or
// isn't provisioned yet): the rest of the matrix stays green.
func connect(t testing.TB, m Machine) *Host {
	t.Helper()
	if reason, down := unreachable.Load(m.Name); down {
		t.Skipf("%s", reason)
	}
	h, err := Connect(m)
	if err != nil {
		unreachable.Store(m.Name, err.Error())
		t.Skipf("%v", err)
	}
	t.Cleanup(h.Close)
	return h
}

// pairs is the client OS x server OS pairs to run: every one, or those in $PSMB_PAIRS
// ("linux>windows,macos>macos").
func pairs() [][2]OS {
	var out [][2]OS
	if env := os.Getenv("PSMB_PAIRS"); env != "" {
		for _, p := range strings.Split(env, ",") {
			cs := strings.SplitN(strings.TrimSpace(p), ">", 2)
			if len(cs) == 2 {
				out = append(out, [2]OS{OS(cs[0]), OS(cs[1])})
			}
		}
		return out
	}
	for _, c := range AllOS {
		for _, s := range AllOS {
			out = append(out, [2]OS{c, s})
		}
	}
	return out
}
