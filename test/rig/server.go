package rig

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// Share is one share the server under test exports.
type Share struct {
	Name string
	// VFS serves the share through the localvfs example provider (the BYO-VFS contract) running
	// on the server host over the share's directory, instead of -folder.
	VFS bool
	// ReadOnly makes a VFS provider declare itself read-only (the server's own -readonly is a
	// ServerOpts field, as it applies to every share).
	ReadOnly bool
}

// ServerOpts is how the server under test is started.
type ServerOpts struct {
	Shares   []Share
	Guest    bool
	User     string
	Pass     string
	ReadOnly bool // -readonly: every share read-only
	Verbose  bool // -v: a log line per request (off for the stress runs)
	Extra    []string
}

// Server is the server under test, running as a plain process on a host: deployed from the build
// TestMain made, serving directories under the host's rig directory, so a test can confirm the
// bytes a client wrote actually landed there.
type Server struct {
	Host *Host
	Port int
	Opts ServerOpts
	Exe  string // the deployed binary
	Log  string // its log file (-log)
	Out  string // its stdout/stderr (startup failures land here)

	providers []string // the localvfs processes' log files, one per VFS share
	stopped   bool
}

const (
	serverImage   = "portable-smb-server"
	providerImage = "localvfs"
	workerImage   = "psmbstress"
	providerBase  = 18080 // the localvfs providers listen on loopback from this port up
)

func image(o OS, name string) string {
	if o == Windows {
		return name + ".exe"
	}
	return name
}

// BackingDir is the directory on the server host that a share exports.
func (s *Server) BackingDir(share string) string {
	return s.Host.Join(s.Host.RigDir(), "serve", share)
}

// Path is a path inside a share's backing directory.
func (s *Server) Path(share string, parts ...string) string {
	return s.Host.Join(append([]string{s.BackingDir(share)}, parts...)...)
}

var (
	localHashMu sync.Mutex
	localHashes = map[string]string{}
)

func localHash(p string) (string, error) {
	localHashMu.Lock()
	defer localHashMu.Unlock()
	if h, ok := localHashes[p]; ok {
		return h, nil
	}
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	s := sha256.New()
	if _, err := io.Copy(s, f); err != nil {
		return "", err
	}
	h := hex.EncodeToString(s.Sum(nil))
	localHashes[p] = h
	return h, nil
}

// Deploy pushes a built binary to the host's bin/ directory, skipping the upload when the host
// already has the identical file (by SHA-256, not size: a rebuilt binary is frequently the same
// size, and a size check would leave stale code in place). It returns the remote path.
func Deploy(h *Host, local, name string) (string, error) {
	remote := h.Join(h.RigDir(), "bin", image(h.OS, name))
	want, err := localHash(local)
	if err != nil {
		return "", err
	}
	var have string
	switch h.OS {
	case Windows:
		have = strings.ToLower(strings.TrimSpace(h.RunLax(fmt.Sprintf(`if (Test-Path -LiteralPath %s) { (Get-FileHash -Algorithm SHA256 -LiteralPath %s).Hash }`, h.Q(remote), h.Q(remote)), opTimeout).Stdout))
	case MacOS:
		have = strings.TrimSpace(h.RunLax(fmt.Sprintf(`shasum -a 256 %s 2>/dev/null | cut -d' ' -f1`, h.Q(remote)), opTimeout).Stdout)
	default:
		have = strings.TrimSpace(h.RunLax(fmt.Sprintf(`sha256sum %s 2>/dev/null | cut -d' ' -f1`, h.Q(remote)), opTimeout).Stdout)
	}
	if have == want {
		return remote, nil
	}
	// Never overwrite a binary in place. macOS caches its code-signing verdict per file (inode):
	// new bytes in the old file no longer match it, and AppleSystemPolicy then refuses to run the
	// binary at all, silently as far as a detached launch can tell. Deleting first gives the
	// upload a new inode. (A running old copy keeps its inode; the caller kills it first.)
	if h.Unix() {
		h.RunLax(`rm -f `+h.Q(remote), opTimeout)
	}
	if err := h.Upload(local, remote); err != nil {
		return "", err
	}
	if h.Unix() {
		if r := h.Run(`chmod +x `+h.Q(remote), opTimeout); !r.OK() {
			return "", r.Err("chmod")
		}
	}
	return remote, nil
}

// StartServer deploys and starts the server under test on a host, waits until it listens, and
// registers its stop with the test. Anything a previous run left (a server, a provider, the
// backing directories) is cleared first.
func StartServer(t testing.TB, h *Host, port int, opts ServerOpts) *Server {
	t.Helper()
	s, err := startServer(h, port, opts)
	if err != nil {
		t.Fatalf("starting the server under test on %s: %v", h.Name, err)
	}
	t.Cleanup(s.Stop)
	return s
}

func startServer(h *Host, port int, opts ServerOpts) (*Server, error) {
	s := &Server{Host: h, Port: port, Opts: opts}
	logDir := h.Join(h.RigDir(), "log")
	s.Log = h.Join(logDir, "server.log")
	s.Out = h.Join(logDir, "server.out")
	if err := Mkdir(h, logDir); err != nil {
		return nil, err
	}

	h.Kill(image(h.OS, serverImage))
	h.Kill(image(h.OS, providerImage))
	killListener(h, port)
	if err := waitPortFree(h, port); err != nil {
		return nil, err
	}

	var err error
	if s.Exe, err = Deploy(h, Binary(h.OS, serverImage), serverImage); err != nil {
		return nil, err
	}
	var providerExe string
	for _, sh := range opts.Shares {
		if sh.VFS {
			if providerExe, err = Deploy(h, Binary(h.OS, providerImage), providerImage); err != nil {
				return nil, err
			}
			break
		}
	}

	// Fresh logs: whoever reads them must only ever see this server's lines.
	Remove(h, s.Log)
	Remove(h, s.Out)

	args := []string{"-ip", "0.0.0.0", "-port", fmt.Sprint(port)}
	nextProvider := providerBase
	for _, sh := range opts.Shares {
		dir := s.BackingDir(sh.Name)
		Remove(h, dir)
		if err := Mkdir(h, dir); err != nil {
			return nil, err
		}
		if sh.VFS {
			addr := fmt.Sprintf("127.0.0.1:%d", nextProvider)
			nextProvider++
			plog := h.Join(logDir, "provider-"+sh.Name+".log")
			Remove(h, plog)
			pargs := fmt.Sprintf(`-addr %s -folder %s -name %s`, addr, qArg(h, dir), sh.Name)
			if sh.ReadOnly {
				pargs += " -readonly"
			}
			if err := h.StartDetached(providerExe, pargs, plog); err != nil {
				return nil, err
			}
			if err := waitListening(h, nextProvider-1, plog); err != nil {
				return nil, fmt.Errorf("localvfs provider for %q: %v", sh.Name, err)
			}
			s.providers = append(s.providers, plog)
			args = append(args, "-vfs", "http://"+addr, "-share", sh.Name)
		} else {
			args = append(args, "-folder", qArg(h, dir), "-share", sh.Name)
		}
	}
	if opts.Guest {
		args = append(args, "-guest")
	} else {
		args = append(args, "-user", opts.User, "-pass", opts.Pass)
	}
	if opts.ReadOnly {
		args = append(args, "-readonly")
	}
	if opts.Verbose {
		args = append(args, "-v")
	}
	args = append(args, "-log", qArg(h, s.Log))
	args = append(args, opts.Extra...)

	if err := h.StartDetached(s.Exe, strings.Join(args, " "), s.Out); err != nil {
		return nil, err
	}
	if err := waitListening(h, port, s.Out); err != nil {
		return nil, err
	}
	return s, nil
}

// qArg quotes a command-line argument for the detached launch: double quotes, which both cmd.exe
// and the Unix shells pass through to the program. (Rig paths never contain quotes.)
func qArg(h *Host, s string) string {
	return `"` + s + `"`
}

// Stop ends the server and its providers. Safe to call twice.
func (s *Server) Stop() {
	if s.stopped {
		return
	}
	s.stopped = true
	s.Host.Kill(image(s.Host.OS, serverImage))
	s.Host.Kill(image(s.Host.OS, providerImage))
}

// Alive reports whether the server process is still running.
func (s *Server) Alive() bool { return s.Host.Alive(image(s.Host.OS, serverImage)) }

// RSSKiB is the server process's resident memory.
func (s *Server) RSSKiB() int64 { return s.Host.RSSKiB(image(s.Host.OS, serverImage)) }

// LogProblems is the server log's ERROR, panic and fatal lines, minus any matching a benign
// pattern, capped at 50. A Go panic that escapes the server's own recovery goes to stderr, not
// the log, so the process's output file is searched too (the log is also echoed there).
func (s *Server) LogProblems(benign []string) []string {
	h := s.Host
	var r Result
	if h.OS == Windows {
		r = h.RunLax(fmt.Sprintf(`foreach ($f in %s, %s) { if (Test-Path -LiteralPath $f) { Select-String -LiteralPath $f -Pattern ' ERROR','panic','fatal error','goroutine ' | Select-Object -First 100 | ForEach-Object { $_.Line } } }`, h.Q(s.Log), h.Q(s.Out)), opTimeout)
	} else {
		r = h.RunLax(fmt.Sprintf(`cat %s %s 2>/dev/null | grep -E ' ERROR|panic|fatal error|goroutine ' | head -n 200`, h.Q(s.Log), h.Q(s.Out)), opTimeout)
	}
	var out []string
lines:
	for _, l := range strings.Split(strings.ReplaceAll(r.Stdout, "\r\n", "\n"), "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		for _, b := range benign {
			if strings.Contains(l, b) {
				continue lines
			}
		}
		out = append(out, l)
		if len(out) == 50 {
			break
		}
	}
	return out
}

// LogTail is the last n lines of the server log, for a failure message.
func (s *Server) LogTail(n int) string {
	h := s.Host
	if h.OS == Windows {
		return h.RunLax(fmt.Sprintf(`Get-Content -LiteralPath %s -Tail %d -ErrorAction SilentlyContinue`, h.Q(s.Log), n), opTimeout).Stdout
	}
	return h.RunLax(fmt.Sprintf(`tail -n %d %s 2>/dev/null`, n, h.Q(s.Log)), opTimeout).Stdout
}

// killListener ends whatever listens on the port: a server under test started some other way (by
// hand, from another path) that Kill's path-anchored pattern doesn't match. The port is the rig's
// on every machine in settings.yml.
func killListener(h *Host, port int) {
	switch h.OS {
	case Windows:
		h.RunLax(fmt.Sprintf(`Get-NetTCPConnection -LocalPort %d -State Listen -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }`, port), opTimeout)
	case MacOS:
		h.RunLax(fmt.Sprintf(`lsof -nP -iTCP:%d -sTCP:LISTEN -t 2>/dev/null | xargs kill -9 2>/dev/null; true`, port), opTimeout)
	default:
		h.RunLax(fmt.Sprintf(`for pid in $(sudo ss -ltnpH "sport = :%d" | sed -n 's/.*pid=\([0-9]*\).*/\1/p'); do sudo kill -9 "$pid"; done; true`, port), opTimeout)
	}
}

// waitPortFree waits until nothing listens on the port (on the host, via loopback) before a start,
// so a stale server can't be mistaken for the one about to start. A Kill that leaked the process
// would otherwise leave it squatting on the port, and the test would run against the wrong
// server, silently.
func waitPortFree(h *Host, port int) error {
	var cmd string
	switch h.OS {
	case Windows:
		cmd = fmt.Sprintf(`for ($i=0; $i -lt 40; $i++) { $free=$false; try { $c=New-Object Net.Sockets.TcpClient; if ($c.ConnectAsync('127.0.0.1',%d).Wait(1000) -and $c.Connected) { $c.Close() } else { $free=$true } } catch { $free=$true }; if ($free) { exit 0 }; Start-Sleep -Milliseconds 500 }; exit 1`, port)
	case MacOS:
		cmd = fmt.Sprintf(`for i in $(seq 1 40); do /usr/bin/nc -z 127.0.0.1 %d 2>/dev/null || exit 0; sleep 0.5; done; exit 1`, port)
	default:
		cmd = fmt.Sprintf(`for i in $(seq 1 40); do (exec 3<>/dev/tcp/127.0.0.1/%d) 2>/dev/null || exit 0; sleep 0.5; done; exit 1`, port)
	}
	if r := h.Run(cmd, 60*time.Second); !r.OK() {
		return fmt.Errorf("port %d on %s is still in use after killing the previous server: a stale process is squatting on it", port, h.Name)
	}
	return nil
}

// waitListening waits (on the host, via loopback) until something accepts connections on the port.
// Paired with waitPortFree, a success here means the freshly started process is the one listening.
func waitListening(h *Host, port int, outFile string) error {
	var cmd string
	switch h.OS {
	case Windows:
		cmd = fmt.Sprintf(`for ($i=0; $i -lt 120; $i++) { try { $c=New-Object Net.Sockets.TcpClient; if ($c.ConnectAsync('127.0.0.1',%d).Wait(1000) -and $c.Connected) { $c.Close(); exit 0 }; $c.Close() } catch { }; Start-Sleep -Milliseconds 500 }; exit 1`, port)
	case MacOS:
		// macOS's default shell is zsh, which lacks bash's /dev/tcp; nc ships by default.
		cmd = fmt.Sprintf(`for i in $(seq 1 120); do /usr/bin/nc -z 127.0.0.1 %d 2>/dev/null && exit 0; sleep 0.5; done; exit 1`, port)
	default:
		cmd = fmt.Sprintf(`for i in $(seq 1 120); do (exec 3<>/dev/tcp/127.0.0.1/%d) 2>/dev/null && exit 0; sleep 0.5; done; exit 1`, port)
	}
	if r := h.Run(cmd, 90*time.Second); !r.OK() {
		var out string
		if h.OS == Windows {
			out = h.RunLax(fmt.Sprintf(`Get-Content -LiteralPath %s -ErrorAction SilentlyContinue | Select-Object -Last 20`, h.Q(outFile)), opTimeout).Stdout
		} else {
			out = h.RunLax(fmt.Sprintf(`tail -n 20 %s 2>/dev/null`, h.Q(outFile)), opTimeout).Stdout
		}
		return fmt.Errorf("nothing listening on 127.0.0.1:%d on %s after 60 s; the process said:\n%s", port, h.Name, tail(out, 2000))
	}
	return nil
}
