package rig

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Host is a test machine the harness drives over SSH with the rig's key: Linux, macOS, or Windows
// (whose OpenSSH default shell the rig sets to PowerShell). It runs short commands and captures
// their output, pushes files (SFTP), launches a long-running process detached (the server under
// test) and kills it by image name. Commands are written in the host's native shell by the callers
// (ops.go, client.go, server.go); the only per-OS differences here are the exit-code wrapper and
// the detach/kill idioms.
//
// One Host is one SSH connection, and on Windows one logon session: a drive `net use` maps is only
// visible to commands on the same connection, so a client's mount and the commands that use it
// always share a Host.
type Host struct {
	Machine
	ssh   *ssh.Client
	sftp  *sftp.Client
	stop  chan struct{}
	close sync.Once
}

// Result is a command's exit code and output.
type Result struct {
	Code   int
	Stdout string
	Stderr string
}

func (r Result) OK() bool { return r.Code == 0 }

// Output is stdout and stderr together, trimmed.
func (r Result) Output() string { return strings.TrimSpace(r.Stdout + "\n" + r.Stderr) }

// Err is nil when the command succeeded, else an error naming what failed and why.
func (r Result) Err(what string) error {
	if r.OK() {
		return nil
	}
	return fmt.Errorf("%s failed (exit %d): %s", what, r.Code, tail(r.Output(), 2000))
}

// Connect opens the SSH connection to a machine. A busy VM occasionally misses the connect
// window, so it tries three times before giving up.
func Connect(m Machine) (*Host, error) {
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		h, err := connectOnce(m)
		if err == nil {
			return h, nil
		}
		last = err
		time.Sleep(3 * time.Second)
	}
	return nil, fmt.Errorf("cannot reach %s (%s@%s): %v", m.Name, m.User, m.IP, last)
}

func connectOnce(m Machine) (*Host, error) {
	keyData, err := os.ReadFile(m.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("the rig's SSH key: %v (vagrant up in the provisioning folder makes it)", err)
	}
	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("the rig's SSH key %s: %v", m.KeyFile, err)
	}
	cfg := &ssh.ClientConfig{
		User:            m.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // a rebuilt VM has new host keys; the rig is ours
		Timeout:         8 * time.Second,
	}
	addr := net.JoinHostPort(m.IP, "22")
	conn, err := net.DialTimeout("tcp", addr, cfg.Timeout)
	if err != nil {
		return nil, err
	}
	// The handshake gets a deadline too: a half-up VM can accept the TCP connection and then say
	// nothing for minutes.
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	client := ssh.NewClient(c, chans, reqs)
	sf, err := sftp.NewClient(client)
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("sftp: %v", err)
	}
	h := &Host{Machine: m, ssh: client, sftp: sf, stop: make(chan struct{})}
	// Keepalives hold the connection open through long blocking commands (the stress workers run
	// in-band for minutes with no output).
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-h.stop:
				return
			case <-t.C:
				_, _, _ = client.SendRequest("keepalive@openssh.com", true, nil)
			}
		}
	}()
	return h, nil
}

// Close drops the connection. Safe to call twice.
func (h *Host) Close() {
	h.close.Do(func() {
		close(h.stop)
		_ = h.sftp.Close()
		_ = h.ssh.Close()
	})
}

// Unix is true for the hosts whose commands are bash/zsh (Linux and macOS).
func (h *Host) Unix() bool { return h.OS != Windows }

// Run runs a command and waits for it, up to timeout. On Windows the command is wrapped so the exit
// code reflects success for both cmdlets (terminating on error) and native commands (their own exit
// code), and the output comes back as UTF-8 whatever the console code page.
func (h *Host) Run(cmd string, timeout time.Duration) Result {
	if h.OS == Windows {
		cmd = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; $OutputEncoding=[Text.Encoding]::UTF8; $ErrorActionPreference='Stop'; " +
			cmd + "; exit $LASTEXITCODE"
	}
	return h.exec(cmd, timeout)
}

// RunLax is Run without the Windows error-to-exit-code wrapper: for best-effort commands whose
// stderr chatter (a `net use /delete` of nothing, say) must not count as failure.
func (h *Host) RunLax(cmd string, timeout time.Duration) Result {
	if h.OS == Windows {
		cmd = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ErrorActionPreference='Continue'; " + cmd + "; exit 0"
	}
	return h.exec(cmd, timeout)
}

func (h *Host) exec(cmd string, timeout time.Duration) Result {
	sess, err := h.ssh.NewSession()
	if err != nil {
		return Result{Code: -1, Stderr: "ssh session: " + err.Error()}
	}
	defer sess.Close()
	var out, errb bytes.Buffer
	sess.Stdout = &out
	sess.Stderr = &errb
	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()
	select {
	case err = <-done:
	case <-time.After(timeout):
		_ = sess.Signal(ssh.SIGKILL)
		_ = sess.Close()
		return Result{Code: -1, Stdout: out.String(), Stderr: fmt.Sprintf("timed out after %s: %s", timeout, errb.String())}
	}
	code := 0
	if err != nil {
		var exit *ssh.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitStatus()
		} else {
			code = -1
			errb.WriteString(" (" + err.Error() + ")")
		}
	}
	return Result{Code: code, Stdout: out.String(), Stderr: errb.String()}
}

// Upload copies a local file to a path on the host, making the parent directories.
func (h *Host) Upload(local, remote string) error {
	f, err := os.Open(local)
	if err != nil {
		return err
	}
	defer f.Close()
	return h.upload(f, remote)
}

// UploadBytes writes data to a path on the host.
func (h *Host) UploadBytes(data []byte, remote string) error {
	return h.upload(bytes.NewReader(data), remote)
}

func (h *Host) upload(r io.Reader, remote string) error {
	// Windows OpenSSH's SFTP server takes forward-slash paths, drive letter and all.
	p := strings.ReplaceAll(remote, `\`, "/")
	if err := h.sftp.MkdirAll(path.Dir(p)); err != nil {
		return fmt.Errorf("mkdir %s: %v", path.Dir(p), err)
	}
	w, err := h.sftp.Create(p)
	if err != nil {
		return fmt.Errorf("create %s: %v", p, err)
	}
	if _, err := io.Copy(w, r); err != nil {
		_ = w.Close()
		return fmt.Errorf("write %s: %v", p, err)
	}
	return w.Close()
}

// StartDetached launches a long-running process that outlives this SSH session, with its stdout
// and stderr appended to logFile. Stop it with Kill.
func (h *Host) StartDetached(exe, args, logFile string) error {
	if h.OS == Windows {
		// Windows OpenSSH kills a non-interactive exec session's process tree when the channel
		// closes, so Start-Process'd children die immediately. Win32_Process.Create spawns the
		// process detached from the SSH session (parented to the WMI host), so it survives. cmd
		// /S /C gives it the redirection. The first launch of a new binary can take tens of
		// seconds: Defender scans all of it first.
		line := fmt.Sprintf(`cmd.exe /S /C ""%s" %s >> "%s" 2>&1"`, exe, args, logFile)
		line = strings.ReplaceAll(line, "'", "''")
		r := h.Run(fmt.Sprintf(`$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = '%s'; CurrentDirectory = '%s' }; if ($r.ReturnValue -ne 0) { throw "Win32_Process.Create returned $($r.ReturnValue)" }`, line, h.RigDir()), 120*time.Second)
		return r.Err("start " + exe)
	}
	r := h.Run(fmt.Sprintf(`nohup %s %s >> %s 2>&1 &`, h.Q(exe), args, h.Q(logFile)), 30*time.Second)
	return r.Err("start " + exe)
}

// Kill ends every process running the named binary deployed under the rig directory. Best effort.
func (h *Host) Kill(image string) {
	if h.OS == Windows {
		h.RunLax(fmt.Sprintf(`taskkill /IM %s /F 2>$null`, image), 30*time.Second)
		return
	}
	// Match the deployed binary's full path, not just its name: `pkill -x` misses names longer than
	// the kernel's 15-character comm, and a bare `pkill -f name` would also match e.g. the `tart run
	// psmb-macos-1` process that IS the macOS VM on the Mac. Bracketing the first character keeps
	// pkill from matching its own command line.
	p := h.Join(h.RigDir(), "bin", image)
	h.RunLax(fmt.Sprintf(`pkill -f "[%s]%s" || true`, p[:1], p[1:]), 30*time.Second)
}

// Alive reports whether a process running the named deployed binary exists.
func (h *Host) Alive(image string) bool {
	var r Result
	if h.OS == Windows {
		name := strings.TrimSuffix(image, ".exe")
		r = h.RunLax(fmt.Sprintf(`if (Get-Process -Name '%s' -ErrorAction SilentlyContinue) { 'yes' } else { 'no' }`, name), 30*time.Second)
	} else {
		p := h.Join(h.RigDir(), "bin", image)
		r = h.RunLax(fmt.Sprintf(`pgrep -f "[%s]%s" >/dev/null && echo yes || echo no`, p[:1], p[1:]), 30*time.Second)
	}
	return strings.TrimSpace(r.Stdout) == "yes"
}

// RSSKiB is the resident memory of the process running the named deployed binary, in KiB (0 when
// there is none).
func (h *Host) RSSKiB(image string) int64 {
	var r Result
	if h.OS == Windows {
		name := strings.TrimSuffix(image, ".exe")
		r = h.RunLax(fmt.Sprintf(`$p = Get-Process -Name '%s' -ErrorAction SilentlyContinue | Select-Object -First 1; if ($p) { [math]::Floor($p.WorkingSet64 / 1024) } else { 0 }`, name), 30*time.Second)
	} else {
		p := h.Join(h.RigDir(), "bin", image)
		r = h.RunLax(fmt.Sprintf(`pid=$(pgrep -f "[%s]%s" | head -1); [ -n "$pid" ] && ps -o rss= -p "$pid" || echo 0`, p[:1], p[1:]), 30*time.Second)
	}
	var n int64
	_, _ = fmt.Sscan(strings.TrimSpace(r.Stdout), &n)
	return n
}

// ---- paths and quoting ----

// Sep is the host's path separator.
func (h *Host) Sep() string {
	if h.OS == Windows {
		return `\`
	}
	return "/"
}

// Join joins path elements with the host's separator.
func (h *Host) Join(parts ...string) string {
	out := strings.TrimRight(parts[0], `\/`)
	for _, p := range parts[1:] {
		out += h.Sep() + p
	}
	return out
}

// RigDir is the directory the rig's provisioning made for the tests on this host: the binaries
// under test go in bin/, the directories the server serves in serve/, logs in log/, the client's
// scratch files in scratch/, and Unix mount points in mnt-*.
func (h *Host) RigDir() string {
	switch h.OS {
	case Windows:
		return `C:\psmb-rig`
	case MacOS:
		return "/Users/" + h.User + "/psmb-rig"
	default:
		return "/home/" + h.User + "/psmb-rig"
	}
}

// Q quotes a string for the host's shell: single quotes, with the host's escape for a quote inside.
func (h *Host) Q(s string) string {
	if h.OS == Windows {
		return "'" + strings.ReplaceAll(s, "'", "''") + "'"
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func tail(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
