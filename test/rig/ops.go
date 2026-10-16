package rig

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Cross-OS file operations, run on a host through its shell: PowerShell on Windows (.NET APIs
// where a cmdlet's behaviour varies between PowerShell 5.1 and 7), bash on Linux, and on macOS the
// BSD userland (shasum, not sha256sum; stat -f, not stat -c; perl for byte-exact work, because
// macOS ships neither truncate(1) nor a GNU dd). Centralised here so every scenario shares one
// definition of "hash", "copy", "list", and they can't drift apart.
//
// Paths are the host's own (a mounted share's or a local directory's); every one is quoted with
// Host.Q, so the special-filename scenarios can use quotes, spaces and non-ASCII freely.

const opTimeout = 120 * time.Second

// Mkdir makes a directory and any missing parents.
func Mkdir(h *Host, dir string) error {
	if h.OS == Windows {
		return h.Run(fmt.Sprintf(`New-Item -ItemType Directory -Force -Path %s | Out-Null`, h.Q(dir)), opTimeout).Err("mkdir")
	}
	return h.Run(`mkdir -p `+h.Q(dir), opTimeout).Err("mkdir")
}

// MkdirStrict makes one directory and fails when it can't (it exists, or the share refuses).
func MkdirStrict(h *Host, dir string) error {
	if h.OS == Windows {
		return h.Run(fmt.Sprintf(`[IO.Directory]::CreateDirectory(%s) | Out-Null; if (-not (Test-Path -LiteralPath %s -PathType Container)) { throw 'not created' }`, h.Q(dir), h.Q(dir)), opTimeout).Err("mkdir")
	}
	return h.Run(`mkdir `+h.Q(dir), opTimeout).Err("mkdir")
}

// Remove deletes a file or directory tree. Best effort: it never fails.
func Remove(h *Host, p string) {
	if h.OS == Windows {
		h.RunLax(fmt.Sprintf(`if (Test-Path -LiteralPath %s) { Remove-Item -LiteralPath %s -Recurse -Force -ErrorAction SilentlyContinue }`, h.Q(p), h.Q(p)), opTimeout)
		return
	}
	h.RunLax(`rm -rf `+h.Q(p), opTimeout)
}

// RemoveStrict deletes a file or directory tree and fails when it can't.
func RemoveStrict(h *Host, p string) error {
	if h.OS == Windows {
		return h.Run(fmt.Sprintf(`Remove-Item -LiteralPath %s -Recurse -Force; if (Test-Path -LiteralPath %s) { throw 'still there' }`, h.Q(p), h.Q(p)), opTimeout).Err("remove")
	}
	return h.Run(fmt.Sprintf(`rm -r %s && ! [ -e %s ]`, h.Q(p), h.Q(p)), opTimeout).Err("remove")
}

// RemoveFile deletes one file (not a tree) and fails when it can't, including when it isn't there.
func RemoveFile(h *Host, p string) error {
	if h.OS == Windows {
		// Remove-Item, not [IO.File]::Delete: .NET's is a silent no-op on a missing file.
		return h.Run(fmt.Sprintf(`Remove-Item -LiteralPath %s -Force; if (Test-Path -LiteralPath %s) { throw 'still there' }`, h.Q(p), h.Q(p)), opTimeout).Err("delete")
	}
	return h.Run(`rm `+h.Q(p), opTimeout).Err("delete")
}

// Rmdir removes one directory, which must be empty: the share's "directory not empty" answer is
// what the delete scenario is after.
func Rmdir(h *Host, dir string) error {
	if h.OS == Windows {
		return h.Run(fmt.Sprintf(`[IO.Directory]::Delete(%s)`, h.Q(dir)), opTimeout).Err("rmdir")
	}
	return h.Run(`rmdir `+h.Q(dir), opTimeout).Err("rmdir")
}

// Exists reports whether a path exists.
func Exists(h *Host, p string) (bool, error) {
	var r Result
	if h.OS == Windows {
		r = h.Run(fmt.Sprintf(`if (Test-Path -LiteralPath %s) { 'yes' } else { 'no' }`, h.Q(p)), opTimeout)
	} else {
		r = h.Run(fmt.Sprintf(`[ -e %s ] && echo yes || echo no`, h.Q(p)), opTimeout)
	}
	if err := r.Err("exists"); err != nil {
		return false, err
	}
	return strings.TrimSpace(r.Stdout) == "yes", nil
}

// IsDir reports whether a path is a directory.
func IsDir(h *Host, p string) (bool, error) {
	var r Result
	if h.OS == Windows {
		r = h.Run(fmt.Sprintf(`if (Test-Path -LiteralPath %s -PathType Container) { 'yes' } else { 'no' }`, h.Q(p)), opTimeout)
	} else {
		r = h.Run(fmt.Sprintf(`[ -d %s ] && echo yes || echo no`, h.Q(p)), opTimeout)
	}
	if err := r.Err("isdir"); err != nil {
		return false, err
	}
	return strings.TrimSpace(r.Stdout) == "yes", nil
}

// Copy copies one file.
func Copy(h *Host, from, to string) error {
	if h.OS == Windows {
		return h.Run(fmt.Sprintf(`Copy-Item -LiteralPath %s -Destination %s -Force`, h.Q(from), h.Q(to)), 20*time.Minute).Err("copy")
	}
	return h.Run(fmt.Sprintf(`cp %s %s`, h.Q(from), h.Q(to)), 20*time.Minute).Err("copy")
}

// Hash is a file's SHA-256, lower-case hex, computed on the host.
func Hash(h *Host, p string) (string, error) {
	var r Result
	switch h.OS {
	case Windows:
		r = h.Run(fmt.Sprintf(`(Get-FileHash -Algorithm SHA256 -LiteralPath %s).Hash`, h.Q(p)), 20*time.Minute)
	case MacOS:
		r = h.Run(fmt.Sprintf(`shasum -a 256 %s | cut -c1-64`, h.Q(p)), 20*time.Minute)
	default:
		r = h.Run(fmt.Sprintf(`sha256sum %s | cut -c1-64`, h.Q(p)), 20*time.Minute)
	}
	if err := r.Err("hash"); err != nil {
		return "", err
	}
	return strings.ToLower(strings.TrimSpace(r.Stdout)), nil
}

// Size is a file's length in bytes.
func Size(h *Host, p string) (int64, error) {
	var r Result
	switch h.OS {
	case Windows:
		r = h.Run(fmt.Sprintf(`(Get-Item -LiteralPath %s -Force).Length`, h.Q(p)), opTimeout)
	case MacOS:
		r = h.Run(fmt.Sprintf(`stat -f %%z %s`, h.Q(p)), opTimeout)
	default:
		r = h.Run(fmt.Sprintf(`stat -c %%s %s`, h.Q(p)), opTimeout)
	}
	if err := r.Err("size"); err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(r.Stdout), 10, 64)
}

// ListNames is a directory's immediate children (without . and ..), as the host lists them.
func ListNames(h *Host, dir string) ([]string, error) {
	var r Result
	if h.OS == Windows {
		r = h.Run(fmt.Sprintf(`Get-ChildItem -LiteralPath %s -Force -Name`, h.Q(dir)), 10*time.Minute)
	} else {
		r = h.Run(`ls -A1 `+h.Q(dir), 10*time.Minute)
	}
	if err := r.Err("list"); err != nil {
		return nil, err
	}
	var names []string
	for _, l := range strings.Split(strings.ReplaceAll(r.Stdout, "\r", ""), "\n") {
		if l != "" {
			names = append(names, l)
		}
	}
	return names, nil
}

// CountEntries counts a directory's children the cheapest way the host has (no sort, no
// attributes): what a bare enumeration costs through the client.
func CountEntries(h *Host, dir string) (int, error) {
	var r Result
	if h.OS == Windows {
		r = h.Run(fmt.Sprintf(`@([IO.Directory]::EnumerateFileSystemEntries(%s)).Count`, h.Q(dir)), 10*time.Minute)
	} else {
		r = h.Run(fmt.Sprintf(`ls -f %s | grep -cv '^\.\.\?$'`, h.Q(dir)), 10*time.Minute)
	}
	if err := r.Err("count"); err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(r.Stdout))
}

// CountWithAttributes counts a directory's children the expensive way: a listing that fetches
// every entry's attributes (ls -l, Get-ChildItem), which is what Finder and Explorer do.
func CountWithAttributes(h *Host, dir string) (int, error) {
	var r Result
	if h.OS == Windows {
		r = h.Run(fmt.Sprintf(`@(Get-ChildItem -LiteralPath %s -Force | ForEach-Object { $_.Length }).Count`, h.Q(dir)), 10*time.Minute)
	} else {
		r = h.Run(fmt.Sprintf(`ls -lA %s | grep -c '^[-dl]'`, h.Q(dir)), 10*time.Minute)
	}
	if err := r.Err("list -l"); err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(r.Stdout))
}

// LookupMany stats each of the named entries of a directory one at a time, in one shell loop on
// the host, and fails on the first that is missing: how a client without directory enumeration
// shortcuts finds every file of a big folder.
func LookupMany(h *Host, dir string, names []string) error {
	var sb strings.Builder
	if h.OS == Windows {
		sb.WriteString("foreach ($n in @(")
		for i, n := range names {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString(h.Q(n))
		}
		sb.WriteString(fmt.Sprintf(")) { $null = (Get-Item -LiteralPath (Join-Path %s $n) -Force).Length }", h.Q(dir)))
	} else {
		stat := "stat -c %s"
		if h.OS == MacOS {
			stat = "stat -f %z"
		}
		sb.WriteString("for n in")
		for _, n := range names {
			sb.WriteString(" " + h.Q(n))
		}
		sb.WriteString(fmt.Sprintf(`; do %s %s/"$n" >/dev/null || exit 1; done`, stat, h.Q(dir)))
	}
	return h.Run(sb.String(), 10*time.Minute).Err("lookups")
}

// ReadText reads a (short) file as text.
func ReadText(h *Host, p string) (string, error) {
	var r Result
	if h.OS == Windows {
		r = h.Run(fmt.Sprintf(`[IO.File]::ReadAllText(%s, [Text.Encoding]::UTF8)`, h.Q(p)), opTimeout)
	} else {
		r = h.Run(`cat `+h.Q(p), opTimeout)
	}
	if err := r.Err("read"); err != nil {
		return "", err
	}
	return strings.TrimRight(strings.ReplaceAll(r.Stdout, "\r\n", "\n"), "\n"), nil
}

// WriteText writes a (short) file as UTF-8 text, creating or replacing it.
func WriteText(h *Host, p, text string) error {
	if h.OS == Windows {
		return h.Run(fmt.Sprintf(`[IO.File]::WriteAllText(%s, %s, (New-Object Text.UTF8Encoding $false))`, h.Q(p), h.Q(text)), opTimeout).Err("write")
	}
	return h.Run(fmt.Sprintf(`printf '%%s' %s > %s`, h.Q(text), h.Q(p)), opTimeout).Err("write")
}

// Append appends the bytes of src onto target (a write at end of file).
func Append(h *Host, target, src string) error {
	if h.OS == Windows {
		return h.Run(fmt.Sprintf(`$b=[IO.File]::ReadAllBytes(%s); $f=[IO.File]::Open(%s,[IO.FileMode]::Append,[IO.FileAccess]::Write); try { $f.Write($b,0,$b.Length) } finally { $f.Close() }`, h.Q(src), h.Q(target)), 10*time.Minute).Err("append")
	}
	return h.Run(fmt.Sprintf(`cat %s >> %s`, h.Q(src), h.Q(target)), 10*time.Minute).Err("append")
}

// Rename renames a file or directory: the rename(2) / MoveFileEx semantics the SMB client maps
// to, replacing an existing file at the destination. (Not mv: for a name that differs only in
// case, mv on a case-insensitive share says the two are identical and refuses.)
func Rename(h *Host, from, to string) error {
	if h.OS == Windows {
		return h.Run(fmt.Sprintf(`Move-Item -LiteralPath %s -Destination %s -Force`, h.Q(from), h.Q(to)), opTimeout).Err("rename")
	}
	return h.Run(fmt.Sprintf(`perl -e 'rename($ARGV[0], $ARGV[1]) or die "rename: $!\n"' %s %s`, h.Q(from), h.Q(to)), opTimeout).Err("rename")
}

// Truncate sets a file's length, shrinking it or growing it with zeros. The file must exist.
func Truncate(h *Host, p string, size int64) error {
	if h.OS == Windows {
		return h.Run(fmt.Sprintf(`$f=[IO.File]::Open(%s,[IO.FileMode]::Open,[IO.FileAccess]::Write); try { $f.SetLength(%d) } finally { $f.Close() }`, h.Q(p), size), opTimeout).Err("truncate")
	}
	return h.Run(fmt.Sprintf(`perl -e 'open(F, "+<", $ARGV[0]) or die "open: $!\n"; truncate(F, $ARGV[1]) or die "truncate: $!\n"; close F' %s %d`, h.Q(p), size), opTimeout).Err("truncate")
}

// WriteAtMiB overwrites the file at a MiB-aligned offset with the bytes of src (a write in the
// middle of a file, without truncating it; past the end it grows the file).
func WriteAtMiB(h *Host, p string, offMiB int64, src string) error {
	if h.OS == Windows {
		return h.Run(fmt.Sprintf(`$b=[IO.File]::ReadAllBytes(%s); $f=[IO.File]::Open(%s,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::Write); try { $f.Seek(%d, 'Begin') | Out-Null; $f.Write($b,0,$b.Length) } finally { $f.Close() }`, h.Q(src), h.Q(p), offMiB<<20), 10*time.Minute).Err("write at")
	}
	return h.Run(fmt.Sprintf(`dd if=%s of=%s bs=1048576 seek=%d conv=notrunc 2>/dev/null`, h.Q(src), h.Q(p), offMiB), 10*time.Minute).Err("write at")
}

// HashRangeMiB is the SHA-256 of a MiB-aligned byte range of a file (a random-access read).
func HashRangeMiB(h *Host, p string, offMiB, lenMiB int64) (string, error) {
	var r Result
	switch h.OS {
	case Windows:
		r = h.Run(fmt.Sprintf(`$f=[IO.File]::Open(%s,[IO.FileMode]::Open,[IO.FileAccess]::Read); try { $f.Seek(%d,'Begin') | Out-Null; $b=New-Object byte[] %d; $n=0; while ($n -lt $b.Length) { $k=$f.Read($b,$n,$b.Length-$n); if ($k -le 0) { break }; $n+=$k }; if ($n -ne $b.Length) { throw "short read: $n" }; $sha=[Security.Cryptography.SHA256]::Create(); ([BitConverter]::ToString($sha.ComputeHash($b)) -replace '-','').ToLower() } finally { $f.Close() }`, h.Q(p), offMiB<<20, lenMiB<<20), 10*time.Minute)
	case MacOS:
		r = h.Run(fmt.Sprintf(`dd if=%s bs=1048576 skip=%d count=%d 2>/dev/null | shasum -a 256 | cut -c1-64`, h.Q(p), offMiB, lenMiB), 10*time.Minute)
	default:
		r = h.Run(fmt.Sprintf(`dd if=%s bs=1048576 skip=%d count=%d 2>/dev/null | sha256sum | cut -c1-64`, h.Q(p), offMiB, lenMiB), 10*time.Minute)
	}
	if err := r.Err("hash range"); err != nil {
		return "", err
	}
	return strings.ToLower(strings.TrimSpace(r.Stdout)), nil
}

// ZeroHashMiB is the SHA-256 of n MiB of zeros: what a hole in a sparse file must read as.
func ZeroHashMiB(n int) string {
	s := sha256.New()
	z := make([]byte, 1<<20)
	for i := 0; i < n; i++ {
		s.Write(z)
	}
	return hex.EncodeToString(s.Sum(nil))
}

// SetMtime sets a file's modification time (seconds since the epoch, UTC).
func SetMtime(h *Host, p string, epoch int64) error {
	if h.OS == Windows {
		return h.Run(fmt.Sprintf(`(Get-Item -LiteralPath %s -Force).LastWriteTimeUtc = [DateTimeOffset]::FromUnixTimeSeconds(%d).UtcDateTime`, h.Q(p), epoch), opTimeout).Err("set mtime")
	}
	return h.Run(fmt.Sprintf(`perl -e 'utime($ARGV[1], $ARGV[1], $ARGV[0]) or die "utime: $!\n"' %s %d`, h.Q(p), epoch), opTimeout).Err("set mtime")
}

// Mtime reads a file's modification time (seconds since the epoch, UTC).
func Mtime(h *Host, p string) (int64, error) {
	var r Result
	switch h.OS {
	case Windows:
		r = h.Run(fmt.Sprintf(`[DateTimeOffset]::new((Get-Item -LiteralPath %s -Force).LastWriteTimeUtc).ToUnixTimeSeconds()`, h.Q(p)), opTimeout)
	case MacOS:
		r = h.Run(fmt.Sprintf(`stat -f %%m %s`, h.Q(p)), opTimeout)
	default:
		r = h.Run(fmt.Sprintf(`stat -c %%Y %s`, h.Q(p)), opTimeout)
	}
	if err := r.Err("mtime"); err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(r.Stdout), 10, 64)
}

// DiskSpace is the total and free space, in bytes, of the volume a path is on (what df and
// Explorer show for a mounted share).
func DiskSpace(h *Host, p string) (total, free int64, err error) {
	var r Result
	switch h.OS {
	case Windows:
		r = h.Run(fmt.Sprintf(`$d = New-Object IO.DriveInfo((Resolve-Path -LiteralPath %s).Path.Substring(0,3)); "$($d.TotalSize) $($d.AvailableFreeSpace)"`, h.Q(p)), opTimeout)
	case MacOS:
		r = h.Run(fmt.Sprintf(`df -k %s | tail -1 | awk '{print $2*1024, $4*1024}'`, h.Q(p)), opTimeout)
	default:
		r = h.Run(fmt.Sprintf(`df -k --output=size,avail %s | tail -1 | awk '{print $1*1024, $2*1024}'`, h.Q(p)), opTimeout)
	}
	if err = r.Err("df"); err != nil {
		return 0, 0, err
	}
	if _, err = fmt.Sscan(strings.TrimSpace(r.Stdout), &total, &free); err != nil {
		return 0, 0, fmt.Errorf("df output %q: %v", r.Stdout, err)
	}
	return total, free, nil
}

// RandomFile makes a file of random bytes on the host (so a 256 MiB payload needn't cross the LAN
// twice) and returns its SHA-256.
func RandomFile(h *Host, p string, size int64) (string, error) {
	var r Result
	switch {
	case h.OS == Windows:
		r = h.Run(fmt.Sprintf(`$rng=[Security.Cryptography.RandomNumberGenerator]::Create(); $b=New-Object byte[] 1048576; $left=[int64]%d; $f=[IO.File]::Create(%s); try { while ($left -gt 0) { $n=[int][math]::Min($left,$b.Length); $rng.GetBytes($b); $f.Write($b,0,$n); $left-=$n } } finally { $f.Close() }`, size, h.Q(p)), 20*time.Minute)
	case size == 0:
		r = h.Run(`: > `+h.Q(p), opTimeout) // BSD head refuses -c 0
	default:
		r = h.Run(fmt.Sprintf(`head -c %d /dev/urandom > %s`, size, h.Q(p)), 20*time.Minute)
	}
	if err := r.Err("random file"); err != nil {
		return "", err
	}
	return Hash(h, p)
}

// NumberedFiles creates f_1.dat .. f_n.dat in a directory, each containing "content-i", in one
// shell loop on the host (one SSH round trip, n CREATE/WRITE/CLOSE sequences on the wire).
func NumberedFiles(h *Host, dir string, n int) error {
	if h.OS == Windows {
		return h.Run(fmt.Sprintf(`$d=%s; 1..%d | ForEach-Object { [IO.File]::WriteAllText("$d\f_$_.dat", "content-$_") }`, h.Q(dir), n), 30*time.Minute).Err("numbered files")
	}
	return h.Run(fmt.Sprintf(`d=%s; for i in $(seq 1 %d); do printf 'content-%%s' "$i" > "$d/f_$i.dat" || exit 1; done`, h.Q(dir), n), 30*time.Minute).Err("numbered files")
}

// Scripts runs several scripts on the host at once (bash on Unix, PowerShell on Windows; each a
// whole script, exiting non-zero on failure) and returns each one's result, in order. They run
// as separate processes in this Host's logon session, so a mapped drive is visible to them.
func Scripts(h *Host, workDir string, scripts []string, timeout time.Duration) ([]Result, error) {
	if err := Mkdir(h, workDir); err != nil {
		return nil, err
	}
	ext := ".sh"
	if h.OS == Windows {
		ext = ".ps1"
	}
	// Each script goes in a file; a runner starts them all, waits, and leaves each one's exit code
	// in par_<i>.code and output in par_<i>.out.
	var runner strings.Builder
	if h.OS == Windows {
		runner.WriteString("$procs = @(); ")
	}
	for i, s := range scripts {
		p := h.Join(workDir, fmt.Sprintf("par_%d%s", i, ext))
		body := "set -e\n" + s + "\n"
		if h.OS == Windows {
			body = "$ErrorActionPreference='Stop'\n" + s + "\nexit 0\n"
		}
		if err := h.UploadBytes([]byte(body), p); err != nil {
			return nil, err
		}
		out := h.Join(workDir, fmt.Sprintf("par_%d.out", i))
		code := h.Join(workDir, fmt.Sprintf("par_%d.code", i))
		if h.OS == Windows {
			runner.WriteString(fmt.Sprintf(`$procs += Start-Process powershell -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',%s -RedirectStandardOutput %s -RedirectStandardError %s -PassThru -WindowStyle Hidden; `,
				h.Q(p), h.Q(out), h.Q(out+".err")))
		} else {
			runner.WriteString(fmt.Sprintf(`( bash %s > %s 2>&1; echo $? > %s ) & `, h.Q(p), h.Q(out), h.Q(code)))
		}
	}
	if h.OS == Windows {
		runner.WriteString(fmt.Sprintf(`$procs | Wait-Process; $i = 0; foreach ($p in $procs) { [IO.File]::WriteAllText((Join-Path %s "par_$i.code"), "$($p.ExitCode)"); $i++ }`, h.Q(workDir)))
	} else {
		runner.WriteString("wait")
	}
	if r := h.Run(runner.String(), timeout); !r.OK() {
		return nil, r.Err("parallel scripts")
	}
	// Collect: one command prints every script's code and output with markers.
	var collect strings.Builder
	for i := range scripts {
		out := h.Join(workDir, fmt.Sprintf("par_%d.out", i))
		code := h.Join(workDir, fmt.Sprintf("par_%d.code", i))
		if h.OS == Windows {
			collect.WriteString(fmt.Sprintf(`"==RESULT $([IO.File]::ReadAllText(%s).Trim())"; Get-Content -LiteralPath %s -Raw -ErrorAction SilentlyContinue; Get-Content -LiteralPath %s -Raw -ErrorAction SilentlyContinue; `, h.Q(code), h.Q(out), h.Q(out+".err")))
		} else {
			collect.WriteString(fmt.Sprintf(`echo "==RESULT $(cat %s)"; cat %s; `, h.Q(code), h.Q(out)))
		}
	}
	r := h.Run(collect.String(), opTimeout)
	if err := r.Err("collect results"); err != nil {
		return nil, err
	}
	var results []Result
	for _, chunk := range strings.Split(strings.ReplaceAll(r.Stdout, "\r\n", "\n"), "==RESULT ")[1:] {
		nl := strings.IndexByte(chunk, '\n')
		if nl < 0 {
			nl = len(chunk)
		}
		code, _ := strconv.Atoi(strings.TrimSpace(chunk[:nl]))
		body := ""
		if nl < len(chunk) {
			body = chunk[nl+1:]
		}
		results = append(results, Result{Code: code, Stdout: body})
	}
	if len(results) != len(scripts) {
		return nil, fmt.Errorf("parallel scripts: %d results for %d scripts:\n%s", len(results), len(scripts), tail(r.Stdout, 3000))
	}
	return results, nil
}

// ---- waits: a client may cache what it saw for a few seconds (Windows' directory and file-info
// caches are 10 s), so anything one party checks after another party acted is polled. ----

func WaitFor(timeout time.Duration, cond func() (bool, error)) error {
	deadline := time.Now().Add(timeout)
	var last error
	for {
		ok, err := cond()
		if ok {
			return nil
		}
		last = err
		if time.Now().After(deadline) {
			if last != nil {
				return fmt.Errorf("gave up after %s: %v", timeout, last)
			}
			return fmt.Errorf("gave up after %s", timeout)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// WaitForHash waits until a file exists with the given SHA-256.
func WaitForHash(h *Host, p, want string, timeout time.Duration) error {
	var got string
	err := WaitFor(timeout, func() (bool, error) {
		ok, err := Exists(h, p)
		if err != nil || !ok {
			return false, fmt.Errorf("%s not there", p)
		}
		got, err = Hash(h, p)
		if err != nil {
			return false, err
		}
		return got == want, fmt.Errorf("%s has hash %s, want %s", p, got, want)
	})
	return err
}

// WaitForGone waits until a path no longer exists.
func WaitForGone(h *Host, p string, timeout time.Duration) error {
	return WaitFor(timeout, func() (bool, error) {
		ok, err := Exists(h, p)
		if err != nil {
			return false, err
		}
		return !ok, fmt.Errorf("%s still exists", p)
	})
}

// WaitForCount waits until a directory has exactly n children.
func WaitForCount(h *Host, dir string, n int, timeout time.Duration) error {
	return WaitFor(timeout, func() (bool, error) {
		got, err := CountEntries(h, dir)
		if err != nil {
			return false, err
		}
		return got == n, fmt.Errorf("%s has %d entries, want %d", dir, got, n)
	})
}
