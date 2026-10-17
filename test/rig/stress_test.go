package rig

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestStress loads one server with every other machine of the rig at once, for a fixed time, with
// the psmbstress worker (test/rig/worker) running on each client: small-file churn, medium and
// large files with random-offset reads, publish-by-rename, in-place overwrites, appends and
// truncates, directory trees with renames, listing checks, a shared corpus, and cross-client reads
// of what the other clients published. Every byte read is verified against deterministic content,
// so "passed" means every client got exactly what was expected.
//
// Byte-perfect results alone aren't enough: SMB clients reconnect and retry transparently, which
// can hide a server that drops connections. A leg also fails on reconnect or signing errors in the
// client OS logs, ERROR/panic lines in the server log, a stalled operation, the server dying or
// its memory not coming back down, and on the audit of the backing store (every published file
// present and byte-exact, nothing left over).
//
//	PSMB_STRESS_SECONDS=300 go test ./rig -run TestStress -v -timeout 2h
//	PSMB_STRESS_LEGS=windows                 only the Windows-hosted server
//	PSMB_STRESS_WORKERS=8 PSMB_STRESS_LARGE_MB=64 PSMB_STRESS_SEED=42
func TestStress(t *testing.T) {
	s := requireRig(t)
	rep := newReport("stress")
	defer rep.write(t)
	seconds := envInt("PSMB_STRESS_SECONDS", 120)
	workers := envInt("PSMB_STRESS_WORKERS", 4)
	largeMB := envInt("PSMB_STRESS_LARGE_MB", 32)
	seed := uint64(envInt("PSMB_STRESS_SEED", rand.Intn(1<<30)+1))
	legs := strings.ToLower(os.Getenv("PSMB_STRESS_LEGS"))
	for _, serverOS := range AllOS {
		if legs != "" && !strings.Contains(legs, string(serverOS)) {
			continue
		}
		t.Run(string(serverOS)+"-server", func(t *testing.T) {
			start := time.Now()
			note := runLeg(t, s, serverOS, seconds, workers, largeMB, seed)
			rep.add(t, string(serverOS)+"-server", fmt.Sprintf("barrage_%ds", seconds), start, note)
		})
	}
}

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil && v > 0 {
		return v
	}
	return def
}

// What a worker reports (see worker/main.go).
type workerResult struct {
	Name         string `json:"name"`
	OS           string `json:"os"`
	DurationSec  float64
	TotalOps     int64 `json:"totalOps"`
	BytesWritten int64 `json:"bytesWritten"`
	BytesRead    int64 `json:"bytesRead"`
	Ops          map[string]struct {
		Count, Errors         int64
		P50ms, P95ms, MaxMs   float64
		BytesWritten, BytesRead int64
	} `json:"ops"`
	FailureCount int      `json:"failureCount"`
	Stalls       int      `json:"stalls"`
	Stuck        []string `json:"stuck"`
	Failures     []struct {
		Time, Op, Path, Err string
		Worker              int
	} `json:"failures"`
	Expected  []struct {
		Path string `json:"path"`
		Size int64  `json:"size"`
	} `json:"expected"`
	CleanExit bool `json:"cleanExit"`
}

type auditResult struct {
	Verified   int      `json:"verified"`
	Bytes      int64    `json:"bytes"`
	Mismatches []string `json:"mismatches"`
	Missing    []string `json:"missing"`
	Strays     []string `json:"strays"`
}

type stressClient struct {
	h       *Host
	tag     string
	mount   *Client
	dialect string
	result  *workerResult
	infra   string
}

func runLeg(t *testing.T, s *Settings, serverOS OS, seconds, workers, largeMB int, seed uint64) string {
	servers := s.Of(serverOS)
	if len(servers) < 2 {
		t.Skipf("the rig has fewer than two %s machines", serverOS)
	}
	sm := servers[1]
	S := connect(t, sm)

	var report strings.Builder
	say := func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		report.WriteString(line + "\n")
		t.Log(line)
	}
	var problems, infra []string

	// The clients: every other machine that can be reached.
	var clients []*stressClient
	for _, m := range s.Machines {
		if m.Name == sm.Name {
			continue
		}
		h, err := Connect(m)
		if err != nil {
			infra = append(infra, fmt.Sprintf("without %s: %v", m.Name, err))
			continue
		}
		t.Cleanup(h.Close)
		clients = append(clients, &stressClient{h: h, tag: m.Name})
	}
	if len(clients) < 2 {
		t.Skipf("only %d client machine(s) reachable: %s", len(clients), strings.Join(infra, "; "))
	}

	// Deploy the worker everywhere (in parallel), and the server.
	workerPaths := map[*Host]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, h := range append([]*Host{S}, hostsOf(clients)...) {
		wg.Add(1)
		go func(h *Host) {
			defer wg.Done()
			h.Kill(image(h.OS, workerImage))
			p, err := Deploy(h, Binary(h.OS, workerImage), workerImage)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				infra = append(infra, fmt.Sprintf("%s: deploying the worker: %v", h.Name, err))
				return
			}
			workerPaths[h] = p
		}(h)
	}
	wg.Wait()
	if workerPaths[S] == "" {
		t.Fatalf("no worker on the server host: %s", strings.Join(infra, "; "))
	}

	srv := StartServer(t, S, s.Port, ServerOpts{Shares: []Share{{Name: shareData}}, User: smbUser, Pass: smbPass})
	backing := srv.Path(shareData)
	if r := S.Run(invoke(S, workerPaths[S], fmt.Sprintf(`seed -dir %s -seed %d`, S.Q(backing), seed)), 10*time.Minute); !r.OK() {
		t.Fatalf("seeding the corpus: %v", r.Err("seed"))
	}
	rss0 := srv.RSSKiB()
	say("=== STRESS  portable-smb-server on %s (%s)  |  %ds  |  seed %d  |  %d workers per client, large files up to %d MiB ===",
		sm.Name, S.IP, seconds, seed, workers, largeMB)
	say("    server at rest: %d MiB resident", rss0>>10)

	// Mount: the Linux clients alternate dialects so both signing algorithms are under load at
	// once (2.1 signs with HMAC-SHA256, 3.x with AES-CMAC; Windows and macOS negotiate 3.0.2).
	linuxDialects := []string{"2.1", "3.02"}
	var mounted []*stressClient
	for _, c := range clients {
		if c.h.OS == Linux {
			c.dialect = linuxDialects[0]
			linuxDialects = append(linuxDialects[1:], linuxDialects[0])
			c.h.RunLax("sudo dmesg -C", opTimeout)
		}
		ForceUnmountAll(c.h)
		c.mount = &Client{Host: c.h, ServerIP: S.IP, Share: shareData, Port: s.Port, User: smbUser, Pass: smbPass, Vers: c.dialect, Tag: fmt.Sprintf("s%d", seed%1000)}
		if err := c.mount.Mount(); err != nil {
			infra = append(infra, err.Error())
			continue
		}
		t.Cleanup(c.mount.Unmount)
		mounted = append(mounted, c)
	}
	clients = mounted
	var names []string
	for _, c := range clients {
		n := c.tag
		if c.dialect != "" {
			n += "(smb" + c.dialect + ")"
		}
		names = append(names, n)
	}
	say("    %d concurrent clients: %s", len(clients), strings.Join(names, ", "))

	// The barrage.
	loadStart := time.Now()
	opTimeoutS := 120
	timeout := time.Duration(seconds+opTimeoutS+180) * time.Second
	wg = sync.WaitGroup{}
	for _, c := range clients {
		wg.Add(1)
		go func(c *stressClient) {
			defer wg.Done()
			if workerPaths[c.h] == "" {
				c.infra = "no worker deployed"
				return
			}
			args := fmt.Sprintf(`run -root %s -name %s -seed %d -duration %ds -workers %d -large-max-mb %d -op-timeout %ds`,
				c.h.Q(c.mount.Root), c.tag, seed, seconds, workers, largeMB, opTimeoutS)
			r := c.h.Run(invoke(c.h, workerPaths[c.h], args), timeout)
			var line string
			for _, l := range strings.Split(r.Stdout, "\n") {
				if l = strings.TrimSpace(l); strings.HasPrefix(l, "{") {
					line = l
				}
			}
			if line == "" {
				c.infra = fmt.Sprintf("no result from the worker (exit %d): %s", r.Code, tail(r.Output(), 600))
				return
			}
			var res workerResult
			if err := json.Unmarshal([]byte(line), &res); err != nil {
				c.infra = "unreadable worker result: " + err.Error()
				return
			}
			c.result = &res
		}(c)
	}
	wg.Wait()

	// The workers' own verdicts.
	say("")
	say("    %-18s%8s%12s%12s%10s%8s", "client", "ops", "written", "read", "failures", "stalls")
	var done []*workerResult
	for _, c := range clients {
		if c.result == nil {
			say("    %-18s  -- %s", c.tag, c.infra)
			infra = append(infra, c.tag+": "+c.infra)
			continue
		}
		r := c.result
		done = append(done, r)
		hung := ""
		if !r.CleanExit {
			hung = "   HUNG: " + strings.Join(r.Stuck, "; ")
		}
		say("    %-18s%8d%9d MiB%9d MiB%10d%8d%s", c.tag, r.TotalOps, r.BytesWritten>>20, r.BytesRead>>20, r.FailureCount, r.Stalls, hung)
		if r.FailureCount > 0 || !r.CleanExit {
			problems = append(problems, fmt.Sprintf("%s: %d failure(s), %d stall(s)%s", c.tag, r.FailureCount, r.Stalls, hung))
			for i, f := range r.Failures {
				if i == 5 {
					break
				}
				problems = append(problems, fmt.Sprintf("    %s [%s] %s %s: %s", c.tag, f.Time, f.Op, f.Path, tail(f.Err, 400)))
			}
		}
	}
	if len(done) > 0 {
		var ops, written, read int64
		for _, r := range done {
			ops += r.TotalOps
			written += r.BytesWritten
			read += r.BytesRead
		}
		say("    %-18s%8d%9d MiB%9d MiB      = %.1f ops/s, %.1f MiB/s verified, from %d clients",
			"TOTAL", ops, written>>20, read>>20, float64(ops)/float64(seconds), float64(written+read)/(1<<20)/float64(seconds), len(done))
		say("")
		say("    %-14s%8s%8s%10s%10s%10s    (p50/p95: worst client)", "operation", "count", "errors", "p50 ms", "p95 ms", "max ms")
		opNames := map[string]bool{}
		for _, r := range done {
			for k := range r.Ops {
				opNames[k] = true
			}
		}
		var sorted []string
		for k := range opNames {
			sorted = append(sorted, k)
		}
		sort.Strings(sorted)
		for _, op := range sorted {
			var count, errs int64
			var p50, p95, max float64
			for _, r := range done {
				if st, ok := r.Ops[op]; ok {
					count += st.Count
					errs += st.Errors
					p50 = maxf(p50, st.P50ms)
					p95 = maxf(p95, st.P95ms)
					max = maxf(max, st.MaxMs)
				}
			}
			say("    %-14s%8d%8d%10.0f%10.0f%10.0f", op, count, errs, p50, p95, max)
			if op == "randio" && count > 0 {
				// 64 requests of 4 KiB per operation: the per-request round trip, as an
				// application with a file open experiences it.
				say("    %-14s%8s%8s%10.1f%10.1f%10.1f    (one 4 KiB request, = randio / 64)", "  per request", "", "", p50/64, p95/64, max/64)
			}
		}
	}

	// The client OS logs, read for the time under load only, before unmounting (macOS logs a
	// burst of "reconnect" on every unmount, even from the healthiest of servers).
	say("")
	window := int(time.Since(loadStart).Seconds()) - 5
	for _, c := range clients {
		lines, bad := clientLogProblems(c, S.IP, window)
		say("    %s client log: %d SMB line(s), %d suspicious", c.tag, len(lines), len(bad))
		for i, l := range bad {
			if i == 10 {
				break
			}
			say("        ! %s", tail(l, 300))
			problems = append(problems, c.tag+" client log: "+tail(l, 300))
		}
	}
	for _, c := range clients {
		c.mount.Unmount()
	}

	// The server: alive, quiet, and back down in memory.
	say("")
	if !srv.Alive() {
		problems = append(problems, "the server died under load; its log ends: "+tail(srv.LogTail(20), 1500))
	} else {
		time.Sleep(10 * time.Second)
		rss1 := srv.RSSKiB()
		say("    server after the load: %d MiB resident (at rest: %d MiB)", rss1>>10, rss0>>10)
		if rss1 > rss0*4+200<<10 {
			problems = append(problems, fmt.Sprintf("the server holds %d MiB after the load, from %d MiB at rest: a leak?", rss1>>10, rss0>>10))
		}
	}
	logBad := srv.LogProblems(nil)
	say("    server log: %d problem line(s)", len(logBad))
	for i, l := range logBad {
		if i == 10 {
			break
		}
		say("        ! %s", tail(l, 300))
		problems = append(problems, "server log: "+tail(l, 300))
	}

	// The audit of the backing store, on the server host.
	var expected []map[string]any
	for _, r := range done {
		for _, e := range r.Expected {
			expected = append(expected, map[string]any{"path": e.Path, "size": e.Size})
		}
	}
	manifest, _ := json.Marshal(expected)
	manifestPath := S.Join(S.RigDir(), "scratch", "stress-manifest.json")
	if err := S.UploadBytes(manifest, manifestPath); err != nil {
		infra = append(infra, "uploading the manifest: "+err.Error())
	} else {
		r := S.Run(invoke(S, workerPaths[S], fmt.Sprintf(`audit -dir %s -seed %d -manifest %s`, S.Q(backing), seed, S.Q(manifestPath))), 30*time.Minute)
		var line string
		for _, l := range strings.Split(r.Stdout, "\n") {
			if l = strings.TrimSpace(l); strings.HasPrefix(l, "{") {
				line = l
			}
		}
		var audit auditResult
		if line == "" || json.Unmarshal([]byte(line), &audit) != nil {
			infra = append(infra, fmt.Sprintf("the audit produced no result (exit %d): %s", r.Code, tail(r.Output(), 400)))
		} else {
			say("    audit of the backing store: %d files / %d MiB verified byte-for-byte (%d published by clients + the corpus); %d mismatched, %d missing, %d stray",
				audit.Verified, audit.Bytes>>20, len(expected), len(audit.Mismatches), len(audit.Missing), len(audit.Strays))
			for i, m := range audit.Mismatches {
				if i == 10 {
					break
				}
				problems = append(problems, "audit: "+m)
			}
			for i, m := range audit.Missing {
				if i == 10 {
					break
				}
				problems = append(problems, "audit: published file missing from the backing store: "+m)
			}
			allClean := len(done) == len(clients)
			for _, r := range done {
				allClean = allClean && r.FailureCount == 0 && r.CleanExit
			}
			if len(audit.Strays) > 0 {
				say("        strays: %s", strings.Join(audit.Strays[:min(len(audit.Strays), 8)], ", "))
				if allClean {
					problems = append(problems, fmt.Sprintf("audit: %d leftover file(s) on the server after a clean run, e.g. %s", len(audit.Strays), strings.Join(audit.Strays[:min(len(audit.Strays), 5)], ", ")))
				}
			}
		}
	}

	// The report file, then the verdict.
	if len(problems) > 0 {
		report.WriteString("\nPROBLEMS:\n  " + strings.Join(problems, "\n  ") + "\n")
	}
	if len(infra) > 0 {
		report.WriteString("\nINFRASTRUCTURE:\n  " + strings.Join(infra, "\n  ") + "\n")
	}
	if err := os.MkdirAll(ResultsDir(), 0o755); err == nil {
		p := fmt.Sprintf("%s/stress-%s-%s.txt", ResultsDir(), serverOS, time.Now().Format("20060102-150405"))
		if err := os.WriteFile(p, []byte(report.String()), 0o644); err == nil {
			t.Logf("report: %s", p)
		}
	}
	if len(problems) > 0 {
		t.Errorf("%d problem(s):\n  %s", len(problems), strings.Join(problems, "\n  "))
	}
	if len(infra) > 0 && len(problems) == 0 {
		t.Skipf("no failures, but the leg did not run completely: %s", strings.Join(infra, "; "))
	}
	var totalOps int64
	for _, r := range done {
		totalOps += r.TotalOps
	}
	return fmt.Sprintf("%d clients, %d ops", len(done), totalOps)
}

func hostsOf(cs []*stressClient) []*Host {
	var out []*Host
	for _, c := range cs {
		out = append(out, c.h)
	}
	return out
}

func invoke(h *Host, exe, args string) string {
	if h.OS == Windows {
		return fmt.Sprintf(`& %s %s`, h.Q(exe), args)
	}
	return fmt.Sprintf(`%s %s`, h.Q(exe), args)
}

func maxf(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// SMB clients reconnect and retry transparently, so a server that drops connections can still
// yield byte-perfect results. These are the client-side fingerprints of that.
var (
	linuxBad = regexp.MustCompile(`(?i)reconnect|not respond|signature|sign fail|send error|error -\d+|status code returned|invalid|overflow|unmatched`)
	macBad   = regexp.MustCompile(`(?i)bad smb|signature|sign.*fail`)
)

// clientLogProblems reads the client's SMB log for the last window seconds: all the lines, and the
// suspicious ones.
func clientLogProblems(c *stressClient, serverIP string, window int) (lines, bad []string) {
	h := c.h
	if window < 1 {
		window = 1
	}
	split := func(s string) []string {
		var out []string
		for _, l := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				out = append(out, l)
			}
		}
		return out
	}
	switch h.OS {
	case Linux:
		lines = split(h.RunLax(`sudo dmesg | grep -iE 'cifs|smb' | tail -n 200; true`, opTimeout).Stdout)
		for _, l := range lines {
			if linuxBad.MatchString(l) {
				bad = append(bad, l)
			}
		}
	case MacOS:
		// The session under test is the one behind this leg's mount point, and smbutil counts the
		// times it had to reconnect. The smbfs log can't be read that way: it mixes in every other
		// session on the Mac (the user's own mounts, Finder's), so it's read for protocol
		// complaints only. The full path matters: in zsh a bare `log` is a shell builtin.
		shares := h.RunLax(fmt.Sprintf(`smbutil statshares -m %s 2>&1; true`, h.Q(c.mount.Root)), opTimeout).Stdout
		lines = split(h.RunLax(fmt.Sprintf(`/usr/bin/log show --start "$(date -v-%dS '+%%Y-%%m-%%d %%H:%%M:%%S')" --style compact --predicate 'sender == "smbfs"' 2>/dev/null | grep -v '^Timestamp' | sed -E 's/^[0-9-]+ [0-9:.]+ +[A-Za-z]+ +//; s/0x[0-9a-fA-F]+/0xN/g; s/[0-9]+/N/g' | sort | uniq -c | sort -rn | head -n 40; true`, window), 10*time.Minute).Stdout)
		for _, l := range lines {
			if macBad.MatchString(l) {
				bad = append(bad, l)
			}
		}
		if m := regexp.MustCompile(`SESSION_RECONNECT_COUNT\s+(\d+)`).FindStringSubmatch(shares); m != nil && m[1] != "0" {
			bad = append([]string{"the mount's session reconnected " + m[1] + " time(s) (smbutil statshares SESSION_RECONNECT_COUNT)"}, bad...)
		}
	default:
		lines = split(h.RunLax(fmt.Sprintf(`$since=(Get-Date).AddSeconds(-%d); Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-SmbClient/Connectivity','Microsoft-Windows-SmbClient/Security','Microsoft-Windows-SmbClient/Operational'; StartTime=$since; Level=1,2,3} -ErrorAction SilentlyContinue | Select-Object -First 100 | ForEach-Object { '{0} id={1} {2}: {3}' -f $_.TimeCreated.ToString('HH:mm:ss'), $_.Id, $_.LevelDisplayName, ((($_.Message -split '\r?\n') | Where-Object { $_.Trim() }) -join ' | ') }`, window), 2*time.Minute).Stdout)
		for _, l := range lines {
			if strings.Contains(l, serverIP) {
				bad = append(bad, l)
			}
		}
	}
	return lines, bad
}
