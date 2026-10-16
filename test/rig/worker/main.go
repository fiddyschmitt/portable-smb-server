// psmbstress is the on-machine load generator and verifier behind portable-smb-server's rig
// stress tests (test/rig, TestStress).
//
// The harness can't load a server by driving file operations over SSH one command at a time, so
// it uploads this binary to every client machine and lets it hammer the mounted share for a fixed
// time, verifying every byte it reads:
//
//	psmbstress run -root <mount dir> -name <client> -seed N -duration 5m ...
//
// and uses it on the server host to prepare and check the backing store:
//
//	psmbstress seed  -dir <backing dir> -seed N                    the shared read-only corpus
//	psmbstress audit -dir <backing dir> -seed N -manifest m.json   what the clients left behind
//
// Standard library only, so it cross-compiles to a single static binary per OS.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"
)

type config struct {
	name       string
	root       string
	seed       uint64
	duration   time.Duration
	workers    int
	opTimeout  time.Duration
	largeMaxMB int
	maxPub     int
	out        string
}

// result is what `run` reports back to the harness (the last line of stdout, and -out).
type result struct {
	Name         string              `json:"name"`
	OS           string              `json:"os"`
	Seed         uint64              `json:"seed"`
	Workers      int                 `json:"workers"`
	DurationSec  float64             `json:"durationSec"`
	TotalOps     int64               `json:"totalOps"`
	BytesWritten int64               `json:"bytesWritten"`
	BytesRead    int64               `json:"bytesRead"`
	Ops          map[string]*opStats `json:"ops"`
	FailureCount int                 `json:"failureCount"`
	Stalls       int                 `json:"stalls"`
	Stuck        []string            `json:"stuck"`
	Failures     []failure           `json:"failures"`
	Expected     []expectedFile      `json:"expected"`
	CleanExit    bool                `json:"cleanExit"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var code int
	switch os.Args[1] {
	case "run":
		code = cmdRun(os.Args[2:])
	case "seed":
		code = cmdSeed(os.Args[2:])
	case "audit":
		code = cmdAudit(os.Args[2:])
	case "version":
		fmt.Println("psmbstress v1")
	default:
		usage()
	}
	os.Exit(code)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: psmbstress run|seed|audit|version [flags]   (see -h of each)")
	os.Exit(2)
}

func cmdRun(args []string) int {
	cfg := &config{}
	fl := flag.NewFlagSet("run", flag.ExitOnError)
	fl.StringVar(&cfg.name, "name", "client", "unique client name; its files live under stress/<name>/")
	fl.StringVar(&cfg.root, "root", "", "the share's mount directory")
	fl.Uint64Var(&cfg.seed, "seed", 1, "run seed shared by every client and the audit")
	fl.DurationVar(&cfg.duration, "duration", 5*time.Minute, "how long to generate load")
	fl.IntVar(&cfg.workers, "workers", 4, "concurrent worker goroutines (in-flight requests on the one SMB connection)")
	fl.DurationVar(&cfg.opTimeout, "op-timeout", 2*time.Minute, "an operation running longer than this is reported as a STALL")
	fl.IntVar(&cfg.largeMaxMB, "large-max-mb", 32, "largest large-file size in MiB (0 disables large files)")
	fl.IntVar(&cfg.maxPub, "max-pub", 12, "published files each worker keeps until the end")
	fl.StringVar(&cfg.out, "out", "", "also write the JSON result to this file")
	_ = fl.Parse(args)
	if cfg.root == "" {
		fmt.Fprintln(os.Stderr, "run: -root is required")
		return 2
	}

	rec := newRecorder()
	var workers []*fsWorker
	for i := 0; i < cfg.workers; i++ {
		workers = append(workers, newFSWorker(cfg, rec, i))
	}

	start := time.Now()
	deadline := start.Add(cfg.duration)
	stop := make(chan struct{})
	go rec.watch(cfg.opTimeout, stop)
	go progress(rec, start, stop)

	var wg sync.WaitGroup
	for _, w := range workers {
		wg.Add(1)
		go func(w *fsWorker) {
			defer wg.Done()
			w.run(deadline)
		}(w)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	// A worker blocked in a syscall on a hung mount never returns; give up on it after a grace
	// period so the run still reports (as a failure) instead of hanging the harness.
	clean := true
	select {
	case <-done:
	case <-time.After(time.Until(deadline) + cfg.opTimeout + 30*time.Second):
		clean = false
	}
	close(stop)

	ops, failures, failureCount, stalls := rec.snapshot()
	res := result{
		Name: cfg.name, OS: runtime.GOOS, Seed: cfg.seed, Workers: cfg.workers,
		DurationSec: time.Since(start).Seconds(), Ops: ops, Failures: failures,
		FailureCount: failureCount, Stalls: stalls, CleanExit: clean, Expected: []expectedFile{}, Stuck: []string{},
	}
	if !clean {
		res.Stuck = rec.stuck()
	} else {
		// expected() reads worker state, which is only quiescent once every worker has returned.
		for _, w := range workers {
			res.Expected = append(res.Expected, w.expected()...)
		}
	}
	for _, s := range ops {
		res.TotalOps += s.Count
		res.BytesWritten += s.BytesWritten
		res.BytesRead += s.BytesRead
	}
	js, _ := json.Marshal(res)
	if cfg.out != "" {
		_ = os.WriteFile(cfg.out, js, 0o666)
	}
	fmt.Println(string(js))
	if failureCount > 0 || !clean {
		return 1
	}
	return 0
}

// progress prints a heartbeat to stderr so a long run is observable from the harness log.
func progress(rec *recorder, start time.Time, stop <-chan struct{}) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			ops, fails := rec.totals()
			fmt.Fprintf(os.Stderr, "[%4.0fs] ops=%d failures=%d\n", time.Since(start).Seconds(), ops, fails)
		}
	}
}
