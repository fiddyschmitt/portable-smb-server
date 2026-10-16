package main

import (
	"sort"
	"sync"
	"time"
)

// opStats is what a worker reports per operation type.
type opStats struct {
	Count        int64   `json:"count"`
	Errors       int64   `json:"errors"`
	BytesWritten int64   `json:"bytesWritten"`
	BytesRead    int64   `json:"bytesRead"`
	P50ms        float64 `json:"p50ms"`
	P95ms        float64 `json:"p95ms"`
	P99ms        float64 `json:"p99ms"`
	MaxMs        float64 `json:"maxMs"`
	samples      []float64
}

type failure struct {
	Time   string `json:"time"`
	Worker int    `json:"worker"`
	Op     string `json:"op"`
	Path   string `json:"path"`
	Err    string `json:"err"`
}

type expectedFile struct {
	Path string `json:"path"` // share-relative, slash-separated
	Size int64  `json:"size"`
}

// recorder collects every worker's operations: counts, latencies, failures, and which operations
// are in flight (an operation past the op timeout is a stall, reported even when it eventually
// returns; one that never returns is a hang).
type recorder struct {
	mu       sync.Mutex
	ops      map[string]*opStats
	failures []failure
	nFail    int
	inflight map[int]inflightOp // worker id -> what it's doing
	stalls   int
	stalled  map[int]bool
}

type inflightOp struct {
	op, path string
	since    time.Time
}

func newRecorder() *recorder {
	return &recorder{ops: map[string]*opStats{}, inflight: map[int]inflightOp{}, stalled: map[int]bool{}}
}

const maxSamples = 20000

func (r *recorder) begin(worker int, op, path string) {
	r.mu.Lock()
	r.inflight[worker] = inflightOp{op, path, time.Now()}
	r.mu.Unlock()
}

// end records a finished operation.
func (r *recorder) end(worker int, op, path string, start time.Time, written, read int64, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.inflight, worker)
	delete(r.stalled, worker)
	s := r.ops[op]
	if s == nil {
		s = &opStats{}
		r.ops[op] = s
	}
	s.Count++
	s.BytesWritten += written
	s.BytesRead += read
	ms := float64(time.Since(start).Microseconds()) / 1000
	if ms > s.MaxMs {
		s.MaxMs = ms
	}
	if len(s.samples) < maxSamples {
		s.samples = append(s.samples, ms)
	} else {
		// Reservoir-ish: keep the sample set bounded without biasing it to the start of the run.
		s.samples[int(s.Count)%maxSamples] = ms
	}
	if err != nil {
		s.Errors++
		r.nFail++
		if len(r.failures) < 50 {
			r.failures = append(r.failures, failure{Time: time.Now().Format("15:04:05"), Worker: worker, Op: op, Path: path, Err: err.Error()})
		}
	}
}

// watch counts operations running longer than the timeout, once each, until stop is closed.
func (r *recorder) watch(timeout time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			r.mu.Lock()
			for w, op := range r.inflight {
				if time.Since(op.since) > timeout && !r.stalled[w] {
					r.stalled[w] = true
					r.stalls++
					r.nFail++
					if len(r.failures) < 50 {
						r.failures = append(r.failures, failure{Time: time.Now().Format("15:04:05"), Worker: w, Op: op.op, Path: op.path,
							Err: "STALL: running for " + time.Since(op.since).Truncate(time.Second).String()})
					}
				}
			}
			r.mu.Unlock()
		}
	}
}

// stuck describes the operations still in flight (for a run that had to give up on its workers).
func (r *recorder) stuck() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for w, op := range r.inflight {
		out = append(out, time.Since(op.since).Truncate(time.Second).String()+" in "+op.op+" "+op.path+" (worker "+itoa(w)+")")
	}
	return out
}

func (r *recorder) totals() (ops int64, fails int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.ops {
		ops += s.Count
	}
	return ops, r.nFail
}

// snapshot finalises the percentiles and returns everything recorded.
func (r *recorder) snapshot() (map[string]*opStats, []failure, int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.ops {
		if len(s.samples) == 0 {
			continue
		}
		sorted := append([]float64(nil), s.samples...)
		sort.Float64s(sorted)
		pct := func(p float64) float64 { return sorted[int(float64(len(sorted)-1)*p)] }
		s.P50ms, s.P95ms, s.P99ms = pct(0.50), pct(0.95), pct(0.99)
	}
	return r.ops, r.failures, r.nFail, r.stalls
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		n--
		b[n] = '-'
	}
	return string(b[n:])
}
