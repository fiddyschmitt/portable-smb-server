package e2e

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// TestLoopbackThroughput measures the server with no network in the way: go-smb2 over loopback,
// 1 MiB reads and writes as a real client issues them, unsigned and signed (3.0.2, AES-CMAC), plus
// the round-trip cost of a metadata operation. It is the server's CPU-bound ceiling on this
// machine, the number to compare before and after a change to the I/O path.
//
//	PSMB_BENCH=1 go test -run TestLoopbackThroughput -v
//	PSMB_BENCH_MB=1024            the payload size (default 256)
//	PSMB_BENCH_ADDR=127.0.0.1:1446 measure a server already running (e.g. one started with -pprof)
//	                              instead of starting one; it must serve a share "data" for
//	                              user/password, and the test leaves its files behind
func TestLoopbackThroughput(t *testing.T) {
	if os.Getenv("PSMB_BENCH") == "" {
		t.Skip("set PSMB_BENCH=1 to run the loopback throughput measurement")
	}
	mb := 256
	if v, err := strconv.Atoi(os.Getenv("PSMB_BENCH_MB")); err == nil && v > 0 {
		mb = v
	}
	size := int64(mb) << 20
	payload := make([]byte, 1<<20)
	for i := range payload {
		payload[i] = byte(i * 7)
	}

	addr := os.Getenv("PSMB_BENCH_ADDR")
	if addr == "" {
		dir := t.TempDir()
		addr = startServer(t, "-folder", dir, "-share", "data")
	}
	for _, signed := range []bool{false, true} {
		share, err := tryDial(t, addr, "user", "password", "data", 0x0302, signed)
		if err != nil {
			t.Fatal(err)
		}
		name := fmt.Sprintf("bench-%d-%v.bin", os.Getpid(), signed)
		defer share.Remove(name)

		// Write: 1 MiB WRITEs, one after the other, as a copy does.
		wf, err := share.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		t0 := time.Now()
		for i := int64(0); i < size>>20; i++ {
			if _, err := wf.Write(payload); err != nil {
				t.Fatal(err)
			}
		}
		if err := wf.Close(); err != nil {
			t.Fatal(err)
		}
		wd := time.Since(t0)

		// Read it back: 1 MiB READs.
		rf, err := share.Open(name)
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 1<<20)
		t0 = time.Now()
		var n int64
		for {
			k, err := rf.Read(buf)
			n += int64(k)
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		rd := time.Since(t0)
		_ = rf.Close()
		if n != size {
			t.Fatalf("read %d bytes, wrote %d", n, size)
		}

		// A metadata round trip: stat by path (CREATE + QUERY_INFO + CLOSE).
		t0 = time.Now()
		const stats = 300
		for i := 0; i < stats; i++ {
			if _, err := share.Stat(name); err != nil {
				t.Fatal(err)
			}
		}
		st := time.Since(t0)

		t.Logf("signed=%-5v  write %6.0f MiB/s   read %6.0f MiB/s   stat %.2f ms   (%d MiB, 1 MiB I/O)",
			signed, float64(size)/(1<<20)/wd.Seconds(), float64(n)/(1<<20)/rd.Seconds(), float64(st.Microseconds())/1000/stats, mb)
		_ = filepath.Base
	}
}
