package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

// The raw-TCP ceiling between two rig machines: what the network and the two stacks can move
// without SMB in the way, which is what an SMB throughput number has to be read against.
//
//	psmbstress tcpserve -addr 0.0.0.0:1447 -seconds 60     on the server host (exits on its own)
//	psmbstress tcpbench -addr 192.168.0.90:1447 -seconds 5  on the client: upload, then download
//
// A connection starts with one byte: 'U' and the client streams to the server, which discards;
// 'D' and the server streams to the client, which discards. Either side measures what it moved.

const benchChunk = 1 << 20

func cmdTCPServe(args []string) int {
	fl := flag.NewFlagSet("tcpserve", flag.ExitOnError)
	addr := fl.String("addr", "0.0.0.0:1447", "listen address")
	seconds := fl.Int("seconds", 120, "exit after this long")
	_ = fl.Parse(args)
	l, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	go func() {
		time.Sleep(time.Duration(*seconds) * time.Second)
		os.Exit(0)
	}()
	buf := make([]byte, benchChunk)
	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			var mode [1]byte
			if _, err := io.ReadFull(c, mode[:]); err != nil {
				return
			}
			switch mode[0] {
			case 'U':
				_, _ = io.CopyBuffer(io.Discard, c, make([]byte, benchChunk))
			case 'D':
				for {
					if _, err := c.Write(buf); err != nil {
						return
					}
				}
			}
		}(c)
	}
}

func cmdTCPBench(args []string) int {
	fl := flag.NewFlagSet("tcpbench", flag.ExitOnError)
	addr := fl.String("addr", "", "the tcpserve address")
	seconds := fl.Int("seconds", 5, "seconds per direction")
	_ = fl.Parse(args)
	if *addr == "" {
		fmt.Fprintln(os.Stderr, "tcpbench: -addr is required")
		return 2
	}
	d := time.Duration(*seconds) * time.Second
	up, err := benchDirection(*addr, 'U', d)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	down, err := benchDirection(*addr, 'D', d)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	js, _ := json.Marshal(map[string]float64{"upMiBps": up, "downMiBps": down})
	fmt.Println(string(js))
	return 0
}

// benchDirection moves data one way for d and returns MiB/s.
func benchDirection(addr string, mode byte, d time.Duration) (float64, error) {
	c, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	if _, err := c.Write([]byte{mode}); err != nil {
		return 0, err
	}
	buf := make([]byte, benchChunk)
	deadline := time.Now().Add(d)
	start := time.Now()
	var n int64
	for time.Now().Before(deadline) {
		var k int
		if mode == 'U' {
			k, err = c.Write(buf)
		} else {
			k, err = c.Read(buf)
		}
		n += int64(k)
		if err != nil {
			return 0, err
		}
	}
	return float64(n) / (1 << 20) / time.Since(start).Seconds(), nil
}
