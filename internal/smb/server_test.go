package smb

import (
	"net"
	"testing"
	"time"
)

// TestPipelinedResponsesStayOrdered sends a burst of requests in one write, as a
// client with credits does, and checks that the responses come back one per
// request and in order. serve hands responses to a writer goroutine so it can
// take up the next request while the last response is still going out; that
// must never reorder or drop them.
func TestPipelinedResponsesStayOrdered(t *testing.T) {
	s := testServer(t, t.TempDir(), "", "")
	go func() { _ = s.Serve() }()
	defer s.Shutdown()
	nc, err := net.Dial("tcp", s.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()

	const n = 3 * outboundDepth // more than the writer's queue holds
	var burst []byte
	for i := 0; i < n; i++ {
		req := make([]byte, smb2HeaderSize+4)
		copy(req[0:4], smb2Magic)
		le.PutUint16(req[4:6], smb2HeaderSize)
		le.PutUint16(req[12:14], cmdEcho)
		le.PutUint64(req[24:32], uint64(i)) // MessageId
		le.PutUint16(req[64:66], 4)          // ECHO request StructureSize
		burst = append(burst, 0, 0, 0, byte(len(req)))
		burst = append(burst, req...)
	}
	if _, err := nc.Write(burst); err != nil {
		t.Fatal(err)
	}
	_ = nc.SetReadDeadline(time.Now().Add(10 * time.Second))
	for i := 0; i < n; i++ {
		resp, err := readMessage(nc)
		if err != nil {
			t.Fatalf("response %d: %v", i, err)
		}
		h, ok := parseHeader(resp)
		if !ok || h.command != cmdEcho || h.messageID != uint64(i) {
			t.Fatalf("response %d: command %d, MessageId %d (want ECHO, %d)", i, h.command, h.messageID, i)
		}
	}
}
