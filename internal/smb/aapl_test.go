package smb

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// aaplCreateSeg builds a CREATE request PDU for name that carries an AAPL
// server-query context asking for the given bitmap with the given client
// capabilities, the way macOS opens the share root after a tree connect.
func aaplCreateSeg(name string, bitmap, clientCaps uint64) []byte {
	n := stringToUTF16le(name)
	nameEnd := 56 + len(n)
	ctxOff := roundUp(nameEnd, 8)
	ctxData := make([]byte, 24)
	le.PutUint32(ctxData[0:4], aaplServerQuery)
	le.PutUint64(ctxData[8:16], bitmap)
	le.PutUint64(ctxData[16:24], clientCaps)
	ctx := createContextBlob(aaplContextName, ctxData)
	body := make([]byte, ctxOff+len(ctx))
	le.PutUint16(body[0:2], 57)
	le.PutUint32(body[36:40], dispOpen)
	le.PutUint16(body[44:46], smb2HeaderSize+56)
	le.PutUint16(body[46:48], uint16(len(n)))
	le.PutUint32(body[48:52], uint32(smb2HeaderSize+ctxOff))
	le.PutUint32(body[52:56], uint32(len(ctx)))
	copy(body[56:], n)
	copy(body[ctxOff:], ctx)
	seg := make([]byte, smb2HeaderSize+len(body))
	copy(seg[smb2HeaderSize:], body)
	return seg
}

// TestAppleCreateContext checks that a CREATE carrying an AAPL server query gets
// the AAPL answer back as a create context (ReadDirAttr granted, volume
// capabilities, the model string) and that the connection remembers it.
func TestAppleCreateContext(t *testing.T) {
	dir := t.TempDir()
	s := testServer(t, dir, "", "")
	c := newConn(s, nil)
	c.diskTrees[1] = s.shares[0]

	seg := aaplCreateSeg("", aaplServerCaps|aaplVolumeCaps|aaplModelInfo, aaplSupportsReadDirAttr|aaplUnixBased)
	status, resp := c.handleCreate(header{}, seg[smb2HeaderSize:], 1)
	if status != statusSuccess {
		t.Fatalf("create: status 0x%08x", status)
	}
	if !c.aapl {
		t.Fatal("the connection should have ReadDirAttr on after the client asked for it")
	}
	off, length := int(le.Uint32(resp[80:84])), int(le.Uint32(resp[84:88]))
	if off != smb2HeaderSize+88 || length == 0 || 88+length != len(resp) {
		t.Fatalf("create contexts at %d, length %d, body %d: want offset 152 and the contexts filling the body", off, length, len(resp))
	}
	ctx := resp[88:]
	nameOff, nameLen := int(le.Uint16(ctx[4:6])), int(le.Uint16(ctx[6:8]))
	dataOff, dataLen := int(le.Uint16(ctx[10:12])), int(le.Uint32(ctx[12:16]))
	if string(ctx[nameOff:nameOff+nameLen]) != aaplContextName {
		t.Fatalf("context name %q", ctx[nameOff:nameOff+nameLen])
	}
	data := ctx[dataOff : dataOff+dataLen]
	if le.Uint32(data[0:4]) != aaplServerQuery || le.Uint64(data[8:16]) != aaplServerCaps|aaplVolumeCaps|aaplModelInfo {
		t.Fatalf("reply head % x", data[:16])
	}
	serverCaps := le.Uint64(data[16:24])
	if serverCaps != aaplSupportsReadDirAttr|aaplUnixBased {
		t.Errorf("server caps %#x, want ReadDirAttr and UNIX-based", serverCaps)
	}
	volumeCaps := le.Uint64(data[24:32])
	if wantCS := !s.shares[0].fs.CaseInsensitive(); (volumeCaps&aaplCaseSensitive != 0) != wantCS {
		t.Errorf("volume caps %#x, case-sensitive backend %v", volumeCaps, wantCS)
	}
	modelLen := int(le.Uint32(data[36:40]))
	if le.Uint32(data[32:36]) != 0 || utf16leToString(data[40:40+modelLen]) != appleModel {
		t.Errorf("model info % x", data[32:])
	}

	// without the client capability the server grants nothing and the connection stays plain
	c2 := newConn(s, nil)
	c2.diskTrees[1] = s.shares[0]
	status, resp = c2.handleCreate(header{}, aaplCreateSeg("", aaplServerCaps, 0)[smb2HeaderSize:], 1)
	if status != statusSuccess || c2.aapl {
		t.Fatalf("status 0x%08x, aapl %v: a client without ReadDirAttr must not switch it on", status, c2.aapl)
	}
	if got := le.Uint64(resp[88+24+16 : 88+24+24]); got != aaplUnixBased {
		t.Errorf("server caps for a client without ReadDirAttr: %#x, want UNIX-based only", got)
	}

	// a CREATE without contexts keeps the plain 89-byte response
	status, resp = c2.handleCreate(header{}, createSeg("")[smb2HeaderSize:], 1)
	if status != statusSuccess || len(resp) != 89 || le.Uint32(resp[80:84]) != 0 {
		t.Fatalf("plain create: status 0x%08x, body %d bytes, contexts offset %d", status, len(resp), le.Uint32(resp[80:84]))
	}
}

// TestQueryDirAppleReadDirAttr checks the entry layout a ReadDirAttr client
// gets: max access in EaSize (all access on a writable share, read and execute
// on a read-only one or for a read-only file), ShortNameLength 24, zero fork
// size, Finder info and UNIX mode, the FileId and the name where they always
// were. A connection without the negotiation gets the plain layout.
func TestQueryDirAppleReadDirAttr(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "file.tmp"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "locked.tmp"), []byte("x"), 0o444); err != nil {
		t.Fatal(err)
	}
	for _, readOnlyShare := range []bool{false, true} {
		s := testServer(t, dir, "", "")
		s.shares[0].readOnly = readOnlyShare
		c := newConn(s, nil)
		c.aapl = true
		of := dirHandle(c, "")
		body := make([]byte, 32)
		body[2] = 0x25
		copy(body[8:24], of.fileID[:])
		le.PutUint32(body[28:32], 1<<16)
		status, resp := c.handleQueryDirectory(header{}, body)
		if status != statusSuccess {
			t.Fatalf("query directory: status 0x%08x", status)
		}
		info := resp[8:]
		seen := 0
		for off := 0; ; {
			e := info[off:]
			nameLen := int(le.Uint32(e[60:64]))
			name := utf16leToString(e[104 : 104+nameLen])
			seen++
			wantAccess := accessAll
			if readOnlyShare || name == "locked.tmp" {
				wantAccess = accessReadExecute
			}
			if got := le.Uint32(e[64:68]); got != wantAccess {
				t.Errorf("share read-only %v, %s: max access %#x, want %#x", readOnlyShare, name, got, wantAccess)
			}
			if e[68] != appleShortNameLength || e[69] != 0 {
				t.Errorf("%s: ShortNameLength %d reserved %d", name, e[68], e[69])
			}
			for i := 70; i < 94; i++ {
				if e[i] != 0 {
					t.Errorf("%s: byte %d of the fork size / Finder info area is %#x", name, i, e[i])
					break
				}
			}
			wantMode := uint16(0o644)
			if readOnlyShare || name == "locked.tmp" {
				wantMode = 0o444
			}
			if got := le.Uint16(e[94:96]); got != wantMode {
				t.Errorf("%s: UNIX mode %#o, want %#o", name, got, wantMode)
			}
			if got, want := le.Uint64(e[96:104]), pathFileID("data", name); got != want {
				t.Errorf("%s: FileId %#x, want %#x", name, got, want)
			}
			next := int(le.Uint32(e[0:4]))
			if next == 0 {
				break
			}
			off += next
		}
		if seen != 2 {
			t.Fatalf("saw %d entries, want 2", seen)
		}
	}

	// plain connection: the ShortName area stays zero and EaSize is zero
	s := testServer(t, dir, "", "")
	c := newConn(s, nil)
	of := dirHandle(c, "")
	body := make([]byte, 32)
	body[2] = 0x25
	copy(body[8:24], of.fileID[:])
	le.PutUint32(body[28:32], 1<<16)
	_, resp := c.handleQueryDirectory(header{}, body)
	e := resp[8:]
	for i := 64; i < 96; i++ {
		if e[i] != 0 {
			t.Fatalf("plain layout: byte %d is %#x", i, e[i])
		}
	}
}

// TestCreateContextsParser covers the request-side parser: a chain of two
// contexts, a malformed offset, and no contexts at all.
func TestCreateContextsParser(t *testing.T) {
	first := createContextBlob("MxAc", nil)
	second := createContextBlob(aaplContextName, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24})
	le.PutUint32(first[0:4], uint32(len(first))) // Next
	chain := append(append([]byte{}, first...), second...)
	body := make([]byte, 56+len(chain))
	le.PutUint32(body[48:52], uint32(smb2HeaderSize+56))
	le.PutUint32(body[52:56], uint32(len(chain)))
	copy(body[56:], chain)
	ctxs := createContexts(body)
	if len(ctxs) != 2 || len(ctxs["MxAc"]) != 0 || len(ctxs[aaplContextName]) != 24 || ctxs[aaplContextName][23] != 24 {
		t.Fatalf("parsed %v", ctxs)
	}
	le.PutUint32(body[52:56], uint32(len(chain)+1000))
	if ctxs := createContexts(body); ctxs != nil {
		t.Fatalf("a length past the body must parse as no contexts, got %v", ctxs)
	}
	if ctxs := createContexts(createSeg("x")[smb2HeaderSize:]); ctxs != nil {
		t.Fatalf("a CREATE without contexts must parse as none, got %v", ctxs)
	}
	if got := fmt.Sprint(len(createContextBlob(aaplContextName, make([]byte, 20)))); got != "48" {
		t.Fatalf("blob with 20 data bytes is %s bytes, want 48 (16 head + 4 name padded to 24, + 20 padded to 24)", got)
	}
}
