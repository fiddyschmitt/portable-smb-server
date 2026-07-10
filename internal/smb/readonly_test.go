package smb

import (
	"os"
	"path/filepath"
	"testing"

	"portable-smb-server/internal/localfs"
)

// roTestServer creates a server whose only share "data" is read-only.
func roTestServer(t *testing.T, dir string) *Server {
	t.Helper()
	f, err := localfs.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(Options{
		ListenAddr: "127.0.0.1:0",
		Shares:     []ShareDef{{Name: "data", FS: f, ReadOnly: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Shutdown() })
	return s
}

// createWriteSeg builds a CREATE request PDU with write access and OPEN_IF.
func createWriteSeg(name string) []byte {
	seg := createSeg(name)
	le.PutUint32(seg[smb2HeaderSize+24:], accFileWriteData) // DesiredAccess
	le.PutUint32(seg[smb2HeaderSize+36:], dispOpenIf)       // CreateDisposition
	return seg
}

// TestReadOnlyShare checks that every mutation on a read-only share is
// refused with STATUS_MEDIA_WRITE_PROTECTED while reads keep working.
func TestReadOnlyShare(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := roTestServer(t, dir)
	c := newConn(s, nil)
	respT := c.handleCommand(header{command: cmdTreeConnect}, treeConnectSeg("data"), &chainCtx{})
	if respStatus(respT) != statusSuccess {
		t.Fatal("tree connect failed")
	}
	treeID := le.Uint32(respT[36:40])

	// Read-only MaximalAccess is advertised on TREE_CONNECT.
	if got := le.Uint32(respT[smb2HeaderSize+12 : smb2HeaderSize+16]); got != 0x001200A9 {
		t.Errorf("MaximalAccess = 0x%08x, want read-only 0x001200A9", got)
	}

	// Opening for write -> refused.
	resp := c.handleCommand(header{command: cmdCreate, treeID: treeID}, createWriteSeg("f.txt"), &chainCtx{})
	if respStatus(resp) != statusMediaWriteProtected {
		t.Errorf("write open: status 0x%08x, want MEDIA_WRITE_PROTECTED", respStatus(resp))
	}

	// Creating a missing file (OPEN_IF, even read access) -> refused.
	segNew := createSeg("new.txt")
	le.PutUint32(segNew[smb2HeaderSize+36:], dispOpenIf)
	resp = c.handleCommand(header{command: cmdCreate, treeID: treeID}, segNew, &chainCtx{})
	if respStatus(resp) != statusMediaWriteProtected {
		t.Errorf("create missing: status 0x%08x, want MEDIA_WRITE_PROTECTED", respStatus(resp))
	}

	// Creating a directory -> refused.
	segDir := createSeg("newdir")
	le.PutUint32(segDir[smb2HeaderSize+36:], dispOpenIf)
	le.PutUint32(segDir[smb2HeaderSize+40:], optDirectoryFile)
	resp = c.handleCommand(header{command: cmdCreate, treeID: treeID}, segDir, &chainCtx{})
	if respStatus(resp) != statusMediaWriteProtected {
		t.Errorf("mkdir: status 0x%08x, want MEDIA_WRITE_PROTECTED", respStatus(resp))
	}

	// Delete-on-close -> refused.
	segDel := createSeg("f.txt")
	le.PutUint32(segDel[smb2HeaderSize+40:], optDeleteOnClose)
	resp = c.handleCommand(header{command: cmdCreate, treeID: treeID}, segDel, &chainCtx{})
	if respStatus(resp) != statusMediaWriteProtected {
		t.Errorf("delete-on-close: status 0x%08x, want MEDIA_WRITE_PROTECTED", respStatus(resp))
	}

	// A plain read open (OPEN_IF on an existing file) still works and reads.
	segRead := createSeg("f.txt")
	le.PutUint32(segRead[smb2HeaderSize+36:], dispOpenIf)
	resp = c.handleCommand(header{command: cmdCreate, treeID: treeID}, segRead, &chainCtx{})
	if respStatus(resp) != statusSuccess {
		t.Fatalf("read open: status 0x%08x, want SUCCESS", respStatus(resp))
	}
	fileID := resp[smb2HeaderSize+64 : smb2HeaderSize+80]

	rbody := make([]byte, 48)
	le.PutUint32(rbody[4:8], 5)
	copy(rbody[16:32], fileID)
	status, rresp := c.handleRead(header{}, rbody)
	if status != statusSuccess || string(rresp[16:21]) != "hello" {
		t.Errorf("read: status 0x%08x data %q", status, rresp[16:21])
	}

	// WRITE on the handle -> refused.
	wbody := make([]byte, 52)
	le.PutUint16(wbody[2:4], smb2HeaderSize+48) // DataOffset
	le.PutUint32(wbody[4:8], 4)                 // Length
	copy(wbody[16:32], fileID)
	copy(wbody[48:], "data")
	status, _ = c.handleWrite(header{}, wbody)
	if status != statusMediaWriteProtected {
		t.Errorf("write: status 0x%08x, want MEDIA_WRITE_PROTECTED", status)
	}

	// SET_INFO rename -> refused.
	var fid [16]byte
	copy(fid[:], fileID)
	status, _ = c.handleSetInfo(header{}, setInfoRenameBody(fid, "moved.txt", false))
	if status != statusMediaWriteProtected {
		t.Errorf("rename: status 0x%08x, want MEDIA_WRITE_PROTECTED", status)
	}

	// SET_INFO delete disposition -> refused.
	dbody := make([]byte, 33)
	dbody[2] = infoTypeFile
	dbody[3] = classFileDisposition
	le.PutUint32(dbody[4:8], 1)
	le.PutUint16(dbody[8:10], smb2HeaderSize+32)
	copy(dbody[16:32], fileID)
	dbody[32] = 1
	status, _ = c.handleSetInfo(header{}, dbody)
	if status != statusMediaWriteProtected {
		t.Errorf("set disposition: status 0x%08x, want MEDIA_WRITE_PROTECTED", status)
	}

	// The FS attribute info advertises FILE_READ_ONLY_VOLUME.
	qbody := make([]byte, 40)
	qbody[2] = infoTypeFilesystem
	qbody[3] = classFsAttribute
	copy(qbody[24:40], fileID)
	status, qresp := c.handleQueryInfo(header{}, qbody)
	if status != statusSuccess {
		t.Fatalf("query fs attribute: status 0x%08x", status)
	}
	if attrs := le.Uint32(qresp[8:12]); attrs&0x00080000 == 0 {
		t.Errorf("FileFsAttributeInformation = 0x%08x, want FILE_READ_ONLY_VOLUME set", attrs)
	}

	// Nothing leaked into the backing store.
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Errorf("backing store changed: %d entries, %v", len(entries), err)
	}
}
