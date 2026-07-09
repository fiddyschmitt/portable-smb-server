package smb

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"portable-smb-server/internal/fsx"
	"portable-smb-server/internal/localfs"
)

// testServer creates a server (not accepting connections) whose first share
// "data" is backed by dir. Extra shares may be supplied as name=folder pairs.
func testServer(t *testing.T, dir, user, pass string, extraShares ...ShareDef) *Server {
	t.Helper()
	f, err := localfs.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	opt := Options{
		ListenAddr: "127.0.0.1:0",
		User:       user,
		Pass:       pass,
		Shares:     append([]ShareDef{{Name: "data", FS: f}}, extraShares...),
	}
	s, err := NewServer(opt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Shutdown() })
	return s
}

// dirHandle registers a directory handle for path on the server's first share.
func dirHandle(c *conn, path string) *openFile {
	of := &openFile{share: c.server.shares[0], path: path, isDir: true}
	of.fileID[0] = 1
	c.handles[of.fileID] = of
	return of
}

func respStatus(resp []byte) uint32 { return le.Uint32(resp[8:12]) }

// treeConnectSeg builds a TREE_CONNECT request PDU (64-byte header + body) for
// \\host\<share>, for driving handleCommand directly.
func treeConnectSeg(share string) []byte {
	path := stringToUTF16le(`\\host\` + share)
	body := make([]byte, 8+len(path))
	le.PutUint16(body[0:2], 9)                 // StructureSize
	le.PutUint16(body[4:6], smb2HeaderSize+8)  // PathOffset (from header)
	le.PutUint16(body[6:8], uint16(len(path))) // PathLength
	copy(body[8:], path)
	seg := make([]byte, smb2HeaderSize+len(body))
	copy(seg[smb2HeaderSize:], body)
	return seg
}

// createSeg builds a CREATE request PDU that opens the named file.
func createSeg(name string) []byte {
	n := stringToUTF16le(name)
	body := make([]byte, 56+len(n))
	le.PutUint16(body[0:2], 57)                  // StructureSize
	le.PutUint32(body[36:40], dispOpen)          // CreateDisposition = OPEN
	le.PutUint16(body[44:46], smb2HeaderSize+56) // NameOffset (from header)
	le.PutUint16(body[46:48], uint16(len(n)))    // NameLength
	copy(body[56:], n)
	seg := make([]byte, smb2HeaderSize+len(body))
	copy(seg[smb2HeaderSize:], body)
	return seg
}

// negotiateBody builds a NEGOTIATE request body offering the given dialects.
func negotiateBody(dialects ...uint16) []byte {
	body := make([]byte, 36+len(dialects)*2)
	le.PutUint16(body[0:2], 36)                    // StructureSize
	le.PutUint16(body[2:4], uint16(len(dialects))) // DialectCount
	for i, d := range dialects {
		le.PutUint16(body[36+i*2:], d)
	}
	return body
}

// TestNegotiateNoOverlap checks that NEGOTIATE fails when the client offers no
// dialect we support, rather than forcing an unrequested 2.0.2.
func TestNegotiateNoOverlap(t *testing.T) {
	s := testServer(t, t.TempDir(), "", "")
	c := newConn(s, nil)

	status, _ := c.handleNegotiate(header{}, negotiateBody(dialect311)) // 3.1.1 only (unsupported)
	if status != statusNotSupported {
		t.Errorf("no supported dialect: status = 0x%08x, want NOT_SUPPORTED", status)
	}
	status, _ = c.handleNegotiate(header{}, negotiateBody(dialect202, dialect302))
	if status != statusSuccess {
		t.Errorf("negotiate: status = 0x%08x, want SUCCESS", status)
	}
	if c.dialect != dialect302 {
		t.Errorf("dialect = 0x%04x, want highest offered (0x0302)", c.dialect)
	}
}

// TestMultiShareRouting checks that TREE_CONNECT routes to the right share and
// that CREATE on each tree opens files on that share's backend.
func TestMultiShareRouting(t *testing.T) {
	dir1, dir2 := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(dir1, "f.txt"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir2, "f.txt"), []byte("two"), 0o644); err != nil {
		t.Fatal(err)
	}
	f2, err := localfs.New(dir2)
	if err != nil {
		t.Fatal(err)
	}
	s := testServer(t, dir1, "", "", ShareDef{Name: "second", FS: f2})
	c := newConn(s, nil)

	readViaShare := func(shareName string) string {
		t.Helper()
		resp := c.handleCommand(header{command: cmdTreeConnect}, treeConnectSeg(shareName), &chainCtx{})
		if respStatus(resp) != statusSuccess {
			t.Fatalf("tree connect %q: status 0x%08x", shareName, respStatus(resp))
		}
		treeID := le.Uint32(resp[36:40])
		respC := c.handleCommand(header{command: cmdCreate, treeID: treeID}, createSeg("f.txt"), &chainCtx{})
		if respStatus(respC) != statusSuccess {
			t.Fatalf("create on %q: status 0x%08x", shareName, respStatus(respC))
		}
		fileID := respC[smb2HeaderSize+64 : smb2HeaderSize+80]
		rbody := make([]byte, 48)
		le.PutUint32(rbody[4:8], 16) // Length
		copy(rbody[16:32], fileID)
		status, rresp := c.handleRead(header{}, rbody)
		if status != statusSuccess {
			t.Fatalf("read on %q: status 0x%08x", shareName, status)
		}
		dataLen := le.Uint32(rresp[4:8])
		return string(rresp[16 : 16+dataLen])
	}

	if got := readViaShare("data"); got != "one" {
		t.Errorf("share data read %q, want %q", got, "one")
	}
	if got := readViaShare("SECOND"); got != "two" { // case-insensitive share names
		t.Errorf("share second read %q, want %q", got, "two")
	}

	// Unknown share -> STATUS_BAD_NETWORK_NAME.
	resp := c.handleCommand(header{command: cmdTreeConnect}, treeConnectSeg("nope"), &chainCtx{})
	if respStatus(resp) != statusBadNetworkName {
		t.Errorf("unknown share: status 0x%08x, want BAD_NETWORK_NAME", respStatus(resp))
	}

	// CREATE on a tree that was never connected -> STATUS_NETWORK_NAME_DELETED.
	respC := c.handleCommand(header{command: cmdCreate, treeID: 9999}, createSeg("f.txt"), &chainCtx{})
	if respStatus(respC) != statusNetworkNameDeleted {
		t.Errorf("create on unknown tree: status 0x%08x, want NETWORK_NAME_DELETED", respStatus(respC))
	}
}

// TestDuplicateShareName checks that NewServer rejects duplicate share names.
func TestDuplicateShareName(t *testing.T) {
	f, err := localfs.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewServer(Options{
		ListenAddr: "127.0.0.1:0",
		Shares:     []ShareDef{{Name: "data", FS: f}, {Name: "DATA", FS: f}},
	})
	if err == nil {
		t.Error("duplicate share names must be rejected")
	}
}

// TestPathFileID checks stability, path-uniqueness and share-uniqueness.
func TestPathFileID(t *testing.T) {
	if pathFileID("s", "a/b") != pathFileID("s", "a/b") {
		t.Error("pathFileID must be stable")
	}
	if pathFileID("s", "a/b") == pathFileID("s", "a/c") {
		t.Error("pathFileID must differ per path")
	}
	if pathFileID("s1", "a/b") == pathFileID("s2", "a/b") {
		t.Error("pathFileID must differ per share")
	}
}

// TestQueryDirSingleEntry checks that QUERY_DIRECTORY honours
// SMB2_RETURN_SINGLE_ENTRY (set by Windows' FindFirstFile): it must return
// exactly one entry, and subsequent calls must not skip entries.
func TestQueryDirSingleEntry(t *testing.T) {
	dir := t.TempDir()
	const n = 5
	for i := 0; i < n; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%d.txt", i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s := testServer(t, dir, "", "")
	c := newConn(s, nil)
	of := dirHandle(c, "")

	// QUERY_DIRECTORY body: InfoClass[2], Flags[3], FileId[8:24], OutputBufferLength[28:32].
	body := make([]byte, 32)
	body[2] = 0x01 // FileDirectoryInformation
	copy(body[8:24], of.fileID[:])
	le.PutUint32(body[28:32], 1<<16)

	body[3] = 0x02 // RETURN_SINGLE_ENTRY
	status, _ := c.handleQueryDirectory(header{}, body)
	if status != statusSuccess || of.dirPos != 1 {
		t.Fatalf("RETURN_SINGLE_ENTRY: status 0x%08x dirPos %d, want SUCCESS/1", status, of.dirPos)
	}
	body[3] = 0x00
	status, _ = c.handleQueryDirectory(header{}, body)
	if status != statusSuccess || of.dirPos != n {
		t.Fatalf("enumeration: status 0x%08x dirPos %d, want SUCCESS/%d", status, of.dirPos, n)
	}
	status, _ = c.handleQueryDirectory(header{}, body)
	if status != statusNoMoreFiles {
		t.Fatalf("exhausted dir: status 0x%08x, want NO_MORE_FILES", status)
	}
}

// TestQueryDirFileID checks that the FileId reported for a directory entry is
// the stable share-qualified path hash.
func TestQueryDirFileID(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "file.tmp"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	s := testServer(t, dir, "", "")
	c := newConn(s, nil)
	of := dirHandle(c, "")

	// FileIdBothDirectoryInformation (0x25): FileId is at offset 96 in each entry.
	body := make([]byte, 32)
	body[2] = 0x25
	copy(body[8:24], of.fileID[:])
	le.PutUint32(body[28:32], 1<<16)
	status, resp := c.handleQueryDirectory(header{}, body)
	if status != statusSuccess {
		t.Fatalf("query directory: status 0x%08x", status)
	}
	info := resp[8:] // QUERY_DIRECTORY response: 8-byte header, then the info buffer
	if len(info) < 104 {
		t.Fatalf("info buffer too short: %d", len(info))
	}
	if got, want := le.Uint64(info[96:104]), pathFileID("data", "file.tmp"); got != want {
		t.Errorf("dir-entry FileId = %#x, want the stable path-derived id %#x", got, want)
	}
}

// TestQueryDirPattern checks that QUERY_DIRECTORY honours the search pattern:
// a client resolves a child by name with a single-entry pattern query, so
// ignoring it makes path resolution follow the wrong entry.
func TestQueryDirPattern(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"alpha", "bravo", "charlie"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	s := testServer(t, dir, "", "")
	c := newConn(s, nil)
	of := dirHandle(c, "")

	pat := stringToUTF16le("bravo")
	body := make([]byte, 32+len(pat))
	body[2] = 0x25 // FileIdBothDirectoryInformation
	body[3] = 0x03 // RESTART_SCANS | RETURN_SINGLE_ENTRY
	copy(body[8:24], of.fileID[:])
	le.PutUint16(body[24:26], uint16(smb2HeaderSize+32)) // FileNameOffset
	le.PutUint16(body[26:28], uint16(len(pat)))          // FileNameLength
	le.PutUint32(body[28:32], 1<<16)                     // OutputBufferLength
	copy(body[32:], pat)

	status, resp := c.handleQueryDirectory(header{}, body)
	if status != statusSuccess {
		t.Fatalf("pattern query: status 0x%08x", status)
	}
	info := resp[8:]
	nameLen := int(le.Uint32(info[60:64]))
	if got := utf16leToString(info[104 : 104+nameLen]); got != "bravo" {
		t.Errorf("pattern query returned %q, want the matching entry %q", got, "bravo")
	}

	for _, tc := range []struct {
		pattern, name string
		insensitive   bool
		want          bool
	}{
		{"Users", "users", true, true},
		{"Users", "users", false, false},
		{"Users", "Users", false, true},
		{"*.txt", "a.TXT", true, true},
		{"*.txt", "a.TXT", false, false},
		{"Users", "Default", true, false},
		{"f?.tx<", "f1.txt", true, true}, // DOS wildcards < > map to * ?
	} {
		if got := matchPattern(tc.pattern, tc.name, tc.insensitive); got != tc.want {
			t.Errorf("matchPattern(%q, %q, %v) = %v, want %v", tc.pattern, tc.name, tc.insensitive, got, tc.want)
		}
	}
}

// TestQueryDirUnreadable checks that a directory whose contents can't be
// listed reports as empty rather than failing the request -- a generic failure
// makes the Windows shell copy engine abort a whole recursive copy.
func TestQueryDirUnreadable(t *testing.T) {
	s := testServer(t, t.TempDir(), "", "")
	c := newConn(s, nil)
	of := dirHandle(c, "nope-does-not-exist")

	body := make([]byte, 32)
	body[2] = 0x25
	copy(body[8:24], of.fileID[:])
	le.PutUint32(body[28:32], 65536)
	status, _ := c.handleQueryDirectory(header{}, body)
	if status != statusNoMoreFiles {
		t.Errorf("unreadable dir: status 0x%08x, want NO_MORE_FILES (reported empty)", status)
	}
}

// TestRequireAuth checks that with a user set, a command on a session that
// never authenticated is rejected, while an authenticated session is allowed
// and a guest server is not gated.
func TestRequireAuth(t *testing.T) {
	seg := treeConnectSeg("data")

	s := testServer(t, t.TempDir(), "alice", "s3cret")
	c := newConn(s, nil)
	status := func(sessionID uint64) uint32 {
		resp := c.handleCommand(header{command: cmdTreeConnect, sessionID: sessionID}, seg, &chainCtx{})
		return respStatus(resp)
	}
	if got := status(999); got != statusUserSessionDeleted {
		t.Errorf("unauthenticated session: status 0x%08x, want USER_SESSION_DELETED", got)
	}
	c.authedSessions[999] = struct{}{}
	if got := status(999); got != statusSuccess {
		t.Errorf("authenticated session: status 0x%08x, want SUCCESS", got)
	}

	sg := testServer(t, t.TempDir(), "", "")
	cg := newConn(sg, nil)
	resp := cg.handleCommand(header{command: cmdTreeConnect, sessionID: 42}, treeConnectSeg("data"), &chainCtx{})
	if respStatus(resp) != statusSuccess {
		t.Errorf("guest server must not gate commands: status 0x%08x", respStatus(resp))
	}
}

// TestVerifySignature checks that a signed request from an authenticated
// session is accepted only if its signature is valid.
func TestVerifySignature(t *testing.T) {
	s := testServer(t, t.TempDir(), "", "")
	c := newConn(s, nil)
	c.signKey = make([]byte, 16) // a session signing key
	c.dialect = dialect202       // HMAC-SHA256 signing path

	seg := make([]byte, smb2HeaderSize+4)
	copy(seg[0:4], smb2Magic)
	le.PutUint16(seg[4:6], smb2HeaderSize) // header StructureSize
	le.PutUint16(seg[12:14], cmdEcho)      // Command
	le.PutUint32(seg[16:20], flagsSigned)  // Flags: SIGNED
	le.PutUint16(seg[smb2HeaderSize:], 4)  // ECHO StructureSize
	signMessage(c.signKey, c.dialect, seg)
	h, ok := parseHeader(seg)
	if !ok {
		t.Fatal("parseHeader failed")
	}

	resp := c.handleCommand(h, seg, &chainCtx{})
	if respStatus(resp) != statusSuccess {
		t.Errorf("correctly signed request: status 0x%08x, want SUCCESS", respStatus(resp))
	}
	seg[48] ^= 0xFF // tamper the signature
	resp = c.handleCommand(h, seg, &chainCtx{})
	if respStatus(resp) != statusAccessDenied {
		t.Errorf("tampered signature: status 0x%08x, want ACCESS_DENIED", respStatus(resp))
	}
}

// TestSMB3Signing checks the AES-CMAC signing path round-trips.
func TestSMB3Signing(t *testing.T) {
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	msg := make([]byte, smb2HeaderSize+8)
	copy(msg[0:4], smb2Magic)
	signMessage(key, dialect302, msg)
	if !verifyMessage(key, dialect302, msg) {
		t.Error("AES-CMAC signed message must verify")
	}
	msg[70] ^= 1
	if verifyMessage(key, dialect302, msg) {
		t.Error("tampered AES-CMAC message must not verify")
	}
}

// TestReadLengthClamp checks that a READ whose Length exceeds MaxReadSize is
// rejected rather than allocating an attacker-chosen buffer.
func TestReadLengthClamp(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := testServer(t, dir, "", "")
	c := newConn(s, nil)
	sh := s.shares[0]
	handle, err := sh.fs.OpenFile("f.txt", os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handle.Close() })
	of := &openFile{share: sh, path: "f.txt", handle: handle}
	of.fileID[0] = 1
	c.handles[of.fileID] = of

	readBody := func(length uint32) []byte {
		body := make([]byte, 48)
		le.PutUint32(body[4:8], length) // Length
		copy(body[16:32], of.fileID[:]) // FileId
		return body
	}
	status, _ := c.handleRead(header{}, readBody(maxIOSize+1))
	if status != statusInvalidParameter {
		t.Errorf("oversized READ: status 0x%08x, want INVALID_PARAMETER", status)
	}
	status, resp := c.handleRead(header{}, readBody(5))
	if status != statusSuccess || string(resp[16:21]) != "hello" {
		t.Errorf("READ: status 0x%08x data %q", status, resp[16:21])
	}
}

// closeErrFile wraps a real file handle but fails on Close, to check that
// CLOSE surfaces the error instead of reporting success (silent data loss).
type closeErrFile struct{ fsx.File }

func (closeErrFile) Close() error { return errors.New("simulated flush failure") }

// TestCloseError checks that a failed handle Close is reported to the client.
func TestCloseError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := testServer(t, dir, "", "")
	c := newConn(s, nil)
	sh := s.shares[0]
	real, err := sh.fs.OpenFile("f.txt", os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = real.Close() })
	of := &openFile{share: sh, path: "f.txt", handle: closeErrFile{real}}
	of.fileID[0] = 1
	c.handles[of.fileID] = of

	body := make([]byte, 24)
	copy(body[8:24], of.fileID[:])
	status, _ := c.handleClose(header{}, body)
	if status == statusSuccess {
		t.Error("CLOSE must surface a handle Close() error, not report success")
	}
}

// setInfoRenameBody builds a SET_INFO FileRenameInformation request body.
func setInfoRenameBody(fileID [16]byte, target string, replace bool) []byte {
	name := stringToUTF16le(target)
	info := make([]byte, 20+len(name))
	if replace {
		info[0] = 1 // ReplaceIfExists
	}
	le.PutUint32(info[16:20], uint32(len(name))) // FileNameLength
	copy(info[20:], name)

	body := make([]byte, 32+len(info))
	body[2] = infoTypeFile                      // InfoType
	body[3] = classFileRename                   // FileInfoClass
	le.PutUint32(body[4:8], uint32(len(info)))  // BufferLength
	le.PutUint16(body[8:10], smb2HeaderSize+32) // BufferOffset (from header)
	copy(body[16:32], fileID[:])                // FileId
	copy(body[32:], info)
	return body
}

// TestRenameReplaceIfExists checks that a rename onto an existing target fails
// with a collision unless ReplaceIfExists is set.
func TestRenameReplaceIfExists(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "src.txt"), []byte("s"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dst.txt"), []byte("d"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := testServer(t, dir, "", "")
	c := newConn(s, nil)
	of := &openFile{share: s.shares[0], path: "src.txt"}
	of.fileID[0] = 1
	c.handles[of.fileID] = of

	status, _ := c.handleSetInfo(header{}, setInfoRenameBody(of.fileID, "dst.txt", false))
	if status != statusObjectNameCollision {
		t.Errorf("rename onto existing target: status 0x%08x, want OBJECT_NAME_COLLISION", status)
	}
	status, _ = c.handleSetInfo(header{}, setInfoRenameBody(of.fileID, "moved.txt", false))
	if status != statusSuccess {
		t.Errorf("rename to free name: status 0x%08x, want SUCCESS", status)
	}
	if _, err := os.Stat(filepath.Join(dir, "moved.txt")); err != nil {
		t.Errorf("renamed file missing in backing store: %v", err)
	}
}

// TestIPCTreeRejectsCreate checks that opening a name on the IPC$ tree is
// rejected instead of being resolved as a filesystem path (which could open a
// real file that happens to share a pipe's name, e.g. srvsvc).
func TestIPCTreeRejectsCreate(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "srvsvc"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := testServer(t, dir, "", "")
	c := newConn(s, nil)

	respD := c.handleCommand(header{command: cmdTreeConnect}, treeConnectSeg("data"), &chainCtx{})
	diskTree := le.Uint32(respD[36:40])
	respC := c.handleCommand(header{command: cmdCreate, treeID: diskTree}, createSeg("srvsvc"), &chainCtx{})
	if respStatus(respC) != statusSuccess {
		t.Errorf("opening a real file on the disk share: status 0x%08x, want SUCCESS", respStatus(respC))
	}

	respI := c.handleCommand(header{command: cmdTreeConnect}, treeConnectSeg("IPC$"), &chainCtx{})
	pipeTree := le.Uint32(respI[36:40])
	respP := c.handleCommand(header{command: cmdCreate, treeID: pipeTree}, createSeg("srvsvc"), &chainCtx{})
	if respStatus(respP) != statusObjectNameNotFound {
		t.Errorf("CREATE on IPC$: status 0x%08x, want OBJECT_NAME_NOT_FOUND", respStatus(respP))
	}
}

// TestPathTraversal checks that names with ".." cannot escape the share root.
func TestPathTraversal(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "shared")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "secret.txt"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := testServer(t, dir, "", "")
	c := newConn(s, nil)
	respT := c.handleCommand(header{command: cmdTreeConnect}, treeConnectSeg("data"), &chainCtx{})
	treeID := le.Uint32(respT[36:40])

	for _, name := range []string{`..\secret.txt`, `foo\..\..\secret.txt`, `\..\secret.txt`} {
		resp := c.handleCommand(header{command: cmdCreate, treeID: treeID}, createSeg(name), &chainCtx{})
		if respStatus(resp) == statusSuccess {
			t.Errorf("CREATE %q escaped the share root", name)
		}
	}
}

// TestHandleCap checks that a connection can't open more than maxOpenFiles
// handles (a leaky client would otherwise exhaust file descriptors).
func TestHandleCap(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := testServer(t, dir, "", "")
	c := newConn(s, nil)
	respT := c.handleCommand(header{command: cmdTreeConnect}, treeConnectSeg("data"), &chainCtx{})
	treeID := le.Uint32(respT[36:40])

	for i := 0; i < maxOpenFiles; i++ {
		var id [16]byte
		le.PutUint64(id[:8], uint64(i)+1)
		c.handles[id] = &openFile{}
	}
	resp := c.handleCommand(header{command: cmdCreate, treeID: treeID}, createSeg("f.txt"), &chainCtx{})
	if respStatus(resp) != statusInsufficientResources {
		t.Errorf("create past handle cap: status 0x%08x, want INSUFFICIENT_RESOURCES", respStatus(resp))
	}
}

// TestRequirePass checks that -user without -pass is rejected.
func TestRequirePass(t *testing.T) {
	f, err := localfs.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mk := func(user, pass string) error {
		s, err := NewServer(Options{
			ListenAddr: "127.0.0.1:0",
			User:       user, Pass: pass,
			Shares: []ShareDef{{Name: "data", FS: f}},
		})
		if s != nil {
			t.Cleanup(func() { _ = s.Shutdown() })
		}
		return err
	}
	if mk("alice", "") == nil {
		t.Error("-user without -pass must be rejected")
	}
	if err := mk("alice", "s3cret"); err != nil {
		t.Error(err)
	}
	if err := mk("", ""); err != nil { // guest is fine
		t.Error(err)
	}
}

// TestProtocolNits covers a few edge-case status codes.
func TestProtocolNits(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := testServer(t, dir, "", "")
	c := newConn(s, nil)
	respT := c.handleCommand(header{command: cmdTreeConnect}, treeConnectSeg("data"), &chainCtx{})
	treeID := le.Uint32(respT[36:40])

	// Opening a regular file with FILE_DIRECTORY_FILE -> NOT_A_DIRECTORY.
	seg := createSeg("f.txt")
	le.PutUint32(seg[smb2HeaderSize+40:], optDirectoryFile) // CreateOptions
	resp := c.handleCommand(header{command: cmdCreate, treeID: treeID}, seg, &chainCtx{})
	if respStatus(resp) != statusNotADirectory {
		t.Errorf("FILE_DIRECTORY_FILE on a file: status 0x%08x, want NOT_A_DIRECTORY", respStatus(resp))
	}

	sh := s.shares[0]
	handle, err := sh.fs.OpenFile("f.txt", os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handle.Close() })
	of := &openFile{share: sh, path: "f.txt", handle: handle}
	of.fileID[0] = 1
	c.handles[of.fileID] = of

	// Zero-length READ -> SUCCESS.
	rbody := make([]byte, 48)
	copy(rbody[16:32], of.fileID[:]) // Length stays 0
	status, _ := c.handleRead(header{}, rbody)
	if status != statusSuccess {
		t.Errorf("zero-length READ: status 0x%08x, want SUCCESS", status)
	}

	// SET_INFO with an unknown info class -> INVALID_INFO_CLASS.
	sbody := make([]byte, 32)
	sbody[2] = infoTypeFile
	sbody[3] = 0xEE // unknown FileInfoClass
	le.PutUint16(sbody[8:10], smb2HeaderSize+32)
	copy(sbody[16:32], of.fileID[:])
	status, _ = c.handleSetInfo(header{}, sbody)
	if status != statusInvalidInfoClass {
		t.Errorf("unknown SET_INFO class: status 0x%08x, want INVALID_INFO_CLASS", status)
	}
}

// panicOnReadConn is a net.Conn whose Read panics, used to check serve() recovers.
type panicOnReadConn struct{}

func (panicOnReadConn) Read([]byte) (int, error)         { panic("simulated panic while processing a message") }
func (panicOnReadConn) Write(b []byte) (int, error)      { return len(b), nil }
func (panicOnReadConn) Close() error                     { return nil }
func (panicOnReadConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (panicOnReadConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (panicOnReadConn) SetDeadline(time.Time) error      { return nil }
func (panicOnReadConn) SetReadDeadline(time.Time) error  { return nil }
func (panicOnReadConn) SetWriteDeadline(time.Time) error { return nil }

// TestServeRecover checks that a panic while serving a connection is recovered
// (the connection is dropped) rather than crashing the whole process.
func TestServeRecover(t *testing.T) {
	s := testServer(t, t.TempDir(), "", "")
	c := newConn(s, panicOnReadConn{})
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("a panic while serving must be recovered, got: %v", r)
		}
	}()
	c.serve()
}

// TestShutdown checks that Shutdown returns promptly with a live connection
// and that a second Shutdown is a no-op.
func TestShutdown(t *testing.T) {
	s := testServer(t, t.TempDir(), "", "")
	go func() { _ = s.Serve() }()

	nc, err := net.Dial("tcp", s.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = nc.Close() }()
	time.Sleep(100 * time.Millisecond) // let the connection register

	done := make(chan struct{})
	go func() { _ = s.Shutdown(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown hung with a live connection")
	}
	if err := s.Shutdown(); err != nil {
		t.Errorf("second Shutdown must be a no-op, got %v", err)
	}
}
