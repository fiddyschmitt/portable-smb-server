package smb

import "time"

// Small fixed-size response bodies for the simple commands.

// echoResponseBody is the SMB2 ECHO response ([MS-SMB2] 2.2.29): StructureSize 4.
func echoResponseBody() []byte {
	b := make([]byte, 4)
	le.PutUint16(b[0:2], 4)
	return b
}

// treeDisconnectResponseBody is the SMB2 TREE_DISCONNECT response: StructureSize 4.
func treeDisconnectResponseBody() []byte {
	b := make([]byte, 4)
	le.PutUint16(b[0:2], 4)
	return b
}

// logoffResponseBody is the SMB2 LOGOFF response: StructureSize 4.
func logoffResponseBody() []byte {
	b := make([]byte, 4)
	le.PutUint16(b[0:2], 4)
	return b
}

// closeResponseBody is the SMB2 CLOSE response ([MS-SMB2] 2.2.16):
// StructureSize 60, Flags 0, with all attribute fields zeroed -- for a close
// whose request did not set SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB.
func closeResponseBody() []byte {
	b := make([]byte, 60)
	le.PutUint16(b[0:2], 60)
	return b
}

// SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB ([MS-SMB2] 2.2.15): the client wants the
// file's final attributes back in the CLOSE response.
const closeFlagPostQueryAttrib = 0x0001

// closeAttrs is the SMB2 CLOSE response with the post-query attributes filled in
// and the flag set, for a request that asked for them. We hold one timestamp per
// file, so creation/access/write/change all carry it, as the other info
// responses do.
func closeAttrs(attrs uint32, size int64, mtime time.Time) []byte {
	b := make([]byte, 60)
	le.PutUint16(b[0:2], 60)
	le.PutUint16(b[2:4], closeFlagPostQueryAttrib)
	ft := timeToFiletime(mtime)
	le.PutUint64(b[8:16], ft)            // CreationTime
	le.PutUint64(b[16:24], ft)           // LastAccessTime
	le.PutUint64(b[24:32], ft)           // LastWriteTime
	le.PutUint64(b[32:40], ft)           // ChangeTime
	le.PutUint64(b[40:48], uint64(size)) // AllocationSize
	le.PutUint64(b[48:56], uint64(size)) // EndOfFile
	le.PutUint32(b[56:60], attrs)        // FileAttributes
	return b
}

// lockResponseBody is the SMB2 LOCK response ([MS-SMB2] 2.2.27): StructureSize
// 4. We do not enforce byte-range locks but grant every request so clients
// (notably Windows) that rely on advisory locking can proceed.
func lockResponseBody() []byte {
	b := make([]byte, 4)
	le.PutUint16(b[0:2], 4)
	return b
}
