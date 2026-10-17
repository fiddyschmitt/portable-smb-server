package smb

import (
	"errors"
	"io"
)

// maxIOSize is the largest single READ/WRITE payload we accept. It matches the
// MaxReadSize/MaxWriteSize advertised in NEGOTIATE, so a client can't drive an
// arbitrarily large allocation off a wire-supplied length.
const maxIOSize = 0x00100000 // 1 MiB

// handleRead handles an SMB2 READ request ([MS-SMB2] 2.2.19).
func (c *conn) handleRead(h header, body []byte) (uint32, []byte) {
	if len(body) < 48 {
		return statusInvalidParameter, errorResponseBody()
	}
	length := le.Uint32(body[4:8])
	offset := le.Uint64(body[8:16])
	of := c.getHandle(body[16:32])
	if of == nil || of.handle == nil {
		return statusInvalidParameter, errorResponseBody()
	}
	// Reject reads larger than the advertised MaxReadSize rather than allocating
	// an attacker-chosen buffer (a 4 GiB Length would otherwise OOM/panic here).
	if length > maxIOSize {
		return statusInvalidParameter, errorResponseBody()
	}
	if length == 0 {
		return statusSuccess, readResponseBody(make([]byte, readRespFixed))
	}

	// The file data is read straight into the response body, behind its fixed
	// part, so a MiB is never copied from a read buffer into the reply.
	resp := make([]byte, readRespFixed+int(length))
	n, err := of.handle.ReadAt(resp[readRespFixed:], int64(offset))
	if n <= 0 {
		// A read entirely at or after EOF must be answered with
		// STATUS_END_OF_FILE, which the client turns into io.EOF.
		if err == nil || errors.Is(err, io.EOF) {
			return statusEndOfFile, errorResponseBody()
		}
		return mapOSError(err), errorResponseBody()
	}
	return statusSuccess, readResponseBody(resp[:readRespFixed+n])
}

// handleWrite handles an SMB2 WRITE request ([MS-SMB2] 2.2.21).
func (c *conn) handleWrite(h header, body []byte) (uint32, []byte) {
	if len(body) < 48 {
		return statusInvalidParameter, errorResponseBody()
	}
	dataOffset := int(le.Uint16(body[2:4])) - smb2HeaderSize
	length := le.Uint32(body[4:8])
	offset := le.Uint64(body[8:16])
	of := c.getHandle(body[16:32])
	if of == nil || of.handle == nil {
		return statusInvalidParameter, errorResponseBody()
	}
	if of.share.readOnly {
		return statusMediaWriteProtected, errorResponseBody()
	}
	// length stays uint32 and is bounded before any int conversion so it cannot
	// wrap negative and defeat the bounds check on 32-bit builds.
	if length > maxIOSize || dataOffset < 0 || dataOffset+int(length) > len(body) {
		return statusInvalidParameter, errorResponseBody()
	}

	n, err := of.handle.WriteAt(body[dataOffset:dataOffset+int(length)], int64(offset))
	if err != nil {
		return mapOSError(err), errorResponseBody()
	}
	return statusSuccess, writeResponseBody(uint32(n))
}

// handleFlush handles an SMB2 FLUSH request ([MS-SMB2] 2.2.17).
func (c *conn) handleFlush(h header, body []byte) (uint32, []byte) {
	if len(body) < 24 {
		return statusInvalidParameter, errorResponseBody()
	}
	if of := c.getHandle(body[8:24]); of != nil && of.handle != nil {
		if err := of.handle.Sync(); err != nil {
			return mapOSError(err), errorResponseBody()
		}
	}
	return statusSuccess, flushResponseBody()
}

// handleClose handles an SMB2 CLOSE request ([MS-SMB2] 2.2.15). If the open was
// marked delete-on-close, the file or directory is removed.
func (c *conn) handleClose(h header, body []byte) (uint32, []byte) {
	if len(body) < 24 {
		return statusInvalidParameter, errorResponseBody()
	}
	flags := le.Uint16(body[2:4])
	of := c.removeHandle(body[8:24])
	// When the client sets SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB it is asking us to return the file's
	// final attributes in the CLOSE response ([MS-SMB2] 2.2.16), sparing it a separate query. The
	// macOS client always asks, and logs "did not return close attributes" when a server ignores it.
	// A delete-on-close is the exception: the file is about to cease to exist, so there are no final
	// attributes to report -- returning them makes a caching client (macOS smbfs) believe the file
	// it just deleted is still there. For those, answer with the plain response (flag clear).
	var postAttrs []byte
	if flags&closeFlagPostQueryAttrib != 0 && of != nil && !of.deleteOnClose {
		attrs, size, mtime := of.attrs()
		postAttrs = closeAttrs(attrs, size, mtime)
	}
	if of != nil {
		if of.handle != nil {
			// A close failure means a buffered write did not land, so report it
			// instead of SUCCESS.
			if err := of.handle.Close(); err != nil {
				return mapOSError(err), errorResponseBody()
			}
		}
		if of.deleteOnClose {
			if err := of.share.fs.Remove(of.path); err != nil {
				return mapOSError(err), errorResponseBody()
			}
		}
	}
	if postAttrs != nil {
		return statusSuccess, postAttrs
	}
	return statusSuccess, closeResponseBody()
}

// readRespFixed is the size of the READ response's fixed part, which the data follows.
const readRespFixed = 16

// readResponseBody fills in the READ response ([MS-SMB2] 2.2.20) around data
// already in place: body is the fixed part followed by the data.
func readResponseBody(body []byte) []byte {
	le.PutUint16(body[0:2], 17) // StructureSize (fixed magic value)
	// DataOffset is measured from the start of the SMB2 header. The data sits
	// at body offset 16, i.e. wire offset 64+16 = 80. The client validates
	// DataOffset >= 80 and then subtracts 64 to locate the data in the body.
	body[2] = smb2HeaderSize + readRespFixed
	le.PutUint32(body[4:8], uint32(len(body)-readRespFixed))
	return body
}

// writeResponseBody builds the WRITE response ([MS-SMB2] 2.2.22).
func writeResponseBody(count uint32) []byte {
	body := make([]byte, 17)
	le.PutUint16(body[0:2], 17)
	le.PutUint32(body[4:8], count)
	return body
}

// flushResponseBody builds the FLUSH response ([MS-SMB2] 2.2.18).
func flushResponseBody() []byte {
	b := make([]byte, 4)
	le.PutUint16(b[0:2], 4)
	return b
}
