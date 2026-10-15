package smb

// Apple's SMB2 extensions. [MS-SMB2] has none of this; the references are Samba's vfs_fruit (check_aapl and
// the readdir_attr marshalling in trans2.c) and Apple's "SMB2 Apple Extensions" note. A macOS client sends an
// "AAPL" create context on its first CREATE after a tree connect. A server that answers it claiming
// kAAPL_SUPPORTS_READ_DIR_ATTR then packs the extra per-entry facts macOS wants (max access, resource fork
// size, Finder info) into every FileIdBothDirectoryInformation entry it sends that client, and the client
// takes a directory from the enumeration alone. Without it macOS looks every entry up one by one: a compound
// CREATE / QUERY_DIRECTORY by name / CLOSE per entry, two or three of them with the AppleDouble sidecar
// checks, each a round trip. On loopback that is merely slow; over a LAN a 5,000-file folder never listed
// within the lab's two-minute bound (about 1,900 lookups in 45 s).

const (
	aaplContextName = "AAPL"

	// command codes
	aaplServerQuery uint32 = 1
	aaplResolveID   uint32 = 2

	// request / reply bitmap
	aaplServerCaps uint64 = 1
	aaplVolumeCaps uint64 = 2
	aaplModelInfo  uint64 = 4

	// client and server capabilities
	aaplSupportsReadDirAttr uint64 = 1
	aaplSupportsOSXCopyfile uint64 = 2
	aaplUnixBased           uint64 = 4
	aaplSupportsNFSACE      uint64 = 8

	// volume capabilities
	aaplSupportResolveID uint64 = 1
	aaplCaseSensitive    uint64 = 2
	aaplSupportsFullSync uint64 = 4

	// The model string only picks the icon macOS shows for the server; Samba's default.
	appleModel = "MacSamba"

	// Max access, a Windows access mask, is what macOS reads from the EaSize field of a ReadDirAttr entry.
	accessAll         uint32 = 0x001F01FF // FILE_ALL_ACCESS
	accessReadExecute uint32 = 0x001200A9 // FILE_GENERIC_READ | FILE_GENERIC_EXECUTE

	// Apple's layout fills the ShortName area of a FileIdBothDirectoryInformation entry: resource fork size at
	// 70, compressed Finder info at 78, the UNIX mode in Reserved2 at 94; FileId follows at 96.
	appleShortNameLength = 24
)

// createContexts returns a CREATE request's create contexts ([MS-SMB2] 2.2.13.2) by name, nil when it carries
// none or they are malformed. Offsets inside a context are relative to that context; the chain's offset is
// from the SMB2 header.
func createContexts(body []byte) map[string][]byte {
	if len(body) < 56 {
		return nil
	}
	off := int(le.Uint32(body[48:52])) - smb2HeaderSize
	length := int(le.Uint32(body[52:56]))
	if off < 0 || length <= 0 || off+length > len(body) {
		return nil
	}
	ctxs := map[string][]byte{}
	for base := off; base+16 <= off+length; {
		next := int(le.Uint32(body[base : base+4]))
		nameOff := int(le.Uint16(body[base+4 : base+6]))
		nameLen := int(le.Uint16(body[base+6 : base+8]))
		dataOff := int(le.Uint16(body[base+10 : base+12]))
		dataLen := int(le.Uint32(body[base+12 : base+16]))
		if nameLen == 0 || base+nameOff+nameLen > len(body) || base+dataOff+dataLen > len(body) {
			break
		}
		name := string(body[base+nameOff : base+nameOff+nameLen])
		var data []byte
		if dataLen > 0 {
			data = body[base+dataOff : base+dataOff+dataLen]
		}
		ctxs[name] = data
		if next <= 0 {
			break
		}
		base += next
	}
	return ctxs
}

// createContextBlob encodes one create context for a CREATE response ([MS-SMB2] 2.2.13.2), the last of its
// chain (Next = 0): the 16-byte head, the name at 16, the data 8-aligned after it.
func createContextBlob(name string, data []byte) []byte {
	dataOff := roundUp(16+len(name), 8)
	b := make([]byte, roundUp(dataOff+len(data), 8))
	le.PutUint16(b[4:6], 16)
	le.PutUint16(b[6:8], uint16(len(name)))
	le.PutUint16(b[10:12], uint16(dataOff))
	le.PutUint32(b[12:16], uint32(len(data)))
	copy(b[16:], name)
	copy(b[dataOff:], data)
	return b
}

// withCreateContexts appends create contexts to a CREATE response body ([MS-SMB2] 2.2.14): after the 88 fixed
// bytes, which puts them at offset 152 from the header (8-aligned); the body's padding byte goes.
func withCreateContexts(resp []byte, contexts []byte) []byte {
	if len(contexts) == 0 {
		return resp
	}
	body := make([]byte, 88+len(contexts))
	copy(body, resp[:88])
	le.PutUint32(body[80:84], smb2HeaderSize+88)
	le.PutUint32(body[84:88], uint32(len(contexts)))
	copy(body[88:], contexts)
	return body
}

// withAppleContext answers the AAPL context of a CREATE request, when it carries one, on the response body,
// and turns ReadDirAttr on for the connection when the client asked for it. Other create contexts (MxAc,
// QFid, DH2Q...) are ignored as before: clients get by without them.
func (c *conn) withAppleContext(reqBody []byte, sh *share, resp []byte) []byte {
	ctxs := createContexts(reqBody)
	if debugEnabled && len(reqBody) >= 56 && le.Uint32(reqBody[52:56]) > 0 {
		names := make([]string, 0, len(ctxs))
		for name := range ctxs {
			names = append(names, name)
		}
		debugf("SMB: CREATE contexts offset=%d length=%d parsed=%v", le.Uint32(reqBody[48:52]), le.Uint32(reqBody[52:56]), names)
	}
	req, ok := ctxs[aaplContextName]
	if !ok {
		return resp
	}
	data := c.appleServerQueryResponse(req, sh)
	if data == nil {
		return resp
	}
	return withCreateContexts(resp, createContextBlob(aaplContextName, data))
}

// appleServerQueryResponse answers a kAAPL_SERVER_QUERY. The request is 24 bytes: command, reserved, the
// request bitmap, the client's capabilities. The reply is the command, the bitmap answered, then, as the
// bitmap asked: the server capabilities (ReadDirAttr when the client has it; no copyfile, no UNIX mode, no
// NFS ACEs), the volume capabilities (case sensitivity, from the backend), and the model string as a
// counted UTF-16 string behind a zero word.
func (c *conn) appleServerQueryResponse(req []byte, sh *share) []byte {
	if len(req) < 24 || le.Uint32(req[0:4]) != aaplServerQuery {
		return nil
	}
	bitmap := le.Uint64(req[8:16])
	clientCaps := le.Uint64(req[16:24])
	out := make([]byte, 16, 64)
	le.PutUint32(out[0:4], aaplServerQuery)
	le.PutUint64(out[8:16], bitmap)
	if bitmap&aaplServerCaps != 0 {
		// UNIX-based unconditionally, as Samba answers: the entries then carry a UNIX mode
		caps := aaplUnixBased
		if clientCaps&aaplSupportsReadDirAttr != 0 {
			caps |= aaplSupportsReadDirAttr
			c.aapl = true
		}
		out = le.AppendUint64(out, caps)
	}
	if bitmap&aaplVolumeCaps != 0 {
		var caps uint64
		if !sh.fs.CaseInsensitive() {
			caps |= aaplCaseSensitive
		}
		out = le.AppendUint64(out, caps)
	}
	if bitmap&aaplModelInfo != 0 {
		model := stringToUTF16le(appleModel)
		out = le.AppendUint32(out, 0)
		out = le.AppendUint32(out, uint32(len(model)))
		out = append(out, model...)
	}
	return out
}

// appleReadDirAttr fills Apple's layout of a FileIdBothDirectoryInformation entry: the max access in EaSize, a
// ShortNameLength of 24 (what clients put on the wire, Samba notes, though Apple's document says 0), the
// resource fork size and the compressed Finder info (zero: no forks, no Finder info), and the UNIX mode in
// Reserved2, since the server says it is UNIX-based: 755 for a folder, 644 for a file, 444 when read-only.
func appleReadDirAttr(e []byte, readOnly, isDir bool) {
	access := accessAll
	mode := uint16(0o644)
	if isDir {
		mode = 0o755
	}
	if readOnly {
		access = accessReadExecute
		mode &^= 0o222
	}
	le.PutUint32(e[64:68], access)
	e[68] = appleShortNameLength
	e[69] = 0
	for i := 70; i < 94; i++ {
		e[i] = 0
	}
	le.PutUint16(e[94:96], mode)
}
