package smb

import (
	"crypto/md5"
	"os"
	"strings"
	"time"

	"portable-smb-server/internal/fsx"
)

// QUERY_INFO / SET_INFO InfoType values ([MS-SMB2] 2.2.37).
const (
	infoTypeFile       byte = 0x01
	infoTypeFilesystem byte = 0x02
)

// File information classes ([MS-FSCC] 2.4).
const (
	classFileBasic        byte = 0x04
	classFileStandard     byte = 0x05
	classFileInternal     byte = 0x06
	classFileEa           byte = 0x07
	classFileRename       byte = 0x0A
	classFileDisposition  byte = 0x0D
	classFileAll          byte = 0x12
	classFileEndOfFile    byte = 0x14
	classFileNetworkOpen  byte = 0x22
	classFileAttributeTag byte = 0x23
)

// File system information classes ([MS-FSCC] 2.5).
const (
	classFsVolume    byte = 0x01
	classFsSize      byte = 0x03
	classFsDevice    byte = 0x04
	classFsAttribute byte = 0x05
	classFsFullSize  byte = 0x07
)

// handleQueryInfo handles an SMB2 QUERY_INFO request ([MS-SMB2] 2.2.37).
func (c *conn) handleQueryInfo(h header, body []byte) (uint32, []byte) {
	if len(body) < 40 {
		return statusInvalidParameter, errorResponseBody()
	}
	infoType := body[2]
	infoClass := body[3]
	of := c.getHandle(body[24:40])
	if of == nil {
		return statusInvalidParameter, errorResponseBody()
	}

	var info []byte
	switch infoType {
	case infoTypeFile:
		attrs, size, mtime := of.attrs()
		isDir := attrs&fileAttrDirectory != 0
		switch infoClass {
		case classFileAll:
			info = fileAllInfo(attrs, size, mtime, of.name(), isDir, pathFileID(of.share.name, of.path))
		case classFileStandard:
			info = fileStandardInfo(size, isDir)
		case classFileBasic:
			info = fileBasicInfo(attrs, mtime)
		case classFileInternal:
			info = fileInternalInfo(pathFileID(of.share.name, of.path))
		case classFileEa:
			info = make([]byte, 4) // FileEaInformation: EaSize = 0
		case classFileNetworkOpen:
			info = fileNetworkOpenInfo(attrs, size, mtime)
		case classFileAttributeTag:
			info = fileAttributeTagInfo(attrs)
		default:
			return statusNotSupported, errorResponseBody()
		}
	case infoTypeFilesystem:
		switch infoClass {
		case classFsFullSize:
			info = fsFullSizeInfo(of.share.fs)
		case classFsSize:
			info = fsSizeInfo(of.share.fs)
		case classFsAttribute:
			info = fsAttributeInfo(of.share.readOnly)
		case classFsVolume:
			info = fsVolumeInfo(c.server.serverGUID, of.share.name)
		case classFsDevice:
			info = fsDeviceInfo()
		default:
			return statusNotSupported, errorResponseBody()
		}
	default:
		return statusNotSupported, errorResponseBody()
	}
	return statusSuccess, infoResponseBody(info)
}

// handleQueryDirectory handles an SMB2 QUERY_DIRECTORY request ([MS-SMB2]
// 2.2.33). We return as many entries as fit per response and
// STATUS_NO_MORE_FILES when the listing is exhausted.
func (c *conn) handleQueryDirectory(h header, body []byte) (uint32, []byte) {
	if len(body) < 32 {
		return statusInvalidParameter, errorResponseBody()
	}
	infoClass := body[2]
	flags := body[3]
	outputBufferLength := int(le.Uint32(body[28:32]))
	if outputBufferLength > 1<<20 {
		outputBufferLength = 1 << 20
	}
	of := c.getHandle(body[8:24])
	if of == nil || !of.isDir {
		return statusInvalidParameter, errorResponseBody()
	}
	// Search pattern ([MS-SMB2] 2.2.33 FileName): a client looks up a child by
	// name with a single-entry pattern query, so it must be honoured -- ignoring
	// it makes Windows path resolution follow the wrong entry (the first one).
	pattern := ""
	if l := le.Uint16(body[26:28]); l > 0 {
		if b := bufferAt(body, le.Uint16(body[24:26]), l); b != nil {
			pattern = utf16leToString(b)
		}
	}
	const (
		flagRestartScans      = 0x01
		flagReturnSingleEntry = 0x02
	)
	if flags&flagRestartScans != 0 {
		of.dirLoaded = false
		of.dirEntries = nil
		of.dirPos = 0
	}
	if !of.dirLoaded {
		entries, err := c.listDir(of.share, of.path)
		if err != nil {
			// A directory we can't enumerate (locked by another process, denied)
			// must not fail the request with a generic error: the Windows shell
			// copy engine aborts a whole recursive copy when its scan hits
			// STATUS_UNSUCCESSFUL. Surface it as empty so the client skips it and
			// keeps going.
			logf("SMB: cannot list %q, reporting it empty: %v", of.path, err)
			entries = nil
		}
		of.dirEntries = filterByPattern(entries, pattern, of.share.fs.CaseInsensitive())
		of.dirPos = 0
		of.dirLoaded = true
	}
	if of.dirPos >= len(of.dirEntries) {
		return statusNoMoreFiles, errorResponseBody()
	}
	// Return as many entries as fit in the client's output buffer; the rest
	// come on subsequent calls until we report STATUS_NO_MORE_FILES.
	// A client may set SMB2_RETURN_SINGLE_ENTRY (e.g. Windows FindFirstFile) to
	// request exactly one entry. We must honour it: if we pack more, the client
	// keeps only the first and resumes after it, while our position advances past
	// all we sent, silently dropping the entries in between from the listing.
	entries := of.dirEntries[of.dirPos:]
	if flags&flagReturnSingleEntry != 0 && len(entries) > 1 {
		entries = entries[:1]
	}
	buf, n := buildDirInfoBuffer(entries, outputBufferLength, infoClass, of)
	if n == 0 {
		return statusNoMoreFiles, errorResponseBody()
	}
	of.dirPos += n
	return statusSuccess, infoResponseBody(buf)
}

// filterByPattern returns the directory entries whose name matches an SMB2
// search pattern. An empty pattern or "*" matches everything. caseInsensitive
// follows the backend so matching is consistent with how it resolves names --
// case-sensitive on Linux, insensitive on Windows/macOS.
func filterByPattern(entries []os.FileInfo, pattern string, caseInsensitive bool) []os.FileInfo {
	if pattern == "" || pattern == "*" {
		return entries
	}
	out := make([]os.FileInfo, 0, len(entries))
	for _, fi := range entries {
		if matchPattern(pattern, fi.Name(), caseInsensitive) {
			out = append(out, fi)
		}
	}
	return out
}

// matchPattern reports whether name matches an SMB2 search pattern. It supports
// the '*' and '?' wildcards (mapping the legacy DOS wildcards '<' and '>' onto
// them); a pattern with no wildcard is matched for equality. Case is folded only
// when caseInsensitive is set.
func matchPattern(pattern, name string, caseInsensitive bool) bool {
	pattern = strings.NewReplacer("<", "*", ">", "?").Replace(pattern)
	if !strings.ContainsAny(pattern, "*?") {
		if caseInsensitive {
			return strings.EqualFold(pattern, name)
		}
		return pattern == name
	}
	if caseInsensitive {
		pattern, name = strings.ToLower(pattern), strings.ToLower(name)
	}
	return wildcardMatch([]rune(pattern), []rune(name))
}

// wildcardMatch matches name against a lower-cased pattern of '*' (any run) and
// '?' (any single rune) using the standard linear backtracking algorithm.
func wildcardMatch(pattern, name []rune) bool {
	p, n, star, mark := 0, 0, -1, 0
	for n < len(name) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == name[n]):
			p++
			n++
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, n
			p++
		case star >= 0:
			p = star + 1
			mark++
			n = mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// handleSetInfo handles an SMB2 SET_INFO request ([MS-SMB2] 2.2.39).
func (c *conn) handleSetInfo(h header, body []byte) (uint32, []byte) {
	if len(body) < 32 {
		return statusInvalidParameter, errorResponseBody()
	}
	infoType := body[2]
	infoClass := body[3]
	bufLen := le.Uint32(body[4:8])
	bufOff := int(le.Uint16(body[8:10])) - smb2HeaderSize
	of := c.getHandle(body[16:32])
	if of == nil {
		return statusInvalidParameter, errorResponseBody()
	}
	// int64 arithmetic so a >2 GiB bufLen can't wrap negative on 32-bit builds.
	if bufOff < 0 || int64(bufOff)+int64(bufLen) > int64(len(body)) {
		return statusInvalidParameter, errorResponseBody()
	}
	buf := body[bufOff : bufOff+int(bufLen)]
	if infoType != infoTypeFile {
		return statusNotSupported, errorResponseBody()
	}

	switch infoClass {
	case classFileDisposition:
		if len(buf) >= 1 {
			if buf[0] != 0 && of.share.readOnly {
				return statusMediaWriteProtected, errorResponseBody()
			}
			of.deleteOnClose = buf[0] != 0
		}
	case classFileEndOfFile:
		if len(buf) >= 8 {
			if of.share.readOnly {
				return statusMediaWriteProtected, errorResponseBody()
			}
			if err := c.truncate(of, int64(le.Uint64(buf[0:8]))); err != nil {
				return mapOSError(err), errorResponseBody()
			}
		}
	case classFileRename:
		if of.share.readOnly {
			return statusMediaWriteProtected, errorResponseBody()
		}
		if len(buf) >= 20 {
			replaceIfExists := buf[0] != 0
			nameLen := le.Uint32(buf[16:20])
			if 20+int64(nameLen) <= int64(len(buf)) {
				newPath := nameToPath(utf16leToString(buf[20 : 20+int(nameLen)]))
				// Honour ReplaceIfExists: without it, refuse to clobber an existing
				// target (Windows relies on this to prompt "replace or skip").
				if !replaceIfExists {
					if _, err := of.share.fs.Stat(newPath); err == nil {
						return statusObjectNameCollision, errorResponseBody()
					}
				}
				if err := of.share.fs.Rename(of.path, newPath); err != nil {
					return mapOSError(err), errorResponseBody()
				}
				of.path = newPath
			}
		}
	case classFileBasic:
		if len(buf) >= 32 {
			if lastWrite := le.Uint64(buf[16:24]); lastWrite != 0 {
				// A read-only share silently ignores the timestamp update (the
				// only FileBasic field we act on) rather than failing the
				// request: clients set it as post-write housekeeping.
				if !of.share.readOnly {
					_ = of.share.fs.Chtimes(of.path, filetimeToTime(lastWrite))
				}
			}
		}
	default:
		// Unhandled info classes (e.g. FileLink, FileAllocation) must not report
		// success having done nothing.
		return statusInvalidInfoClass, errorResponseBody()
	}
	return statusSuccess, setInfoResponseBody()
}

// truncate sets the size of an open file.
func (c *conn) truncate(of *openFile, size int64) error {
	if of.handle != nil {
		return of.handle.Truncate(size)
	}
	return of.share.fs.Truncate(of.path, size)
}

// --- response wrappers ---

// infoResponseBody wraps an info buffer in a QUERY_INFO / QUERY_DIRECTORY
// response body ([MS-SMB2] 2.2.34 / 2.2.38), which share a layout.
func infoResponseBody(info []byte) []byte {
	body := make([]byte, 8+len(info))
	le.PutUint16(body[0:2], 9)                // StructureSize (fixed magic value)
	le.PutUint16(body[2:4], smb2HeaderSize+8) // OutputBufferOffset = 72
	le.PutUint32(body[4:8], uint32(len(info)))
	copy(body[8:], info)
	return body
}

// setInfoResponseBody builds the SET_INFO response ([MS-SMB2] 2.2.40).
func setInfoResponseBody() []byte {
	b := make([]byte, 2)
	le.PutUint16(b[0:2], 2)
	return b
}

// --- information class encoders ([MS-FSCC]) ---

func fileBasicInfo(attrs uint32, t time.Time) []byte {
	b := make([]byte, 40)
	ft := timeToFiletime(t)
	le.PutUint64(b[0:8], ft)
	le.PutUint64(b[8:16], ft)
	le.PutUint64(b[16:24], ft)
	le.PutUint64(b[24:32], ft)
	le.PutUint32(b[32:36], attrs)
	return b
}

// pathFileID returns a stable, unique 64-bit FileId for a path. Windows
// clients cache FileIds and treat them as stable identifiers, so they must
// stay constant across server restarts; deriving them from the share name and
// path guarantees that (and keeps ids unique across shares).
func pathFileID(shareName, path string) uint64 {
	sum := md5.Sum([]byte(shareName + "\x00" + path))
	return le.Uint64(sum[:8])
}

func fileInternalInfo(inode uint64) []byte {
	b := make([]byte, 8)
	le.PutUint64(b[0:8], inode) // IndexNumber
	return b
}

func fileNetworkOpenInfo(attrs uint32, size int64, t time.Time) []byte {
	b := make([]byte, 56)
	ft := timeToFiletime(t)
	le.PutUint64(b[0:8], ft)
	le.PutUint64(b[8:16], ft)
	le.PutUint64(b[16:24], ft)
	le.PutUint64(b[24:32], ft)
	le.PutUint64(b[32:40], uint64(size)) // AllocationSize
	le.PutUint64(b[40:48], uint64(size)) // EndOfFile
	le.PutUint32(b[48:52], attrs)
	return b
}

func fileAttributeTagInfo(attrs uint32) []byte {
	b := make([]byte, 8)
	le.PutUint32(b[0:4], attrs) // FileAttributes; ReparseTag (4:8) = 0
	return b
}

func fileStandardInfo(size int64, isDir bool) []byte {
	b := make([]byte, 24)
	le.PutUint64(b[0:8], uint64(size))  // AllocationSize
	le.PutUint64(b[8:16], uint64(size)) // EndOfFile
	le.PutUint32(b[16:20], 1)           // NumberOfLinks
	if isDir {
		b[21] = 1 // Directory
	}
	return b
}

func fileAllInfo(attrs uint32, size int64, t time.Time, name string, isDir bool, fileID uint64) []byte {
	// The name keeps the buffer at or above the 101-byte minimum that clients
	// (cifs) require for FileAllInformation.
	nameBytes := stringToUTF16le(name)
	if len(nameBytes) == 0 {
		nameBytes = []byte{0x00, 0x00}
	}
	b := make([]byte, 96+4+len(nameBytes))
	copy(b[0:40], fileBasicInfo(attrs, t))
	copy(b[40:64], fileStandardInfo(size, isDir))
	le.PutUint64(b[64:72], fileID) // InternalInformation.IndexNumber
	// EaInformation, AccessInformation, PositionInformation, ModeInformation and
	// AlignmentInformation (offsets 72-96) are left zero.
	le.PutUint32(b[96:100], uint32(len(nameBytes))) // NameInformation.FileNameLength
	copy(b[100:], nameBytes)
	return b
}

func fsFullSizeInfo(f fsx.FileSystem) []byte {
	total, free, _ := f.Statfs()
	const bytesPerSector = 512
	const sectorsPerUnit = 8
	unit := int64(bytesPerSector * sectorsPerUnit)
	b := make([]byte, 32)
	le.PutUint64(b[0:8], allocUnits(total, unit))  // TotalAllocationUnits
	le.PutUint64(b[8:16], allocUnits(free, unit))  // CallerAvailableAllocationUnits
	le.PutUint64(b[16:24], allocUnits(free, unit)) // ActualAvailableAllocationUnits
	le.PutUint32(b[24:28], sectorsPerUnit)
	le.PutUint32(b[28:32], bytesPerSector)
	return b
}

func fsSizeInfo(f fsx.FileSystem) []byte {
	total, free, _ := f.Statfs()
	const bytesPerSector = 512
	const sectorsPerUnit = 8
	unit := int64(bytesPerSector * sectorsPerUnit)
	b := make([]byte, 24)
	le.PutUint64(b[0:8], allocUnits(total, unit))
	le.PutUint64(b[8:16], allocUnits(free, unit))
	le.PutUint32(b[16:20], sectorsPerUnit)
	le.PutUint32(b[20:24], bytesPerSector)
	return b
}

func fsAttributeInfo(readOnly bool) []byte {
	name := stringToUTF16le("psmb")
	b := make([]byte, 12+len(name))
	attrs := uint32(0x00000002) // FILE_CASE_PRESERVED_NAMES
	if readOnly {
		attrs |= 0x00080000 // FILE_READ_ONLY_VOLUME
	}
	le.PutUint32(b[0:4], attrs)
	le.PutUint32(b[4:8], 255) // MaximumComponentNameLength
	le.PutUint32(b[8:12], uint32(len(name)))
	copy(b[12:], name)
	return b
}

func fsVolumeInfo(guid [16]byte, label string) []byte {
	labelBytes := stringToUTF16le(label)
	b := make([]byte, 18+len(labelBytes))
	le.PutUint32(b[8:12], le.Uint32(guid[0:4])) // VolumeSerialNumber
	le.PutUint32(b[12:16], uint32(len(labelBytes)))
	copy(b[18:], labelBytes)
	return b
}

func fsDeviceInfo() []byte {
	b := make([]byte, 8)
	le.PutUint32(b[0:4], 0x00000007) // FILE_DEVICE_DISK
	return b
}

// allocUnits returns n/unit clamped to be non-negative.
func allocUnits(n, unit int64) uint64 {
	if n <= 0 {
		return 0
	}
	return uint64(n / unit)
}

// dirInfoLayout returns the fixed-part size and the file-name offset for a
// directory-enumeration FileInformationClass ([MS-FSCC] 2.4), and whether the
// class is supported.
func dirInfoLayout(class byte) (fixed, nameOff int, ok bool) {
	switch class {
	case 0x01: // FileDirectoryInformation
		return 64, 64, true
	case 0x02: // FileFullDirectoryInformation
		return 68, 68, true
	case 0x03: // FileBothDirectoryInformation
		return 94, 94, true
	case 0x0C: // FileNamesInformation
		return 12, 12, true
	case 0x25: // FileIdBothDirectoryInformation
		return 104, 104, true
	case 0x26: // FileIdFullDirectoryInformation
		return 80, 80, true
	}
	return 0, 0, false
}

// buildDirInfoBuffer encodes directory entries as a chain of directory
// information structures of the requested class, packing as many as fit within
// maxLen bytes. It returns the buffer and the number of entries encoded (always
// at least one, to guarantee progress). of is the directory being enumerated;
// it provides the share and parent path for the entries' FileIds.
func buildDirInfoBuffer(entries []os.FileInfo, maxLen int, class byte, of *openFile) ([]byte, int) {
	fixed, nameOff, ok := dirInfoLayout(class)
	if !ok {
		fixed, nameOff = 64, 64 // default to FileDirectoryInformation
	}
	var buf []byte
	count := 0
	lastStart := 0
	for _, fi := range entries {
		nameBytes := stringToUTF16le(fi.Name())
		padded := roundUp(fixed+len(nameBytes), 8)
		if count > 0 && len(buf)+padded > maxLen {
			break
		}
		start := len(buf)
		e := make([]byte, padded)
		le.PutUint32(e[0:4], uint32(padded)) // NextEntryOffset (cleared on the last entry below)
		if class == 0x0C {
			// FileNamesInformation: only the name.
			le.PutUint32(e[8:12], uint32(len(nameBytes)))
		} else {
			ft := timeToFiletime(fi.ModTime())
			le.PutUint64(e[8:16], ft)
			le.PutUint64(e[16:24], ft)
			le.PutUint64(e[24:32], ft)
			le.PutUint64(e[32:40], ft)
			le.PutUint64(e[40:48], uint64(fi.Size())) // EndOfFile
			le.PutUint64(e[48:56], uint64(fi.Size())) // AllocationSize
			le.PutUint32(e[56:60], fileInfoAttrs(fi))
			le.PutUint32(e[60:64], uint32(len(nameBytes)))
			switch class {
			case 0x26: // FileId at offset 72
				le.PutUint64(e[72:80], pathFileID(of.share.name, joinPath(of.path, fi.Name())))
			case 0x25: // FileId at offset 96
				le.PutUint64(e[96:104], pathFileID(of.share.name, joinPath(of.path, fi.Name())))
			}
		}
		copy(e[nameOff:], nameBytes)
		buf = append(buf, e...)
		lastStart = start
		count++
	}
	if count > 0 {
		le.PutUint32(buf[lastStart:lastStart+4], 0) // last entry terminates the chain
	}
	return buf, count
}

func fileInfoAttrs(fi os.FileInfo) uint32 {
	if fi.IsDir() {
		return fileAttrDirectory
	}
	return fileAttrNormal
}

// roundUp rounds n up to the next multiple of align (a power of two).
func roundUp(n, align int) int {
	return (n + align - 1) &^ (align - 1)
}
