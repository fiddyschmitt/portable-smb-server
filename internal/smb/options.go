package smb

import "portable-smb-server/internal/fsx"

// ShareDef is one share to export: a name and the filesystem behind it.
type ShareDef struct {
	Name     string
	FS       fsx.FileSystem
	ReadOnly bool // reject all mutations with STATUS_MEDIA_WRITE_PROTECTED
}

// Options configures the SMB server.
type Options struct {
	ListenAddr string     // address to listen on, e.g. "127.0.0.1:1445"
	User       string     // username for NTLM authentication; empty allows guest access
	Pass       string     // password for NTLM authentication
	Shares     []ShareDef // shares to export (at least one)
}
