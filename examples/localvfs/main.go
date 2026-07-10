// localvfs is a reference VFS provider for portable-smb-server: it serves a
// local folder over the provider contract (fetch the spec from
// `portable-smb-server -openapi <addr>`). It exists to show what an external
// program must implement — in any language — for portable-smb-server to
// expose it as an SMB share, and to test the -vfs plumbing end to end:
//
//	localvfs -folder D:\Data -addr 127.0.0.1:9000
//	portable-smb-server -vfs http://127.0.0.1:9000
package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"portable-smb-server/internal/localfs"
	"portable-smb-server/internal/vfsprovider"
)

func main() {
	var (
		addr     = flag.String("addr", "127.0.0.1:9000", "address to serve the VFS provider API on")
		folder   = flag.String("folder", "", "folder to expose (default: current directory)")
		name     = flag.String("name", "", "share name to suggest via /capabilities (default: folder's base name)")
		readOnly = flag.Bool("readonly", false, "declare the provider read-only")
	)
	flag.Parse()

	dir := *folder
	if dir == "" {
		var err error
		if dir, err = os.Getwd(); err != nil {
			log.Fatal(err)
		}
	}
	f, err := localfs.New(dir)
	if err != nil {
		log.Fatal(err)
	}
	shareName := *name
	if shareName == "" {
		shareName = filepath.Base(f.Root())
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("localvfs provider serving %s as %q on http://%s", f.Root(), shareName, ln.Addr())
	log.Printf("connect it with: portable-smb-server -vfs http://%s", ln.Addr())
	log.Fatal(http.Serve(ln, vfsprovider.Handler(f, vfsprovider.Options{Name: shareName, ReadOnly: *readOnly})))
}
