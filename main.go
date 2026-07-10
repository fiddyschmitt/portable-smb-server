// portable-smb-server is a portable SMB server: a single executable, no admin
// rights required, no dependencies.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"

	"portable-smb-server/internal/httpvfs"
	"portable-smb-server/internal/localfs"
	"portable-smb-server/internal/openapi"
	"portable-smb-server/internal/smb"
)

// version is the semantic version of portable-smb-server. Update on release.
const version = "0.1.0"

// shareArg is one -folder or -vfs occurrence, optionally named by a following
// -share.
type shareArg struct {
	folder string // local folder to serve (exclusive with vfs)
	vfs    string // base URL of an external VFS provider (exclusive with folder)
	name   string // "" until a -share names it (or a default is assigned)
}

// source describes where the share's data comes from, for messages.
func (a shareArg) source() string {
	if a.vfs != "" {
		return a.vfs
	}
	return a.folder
}

// folderFlag appends a new local-folder share for each -folder occurrence.
type folderFlag struct{ args *[]shareArg }

func (f folderFlag) String() string { return "" }
func (f folderFlag) Set(v string) error {
	*f.args = append(*f.args, shareArg{folder: v})
	return nil
}

// vfsFlag appends a new provider-backed share for each -vfs occurrence.
type vfsFlag struct{ args *[]shareArg }

func (f vfsFlag) String() string { return "" }
func (f vfsFlag) Set(v string) error {
	*f.args = append(*f.args, shareArg{vfs: v})
	return nil
}

// shareNameFlag names the most recent -folder or -vfs. The flag package calls
// Set in argument order, which is what pairs each -share with its source.
type shareNameFlag struct{ args *[]shareArg }

func (f shareNameFlag) String() string { return "" }
func (f shareNameFlag) Set(v string) error {
	if v == "" {
		return errors.New("share name cannot be empty")
	}
	if len(*f.args) == 0 {
		return errors.New("-share must follow a -folder or -vfs")
	}
	last := &(*f.args)[len(*f.args)-1]
	if last.name != "" {
		return fmt.Errorf("%q already has share name %q", last.source(), last.name)
	}
	last.name = v
	return nil
}

func main() {
	var (
		ip       = flag.String("ip", "127.0.0.1", "IP address to bind to")
		port     = flag.Int("port", 1445, "TCP port to bind to")
		user     = flag.String("user", "user", "username for NTLM authentication")
		pass     = flag.String("pass", "password", "password for NTLM authentication")
		guest    = flag.Bool("guest", false, "allow unauthenticated guest access (ignores -user/-pass)")
		logFile  = flag.String("log", "", "also write the log to this file")
		verbose  = flag.Bool("v", false, "verbose (per-request) logging")
		showVer  = flag.Bool("version", false, "print the version and exit")
		readOnly = flag.Bool("readonly", false, "expose every share read-only")
		oapiAddr = flag.String("openapi", "", "also serve the VFS provider OpenAPI spec (Swagger UI) on this address, e.g. 127.0.0.1:8081")
	)
	var args []shareArg
	flag.Var(folderFlag{&args}, "folder", "folder to share; repeatable (default: current directory)")
	flag.Var(vfsFlag{&args}, "vfs", "base URL of an external VFS provider to share (implements the -openapi contract); repeatable")
	flag.Var(shareNameFlag{&args}, "share", "share name for the preceding -folder or -vfs (default: folder base name / provider's suggested name)")
	flag.Usage = usage
	flag.Parse()
	if *showVer {
		fmt.Printf("portable-smb-server v%s\n", version)
		return
	}
	if flag.NArg() > 0 {
		fatalf("unexpected argument %q (folders are passed with -folder)", flag.Arg(0))
	}

	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o666)
		if err != nil {
			fatalf("cannot open log file: %v", err)
		}
		defer f.Close()
		log.SetOutput(io.MultiWriter(os.Stderr, f))
	}
	smb.SetDebug(*verbose)
	log.Printf("portable-smb-server v%s", version)

	if *oapiAddr != "" {
		go func() {
			if err := openapi.Serve(*oapiAddr); err != nil {
				fatalf("openapi endpoint: %v", err)
			}
		}()
	}

	if len(args) == 0 {
		cwd, err := os.Getwd()
		if err != nil {
			fatalf("cannot determine working directory: %v", err)
		}
		args = []shareArg{{folder: cwd, name: "data"}}
	}

	// Connect provider-backed shares first: their default name can come from
	// the provider's /capabilities, and it must be known before deconfliction.
	vfsShares := map[int]*httpvfs.FS{}
	for i := range args {
		if args[i].vfs == "" {
			continue
		}
		f, err := httpvfs.New(args[i].vfs)
		if err != nil {
			fatalf("%v", err)
		}
		vfsShares[i] = f
		if args[i].name == "" {
			args[i].name = f.Name()
		}
		if args[i].name == "" {
			args[i].name = flattenHost(args[i].vfs)
		}
	}
	assignShareNames(args)

	opt := smb.Options{
		ListenAddr: net.JoinHostPort(*ip, strconv.Itoa(*port)),
		User:       *user,
		Pass:       *pass,
	}
	if *guest {
		opt.User, opt.Pass = "", ""
	}
	for i, a := range args {
		var def smb.ShareDef
		if f := vfsShares[i]; f != nil {
			def = smb.ShareDef{Name: a.name, FS: f, ReadOnly: *readOnly || f.ReadOnly()}
			log.Printf("share %q -> %s%s", a.name, f.BaseURL(), roSuffix(def.ReadOnly))
		} else {
			f, err := localfs.New(a.folder)
			if err != nil {
				fatalf("share %q: %v", a.name, err)
			}
			def = smb.ShareDef{Name: a.name, FS: f, ReadOnly: *readOnly}
			log.Printf("share %q -> %s%s", a.name, f.Root(), roSuffix(def.ReadOnly))
		}
		opt.Shares = append(opt.Shares, def)
	}

	server, err := smb.NewServer(opt)
	if err != nil {
		fatalf("%v", err)
	}

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	go func() {
		<-interrupt
		log.Printf("shutting down")
		_ = server.Shutdown()
	}()

	if err := server.Serve(); err != nil {
		fatalf("%v", err)
	}
}

// assignShareNames fills in a name for every share that was not explicitly
// named: the folder's base name, unless that collides with another share's
// name (case-insensitive), in which case the colliding shares deconflict by
// flattening their full path (D:\Temp -> d_temp).
func assignShareNames(args []shareArg) {
	nameCount := func(name string, skip int) int {
		n := 0
		for i, a := range args {
			if i == skip {
				continue
			}
			candidate := a.name
			if candidate == "" {
				candidate = baseName(a.folder)
			}
			if strings.EqualFold(candidate, name) {
				n++
			}
		}
		return n
	}
	for i := range args {
		if args[i].name != "" {
			continue
		}
		base := baseName(args[i].folder)
		if base == "" || nameCount(base, i) > 0 {
			args[i].name = flattenName(args[i].folder)
		} else {
			args[i].name = base
		}
	}
	seen := map[string]string{}
	for _, a := range args {
		key := strings.ToLower(a.name)
		if other, dup := seen[key]; dup {
			fatalf("share name %q used for both %q and %q", a.name, other, a.folder)
		}
		seen[key] = a.folder
	}
}

// baseName returns the final path component of a folder, or "" when the folder
// is a filesystem root (e.g. D:\ or /).
func baseName(folder string) string {
	abs, err := filepath.Abs(folder)
	if err != nil {
		abs = folder
	}
	base := filepath.Base(abs)
	if base == "." || base == string(filepath.Separator) || strings.HasSuffix(base, ":") {
		return ""
	}
	return base
}

// roSuffix annotates a share's startup log line when it is read-only.
func roSuffix(readOnly bool) string {
	if readOnly {
		return " (read-only)"
	}
	return ""
}

// flattenHost turns a provider URL's host into a share name:
// http://127.0.0.1:8080 -> 127_0_0_1_8080.
func flattenHost(rawURL string) string {
	s := rawURL
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		s = u.Host
	}
	s = strings.ToLower(s)
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return '_'
	}, s)
}

// flattenName turns a folder's absolute path into a share name:
// D:\Temp -> d_temp, /mnt/data -> mnt_data.
func flattenName(folder string) string {
	abs, err := filepath.Abs(folder)
	if err != nil {
		abs = folder
	}
	s := strings.ToLower(abs)
	s = strings.ReplaceAll(s, ":", "")
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == '\\' || r == '/' })
	return strings.Join(parts, "_")
}

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), `portable-smb-server v%s - a portable SMB server (single exe, no admin rights, no dependencies)

Usage:
  %s [flags]

Flags:
`, version, filepath.Base(os.Args[0]))
	flag.PrintDefaults()
	fmt.Fprint(flag.CommandLine.Output(), `
Shares are passed as -folder/-share (or -vfs/-share) pairs; -share names the
source before it and may be omitted:

  portable-smb-server -folder "D:\Temp" -share "temp" -folder "D:\Photos"

exports \\HOST\temp and \\HOST\Photos. Unnamed folders default to their base
name; if two unnamed folders share a base name they deconflict by flattening
the path (D:\Temp and E:\Temp become d_temp and e_temp). With no -folder at
all, the current directory is exported as "data".

Bring-your-own VFS: an external program can provide the files by implementing
a small HTTP service (file lists, file contents, ranged sub-file reads); this
server then exposes it as an SMB share:

  portable-smb-server -openapi 127.0.0.1:8081          # browse/fetch the contract
  portable-smb-server -vfs http://127.0.0.1:9000 -share cloud

-vfs and -folder shares can be mixed freely. A provider can declare itself
read-only via its /capabilities endpoint, and -readonly forces every share
read-only from this side.

Connecting (default port 1445 avoids needing admin rights):

  Windows:  net use X: \\127.0.0.1\data /TCPPORT:1445 /USER:user password
  Linux:    sudo mount -t cifs //HOST/data /mnt -o port=1445,vers=3.0,user=user,pass=password
  macOS:    smb://user@HOST:1445/data
`)
}

func fatalf(format string, args ...any) {
	log.Printf(format, args...)
	os.Exit(1)
}
