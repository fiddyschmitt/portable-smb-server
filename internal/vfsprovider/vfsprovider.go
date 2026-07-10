// Package vfsprovider is a reference implementation of the VFS provider
// contract (internal/openapi/openapi.json), serving a local folder. It is
// what an external program would implement in any language; here it doubles
// as the example provider and as the test double for the httpvfs client.
package vfsprovider

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"portable-smb-server/internal/localfs"
)

// maxReadChunk caps a single /read response so a bogus length parameter
// cannot make us allocate arbitrarily much.
const maxReadChunk = 8 << 20

// Options configures the provider.
type Options struct {
	Name     string // suggested share name advertised via /capabilities
	ReadOnly bool   // reject all write endpoints with 403
}

// Handler returns an http.Handler implementing the VFS provider contract on
// top of a localfs root.
func Handler(f *localfs.FS, opt Options) http.Handler {
	p := &provider{fs: f, opt: opt}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /capabilities", p.capabilities)
	mux.HandleFunc("GET /stat", p.stat)
	mux.HandleFunc("GET /list", p.list)
	mux.HandleFunc("GET /read", p.read)
	mux.HandleFunc("GET /statfs", p.statfs)
	mux.HandleFunc("POST /create", p.writeGate(p.create))
	mux.HandleFunc("PUT /write", p.writeGate(p.write))
	mux.HandleFunc("POST /mkdir", p.writeGate(p.mkdir))
	mux.HandleFunc("POST /rename", p.writeGate(p.rename))
	mux.HandleFunc("DELETE /remove", p.writeGate(p.remove))
	mux.HandleFunc("POST /truncate", p.writeGate(p.truncate))
	mux.HandleFunc("POST /chtimes", p.writeGate(p.chtimes))
	return mux
}

type provider struct {
	fs  *localfs.FS
	opt Options
}

type fileInfoJSON struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"modTime"`
	IsDir   bool      `json:"isDir"`
}

func toJSON(fi os.FileInfo) fileInfoJSON {
	return fileInfoJSON{Name: fi.Name(), Size: fi.Size(), ModTime: fi.ModTime(), IsDir: fi.IsDir()}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

// fail maps a filesystem error onto the contract's status codes.
func fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, os.ErrNotExist):
		writeErr(w, http.StatusNotFound, err)
	case errors.Is(err, os.ErrExist):
		writeErr(w, http.StatusConflict, err)
	case errors.Is(err, os.ErrPermission):
		writeErr(w, http.StatusForbidden, err)
	default:
		writeErr(w, http.StatusInternalServerError, err)
	}
}

// writeGate rejects write endpoints when the provider is read-only.
func (p *provider) writeGate(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if p.opt.ReadOnly {
			writeErr(w, http.StatusForbidden, errors.New("provider is read-only"))
			return
		}
		h(w, r)
	}
}

func (p *provider) capabilities(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"name":            p.opt.Name,
		"readOnly":        p.opt.ReadOnly,
		"caseInsensitive": p.fs.CaseInsensitive(),
	})
}

func (p *provider) stat(w http.ResponseWriter, r *http.Request) {
	fi, err := p.fs.Stat(r.URL.Query().Get("path"))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toJSON(fi))
}

func (p *provider) list(w http.ResponseWriter, r *http.Request) {
	infos, err := p.fs.ReadDir(r.URL.Query().Get("path"))
	if err != nil {
		fail(w, err)
		return
	}
	entries := make([]fileInfoJSON, len(infos))
	for i, fi := range infos {
		entries[i] = toJSON(fi)
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

func (p *provider) read(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	offset, err1 := strconv.ParseInt(q.Get("offset"), 10, 64)
	length, err2 := strconv.Atoi(q.Get("length"))
	if err1 != nil || err2 != nil || offset < 0 || length < 0 {
		writeErr(w, http.StatusBadRequest, errors.New("bad offset/length"))
		return
	}
	if length > maxReadChunk {
		length = maxReadChunk
	}
	h, err := p.fs.OpenFile(q.Get("path"), os.O_RDONLY, 0)
	if err != nil {
		fail(w, err)
		return
	}
	defer h.Close()
	buf := make([]byte, length)
	n, err := h.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(buf[:n])
}

func (p *provider) statfs(w http.ResponseWriter, r *http.Request) {
	total, free, err := p.fs.Statfs()
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"totalBytes": total, "freeBytes": free})
}

func (p *provider) create(w http.ResponseWriter, r *http.Request) {
	flag := os.O_WRONLY | os.O_CREATE
	if r.URL.Query().Get("exclusive") == "true" {
		flag |= os.O_EXCL
	}
	h, err := p.fs.OpenFile(r.URL.Query().Get("path"), flag, 0o666)
	if err != nil {
		fail(w, err)
		return
	}
	_ = h.Close()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (p *provider) write(w http.ResponseWriter, r *http.Request) {
	offset, err := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
	if err != nil || offset < 0 {
		writeErr(w, http.StatusBadRequest, errors.New("bad offset"))
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, maxReadChunk+1))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if len(data) > maxReadChunk {
		writeErr(w, http.StatusBadRequest, errors.New("write body too large"))
		return
	}
	h, err := p.fs.OpenFile(r.URL.Query().Get("path"), os.O_RDWR, 0o666)
	if err != nil {
		fail(w, err)
		return
	}
	defer h.Close()
	n, err := h.WriteAt(data, offset)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"written": n})
}

func (p *provider) mkdir(w http.ResponseWriter, r *http.Request) {
	if err := p.fs.Mkdir(r.URL.Query().Get("path"), 0o777); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (p *provider) rename(w http.ResponseWriter, r *http.Request) {
	var req struct {
		From    string `json:"from"`
		To      string `json:"to"`
		Replace bool   `json:"replace"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if !req.Replace {
		if _, err := p.fs.Stat(req.To); err == nil {
			writeErr(w, http.StatusConflict, errors.New("target exists"))
			return
		}
	}
	if err := p.fs.Rename(req.From, req.To); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (p *provider) remove(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if err := p.fs.Remove(path); err != nil {
		// The contract reports a non-empty directory as 409. Detect it
		// portably: the path still exists, is a dir, and has entries.
		if fi, serr := p.fs.Stat(path); serr == nil && fi.IsDir() {
			if entries, lerr := p.fs.ReadDir(path); lerr == nil && len(entries) > 0 {
				writeErr(w, http.StatusConflict, errors.New("directory not empty"))
				return
			}
		}
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (p *provider) truncate(w http.ResponseWriter, r *http.Request) {
	size, err := strconv.ParseInt(r.URL.Query().Get("size"), 10, 64)
	if err != nil || size < 0 {
		writeErr(w, http.StatusBadRequest, errors.New("bad size"))
		return
	}
	if err := p.fs.Truncate(r.URL.Query().Get("path"), size); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (p *provider) chtimes(w http.ResponseWriter, r *http.Request) {
	mtime, err := time.Parse(time.RFC3339Nano, r.URL.Query().Get("modTime"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("bad modTime (want RFC3339)"))
		return
	}
	if err := p.fs.Chtimes(r.URL.Query().Get("path"), mtime); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
