// Package httpvfs adapts an external VFS provider service (implementing the
// OpenAPI contract in internal/openapi) into the fsx.FileSystem the SMB
// server serves. portable-smb-server is the HTTP client; the provider is the
// server.
package httpvfs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"portable-smb-server/internal/fsx"
)

// FS is a filesystem backed by a VFS provider service.
type FS struct {
	base            string // base URL without trailing slash
	client          *http.Client
	name            string // suggested share name from /capabilities ("" if none)
	readOnly        bool
	caseInsensitive bool
}

// capabilities mirrors the /capabilities response.
type capabilities struct {
	Name            string `json:"name"`
	ReadOnly        bool   `json:"readOnly"`
	CaseInsensitive bool   `json:"caseInsensitive"`
}

// fileInfoJSON mirrors the FileInfo schema.
type fileInfoJSON struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"modTime"`
	IsDir   bool      `json:"isDir"`
}

// New connects to a provider at baseURL and queries its capabilities. A
// provider that does not implement /capabilities (404) is assumed writable
// and case-sensitive.
func New(baseURL string) (*FS, error) {
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid VFS provider URL %q (want http(s)://host[:port][/prefix])", baseURL)
	}
	f := &FS{
		base:   strings.TrimRight(baseURL, "/"),
		client: &http.Client{Timeout: 60 * time.Second},
	}
	resp, err := f.client.Get(f.base + "/capabilities")
	if err != nil {
		return nil, fmt.Errorf("cannot reach VFS provider at %s: %w", baseURL, err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		var caps capabilities
		if err := json.NewDecoder(resp.Body).Decode(&caps); err != nil {
			return nil, fmt.Errorf("VFS provider %s: bad /capabilities response: %w", baseURL, err)
		}
		f.name = caps.Name
		f.readOnly = caps.ReadOnly
		f.caseInsensitive = caps.CaseInsensitive
	case http.StatusNotFound:
		// Optional endpoint: assume defaults.
	default:
		return nil, fmt.Errorf("VFS provider %s: /capabilities returned %s", baseURL, resp.Status)
	}
	return f, nil
}

// Name returns the provider's suggested share name ("" if it gave none).
func (f *FS) Name() string { return f.name }

// ReadOnly reports whether the provider declared itself read-only.
func (f *FS) ReadOnly() bool { return f.readOnly }

// BaseURL returns the provider's base URL (for display).
func (f *FS) BaseURL() string { return f.base }

// --- request plumbing ---

// endpointURL builds base + endpoint + query, with path as a query parameter.
func (f *FS) endpointURL(endpoint, path string, extra url.Values) string {
	q := url.Values{}
	q.Set("path", path)
	for k, vs := range extra {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	return f.base + endpoint + "?" + q.Encode()
}

// checkResp maps provider HTTP status codes onto the error sentinels the SMB
// layer understands. notEmpty selects what a 409 means for this call.
func checkResp(resp *http.Response, notEmpty bool) error {
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	msg := readErrMsg(resp)
	var sentinel error
	switch resp.StatusCode {
	case http.StatusNotFound:
		sentinel = os.ErrNotExist
	case http.StatusConflict:
		if notEmpty {
			sentinel = fsx.ErrNotEmpty
		} else {
			sentinel = os.ErrExist
		}
	case http.StatusForbidden, http.StatusMethodNotAllowed, http.StatusNotImplemented:
		// Providers may omit write endpoints entirely instead of returning 403.
		sentinel = fsx.ErrReadOnly
	case http.StatusBadRequest:
		sentinel = os.ErrInvalid
	default:
		return fmt.Errorf("VFS provider: %s: %s", resp.Status, msg)
	}
	if msg == "" {
		msg = resp.Status
	}
	return fmt.Errorf("VFS provider: %s: %w", msg, sentinel)
}

func readErrMsg(resp *http.Response) string {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		return e.Error
	}
	return strings.TrimSpace(string(body))
}

// do performs a request with no response body of interest.
func (f *FS) do(method, u string, body io.Reader, notEmpty bool) error {
	req, err := http.NewRequest(method, u, body)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := checkResp(resp, notEmpty); err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// getJSON performs a GET and decodes a JSON response into out.
func (f *FS) getJSON(u string, out any) error {
	resp, err := f.client.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := checkResp(resp, false); err != nil {
		return err
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// --- fsx.FileSystem ---

func (f *FS) Stat(path string) (os.FileInfo, error) {
	var fi fileInfoJSON
	if err := f.getJSON(f.endpointURL("/stat", path, nil), &fi); err != nil {
		return nil, err
	}
	return remoteInfo{fi}, nil
}

func (f *FS) OpenFile(path string, flag int, perm os.FileMode) (fsx.File, error) {
	writeIntent := flag&(os.O_WRONLY|os.O_RDWR|os.O_APPEND|os.O_CREATE|os.O_TRUNC) != 0
	if f.readOnly && writeIntent {
		return nil, fmt.Errorf("open %s for writing: %w", path, fsx.ErrReadOnly)
	}
	if flag&os.O_CREATE != 0 {
		q := url.Values{}
		if flag&os.O_EXCL != 0 {
			q.Set("exclusive", "true")
		}
		if err := f.do(http.MethodPost, f.endpointURL("/create", path, q), nil, false); err != nil {
			return nil, err
		}
	} else {
		// Plain open: verify the path exists and is a file, mirroring
		// os.OpenFile semantics.
		fi, err := f.Stat(path)
		if err != nil {
			return nil, err
		}
		if fi.IsDir() {
			return nil, fmt.Errorf("open %s: is a directory: %w", path, os.ErrInvalid)
		}
	}
	if flag&os.O_TRUNC != 0 {
		if err := f.Truncate(path, 0); err != nil {
			return nil, err
		}
	}
	return &file{fs: f, path: path}, nil
}

func (f *FS) Mkdir(path string, perm os.FileMode) error {
	return f.do(http.MethodPost, f.endpointURL("/mkdir", path, nil), nil, false)
}

func (f *FS) ReadDir(path string) ([]os.FileInfo, error) {
	var out struct {
		Entries []fileInfoJSON `json:"entries"`
	}
	if err := f.getJSON(f.endpointURL("/list", path, nil), &out); err != nil {
		return nil, err
	}
	infos := make([]os.FileInfo, len(out.Entries))
	for i, e := range out.Entries {
		infos[i] = remoteInfo{e}
	}
	return infos, nil
}

func (f *FS) Rename(oldPath, newPath string) error {
	// replace=true mirrors os.Rename; the SMB layer has already enforced the
	// client's ReplaceIfExists choice before calling us.
	body, _ := json.Marshal(map[string]any{"from": oldPath, "to": newPath, "replace": true})
	req, err := http.NewRequest(http.MethodPost, f.base+"/rename", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return checkResp(resp, false)
}

func (f *FS) Remove(path string) error {
	return f.do(http.MethodDelete, f.endpointURL("/remove", path, nil), nil, true)
}

func (f *FS) Truncate(path string, size int64) error {
	q := url.Values{}
	q.Set("size", strconv.FormatInt(size, 10))
	return f.do(http.MethodPost, f.endpointURL("/truncate", path, q), nil, false)
}

func (f *FS) Chtimes(path string, mtime time.Time) error {
	q := url.Values{}
	q.Set("modTime", mtime.UTC().Format(time.RFC3339Nano))
	return f.do(http.MethodPost, f.endpointURL("/chtimes", path, q), nil, false)
}

func (f *FS) Statfs() (total, free int64, err error) {
	var out struct {
		TotalBytes int64 `json:"totalBytes"`
		FreeBytes  int64 `json:"freeBytes"`
	}
	if err := f.getJSON(f.base+"/statfs", &out); err != nil {
		// Optional endpoint: report a large synthetic volume.
		if errors.Is(err, os.ErrNotExist) {
			return 1 << 40, 1 << 39, nil
		}
		return 0, 0, err
	}
	return out.TotalBytes, out.FreeBytes, nil
}

func (f *FS) CaseInsensitive() bool { return f.caseInsensitive }

// --- file handle ---

// file is an open handle on the provider. The provider is stateless (every
// IO carries the path), so the handle is just the path.
type file struct {
	fs   *FS
	path string
}

func (h *file) ReadAt(p []byte, off int64) (int, error) {
	q := url.Values{}
	q.Set("offset", strconv.FormatInt(off, 10))
	q.Set("length", strconv.Itoa(len(p)))
	resp, err := h.fs.client.Get(h.fs.endpointURL("/read", h.path, q))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if err := checkResp(resp, false); err != nil {
		return 0, err
	}
	n, err := io.ReadFull(resp.Body, p)
	if err == io.ErrUnexpectedEOF || err == io.EOF {
		// Fewer bytes than asked: at/past EOF. The io.ReaderAt contract wants
		// io.EOF alongside the short count.
		return n, io.EOF
	}
	return n, err
}

func (h *file) WriteAt(p []byte, off int64) (int, error) {
	q := url.Values{}
	q.Set("offset", strconv.FormatInt(off, 10))
	req, err := http.NewRequest(http.MethodPut, h.fs.endpointURL("/write", h.path, q), bytes.NewReader(p))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := h.fs.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if err := checkResp(resp, false); err != nil {
		return 0, err
	}
	var out struct {
		Written int `json:"written"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, fmt.Errorf("VFS provider: bad /write response: %w", err)
	}
	if out.Written != len(p) {
		return out.Written, io.ErrShortWrite
	}
	return out.Written, nil
}

func (h *file) Truncate(size int64) error  { return h.fs.Truncate(h.path, size) }
func (h *file) Sync() error                { return nil }
func (h *file) Close() error               { return nil }
func (h *file) Stat() (os.FileInfo, error) { return h.fs.Stat(h.path) }

// --- os.FileInfo adapter ---

type remoteInfo struct{ i fileInfoJSON }

func (r remoteInfo) Name() string { return r.i.Name }
func (r remoteInfo) Size() int64  { return r.i.Size }
func (r remoteInfo) Mode() fs.FileMode {
	if r.i.IsDir {
		return fs.ModeDir | 0o777
	}
	return 0o666
}
func (r remoteInfo) ModTime() time.Time { return r.i.ModTime }
func (r remoteInfo) IsDir() bool        { return r.i.IsDir }
func (r remoteInfo) Sys() any           { return nil }
