package main

import (
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// An fsWorker drives one share through its mount with the OS's own file API, which is what every
// application does. Several run at once in one process, so one client issues concurrent requests
// on its one SMB connection; several clients run at once on several machines.
//
// Each worker owns stress/<client>/w<N>/ on the share. The names of the files it publishes there
// encode their size (pub_<seq>_<size>.bin) and their content is a function of their share-relative
// path, so any other client, and the audit, can verify them by name alone.

// Published file names: pub_<seq>_<size>.bin.
func pubName(seq int, size int64) string { return fmt.Sprintf("pub_%d_%d.bin", seq, size) }

func parsePubName(name string) (size int64, ok bool) {
	if !strings.HasPrefix(name, "pub_") || !strings.HasSuffix(name, ".bin") {
		return 0, false
	}
	parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(name, "pub_"), ".bin"), "_")
	if len(parts) != 2 {
		return 0, false
	}
	size, err := strconv.ParseInt(parts[1], 10, 64)
	return size, err == nil
}

// Names other software leaves in a directory (Finder's .DS_Store, Windows' thumbs) are ignored in
// listing checks.
func ignoredName(name string) bool { return strings.HasPrefix(name, ".") || strings.EqualFold(name, "Thumbs.db") }

type weightedOp struct {
	name   string
	weight int
	run    func() error
}

func pickOp(rng *rand.Rand, ops []weightedOp) weightedOp {
	total := 0
	for _, o := range ops {
		total += o.weight
	}
	n := rng.Intn(total)
	for _, o := range ops {
		if n < o.weight {
			return o
		}
		n -= o.weight
	}
	return ops[len(ops)-1]
}

type pubFile struct {
	rel  string // share-relative, slash-separated: the content key
	size int64
}

type fsWorker struct {
	cfg  *config
	rec  *recorder
	id   int
	rng  *rand.Rand
	rel  string // this worker's directory, share-relative
	seq  int
	pubs []pubFile

	written, read int64 // bytes moved by the operation in progress
}

func newFSWorker(cfg *config, rec *recorder, id int) *fsWorker {
	return &fsWorker{
		cfg: cfg, rec: rec, id: id,
		rng: rand.New(rand.NewSource(int64(cfg.seed) ^ int64(hashKey(cfg.name))<<8 ^ int64(id))),
		rel: path.Join("stress", cfg.name, fmt.Sprintf("w%d", id)),
	}
}

func (w *fsWorker) abs(rel string) string {
	return filepath.Join(w.cfg.root, filepath.FromSlash(rel))
}

func (w *fsWorker) next() int { w.seq++; return w.seq }

func (w *fsWorker) run(deadline time.Time) {
	if err := os.MkdirAll(w.abs(w.rel), 0o777); err != nil {
		w.rec.begin(w.id, "mkdir", w.rel)
		w.rec.end(w.id, "mkdir", w.rel, time.Now(), 0, 0, err)
		return
	}
	ops := []weightedOp{
		{"small", 25, w.opSmall},
		{"medium", 12, w.opMedium},
		{"large", 4, w.opLarge},
		{"publish", 10, w.opPublish},
		{"mutate", 12, w.opMutate},
		{"tree", 8, w.opTree},
		{"list", 8, w.opList},
		{"corpus", 12, w.opCorpus},
		{"cross", 9, w.opCross},
		{"randio", 10, w.opRandIO},
	}
	if w.cfg.largeMaxMB <= 0 {
		ops[2].weight = 0
	}
	for time.Now().Before(deadline) {
		op := pickOp(w.rng, ops)
		if op.weight == 0 {
			continue
		}
		start := time.Now()
		w.rec.begin(w.id, op.name, w.rel)
		var written, read int64
		err := op.run()
		// The op functions report their bytes through these package-level helpers.
		written, read = w.takeBytes()
		w.rec.end(w.id, op.name, w.rel, start, written, read, err)
	}
	// Leave only what the audit expects: the published files.
	entries, err := os.ReadDir(w.abs(w.rel))
	if err == nil {
		for _, e := range entries {
			if _, isPub := parsePubName(e.Name()); !isPub && !ignoredName(e.Name()) {
				_ = os.RemoveAll(filepath.Join(w.abs(w.rel), e.Name()))
			}
		}
	}
}

// Byte accounting per operation, through the worker (single goroutine per worker).
func (w *fsWorker) note(written, read int64) { w.written += written; w.read += read }
func (w *fsWorker) takeBytes() (written, read int64) {
	written, read = w.written, w.read
	w.written, w.read = 0, 0
	return
}

func (w *fsWorker) expected() []expectedFile {
	out := make([]expectedFile, 0, len(w.pubs))
	for _, p := range w.pubs {
		out = append(out, expectedFile{Path: p.rel, Size: p.size})
	}
	return out
}

// ---- file helpers ----

func writeFile(p string, c *content, size int64, chunk int, doSync bool) error {
	f, err := os.Create(p)
	if err != nil {
		return err
	}
	if err := c.writeTo(f, 0, size, chunk); err != nil {
		_ = f.Close()
		return err
	}
	if doSync {
		if err := f.Sync(); err != nil {
			_ = f.Close()
			return err
		}
	}
	return f.Close()
}

func verifyFile(p string, c *content, size int64) (int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if fi.Size() != size {
		return 0, fmt.Errorf("%q: size %d, want %d", c.key, fi.Size(), size)
	}
	return c.verifyReader(f, 0, size, true)
}

// settle runs a metadata check that may briefly disagree with the server because the client caches
// it. macOS smbfs holds directory entries and file attributes for a few seconds, so a name this
// client just deleted, or a listing it just changed, can linger in its own cache after the server
// has applied the change -- close-to-open, not instantaneous, consistency. Give that cache a
// bounded window to revalidate before calling it a failure. The server's real state is checked
// independently by the harness's backing-store audit, which stays strict. Other clients (Linux
// cifs, the Windows redirector) are coherent here, so they are checked once.
func settle(check func() error) error {
	err := check()
	if err == nil || runtime.GOOS != "darwin" {
		return err
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(250 * time.Millisecond)
		if err = check(); err == nil {
			return nil
		}
	}
	return err
}

func expectGone(p string) error {
	return settle(func() error {
		_, err := os.Lstat(p)
		if err == nil {
			return fmt.Errorf("%s still exists after delete", filepath.Base(p))
		}
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	})
}

func listDir(dir string) (map[string]int64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := map[string]int64{}
	for _, e := range entries {
		if ignoredName(e.Name()) {
			continue
		}
		if e.IsDir() {
			out[e.Name()] = -1
			continue
		}
		fi, err := e.Info()
		if err != nil {
			return nil, err
		}
		out[e.Name()] = fi.Size()
	}
	return out, nil
}

func diffListing(dir string, got, want map[string]int64) error {
	var problems []string
	for name, size := range want {
		g, ok := got[name]
		switch {
		case !ok:
			problems = append(problems, "missing "+name)
		case g != size:
			problems = append(problems, fmt.Sprintf("%s: size %d, want %d", name, g, size))
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			problems = append(problems, "unexpected "+name)
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		if len(problems) > 6 {
			problems = append(problems[:6], fmt.Sprintf("... %d more", len(problems)-6))
		}
		return fmt.Errorf("listing of %s wrong: %s", dir, strings.Join(problems, "; "))
	}
	return nil
}

// ---- the operations ----

// churn writes a file of the given size, reads it back whole, and deletes it.
func (w *fsWorker) churn(op string, size int64, chunk int, doSync bool) error {
	rel := path.Join(w.rel, fmt.Sprintf("%s_%d.bin", op, w.next()))
	c := newContent(w.cfg.seed, rel)
	p := w.abs(rel)
	if err := writeFile(p, c, size, chunk, doSync); err != nil {
		return err
	}
	w.note(size, 0)
	if n, err := verifyFile(p, c, size); err != nil {
		w.note(0, n)
		return err
	}
	w.note(0, size)
	if err := os.Remove(p); err != nil {
		return err
	}
	return expectGone(p)
}

func (w *fsWorker) opSmall() error {
	return w.churn("small", int64(w.rng.Intn(60<<10)+4<<10), 64<<10, false)
}

func (w *fsWorker) opMedium() error {
	return w.churn("medium", int64(w.rng.Intn(7<<20)+1<<20), 1<<20, w.rng.Intn(3) == 0)
}

// opLarge streams a big file, verifies it sequentially and then with random-offset reads.
func (w *fsWorker) opLarge() error {
	size := int64(w.rng.Intn(w.cfg.largeMaxMB*3/4)+w.cfg.largeMaxMB/4+1) << 20
	rel := path.Join(w.rel, fmt.Sprintf("large_%d.bin", w.next()))
	c := newContent(w.cfg.seed, rel)
	p := w.abs(rel)
	if err := writeFile(p, c, size, 1<<20, true); err != nil {
		return err
	}
	w.note(size, 0)
	if n, err := verifyFile(p, c, size); err != nil {
		w.note(0, n)
		return err
	}
	w.note(0, size)
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	for i := 0; i < 8; i++ {
		n := int64(w.rng.Intn(1<<20) + 1)
		off := w.rng.Int63n(size - n + 1)
		if err := c.verifyAt(f, off, n); err != nil {
			_ = f.Close()
			return err
		}
		w.note(0, n)
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Remove(p); err != nil {
		return err
	}
	return expectGone(p)
}

// opPublish writes a temp file and renames it to its final verifiable name. Once the quota of
// published files is reached the oldest is deleted first (it must be gone afterwards).
func (w *fsWorker) opPublish() error {
	if len(w.pubs) >= w.cfg.maxPub {
		old := w.pubs[0]
		w.pubs = w.pubs[1:]
		if err := os.Remove(w.abs(old.rel)); err != nil {
			return err
		}
		if err := expectGone(w.abs(old.rel)); err != nil {
			return err
		}
	}
	size := int64(w.rng.Intn(3<<20) + 1<<10)
	name := pubName(w.next(), size)
	rel := path.Join(w.rel, name)
	tmp := w.abs(path.Join(w.rel, "tmp_"+name))
	c := newContent(w.cfg.seed, rel)
	if err := writeFile(tmp, c, size, 256<<10, false); err != nil {
		return err
	}
	w.note(size, 0)
	if err := os.Rename(tmp, w.abs(rel)); err != nil {
		return err
	}
	if err := expectGone(tmp); err != nil {
		return err
	}
	if n, err := verifyFile(w.abs(rel), c, size); err != nil {
		w.note(0, n)
		return err
	}
	w.note(0, size)
	w.pubs = append(w.pubs, pubFile{rel: rel, size: size})
	return nil
}

// opMutate overwrites random blocks of, appends to, or truncates a private file, then verifies
// the whole file: the writes must land, nothing stale may be read back.
func (w *fsWorker) opMutate() error {
	size := int64(w.rng.Intn(2<<20) + 64<<10)
	rel := path.Join(w.rel, fmt.Sprintf("mut_%d.bin", w.next()))
	c := newContent(w.cfg.seed, rel)
	p := w.abs(rel)
	if err := writeFile(p, c, size, 256<<10, false); err != nil {
		return err
	}
	w.note(size, 0)
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, 1<<20)
	for step := 0; step < 6; step++ {
		switch w.rng.Intn(4) {
		case 0, 1: // overwrite a block-aligned range in place
			if size < blockSize {
				continue
			}
			blocks := size / blockSize
			b0 := w.rng.Int63n(blocks)
			n := w.rng.Int63n(min64(blocks-b0, 64)) + 1
			c.bump(b0, b0+n)
			off, ln := b0*blockSize, n*blockSize
			c.fill(buf[:ln], off)
			if _, err := f.WriteAt(buf[:ln], off); err != nil {
				return err
			}
			w.note(ln, 0)
		case 2: // append
			n := int64(w.rng.Intn(256<<10) + 1)
			// Blocks the append touches that already had content keep their generation; the
			// partial last block, if any, is rewritten whole in its current generation.
			start := size - size%blockSize
			c.fill(buf[:size+n-start], start)
			if _, err := f.WriteAt(buf[:size+n-start], start); err != nil {
				return err
			}
			w.note(n, 0)
			size += n
		case 3: // truncate (shrink)
			if size <= blockSize {
				continue
			}
			size = w.rng.Int63n(size-1) + 1
			if err := f.Truncate(size); err != nil {
				return err
			}
			c.truncate(size)
		}
		if err := c.verifyAt(f, 0, size); err != nil {
			return err
		}
		fi, err := f.Stat()
		if err != nil {
			return err
		}
		if fi.Size() != size {
			return fmt.Errorf("%q: size %d after step %d, want %d", rel, fi.Size(), step, size)
		}
		w.note(0, size)
	}
	if err := f.Close(); err != nil {
		return err
	}
	// Once more from a fresh open: what a later reader sees.
	if n, err := verifyFile(p, c, size); err != nil {
		w.note(0, n)
		return err
	}
	w.note(0, size)
	if err := os.Remove(p); err != nil {
		return err
	}
	return expectGone(p)
}

// randIOCount is how many 4 KiB requests one randio operation issues; the operation's latency
// divided by it is the per-request round trip.
const randIOCount = 64

// opRandIO is what an application does to a file it keeps open: small reads and writes at random
// offsets through one handle -- a database's pages, a document being saved, a zip's directory --
// 4 KiB at a time, one write in four, every read verified. A sequential copy hides the per-request
// round trip behind pipelining; this measures it.
func (w *fsWorker) opRandIO() error {
	const size = 4 << 20
	rel := path.Join(w.rel, fmt.Sprintf("rand_%d.bin", w.next()))
	c := newContent(w.cfg.seed, rel)
	p := w.abs(rel)
	if err := writeFile(p, c, size, 1<<20, false); err != nil {
		return err
	}
	w.note(size, 0)
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, blockSize)
	const blocks = size / blockSize
	for i := 0; i < randIOCount; i++ {
		b := w.rng.Int63n(blocks)
		off := b * blockSize
		if i%4 == 3 {
			c.bump(b, b+1)
			c.fill(buf, off)
			if _, err := f.WriteAt(buf, off); err != nil {
				return err
			}
			w.note(blockSize, 0)
			continue
		}
		if err := c.verifyAt(f, off, blockSize); err != nil {
			return err
		}
		w.note(0, blockSize)
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Remove(p); err != nil {
		return err
	}
	return expectGone(p)
}

// opTree builds a nested tree, checks every listing, renames a directory and a file, and
// removes it all.
func (w *fsWorker) opTree() error {
	root := path.Join(w.rel, fmt.Sprintf("tree_%d", w.next()))
	type file struct {
		rel  string
		size int64
	}
	var files []file
	dirs := []string{root}
	// Three levels, two directories each, two or three files per directory.
	for lvl := 0; lvl < 3; lvl++ {
		var next []string
		for _, d := range dirs {
			if err := os.MkdirAll(w.abs(d), 0o777); err != nil {
				return err
			}
			for i := 0; i < 2+w.rng.Intn(2); i++ {
				f := file{rel: path.Join(d, fmt.Sprintf("f%d.dat", i)), size: int64(w.rng.Intn(32<<10) + 1)}
				if err := writeFile(w.abs(f.rel), newContent(w.cfg.seed, f.rel), f.size, 32<<10, false); err != nil {
					return err
				}
				w.note(f.size, 0)
				files = append(files, f)
			}
			if lvl < 2 {
				next = append(next, path.Join(d, "a"), path.Join(d, "b"))
			}
		}
		dirs = next
	}
	// Every directory lists exactly what was put in it.
	want := map[string]map[string]int64{}
	for _, f := range files {
		d := path.Dir(f.rel)
		if want[d] == nil {
			want[d] = map[string]int64{}
		}
		want[d][path.Base(f.rel)] = f.size
	}
	for d := range want {
		if d != root && !strings.HasSuffix(d, "/a") && !strings.HasSuffix(d, "/b") {
			continue
		}
		for _, sub := range []string{"a", "b"} {
			if _, err := os.Stat(w.abs(path.Join(d, sub))); err == nil {
				want[d][sub] = -1
			}
		}
		got, err := listDir(w.abs(d))
		if err != nil {
			return err
		}
		if err := diffListing(d, got, want[d]); err != nil {
			return err
		}
	}
	// Rename a subdirectory, then a file inside it; both must be readable at their new names and
	// gone from the old ones.
	oldDir, newDir := path.Join(root, "a"), path.Join(root, "a-renamed")
	if err := os.Rename(w.abs(oldDir), w.abs(newDir)); err != nil {
		return err
	}
	if err := expectGone(w.abs(oldDir)); err != nil {
		return err
	}
	for _, f := range files {
		if strings.HasPrefix(f.rel, oldDir+"/") {
			moved := newDir + strings.TrimPrefix(f.rel, oldDir)
			// Content key stays the original path: the bytes don't change with the name.
			if n, err := verifyFile(w.abs(moved), newContent(w.cfg.seed, f.rel), f.size); err != nil {
				w.note(0, n)
				return fmt.Errorf("after directory rename: %v", err)
			}
			w.note(0, f.size)
		}
	}
	f0 := files[0]
	renamed := path.Join(path.Dir(f0.rel), "renamed.dat")
	if err := os.Rename(w.abs(f0.rel), w.abs(renamed)); err != nil {
		return err
	}
	if err := expectGone(w.abs(f0.rel)); err != nil {
		return err
	}
	if n, err := verifyFile(w.abs(renamed), newContent(w.cfg.seed, f0.rel), f0.size); err != nil {
		w.note(0, n)
		return fmt.Errorf("after file rename: %v", err)
	}
	w.note(0, f0.size)
	if err := os.RemoveAll(w.abs(root)); err != nil {
		return err
	}
	return expectGone(w.abs(root))
}

// opList checks that the client sees exactly the files this worker has published (plus nothing
// of its own in flight, as every other op cleans up after itself).
func (w *fsWorker) opList() error {
	want := map[string]int64{}
	for _, p := range w.pubs {
		want[path.Base(p.rel)] = p.size
	}
	return settle(func() error {
		got, err := listDir(w.abs(w.rel))
		if err != nil {
			return err
		}
		return diffListing(w.rel, got, want)
	})
}

// readShared verifies a file some client published (or the corpus), whole or in part.
func (w *fsWorker) readShared(p pubFile) error {
	c := newContent(w.cfg.seed, p.rel)
	if w.rng.Intn(2) == 0 || p.size < 2*blockSize {
		n, err := verifyFile(w.abs(p.rel), c, p.size)
		w.note(0, n)
		return err
	}
	f, err := os.Open(w.abs(p.rel))
	if err != nil {
		return err
	}
	defer f.Close()
	for i := 0; i < 4; i++ {
		n := int64(w.rng.Intn(64<<10) + 1)
		if n > p.size {
			n = p.size
		}
		off := w.rng.Int63n(p.size - n + 1)
		if err := c.verifyAt(f, off, n); err != nil {
			return err
		}
		w.note(0, n)
	}
	return nil
}

// opCorpus reads a file of the shared read-only corpus the harness seeded on the server.
func (w *fsWorker) opCorpus() error {
	files := corpusFiles()
	return w.readShared(files[w.rng.Intn(len(files))])
}

// opCross reads a file published by a different client (or a different worker of this one).
func (w *fsWorker) opCross() error {
	clients, err := os.ReadDir(w.abs("stress"))
	if err != nil {
		return err
	}
	var candidates []pubFile
	for _, cl := range clients {
		if !cl.IsDir() || ignoredName(cl.Name()) {
			continue
		}
		workers, err := os.ReadDir(w.abs(path.Join("stress", cl.Name())))
		if err != nil {
			continue // a client that is just starting up, or finished and cleaned up
		}
		for _, wd := range workers {
			if !wd.IsDir() || path.Join("stress", cl.Name(), wd.Name()) == w.rel {
				continue
			}
			entries, err := os.ReadDir(w.abs(path.Join("stress", cl.Name(), wd.Name())))
			if err != nil {
				continue
			}
			for _, e := range entries {
				if size, ok := parsePubName(e.Name()); ok {
					candidates = append(candidates, pubFile{rel: path.Join("stress", cl.Name(), wd.Name(), e.Name()), size: size})
				}
			}
		}
	}
	if len(candidates) == 0 {
		return nil // nobody has published yet
	}
	p := candidates[w.rng.Intn(len(candidates))]
	err = w.readShared(p)
	// The publisher may have rotated the file out between the listing and the read (its quota of
	// published files is bounded): a vanished file is not a failure, a wrong one is.
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// discard reads and drops everything (for size probes).
var _ = io.Discard
