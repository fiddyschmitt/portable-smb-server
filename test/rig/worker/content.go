package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Deterministic file content.
//
// Every byte any worker writes is a pure function of (run seed, content key, offset, block
// generation). The key is the file's share-relative path (slash-separated) at creation, so any
// party - the writer, a different client reading it across the share, or the audit running on
// the server's backing store - can verify any byte range of a file knowing only its path. Nothing
// is shared between machines except the seed.
//
// Content is generated per 4 KiB block. Mutable files additionally carry a per-block generation
// that is bumped on every overwrite, so a stale read (old data served from a cache) is told apart
// from plain corruption.

const blockSize = 4096

// hashKey is FNV-1a 64 over the content key.
func hashKey(s string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

// mix is the splitmix64 finaliser.
func mix(x uint64) uint64 {
	x += 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}

// fillBlock writes one whole block of the splitmix64 stream starting at state.
func fillBlock(dst *[blockSize]byte, state uint64) {
	for i := 0; i < blockSize; i += 8 {
		state += 0x9e3779b97f4a7c15
		z := state
		z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
		z = (z ^ (z >> 27)) * 0x94d049bb133111eb
		z ^= z >> 31
		binary.LittleEndian.PutUint64(dst[i:], z)
	}
}

// content describes the expected bytes of one file.
type content struct {
	seed uint64
	key  string
	kh   uint64
	gens []uint32 // per-block generation; nil means every block is generation 0 (immutable file)
}

func newContent(seed uint64, key string) *content {
	return &content{seed: seed, key: key, kh: hashKey(key)}
}

func (c *content) gen(block int64) uint32 {
	if block < int64(len(c.gens)) {
		return c.gens[block]
	}
	return 0
}

// bump advances the generation of every block in [b0, b1).
func (c *content) bump(b0, b1 int64) {
	for int64(len(c.gens)) < b1 {
		c.gens = append(c.gens, 0)
	}
	for b := b0; b < b1; b++ {
		c.gens[b]++
	}
}

// truncate drops generations of blocks wholly beyond size (a partial last block keeps its own).
func (c *content) truncate(size int64) {
	keep := (size + blockSize - 1) / blockSize
	if int64(len(c.gens)) > keep {
		c.gens = c.gens[:keep]
	}
}

func (c *content) blockState(block int64, gen uint32) uint64 {
	return mix(c.seed ^ mix(c.kh^mix(uint64(block)^(uint64(gen)<<40))))
}

// fill writes the expected bytes for [off, off+len(dst)) into dst.
func (c *content) fill(dst []byte, off int64) { c.fillGen(dst, off, 0) }

// fillGen is fill with every block's generation lowered by back (used to recognise stale data).
func (c *content) fillGen(dst []byte, off int64, back uint32) {
	var blk [blockSize]byte
	for len(dst) > 0 {
		b := off / blockSize
		inBlk := int(off % blockSize)
		g := c.gen(b)
		if back > g {
			g = 0
		} else {
			g -= back
		}
		fillBlock(&blk, c.blockState(b, g))
		n := copy(dst, blk[inBlk:])
		dst = dst[n:]
		off += int64(n)
	}
}

// writeTo streams the expected bytes for [off, off+n) to w in chunks of at most chunk bytes.
func (c *content) writeTo(w io.Writer, off, n int64, chunk int) error {
	buf := make([]byte, chunk)
	for n > 0 {
		m := int64(len(buf))
		if m > n {
			m = n
		}
		c.fill(buf[:m], off)
		if _, err := w.Write(buf[:m]); err != nil {
			return err
		}
		off += m
		n -= m
	}
	return nil
}

// mismatchError reports the first differing byte, with a diagnosis of what was read instead.
type mismatchError struct {
	key    string
	offset int64
	hint   string
}

func (e *mismatchError) Error() string {
	return fmt.Sprintf("content mismatch in %q at offset %d (block %d): %s", e.key, e.offset, e.offset/blockSize, e.hint)
}

// diagnose classifies a wrong chunk: zeros, an older generation (stale cache), or plain garbage.
func (c *content) diagnose(got []byte, off int64) string {
	if len(bytes.TrimLeft(got, "\x00")) == 0 {
		return "read all zeros"
	}
	stale := make([]byte, len(got))
	for back := uint32(1); back <= 3; back++ {
		c.fillGen(stale, off, back)
		if bytes.Equal(stale, got) {
			return fmt.Sprintf("read STALE data (%d generation(s) old)", back)
		}
	}
	return "read unexpected bytes"
}

func (c *content) compare(got []byte, off int64, want []byte) error {
	c.fill(want, off)
	if bytes.Equal(got, want) {
		return nil
	}
	i := 0
	for i < len(got) && got[i] == want[i] {
		i++
	}
	// Diagnose on the block containing the first difference.
	bad := off + int64(i)
	bs := bad - bad%blockSize
	if bs < off {
		bs = off
	}
	be := bs + blockSize - bs%blockSize
	if be > off+int64(len(got)) {
		be = off + int64(len(got))
	}
	return &mismatchError{key: c.key, offset: bad, hint: c.diagnose(got[bs-off:be-off], bs)}
}

const verifyChunk = 1 << 20

// verifyReader reads exactly n bytes from r and checks them against [off, off+n). With atEOF it
// also requires r to end there, catching files that are longer than expected.
func (c *content) verifyReader(r io.Reader, off, n int64, atEOF bool) (int64, error) {
	chunk := int64(verifyChunk)
	if n < chunk {
		chunk = n // a 4 KiB read needn't allocate a MiB
	}
	got := make([]byte, chunk)
	want := make([]byte, chunk)
	var total int64
	for n > 0 {
		m := int64(len(got))
		if m > n {
			m = n
		}
		k, err := io.ReadFull(r, got[:m])
		total += int64(k)
		if k > 0 {
			if cerr := c.compare(got[:k], off, want[:k]); cerr != nil {
				return total, cerr
			}
		}
		if err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
				return total, fmt.Errorf("short read of %q: got %d bytes, want %d more at offset %d", c.key, k, m, off)
			}
			return total, err
		}
		off += m
		n -= m
	}
	if atEOF {
		var one [1]byte
		if k, _ := r.Read(one[:]); k > 0 {
			return total, fmt.Errorf("%q is longer than expected: data past offset %d", c.key, off)
		}
	}
	return total, nil
}

// verifyAt checks [off, off+n) through a ReaderAt (random-access reads).
func (c *content) verifyAt(r io.ReaderAt, off, n int64) error {
	_, err := c.verifyReader(io.NewSectionReader(r, off, n), off, n, false)
	return err
}
