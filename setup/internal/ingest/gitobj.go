package ingest

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
)

// Bounds on what the object reader will do for one analysis, whatever the
// repository holds.
const (
	maxObject   = 1 << 20  // bytes of one inflated object
	maxBudget   = 32 << 20 // bytes inflated in all
	maxPacks    = 32
	maxDeltaLen = 50 // delta chain depth
)

const (
	objCommit   = 1
	objTree     = 2
	objBlob     = 3
	objTag      = 4
	objOfsDelta = 6
	objRefDelta = 7
)

var errNotFound = errors.New("object not found")

// objStore reads git objects out of a .git directory with no git program: the
// directory is opened as an os.Root, so a symlink inside it cannot lead out of
// the repository, and nothing in it is executed. Loose objects and packfiles
// (index version 2) are understood; alternates are not.
//
// Abuse: the repository is the attacker's. It can ship an object that inflates
// to gigabytes, a delta chain a million deep, an index whose offsets point
// outside the pack, a pack that is a FIFO. Each inflate is capped at maxObject
// and the total at maxBudget, delta depth at maxDeltaLen, every offset is
// checked against the file size, and every file is opened O_NONBLOCK and
// refused unless regular. What this reads is never run.
type objStore struct {
	git    *os.Root
	packs  []*packFile
	budget int64
}

type packFile struct {
	idx, pack *os.File
	n         uint32
	fan       [256]uint32
	size      int64
}

func (p *packFile) close() {
	p.idx.Close()
	p.pack.Close()
}

func openStore(git *os.Root) *objStore {
	s := &objStore{git: git, budget: maxBudget}
	d, err := git.Open("objects/pack")
	if err != nil {
		return s
	}
	defer d.Close()
	ents, _ := d.ReadDir(4 * maxPacks)
	for _, e := range ents {
		n := e.Name()
		if !strings.HasSuffix(n, ".idx") || len(s.packs) >= maxPacks {
			continue
		}
		if p, err := openPack(git, "objects/pack/"+n); err == nil {
			s.packs = append(s.packs, p)
		}
	}
	return s
}

func (s *objStore) close() {
	for _, p := range s.packs {
		p.close()
	}
}

func openRegular(r *os.Root, name string) (*os.File, error) {
	li, err := r.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !li.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	f, err := r.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	return f, nil
}

func openPack(git *os.Root, idxName string) (*packFile, error) {
	idx, err := openRegular(git, idxName)
	if err != nil {
		return nil, err
	}
	pack, err := openRegular(git, strings.TrimSuffix(idxName, ".idx")+".pack")
	if err != nil {
		idx.Close()
		return nil, err
	}
	p := &packFile{idx: idx, pack: pack}
	var hdr [8 + 1024]byte
	if _, err := idx.ReadAt(hdr[:], 0); err != nil || !bytes.Equal(hdr[:8], []byte("\xfftOc\x00\x00\x00\x02")) {
		p.close()
		return nil, errors.New("not a version 2 pack index")
	}
	for i := range p.fan {
		p.fan[i] = binary.BigEndian.Uint32(hdr[8+4*i:])
	}
	p.n = p.fan[255]
	fi, err := pack.Stat()
	if err != nil {
		p.close()
		return nil, err
	}
	p.size = fi.Size()
	if ifi, err := idx.Stat(); err != nil || ifi.Size() < int64(8+1024+int64(p.n)*28) {
		p.close()
		return nil, errors.New("pack index shorter than its object count")
	}
	return p, nil
}

// find returns the pack offset of sha, false when the pack lacks it.
func (p *packFile) find(sha [20]byte) (int64, bool) {
	lo, hi := uint32(0), p.n
	if sha[0] > 0 {
		lo = p.fan[sha[0]-1]
	}
	hi = p.fan[sha[0]]
	if hi > p.n || lo > hi {
		return 0, false
	}
	base := int64(8 + 1024)
	var got [20]byte
	for lo < hi {
		mid := (lo + hi) / 2
		if _, err := p.idx.ReadAt(got[:], base+int64(mid)*20); err != nil {
			return 0, false
		}
		switch c := bytes.Compare(got[:], sha[:]); {
		case c == 0:
			var o [4]byte
			offTable := base + int64(p.n)*24
			if _, err := p.idx.ReadAt(o[:], offTable+int64(mid)*4); err != nil {
				return 0, false
			}
			off := binary.BigEndian.Uint32(o[:])
			if off&0x80000000 == 0 {
				return int64(off), int64(off) < p.size
			}
			var big [8]byte
			if _, err := p.idx.ReadAt(big[:], offTable+int64(p.n)*4+int64(off&0x7fffffff)*8); err != nil {
				return 0, false
			}
			v := binary.BigEndian.Uint64(big[:])
			return int64(v), v < uint64(p.size)
		case c < 0:
			lo = mid + 1
		default:
			hi = mid
		}
	}
	return 0, false
}

// read returns the type and inflated bytes of the object named sha.
func (s *objStore) read(sha [20]byte) (int, []byte, error) {
	hexs := hex.EncodeToString(sha[:])
	if f, err := openRegular(s.git, "objects/"+hexs[:2]+"/"+hexs[2:]); err == nil {
		defer f.Close()
		return s.readLoose(f)
	}
	for _, p := range s.packs {
		if off, ok := p.find(sha); ok {
			return s.readPacked(p, off, 0)
		}
	}
	return 0, nil, errNotFound
}

func (s *objStore) inflate(r io.Reader, size int64) ([]byte, error) {
	if size > maxObject || size > s.budget {
		return nil, errors.New("object over the size bound")
	}
	zr, err := zlib.NewReader(r)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	b, err := io.ReadAll(io.LimitReader(zr, size+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) != size {
		return nil, errors.New("object length differs from its header")
	}
	s.budget -= size
	return b, nil
}

func (s *objStore) readLoose(f *os.File) (int, []byte, error) {
	zr, err := zlib.NewReader(f)
	if err != nil {
		return 0, nil, err
	}
	defer zr.Close()
	b, err := io.ReadAll(io.LimitReader(zr, maxObject+64))
	if err != nil {
		return 0, nil, err
	}
	nul := bytes.IndexByte(b, 0)
	if nul < 0 {
		return 0, nil, errors.New("loose object without a header")
	}
	var typ string
	var size int64
	if _, err := fmt.Sscanf(string(b[:nul]), "%s %d", &typ, &size); err != nil || size != int64(len(b)-nul-1) || size > maxObject || size > s.budget {
		return 0, nil, errors.New("loose object header does not match its body")
	}
	s.budget -= size
	t := map[string]int{"commit": objCommit, "tree": objTree, "blob": objBlob, "tag": objTag}[typ]
	if t == 0 {
		return 0, nil, errors.New("unknown loose object type")
	}
	return t, b[nul+1:], nil
}

func (s *objStore) readPacked(p *packFile, off int64, depth int) (int, []byte, error) {
	if depth > maxDeltaLen {
		return 0, nil, errors.New("delta chain too deep")
	}
	if off < 12 || off >= p.size {
		return 0, nil, errors.New("pack offset outside the pack")
	}
	var h [32]byte
	n, _ := p.pack.ReadAt(h[:], off)
	if n < 2 {
		return 0, nil, errors.New("short pack entry")
	}
	typ := int(h[0]>>4) & 7
	size := int64(h[0] & 15)
	shift := uint(4)
	i := 1
	for h[i-1]&0x80 != 0 {
		if i >= n || shift > 56 {
			return 0, nil, errors.New("bad pack entry size")
		}
		size |= int64(h[i]&0x7f) << shift
		shift += 7
		i++
	}
	switch typ {
	case objCommit, objTree, objBlob, objTag:
		b, err := s.inflate(io.NewSectionReader(p.pack, off+int64(i), p.size-off-int64(i)), size)
		return typ, b, err
	case objOfsDelta:
		if i >= n {
			return 0, nil, errors.New("short ofs-delta")
		}
		c := h[i]
		i++
		back := int64(c & 0x7f)
		for c&0x80 != 0 {
			if i >= n {
				return 0, nil, errors.New("short ofs-delta")
			}
			c = h[i]
			i++
			back = (back+1)<<7 | int64(c&0x7f)
		}
		bt, base, err := s.readPacked(p, off-back, depth+1)
		if err != nil {
			return 0, nil, err
		}
		d, err := s.inflate(io.NewSectionReader(p.pack, off+int64(i), p.size-off-int64(i)), size)
		if err != nil {
			return 0, nil, err
		}
		out, err := s.applyDelta(base, d)
		return bt, out, err
	case objRefDelta:
		if i+20 > n {
			return 0, nil, errors.New("short ref-delta")
		}
		var sha [20]byte
		copy(sha[:], h[i:i+20])
		bt, base, err := s.read(sha)
		if err != nil {
			return 0, nil, err
		}
		d, err := s.inflate(io.NewSectionReader(p.pack, off+int64(i)+20, p.size-off-int64(i)-20), size)
		if err != nil {
			return 0, nil, err
		}
		out, err := s.applyDelta(base, d)
		return bt, out, err
	}
	return 0, nil, errors.New("unknown pack entry type")
}

func (s *objStore) applyDelta(base, d []byte) ([]byte, error) {
	varint := func() (int64, bool) {
		var v int64
		for shift := uint(0); shift < 56; shift += 7 {
			if len(d) == 0 {
				return 0, false
			}
			c := d[0]
			d = d[1:]
			v |= int64(c&0x7f) << shift
			if c&0x80 == 0 {
				return v, true
			}
		}
		return 0, false
	}
	src, ok1 := varint()
	dst, ok2 := varint()
	if !ok1 || !ok2 || src != int64(len(base)) || dst > maxObject || dst > s.budget {
		return nil, errors.New("bad delta header")
	}
	out := make([]byte, 0, dst)
	for len(d) > 0 {
		op := d[0]
		d = d[1:]
		if op&0x80 != 0 {
			var off, n int64
			for b := uint(0); b < 4; b++ {
				if op&(1<<b) != 0 {
					if len(d) == 0 {
						return nil, errors.New("short delta")
					}
					off |= int64(d[0]) << (8 * b)
					d = d[1:]
				}
			}
			for b := uint(0); b < 3; b++ {
				if op&(0x10<<b) != 0 {
					if len(d) == 0 {
						return nil, errors.New("short delta")
					}
					n |= int64(d[0]) << (8 * b)
					d = d[1:]
				}
			}
			if n == 0 {
				n = 0x10000
			}
			if off < 0 || off+n > int64(len(base)) || int64(len(out))+n > dst {
				return nil, errors.New("delta copies outside its base")
			}
			out = append(out, base[off:off+n]...)
		} else if op != 0 {
			if int(op) > len(d) || int64(len(out))+int64(op) > dst {
				return nil, errors.New("delta inserts past its end")
			}
			out = append(out, d[:op]...)
			d = d[op:]
		} else {
			return nil, errors.New("delta opcode 0")
		}
	}
	if int64(len(out)) != dst {
		return nil, errors.New("delta result has the wrong length")
	}
	s.budget -= dst
	return out, nil
}

func parseSHA(s string) ([20]byte, bool) {
	var sha [20]byte
	if len(s) != 40 {
		return sha, false
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return sha, false
	}
	copy(sha[:], b)
	return sha, true
}
