package dlmsal

import (
	"errors"
	"fmt"
	"io"
)

const (
	memchunksize = 8192
)

type ChunkedStream interface {
	Read(p []byte) (n int, err error)
	Write(p []byte) (n int, err error)
	CopyFrom(src io.Reader) (err error)
	Rewind()
}

type chunkitem struct {
	data [memchunksize]byte
	size int
	next *chunkitem
}

type chunkedstream struct {
	first  *chunkitem
	last   *chunkitem
	curr   *chunkitem
	offset int
}

func (d *chunkedstream) Rewind() {
	d.offset = 0
	d.curr = d.first
}

func (d *chunkedstream) CopyFrom(src io.Reader) (err error) {
	curr := d.curr
	for {
		if curr.size == memchunksize { // a new chunk
			d.last.next = &chunkitem{}
			d.last = d.last.next
			curr = d.last
		}
		n, err := src.Read(curr.data[curr.size:])
		curr.size += n
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if n == 0 { // that shouldnt happen
			panic(fmt.Errorf("no data read"))
		}
	}
}

func (d *chunkedstream) Write(p []byte) (n int, err error) { // always write everything, panic in case out of memory
	n = len(p)
	for len(p) > 0 {
		if d.offset == memchunksize { // a new chunk
			d.last.next = &chunkitem{}
			d.last = d.last.next
			d.curr = d.last
			d.offset = 0
		}
		// having at least some space in d.curr
		nn := copy(d.curr.data[d.offset:], p)
		d.offset += nn
		d.curr.size = d.offset
		p = p[nn:]
	}
	return
}

func (d *chunkedstream) Read(p []byte) (n int, err error) {
	if d.curr == nil {
		return 0, io.EOF
	}
	if d.offset == d.curr.size {
		d.offset = 0
		d.curr = d.curr.next
		return d.Read(p)
	}

	n = copy(p, d.curr.data[d.offset:d.curr.size])
	d.offset += n
	return
}

func NewChunkedStream() ChunkedStream {
	ret := &chunkedstream{}
	ret.first = &chunkitem{}
	ret.last = ret.first
	ret.curr = ret.first
	return ret
}
