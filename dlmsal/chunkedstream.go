package dlmsal

import (
	"fmt"
	"io"
)

type ChunkedStream interface {
	Read(p []byte) (n int, err error)
	Write(p []byte) (n int, err error)
	CopyFrom(src io.Reader) (err error)
	Rewind()
	Clear()
}

type chunkedstream struct {
	buffers [][]byte
	offset  int
	size    int
}

func (d *chunkedstream) Rewind() {
	d.offset = 0
}

func (d *chunkedstream) CopyFrom(src io.Reader) (err error) {
	var rem int
	var l int
	if len(d.buffers) == 0 {
		d.buffers = make([][]byte, 1)
		d.buffers[0] = make([]byte, memchunksize)
		rem = memchunksize
		l = 0
	} else {
		l = len(d.buffers) - 1
		rem = cap(d.buffers[l]) - len(d.buffers[l])
		if rem != 0 {
			d.buffers[l] = d.buffers[l][:memchunksize]
		}
	}
	var n int
	for {
		if rem == 0 { // i have to append something
			d.buffers = append(d.buffers, make([]byte, memchunksize))
			l++
			rem = memchunksize
		}
		n, err = src.Read(d.buffers[l][memchunksize-rem:])
		d.size += n
		rem -= n
		if err != nil {
			d.buffers[l] = d.buffers[l][:memchunksize-rem]
			if err == io.EOF {
				return nil
			}
			return err
		}
		if n == 0 {
			d.buffers[l] = d.buffers[l][:memchunksize-rem]
			return fmt.Errorf("no data read") // that shouldnt happen
		}
	}
}

func (d *chunkedstream) Clear() {
	if len(d.buffers) > 0 { // reuse the first chunk
		d.buffers = d.buffers[:1]
		d.buffers[0] = d.buffers[0][:0]
	}
	d.offset = 0
	d.size = 0
}

func (d *chunkedstream) Write(p []byte) (n int, err error) { // always write everything, panic in case out of memory
	var nn int
	n = d.size
	if len(d.buffers) == 0 {
		d.buffers = make([][]byte, 1)
		d.buffers[0] = make([]byte, 0, memchunksize)
		nn = memchunksize
	}
	l := len(d.buffers) - 1
	for len(p) > 0 {
		nn = cap(d.buffers[l]) - len(d.buffers[l])
		if nn == 0 {
			d.buffers = append(d.buffers, make([]byte, 0, memchunksize))
			l++
			nn = memchunksize
		}
		if nn > len(p) {
			nn = len(p)
		}
		d.buffers[l] = append(d.buffers[l], p[:nn]...)
		d.size += nn
		p = p[nn:]
	}
	return d.size - n, nil
}

func (d *chunkedstream) Read(p []byte) (n int, err error) {
	if d.offset == d.size {
		return 0, io.EOF
	}
	n = copy(p, d.buffers[d.offset>>memchunkbits][d.offset&(memchunksize-1):])
	d.offset += n
	return
}

func NewChunkedStream() ChunkedStream {
	return &chunkedstream{offset: 0, size: 0}
}
