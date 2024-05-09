package dlmsal

import (
	"fmt"
	"io"

	"go.uber.org/zap"
)

type streamItemType byte

const (
	memchunksize = 4096
	memchunkbits = 12
)

const (
	StreamElementStart streamItemType = iota
	StreamElementEnd
	StreamElementData
)

type DlmsDataStreamItem struct {
	Type  streamItemType
	Count int
	Data  DlmsData
}

type DlmsDataStream interface {
	NextElement() (*DlmsDataStreamItem, error)
	Rewind() error
	Close() error
}

type datastream struct {
	src      io.Reader
	buffer   []byte
	stack    []datastreamstate
	inerror  bool
	ineof    bool
	logger   *zap.SugaredLogger
	inmemory bool
	mem      *datachunked
}

type datachunked struct {
	buffers [][]byte
	offset  int
	size    int
}

func (d *datachunked) rewind() {
	d.offset = 0
}

func (d *datachunked) appendfrom(src io.Reader) (err error) {
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

func (d *datachunked) clear() {
	if len(d.buffers) > 0 { // reuse the first chunk
		d.buffers = d.buffers[:1]
		d.buffers[0] = d.buffers[0][:0]
	}
	d.offset = 0
	d.size = 0
}

func (d *datachunked) append(p []byte) { // always write everything, panic in case out of memory
	var n int
	if len(d.buffers) == 0 {
		d.buffers = make([][]byte, 1)
		d.buffers[0] = make([]byte, 0, memchunksize)
		n = memchunksize
	}
	l := len(d.buffers) - 1
	for len(p) > 0 {
		n = cap(d.buffers[l]) - len(d.buffers[l])
		if n == 0 {
			d.buffers = append(d.buffers, make([]byte, 0, memchunksize))
			l++
			n = memchunksize
		}
		if n > len(p) {
			n = len(p)
		}
		d.buffers[l] = append(d.buffers[l], p[:n]...)
		d.size += n
		p = p[n:]
	}
}

func (d *datachunked) Read(p []byte) (n int, err error) {
	if d.offset == d.size {
		return 0, io.EOF
	}
	n = copy(p, d.buffers[d.offset>>memchunkbits][d.offset&(memchunksize-1):])
	d.offset += n
	return
}

func newdatachunked() *datachunked {
	return &datachunked{offset: 0, size: 0}
}

type datastreamstate struct {
	items   int
	element dataTag // which element is this
}

func newDataStream(src io.Reader, inmem bool, logger *zap.SugaredLogger) (DlmsDataStream, error) {
	ret := datastream{
		buffer:   make([]byte, 128),
		stack:    make([]datastreamstate, 1),
		inerror:  false,
		ineof:    false,
		logger:   logger,
		inmemory: inmem,
	}
	if inmem { // readout everything from src
		ret.mem = newdatachunked()
		err := ret.mem.appendfrom(src)
		if err != nil {
			return nil, err
		}
		ret.src = ret.mem
	} else {
		ret.src = src
	}
	ret.stack[0] = datastreamstate{items: 1, element: TagError} // fake
	return &ret, nil
}

func (d *datastream) Rewind() error {
	if d.inmemory {
		d.mem.rewind()
		if len(d.stack) == 0 {
			d.stack = append(d.stack, datastreamstate{items: 1, element: TagError})
		} else {
			d.stack = d.stack[:1]
			d.stack[0].items = 1
		}
		return nil
	}
	return fmt.Errorf("rewind not supported")
}

func (d *datastream) NextElement() (*DlmsDataStreamItem, error) {
	if d.ineof {
		return nil, io.EOF
	}
	if d.inerror { // already in error state, in case this is deferred
		return nil, fmt.Errorf("already in error state")
	}

	if d.stack[len(d.stack)-1].items == 0 {
		tag := d.stack[len(d.stack)-1].element
		d.stack = d.stack[:len(d.stack)-1]
		if len(d.stack) == 0 { // first fake item ignore
			d.ineof = true
			return nil, io.EOF
		}
		d.stack[len(d.stack)-1].items--
		return &DlmsDataStreamItem{Type: StreamElementEnd, Data: DlmsData{Tag: tag}}, nil
	}

	_, err := io.ReadFull(d.src, d.buffer[:1])
	if err != nil {
		d.inerror = true
		if err == io.EOF {
			return nil, fmt.Errorf("unexpected EOF")
		}
		return nil, err
	}
	t := dataTag(d.buffer[0])
	// direct exception in case of array and struct here, these items should be stacked, screw compact array...
	switch t {
	case TagArray: // slighlty duplicit code
		return d.arrayElement(t)
	case TagStructure:
		return d.arrayElement(t)
	default:
		next, _, err := decodeData(d.src, t, d.buffer)
		if err != nil {
			d.inerror = true
			return nil, err
		}
		d.stack[len(d.stack)-1].items--
		return &DlmsDataStreamItem{Type: StreamElementData, Data: next}, nil
	}
}

func (d *datastream) arrayElement(t dataTag) (*DlmsDataStreamItem, error) {
	l, _, err := decodelength(d.src, d.buffer)
	if err != nil {
		d.inerror = true
		return nil, err
	}
	d.stack = append(d.stack, datastreamstate{items: int(l), element: t})
	return &DlmsDataStreamItem{Type: StreamElementStart, Count: int(l), Data: DlmsData{Tag: t}}, nil
}

func (d *datastream) Close() error { // artifically read out the rest
	if d.inmemory || d.inerror || d.ineof {
		return nil
	}
	cnt := 0
	for {
		n, err := d.src.Read(d.buffer)
		cnt += n
		if err != nil {
			if err == io.EOF {
				if d.logger != nil {
					d.logger.Warnf("data stream readout %v bytes", cnt)
				}
				return nil
			}
			return err
		}
		if n == 0 {
			return fmt.Errorf("no data read, shouldnt happen")
		}
		// make buffer a bit bigger because this is used to readout nothing usually
		if len(d.buffer) < 4096 {
			d.buffer = make([]byte, 4096)
		}
	}
}
