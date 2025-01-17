package dlmsal

import (
	"fmt"
	"io"

	"go.uber.org/zap"
)

type streamItemType byte

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
	buffer   tmpbuffer
	stack    []datastreamstate
	inerror  bool
	ineof    bool
	logger   *zap.SugaredLogger
	inmemory bool
	mem      ChunkedStream
}

type datastreamstate struct {
	items   int
	element dataTag // which element is this
}

func newDataStream(src io.Reader, inmem bool, logger *zap.SugaredLogger) (DlmsDataStream, error) {
	ret := datastream{
		stack:    make([]datastreamstate, 1),
		inerror:  false,
		ineof:    false,
		logger:   logger,
		inmemory: inmem,
	}
	if inmem { // readout everything from src
		ret.mem = NewChunkedStream()
		err := ret.mem.CopyFrom(src)
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
		d.mem.Rewind()
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
	case TagArray, TagStructure:
		return d.arrayElement(t)
	default:
		next, _, err := decodeData(d.src, t, &d.buffer)
		if err != nil {
			d.inerror = true
			return nil, err
		}
		d.stack[len(d.stack)-1].items--
		return &DlmsDataStreamItem{Type: StreamElementData, Data: next}, nil
	}
}

func (d *datastream) arrayElement(t dataTag) (*DlmsDataStreamItem, error) {
	l, _, err := decodelength(d.src, &d.buffer)
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
	rb := d.buffer[:]
	for {
		n, err := d.src.Read(rb)
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
		if len(rb) < 4096 {
			rb = make([]byte, 4096)
		}
	}
}
