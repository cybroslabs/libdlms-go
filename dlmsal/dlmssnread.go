package dlmsal

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/cybroslabs/libdlms-go/base"
)

type dlmssnblockread struct {
	io.Reader
	master    *dlmsal
	state     int
	blockexp  uint16
	lastblock bool
	transport io.Reader
	remain    uint
	err       error
}

// SN func read, for now it should be enough
func (d *dlmsal) Read(items []DlmsSNRequestItem) ([]DlmsData, error) {
	if !d.transport.isopen {
		return nil, base.ErrNotOpened
	}

	switch len(items) {
	case 0:
		return nil, base.ErrNothingToRead
	case 1:
	default:
		if d.settings.computedconf&base.ConformanceBlockMultipleReferences == 0 { // one by one
			var tmp [1]DlmsSNRequestItem
			ret := make([]DlmsData, 0, len(items))
			for _, item := range items {
				tmp[0] = item
				data, err := d.Read(tmp[:])
				if err != nil {
					return nil, err
				}
				ret = append(ret, data[0])
			}
			return ret, nil
		}
	}

	local := &d.pdu
	// format request into byte slice and send that to unit
	local.Reset()
	local.WriteByte(byte(base.TagReadRequest))
	encodelength(local, uint(len(items)))
	for _, item := range items {
		if item.HasAccess {
			local.WriteByte(4)
			local.WriteByte(byte(item.Address >> 8))
			local.WriteByte(byte(item.Address))
			local.WriteByte(item.AccessDescriptor)
			err := encodeData(local, item.AccessData)
			if err != nil {
				return nil, err
			}
		} else {
			local.WriteByte(2)
			local.WriteByte(byte(item.Address >> 8))
			local.WriteByte(byte(item.Address))
		}
	}

	tag, str, err := d.sendpdu()
	if err != nil {
		return nil, err
	}

	if tag != base.TagReadResponse {
		return nil, fmt.Errorf("unexpected tag: 0x%02x", tag)
	}
	l, _, err := decodelength(str, &d.tmpbuffer)
	if err != nil {
		return nil, err
	}
	ret := make([]DlmsData, len(items))
	for i := 0; i < len(ret); i++ {
		_, err = io.ReadFull(str, d.tmpbuffer[:1])
		if err != nil {
			if i < len(items) {
				return nil, fmt.Errorf("incomplete list of returned values, main list has %d items, but wanted %d items: %w", l, len(items), err)
			}
			return nil, err
		}
		switch d.tmpbuffer[0] {
		case 0:
			ret[i], _, err = decodeDataTag(str, &d.tmpbuffer)
			if err != nil {
				return nil, err
			}
		case 1:
			_, err = io.ReadFull(str, d.tmpbuffer[:1])
			if err != nil {
				return nil, err
			}
			ret[i] = NewDlmsDataError(base.DlmsResultTag(d.tmpbuffer[0]))
		case 2:
			i, err = d.decodesnblockreader(str, i, ret) // maybe only one result should be here in case of block transfer, check that?
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unexpected response tag: 0x%02x", d.tmpbuffer[0])
		}
	}

	return ret, nil
}

func (d *dlmsal) decodesnblockreader(str io.Reader, i int, ret []DlmsData) (int, error) {
	var tmp tmpbuffer
	blc := &dlmssnblockread{
		transport: str,
		master:    d,
		blockexp:  1,
	}

	// read list of items after block header
	items, _, err := decodelength(blc, &tmp) // that should fit too, fucking fuck
	if err != nil {
		return i, err
	}
	if i+int(items) > len(ret) {
		return i, fmt.Errorf("block read items exceed expected amount, have %d need %d", len(ret)-i, items)
	}
	// ok, so inner block cycle
	for j := uint(0); j < items; j++ {
		_, err = io.ReadFull(blc, tmp[:1])
		if err != nil {
			return i, err
		}
		switch tmp[0] {
		case 0:
			ret[i+int(j)], _, err = decodeDataTag(blc, &tmp)
			if err != nil {
				return i, err
			}
		case 1:
			_, err = io.ReadFull(blc, tmp[:1])
			if err != nil {
				return i, err
			}
			ret[i+int(j)] = NewDlmsDataError(base.DlmsResultTag(tmp[0]))
		default:
			return i, fmt.Errorf("unexpected response inner tag: 0x%02x", tmp[0])
		}
	}
	if blc.remain != 0 || !blc.lastblock {
		return i, fmt.Errorf("incomplete block read, remaining %d bytes, last block %v", blc.remain, blc.lastblock)
	}
	return i + int(items), nil
}

func (d *dlmsal) decodesnstreamblockreader(str io.Reader, inmem bool) (DlmsDataStream, error) {
	var tmp tmpbuffer
	blc := &dlmssnblockread{
		transport: str,
		master:    d,
		blockexp:  1,
	}

	// read list of items after block header
	items, _, err := decodelength(blc, &tmp) // that should fit too, fucking fuck
	if err != nil {
		return nil, err
	}
	if items != 1 {
		return nil, fmt.Errorf("only single item is expected in stream block sn read, got %d", items)
	}
	_, err = io.ReadFull(blc, tmp[:1])
	if err != nil {
		return nil, err
	}
	switch tmp[0] {
	case 0:
		str, err := newDataStream(blc, inmem, d.logger)
		if err != nil {
			return nil, err
		}
		return str, nil
	case 1: // that really should not happen, but who knows
		_, err = io.ReadFull(blc, tmp[:1])
		if err != nil {
			return nil, err
		}
		if blc.remain != 0 || !blc.lastblock {
			return nil, fmt.Errorf("incomplete block read, remaining %d bytes, last block %v", blc.remain, blc.lastblock)
		}
		return nil, NewDlmsError(base.DlmsResultTag(tmp[0]))
	}
	return nil, fmt.Errorf("unexpected response inner tag: 0x%02x", tmp[0])
}

func (d *dlmssnblockread) Read(p []byte) (n int, err error) {
	var header [3]byte
	// read header
	switch d.state {
	case 0:
		_, d.err = io.ReadFull(d.transport, header[:])
		if d.err != nil {
			return 0, d.err // no mercy
		}
		d.lastblock = header[0] != 0
		dno := binary.BigEndian.Uint16(header[1:])
		if dno != d.blockexp {
			d.err = fmt.Errorf("block read sequence error, expected %d got %d", d.blockexp, dno)
			return 0, d.err
		}
		d.remain, _, d.err = decodelength(d.transport, &d.master.tmpbuffer)
		if d.err != nil {
			return 0, d.err
		}
		d.state = 1
		return d.Read(p)
	case 1: // inside block data
		if d.remain == 0 {
			if d.lastblock {
				d.err = io.EOF
				return 0, d.err
			}
			// need another block
			local := &d.master.pdu
			// format request into byte slice and send that to unit
			local.Reset()
			local.WriteByte(byte(base.TagReadRequest))
			encodelength(local, 1)
			local.WriteByte(5) // next block
			local.WriteByte(byte(d.blockexp >> 8))
			local.WriteByte(byte(d.blockexp))
			tag, str, err := d.master.sendpdu()
			if err != nil {
				d.err = err
				return 0, err
			}
			d.transport = str
			if tag != base.TagReadResponse {
				d.err = fmt.Errorf("unexpected tag: 0x%02x", tag)
				return 0, d.err
			}
			l, _, err := decodelength(str, &d.master.tmpbuffer)
			if err != nil {
				d.err = err
				return 0, err
			}
			if l != 1 { // this is TODO big hardcore, in case of some list and only SOMETHING is blocked, them what the fuck to do?
				d.err = fmt.Errorf("expecting only one item during block transfer, need to experiment")
				return 0, d.err
			}
			_, d.err = io.ReadFull(str, d.master.tmpbuffer[:1])
			if d.err != nil {
				return 0, d.err
			}
			if d.master.tmpbuffer[0] != 2 {
				d.err = fmt.Errorf("expecting block transfer for that single item during processing")
				return 0, d.err
			}

			d.blockexp++
			d.state = 0
			return d.Read(p)
		}
		if uint(len(p)) > d.remain {
			p = p[:d.remain]
		}
		n, d.err = io.ReadFull(d.transport, p)
		d.remain -= uint(n)
		return n, d.err
	default:
		d.err = fmt.Errorf("unimplemented state %d, program error", d.state)
		return 0, d.err
	}
}

func (d *dlmsal) ReadStream(item DlmsSNRequestItem, inmem bool) (DlmsDataStream, error) {
	if !d.transport.isopen {
		return nil, base.ErrNotOpened
	}

	local := &d.pdu
	// format request into byte slice and send that to unit
	local.Reset()
	local.WriteByte(byte(base.TagReadRequest))
	encodelength(local, 1)
	if item.HasAccess {
		local.WriteByte(4)
		local.WriteByte(byte(item.Address >> 8))
		local.WriteByte(byte(item.Address))
		local.WriteByte(item.AccessDescriptor)
		err := encodeData(local, item.AccessData)
		if err != nil {
			return nil, err
		}
	} else {
		local.WriteByte(2)
		local.WriteByte(byte(item.Address >> 8))
		local.WriteByte(byte(item.Address))
	}

	tag, str, err := d.sendpdu()
	if err != nil {
		return nil, err
	}

	if tag != base.TagReadResponse {
		return nil, fmt.Errorf("unexpected tag: 0x%02x", tag)
	}
	l, _, err := decodelength(str, &d.tmpbuffer)
	if err != nil {
		return nil, err
	}
	if l != 1 {
		return nil, fmt.Errorf("only one item was expected")
	}

	_, err = io.ReadFull(str, d.tmpbuffer[:1])
	if err != nil {
		return nil, err
	}
	switch d.tmpbuffer[0] {
	case 0:
		str, err := newDataStream(str, inmem, d.logger)
		if err != nil {
			return nil, err
		}
		return str, nil
	case 1:
		_, err = io.ReadFull(str, d.tmpbuffer[:1])
		if err != nil {
			return nil, err
		}
		return nil, NewDlmsError(base.DlmsResultTag(d.tmpbuffer[0]))
	case 2:
		return d.decodesnstreamblockreader(str, inmem)
	}

	return nil, fmt.Errorf("unexpected response tag: 0x%02x", d.tmpbuffer[0])
}
