package dlmsal

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/cybroslabs/libdlms-go/base"
)

type dlmsalget struct { // this will implement io.Reader for LN Get operation
	io.Reader
	master *dlmsal
	state  int
	// 0 before first response
	// 1 block header expected
	// 2 block content, remaining/lastblock is set
	// 100 game over all read
	data      []DlmsData
	blockexp  uint32
	lastblock bool
	remaining uint
	transport io.Reader
}

func encodelncosemattr(dst *bytes.Buffer, item *DlmsLNRequestItem) {
	dst.WriteByte(byte(item.ClassId >> 8))
	dst.WriteByte(byte(item.ClassId))
	dst.WriteByte(item.Obis.A)
	dst.WriteByte(item.Obis.B)
	dst.WriteByte(item.Obis.C)
	dst.WriteByte(item.Obis.D)
	dst.WriteByte(item.Obis.E)
	dst.WriteByte(item.Obis.F)
	dst.WriteByte(byte(item.Attribute))
}

func encodelngetitem(dst *bytes.Buffer, item *DlmsLNRequestItem) error {
	encodelncosemattr(dst, item)
	if item.HasAccess {
		dst.WriteByte(1)
		dst.WriteByte(item.AccessDescriptor)
		err := encodeData(dst, item.AccessData)
		if err != nil {
			return fmt.Errorf("unable to encode data: %w", err)
		}
	} else {
		dst.WriteByte(0)
	}

	return nil
}

func (ln *dlmsalget) get(items []DlmsLNRequestItem) ([]DlmsData, error) {
	master := ln.master
	local := &master.pdu
	local.Reset()
	local.WriteByte(byte(base.TagGetRequest))
	if len(items) > 1 {
		local.WriteByte(byte(TagGetRequestWithList))
	} else {
		local.WriteByte(byte(TagGetRequestNormal))
	}
	master.invokeid = (master.invokeid + 1) & 7
	local.WriteByte(master.invokeid | master.settings.invokebyte)

	if len(items) > 1 {
		encodelength(local, uint(len(items)))
	}

	for _, i := range items {
		err := encodelngetitem(local, &i)
		if err != nil {
			return nil, err
		}
	}

	// send itself, that could be fun, do that in one step for now
	tag, str, err := master.sendpdu()
	if err != nil {
		return nil, err
	}
	ln.transport = str

	// start streaming response
	ln.data = make([]DlmsData, len(items))
	var end bool
	for i := range ln.data {
		end, err = ln.getnextdata(tag, i)
		if err != nil {
			return nil, err
		}
		if end {
			break
		}
	}
	return ln.data, nil
}

func (ln *dlmsalget) getstream(item DlmsLNRequestItem, inmem bool) (DlmsDataStream, error) {
	master := ln.master
	local := &master.pdu
	local.Reset()
	local.WriteByte(byte(base.TagGetRequest))
	local.WriteByte(byte(TagGetRequestNormal))
	master.invokeid = (master.invokeid + 1) & 7
	local.WriteByte(master.invokeid | master.settings.invokebyte)

	err := encodelngetitem(local, &item)
	if err != nil {
		return nil, err
	}

	// send itself, that could be fun, do that in one step for now
	tag, str, err := master.sendpdu()
	if err != nil {
		return nil, err
	}
	ln.transport = str
	return ln.getstreamdata(tag, inmem)
}

func (ln *dlmsalget) getstreamdata(tag base.CosemTag, inmem bool) (s DlmsDataStream, err error) {
	master := ln.master
	switch tag {
	case base.TagGetResponse:
	case base.TagExceptionResponse: // no lower layer readout
		d, err := decodeException(ln.transport, &master.tmpbuffer)
		if err != nil {
			return nil, err
		}
		ex := d.Value.(*DlmsError)
		return nil, ex // dont decode exception pdu, maybe todo, should be 2 bytes
	default:
		return nil, fmt.Errorf("unexpected tag: %02x", tag)
	}
	_, err = io.ReadFull(ln.transport, master.tmpbuffer[:2])
	if err != nil {
		return nil, err
	}

	if master.tmpbuffer[1]&7 != master.invokeid {
		return nil, fmt.Errorf("unexpected invoke id")
	}

	switch GetResponseTag(master.tmpbuffer[0]) {
	case TagGetResponseNormal:
		// decode data themselves
		_, err = io.ReadFull(ln.transport, master.tmpbuffer[:1])
		if err != nil {
			return nil, err
		}

		if master.tmpbuffer[0] != 0 {
			_, err = io.ReadFull(ln.transport, master.tmpbuffer[:1])
			if err != nil {
				if errors.Is(err, io.ErrUnexpectedEOF) {
					return nil, NewDlmsError(base.TagResultOtherReason) // this kind of data cant be decoded, so that is why
				}
				return nil, err
			}
			return nil, NewDlmsError(base.DlmsResultTag(master.tmpbuffer[0]))
		}
		str, err := newDataStream(ln.transport, inmem, master.logger)
		if err != nil {
			return nil, err
		}
		return str, nil
	case TagGetResponseWithDataBlock: // this is a bit of hell, read till eof from lower layer and then ask for next block and so on
		ln.state = 1
		str, err := newDataStream(ln, inmem, master.logger)
		if err != nil {
			return nil, err
		}
		return str, nil
	}
	return nil, fmt.Errorf("unexpected response tag: 0x%02x", master.tmpbuffer[0])
}

func (ln *dlmsalget) getnextdata(tag base.CosemTag, i int) (cont bool, err error) {
	master := ln.master
	switch ln.state {
	case 0: // read first things as a response
		switch tag {
		case base.TagGetResponse:
		case base.TagExceptionResponse: // no lower layer readout
			d, err := decodeException(ln.transport, &master.tmpbuffer)
			for i := range ln.data {
				ln.data[i] = d
			}
			ln.state = 100
			return true, err
		default:
			return false, fmt.Errorf("unexpected tag: %02x", tag)
		}
		_, err = io.ReadFull(ln.transport, master.tmpbuffer[:2])
		if err != nil {
			return false, err
		}

		if master.tmpbuffer[1]&7 != master.invokeid {
			return false, fmt.Errorf("unexpected invoke id")
		}

		switch GetResponseTag(master.tmpbuffer[0]) {
		case TagGetResponseNormal:
			if len(ln.data) > 1 {
				return false, fmt.Errorf("expecting list response")
			}
			// decode data themselves
			_, err = io.ReadFull(ln.transport, master.tmpbuffer[:1])
			if err != nil {
				return false, err
			}

			if master.tmpbuffer[0] != 0 {
				_, err = io.ReadFull(ln.transport, master.tmpbuffer[:1])
				if err != nil {
					if errors.Is(err, io.ErrUnexpectedEOF) {
						ln.data[i] = NewDlmsDataError(base.TagResultOtherReason) // this kind of data cant be decoded, so that is why
					} else {
						return false, err
					}
				} else {
					ln.data[i] = NewDlmsDataError(base.DlmsResultTag(master.tmpbuffer[0]))
				}
			} else {
				ln.data[i], _, err = decodeDataTag(ln.transport, &master.tmpbuffer)
			}
			ln.state = 100
			return false, err
		case TagGetResponseWithList:
			if len(ln.data) == 1 {
				return false, fmt.Errorf("expecting normal response")
			}
			l, _, err := decodelength(ln.transport, &master.tmpbuffer)
			if err != nil {
				return false, err
			}
			if l != uint(len(ln.data)) {
				return false, fmt.Errorf("different amount of data received, expected %d got %d", len(ln.data), l)
			}
			for i := range ln.data {
				_, err = io.ReadFull(ln.transport, master.tmpbuffer[:1])
				if err != nil {
					return false, err
				}
				if master.tmpbuffer[0] != 0 {
					_, err = io.ReadFull(ln.transport, master.tmpbuffer[:1])
					if err != nil {
						return false, err
					}
					ln.data[i] = NewDlmsDataError(base.DlmsResultTag(master.tmpbuffer[0]))
				} else {
					ln.data[i], _, err = decodeDataTag(ln.transport, &master.tmpbuffer)
					if err != nil {
						return false, err
					}
				}
			}
			ln.state = 100
			return true, nil
		case TagGetResponseWithDataBlock: // this is a bit of hell, read till eof from lower layer and then ask for next block and so on
			ln.state = 1
			if len(ln.data) == 1 {
				ln.data[i], _, err = decodeDataTag(ln, &master.tmpbuffer)
			} else { // with list, so read first byte to decide if there is an error and result byte or decode data
				var l uint
				l, _, err = decodelength(ln, &master.tmpbuffer)
				if err != nil {
					return false, err
				}
				if l != uint(len(ln.data)) {
					return false, fmt.Errorf("different amount of data received, expected %d got %d", len(ln.data), l)
				}
				err = ln.decodedata(i)
			}
			return false, err
		}
		return false, fmt.Errorf("unexpected response tag: 0x%02x", master.tmpbuffer[0])
	case 2: // block content
		err = ln.decodedata(i)
		return false, err
	case 100:
		return false, fmt.Errorf("program error, all data are read")
	}
	return false, fmt.Errorf("program error, unexpected state: %v", ln.state)
}

func (ln *dlmsalget) decodedata(i int) (err error) {
	master := ln.master
	_, err = io.ReadFull(ln, master.tmpbuffer[:1])
	if err != nil {
		return
	}
	if master.tmpbuffer[0] != 0 {
		_, err = io.ReadFull(ln, master.tmpbuffer[:1])
		if err != nil {
			return
		}
		ln.data[i] = NewDlmsDataError(base.DlmsResultTag(master.tmpbuffer[0]))
	} else {
		ln.data[i], _, err = decodeDataTag(ln, &master.tmpbuffer)
	}
	return
}

func (ln *dlmsalget) Read(p []byte) (n int, err error) { // this will go to data decoder
	if len(p) == 0 { // that shouldnt happen
		return 0, base.ErrNothingToRead
	}
	master := ln.master
	switch ln.state {
	case 1: // read block header
		_, err = io.ReadFull(ln.transport, master.tmpbuffer[:6])
		if err != nil {
			return
		}
		ln.lastblock = master.tmpbuffer[0] != 0
		if master.tmpbuffer[5] != 0 {
			return 0, fmt.Errorf("returned failed request, not handled, error: %v", master.tmpbuffer[5])
		}
		blockno := (uint32(master.tmpbuffer[1]) << 24) | (uint32(master.tmpbuffer[2]) << 16) | (uint32(master.tmpbuffer[3]) << 8) | uint32(master.tmpbuffer[4])
		ln.blockexp = blockno
		ln.remaining, _, err = decodelength(ln.transport, &master.tmpbuffer) // refactor usage of these tmp buffers...
		if err != nil {
			return 0, err
		}
		if ln.remaining == 0 {
			return 0, fmt.Errorf("zero length block")
		}
		ln.state = 2
		if uint(len(p)) > ln.remaining {
			p = p[:ln.remaining]
		}
		n, err = ln.transport.Read(p)
		ln.remaining -= uint(n) // hopefully this never returns negative value ;)
		return n, err
	case 2: // read block content
		if ln.remaining == 0 { // next block please
			if ln.lastblock {
				return 0, io.EOF // or some common error?
			}
			// ask for the next block
			local := &master.pdu
			local.Reset()
			local.WriteByte(byte(base.TagGetRequest))
			local.WriteByte(byte(TagGetRequestNext))
			local.WriteByte(master.invokeid | master.settings.invokebyte)
			local.WriteByte(byte(ln.blockexp >> 24))
			local.WriteByte(byte(ln.blockexp >> 16))
			local.WriteByte(byte(ln.blockexp >> 8))
			local.WriteByte(byte(ln.blockexp))
			tag, str, err := master.sendpdu()
			if err != nil {
				return 0, err
			}
			if tag != base.TagGetResponse {
				return 0, fmt.Errorf("unexpected response tag: 0x%02x", tag)
			}
			ln.transport = str

			_, err = io.ReadFull(ln.transport, master.tmpbuffer[:8]) // read block answer header
			if err != nil {
				return 0, err
			}
			if master.tmpbuffer[0] != byte(TagGetResponseWithDataBlock) || master.tmpbuffer[1]&7 != master.invokeid {
				return 0, fmt.Errorf("unexpected response tag: 0x%02x", master.tmpbuffer[0])
			}
			// set last, check block number and set remaining
			ln.lastblock = master.tmpbuffer[2] != 0
			if master.tmpbuffer[7] != 0 {
				return 0, fmt.Errorf("returned failed request, not handled, error: %v", master.tmpbuffer[7])
			}
			ln.blockexp++
			blockno := (uint32(master.tmpbuffer[3]) << 24) | (uint32(master.tmpbuffer[4]) << 16) | (uint32(master.tmpbuffer[5]) << 8) | uint32(master.tmpbuffer[6])
			if ln.blockexp != blockno {
				return 0, fmt.Errorf("unexpected block number")
			}
			ln.remaining, _, err = decodelength(ln.transport, &master.tmpbuffer) // refactor usage of these tmp buffers...
			if err != nil {
				return 0, err
			}
			if ln.remaining == 0 {
				return 0, fmt.Errorf("zero length block")
			}
		}
		if uint(len(p)) > ln.remaining {
			p = p[:ln.remaining]
		}
		n, err = ln.transport.Read(p)
		ln.remaining -= uint(n) // hopefully this never returns negative value ;)
		return n, err
	}
	return 0, fmt.Errorf("program error, unexpected state: %v", ln.state)
}

func (d *dlmsal) Get(items []DlmsLNRequestItem) ([]DlmsData, error) {
	if !d.transport.isopen {
		return nil, base.ErrNotOpened
	}

	if len(items) == 0 {
		return nil, base.ErrNothingToRead
	}

	if d.settings.computedconf&base.ConformanceBlockMultipleReferences == 0 { // ok, one by one
		var tmp [1]DlmsLNRequestItem
		ret := make([]DlmsData, 0, len(items))
		for _, i := range items {
			tmp[0] = i
			ln := &dlmsalget{master: d, state: 0, blockexp: 0}
			rget, err := ln.get(tmp[:])
			if err != nil {
				return nil, err
			}
			ret = append(ret, rget[0])
		}
		return ret, nil
	}
	ln := &dlmsalget{master: d, state: 0, blockexp: 0}
	return ln.get(items)
}

func (d *dlmsal) GetStream(item DlmsLNRequestItem, inmem bool) (DlmsDataStream, error) {
	if !d.transport.isopen {
		return nil, base.ErrNotOpened
	}

	ln := &dlmsalget{master: d, state: 0, blockexp: 0}
	return ln.getstream(item, inmem)
}
