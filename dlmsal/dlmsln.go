package dlmsal

import (
	"fmt"
	"io"

	"github.com/cybroslabs/libdlms-go/base"
)

type dlmsalget struct { // this will implement io.Reader for LN Get operation
	base  *dlmsal
	state int
	// 0 before first response
	// 1 block header expected
	// 2 block content, remaining/lastblock is set
	// 100 game over all read
	data      []DlmsData
	blockexp  uint32
	lastblock bool
	remaining uint
}

func (ln *dlmsalget) get(items []DlmsLNRequestItem) ([]DlmsData, error) {
	if len(items) == 0 {
		return nil, base.ErrNothingToRead
	}
	base := ln.base
	local := &base.pdu
	local.Reset()
	local.WriteByte(byte(TagGetRequest))
	if len(items) > 1 {
		local.WriteByte(byte(TagGetRequestWithList))
	} else {
		local.WriteByte(byte(TagGetRequestNormal))
	}
	base.invokeid = (base.invokeid + 1) & 7
	local.WriteByte(base.invokeid | base.settings.HighPriority | base.settings.ConfirmedRequests)

	if len(items) > 1 {
		encodelength(local, uint(len(items)))
	}

	for _, i := range items {
		local.WriteByte(byte(i.ClassId >> 8))
		local.WriteByte(byte(i.ClassId))
		local.WriteByte(i.Obis.A)
		local.WriteByte(i.Obis.B)
		local.WriteByte(i.Obis.C)
		local.WriteByte(i.Obis.D)
		local.WriteByte(i.Obis.E)
		local.WriteByte(i.Obis.F)
		local.WriteByte(byte(i.Attribute))
		if i.HasAccess {
			local.WriteByte(1)
			local.WriteByte(i.AccessDescriptor)
			err := encodeData(local, i.AccessData)
			if err != nil {
				return nil, fmt.Errorf("unable to encode data: %v", err)
			}
		} else {
			local.WriteByte(0)
		}
	}

	if local.Len() > base.maxPduSendSize {
		return nil, fmt.Errorf("PDU size exceeds maximum size: %v > %v", local.Len(), base.maxPduSendSize)
	}

	// send itself, that could be fun, do that in one step for now
	err := base.transport.Write(local.Bytes())
	if err != nil {
		return nil, err
	}

	// start streaming response
	ln.data = make([]DlmsData, len(items))
	var end bool
	for i := 0; i < len(ln.data); i++ {
		end, err = ln.getnextdata(i)
		if err != nil {
			return nil, err
		}
		if end {
			break
		}
	}
	return ln.data, nil
}

func (ln *dlmsalget) getstream(item DlmsLNRequestItem, inmem bool) (DlmsDataStream, *DlmsError, error) {
	base := ln.base
	local := &base.pdu
	local.Reset()
	local.WriteByte(byte(TagGetRequest))
	local.WriteByte(byte(TagGetRequestNormal))
	base.invokeid = (base.invokeid + 1) & 7
	local.WriteByte(base.invokeid | base.settings.HighPriority | base.settings.ConfirmedRequests)

	local.WriteByte(byte(item.ClassId >> 8))
	local.WriteByte(byte(item.ClassId))
	local.WriteByte(item.Obis.A)
	local.WriteByte(item.Obis.B)
	local.WriteByte(item.Obis.C)
	local.WriteByte(item.Obis.D)
	local.WriteByte(item.Obis.E)
	local.WriteByte(item.Obis.F)
	local.WriteByte(byte(item.Attribute))
	if item.HasAccess {
		local.WriteByte(1)
		local.WriteByte(item.AccessDescriptor)
		err := encodeData(local, item.AccessData)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to encode data: %v", err)
		}
	} else {
		local.WriteByte(0)
	}

	if local.Len() > base.maxPduSendSize {
		return nil, nil, fmt.Errorf("PDU size exceeds maximum size: %v > %v", local.Len(), base.maxPduSendSize)
	}

	// send itself, that could be fun, do that in one step for now
	err := base.transport.Write(local.Bytes())
	if err != nil {
		return nil, nil, err
	}
	return ln.getstreamdata(inmem)
}

func (ln *dlmsalget) getstreamdata(inmem bool) (s DlmsDataStream, e *DlmsError, err error) {
	base := ln.base
	_, err = io.ReadFull(base.transport, base.tmpbuffer[:1])
	if err != nil {
		return nil, nil, err
	}
	switch CosemTag(base.tmpbuffer[0]) {
	case TagGetResponse:
	case TagExceptionResponse: // no lower layer readout
		return nil, &DlmsError{Result: TagAccOtherReason}, nil // dont decode exception pdu, TODO !!!
	default:
		return nil, nil, fmt.Errorf("unexpected tag: %x", base.tmpbuffer[0])
	}
	_, err = io.ReadFull(base.transport, base.tmpbuffer[:2])
	if err != nil {
		return nil, nil, err
	}

	if base.tmpbuffer[1]&7 != base.invokeid {
		return nil, nil, fmt.Errorf("unexpected invoke id")
	}

	switch getResponseTag(base.tmpbuffer[0]) {
	case TagGetResponseNormal:
		// decode data themselves
		_, err = io.ReadFull(base.transport, base.tmpbuffer[:1])
		if err != nil {
			return nil, nil, err
		}

		if base.tmpbuffer[0] != 0 {
			_, err = io.ReadFull(base.transport, base.tmpbuffer[:1])
			if err == io.ErrUnexpectedEOF {
				return nil, &DlmsError{Result: TagAccOtherReason}, nil // this kind of data cant be decoded, so that is why
			} else {
				if err != nil {
					return nil, nil, err
				}
			}
			return nil, &DlmsError{Result: AccessResultTag(base.tmpbuffer[0])}, nil
		}
		str, err := newDataStream(base.transport, inmem, base.logger)
		if err != nil {
			return nil, nil, err
		}
		return str, nil, nil
	case TagGetResponseWithDataBlock: // this is a bit of hell, read till eof from lower layer and then ask for next block and so on
		ln.state = 1
		str, err := newDataStream(ln, inmem, base.logger)
		if err != nil {
			return nil, nil, err
		}
		return str, nil, nil
	}
	return nil, nil, fmt.Errorf("unexpected response tag: %x", base.tmpbuffer[0])
}

func (ln *dlmsalget) getnextdata(i int) (cont bool, err error) {
	base := ln.base
	switch ln.state {
	case 0: // read first things as a response
		_, err = io.ReadFull(base.transport, base.tmpbuffer[:1])
		if err != nil {
			return false, err
		}
		switch CosemTag(base.tmpbuffer[0]) {
		case TagGetResponse:
		case TagExceptionResponse: // no lower layer readout
			for i := 0; i < len(ln.data); i++ {
				ln.data[i] = NewDlmsDataError(DlmsError{Result: TagAccOtherReason}) // dont decode exception pdu
			}
			ln.state = 100
			return true, nil
		default:
			return false, fmt.Errorf("unexpected tag: %x", base.tmpbuffer[0])
		}
		_, err = io.ReadFull(base.transport, base.tmpbuffer[:2])
		if err != nil {
			return false, err
		}

		if base.tmpbuffer[1]&7 != base.invokeid {
			return false, fmt.Errorf("unexpected invoke id")
		}

		switch getResponseTag(base.tmpbuffer[0]) {
		case TagGetResponseNormal:
			if len(ln.data) > 1 {
				return false, fmt.Errorf("expecting list response")
			}
			// decode data themselves
			_, err = io.ReadFull(base.transport, base.tmpbuffer[:1])
			if err != nil {
				return false, err
			}

			if base.tmpbuffer[0] != 0 {
				_, err = io.ReadFull(base.transport, base.tmpbuffer[:1])
				if err == io.ErrUnexpectedEOF {
					ln.data[i] = NewDlmsDataError(DlmsError{Result: TagAccOtherReason}) // this kind of data cant be decoded, so that is why
				} else {
					if err != nil {
						return false, err
					}
				}
				ln.data[i] = NewDlmsDataError(DlmsError{Result: AccessResultTag(base.tmpbuffer[0])})
			} else {
				ln.data[i], _, err = decodeDataTag(base.transport, &base.tmpbuffer)
				if err != nil {
					return false, err
				}
			}
			ln.state = 100
		case TagGetResponseWithList:
			if len(ln.data) == 1 {
				return false, fmt.Errorf("expecting normal response")
			}
			l, _, err := decodelength(base.transport, &base.tmpbuffer)
			if err != nil {
				return false, err
			}
			if l != uint(len(ln.data)) {
				return false, fmt.Errorf("different amount of data received")
			}
			for i := 0; i < len(ln.data); i++ {
				_, err = io.ReadFull(base.transport, base.tmpbuffer[:1])
				if err != nil {
					return false, err
				}
				if base.tmpbuffer[0] != 0 {
					_, err = io.ReadFull(base.transport, base.tmpbuffer[:1])
					if err != nil {
						return false, err
					}
					ln.data[i] = NewDlmsDataError(DlmsError{Result: AccessResultTag(base.tmpbuffer[0])})
				} else {
					ln.data[i], _, err = decodeDataTag(base.transport, &base.tmpbuffer)
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
				ln.data[i], _, err = decodeDataTag(ln, &base.tmpbuffer)
			} else { // with list, so read first byte to decide if there is an error and result byte or decode data
				err = ln.decodedata(i)
			}
			if err != nil {
				return false, err
			}
		default:
			return false, fmt.Errorf("unexpected response tag: %x", base.tmpbuffer[0])
		}
	case 2: // block content
		err = ln.decodedata(i)
		return false, err
	case 100:
		return false, fmt.Errorf("program error, all data are read")
	default:
		return false, fmt.Errorf("program error, unexpected state: %v", ln.state)
	}
	return false, nil
}

func (ln *dlmsalget) decodedata(i int) (err error) {
	base := ln.base
	_, err = io.ReadFull(ln, base.tmpbuffer[:1])
	if err != nil {
		return
	}
	if base.tmpbuffer[0] != 0 {
		_, err = io.ReadFull(ln, base.tmpbuffer[:1])
		if err != nil {
			return
		}
		ln.data[i] = NewDlmsDataError(DlmsError{Result: AccessResultTag(base.tmpbuffer[0])})
	} else {
		ln.data[i], _, err = decodeDataTag(ln, &base.tmpbuffer)
	}
	return
}

func (ln *dlmsalget) Read(p []byte) (n int, err error) { // this will go to data decoder
	if len(p) == 0 { // that shouldnt happen
		return 0, base.ErrNothingToRead
	}
	base := ln.base
	switch ln.state {
	case 1: // read block header
		_, err = io.ReadFull(base.transport, base.tmpbuffer[:6])
		if err != nil {
			return
		}
		ln.lastblock = base.tmpbuffer[0] != 0
		if base.tmpbuffer[5] != 0 {
			return 0, fmt.Errorf("returned failed request, not handled, error: %v", base.tmpbuffer[5])
		}
		blockno := (uint32(base.tmpbuffer[1]) << 24) | (uint32(base.tmpbuffer[2]) << 16) | (uint32(base.tmpbuffer[3]) << 8) | uint32(base.tmpbuffer[4])
		ln.blockexp = blockno
		ln.remaining, _, err = decodelength(base.transport, &base.tmpbuffer) // refactor usage of these tmp buffers...
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
		n, err = base.transport.Read(p)
		ln.remaining -= uint(n) // hopefully this never returns negative value ;)
		return n, err
	case 2: // read block content
		if ln.remaining == 0 { // next block please
			if ln.lastblock {
				return 0, io.EOF // or some common error?
			}
			// ask for the next block
			base.tmpbuffer[0] = byte(TagGetRequest)
			base.tmpbuffer[1] = byte(TagGetRequestNext)
			base.tmpbuffer[2] = base.invokeid | base.settings.HighPriority | base.settings.ConfirmedRequests
			base.tmpbuffer[3] = byte(ln.blockexp >> 24)
			base.tmpbuffer[4] = byte(ln.blockexp >> 16)
			base.tmpbuffer[5] = byte(ln.blockexp >> 8)
			base.tmpbuffer[6] = byte(ln.blockexp)
			err = base.transport.Write(base.tmpbuffer[:7])
			if err != nil {
				return 0, err
			}
			_, err = io.ReadFull(base.transport, base.tmpbuffer[:9]) // read block answer header
			if err != nil {
				return 0, err
			}
			if base.tmpbuffer[0] != byte(TagGetResponse) || base.tmpbuffer[1] != byte(TagGetResponseWithDataBlock) || base.tmpbuffer[2]&7 != base.invokeid {
				return 0, fmt.Errorf("unexpected response tag: %x", base.tmpbuffer[1])
			}
			// set last, check block number and set remaining
			ln.lastblock = base.tmpbuffer[3] != 0
			if base.tmpbuffer[8] != 0 {
				return 0, fmt.Errorf("returned failed request, not handled, error: %v", base.tmpbuffer[8])
			}
			ln.blockexp++
			blockno := (uint32(base.tmpbuffer[4]) << 24) | (uint32(base.tmpbuffer[5]) << 16) | (uint32(base.tmpbuffer[6]) << 8) | uint32(base.tmpbuffer[7])
			if ln.blockexp != blockno {
				return 0, fmt.Errorf("unexpected block number")
			}
			ln.remaining, _, err = decodelength(base.transport, &base.tmpbuffer) // refactor usage of these tmp buffers...
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
		n, err = base.transport.Read(p)
		ln.remaining -= uint(n) // hopefully this never returns negative value ;)
		return n, err
	default:
		return 0, fmt.Errorf("program error, unexpected state: %v", ln.state)
	}
}

func (d *dlmsal) Get(items []DlmsLNRequestItem) ([]DlmsData, error) {
	ln := &dlmsalget{base: d, state: 0, blockexp: 0}
	return ln.get(items)
}

func (d *dlmsal) GetStream(item DlmsLNRequestItem, inmem bool) (DlmsDataStream, *DlmsError, error) {
	ln := &dlmsalget{base: d, state: 0, blockexp: 0}
	return ln.getstream(item, inmem)
}
