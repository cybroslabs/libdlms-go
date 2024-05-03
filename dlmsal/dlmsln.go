package dlmsal

import (
	"fmt"
	"io"
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
		return nil, fmt.Errorf("no items to read")
	}

	ln.base.pdu.Reset()
	ln.base.pdu.WriteByte(byte(TagGetRequest))
	if len(items) > 1 {
		ln.base.pdu.WriteByte(byte(TagGetRequestWithList))
	} else {
		ln.base.pdu.WriteByte(byte(TagGetRequestNormal))
	}
	ln.base.invokeid = (ln.base.invokeid + 1) & 7
	ln.base.pdu.WriteByte(ln.base.invokeid | ln.base.settings.HighPriority | ln.base.settings.ConfirmedRequests)

	if len(items) > 1 {
		encodelength(&ln.base.pdu, uint(len(items)))
	}

	for _, i := range items {
		ln.base.pdu.WriteByte(byte(i.ClassId >> 8))
		ln.base.pdu.WriteByte(byte(i.ClassId))
		ln.base.pdu.WriteByte(i.Obis.A)
		ln.base.pdu.WriteByte(i.Obis.B)
		ln.base.pdu.WriteByte(i.Obis.C)
		ln.base.pdu.WriteByte(i.Obis.D)
		ln.base.pdu.WriteByte(i.Obis.E)
		ln.base.pdu.WriteByte(i.Obis.F)
		ln.base.pdu.WriteByte(byte(i.Attribute))
		if i.HasAccess {
			ln.base.pdu.WriteByte(1)
			ln.base.pdu.WriteByte(i.AccessDescriptor)
			err := encodeData(&ln.base.pdu, i.AccessData)
			if err != nil {
				return nil, fmt.Errorf("unable to encode data: %v", err)
			}
		} else {
			ln.base.pdu.WriteByte(0)
		}
	}

	if ln.base.pdu.Len() > ln.base.maxPduSendSize {
		return nil, fmt.Errorf("PDU size exceeds maximum size: %v > %v", ln.base.pdu.Len(), ln.base.maxPduSendSize)
	}

	// send itself, that could be fun, do that in one step for now
	err := ln.base.transport.Write(ln.base.pdu.Bytes())
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

func (ln *dlmsalget) getnextdata(i int) (cont bool, err error) {
	switch ln.state {
	case 0: // read first things as a response
		_, err = io.ReadFull(ln.base.transport, ln.base.tmpbuffer[:1])
		if err != nil {
			return false, err
		}
		switch CosemTag(ln.base.tmpbuffer[0]) {
		case TagGetResponse:
		case TagExceptionResponse: // no lower layer readout
			for i := 0; i < len(ln.data); i++ {
				ln.data[i] = DlmsData{Tag: TagError, Value: DlmsError{Result: TagAccOtherReason}} // dont decode exception pdu
			}
			ln.state = 100
			return true, nil
		default:
			return false, fmt.Errorf("unexpected tag: %x", ln.base.tmpbuffer[0])
		}
		_, err = io.ReadFull(ln.base.transport, ln.base.tmpbuffer[:2])
		if err != nil {
			return false, err
		}

		if ln.base.tmpbuffer[1]&7 != ln.base.invokeid {
			return false, fmt.Errorf("unexpected invoke id")
		}

		switch getResponseTag(ln.base.tmpbuffer[0]) {
		case TagGetResponseNormal:
			if len(ln.data) > 1 {
				return false, fmt.Errorf("expecting list response")
			}
			// decode data themselves
			_, err = io.ReadFull(ln.base.transport, ln.base.tmpbuffer[:1])
			if err != nil {
				return false, err
			}

			if ln.base.tmpbuffer[0] != 0 {
				_, err = io.ReadFull(ln.base.transport, ln.base.tmpbuffer[:1])
				if err == io.ErrUnexpectedEOF {
					ln.data[i] = DlmsData{Tag: TagError, Value: DlmsError{Result: TagAccOtherReason}} // this kind of data cant be decoded, so that is why
				} else {
					if err != nil {
						return false, err
					}
				}
				ln.data[i] = DlmsData{Tag: TagError, Value: DlmsError{Result: AccessResultTag(ln.base.tmpbuffer[0])}}
			} else {
				ln.data[i], _, err = ln.base.decodeDataTag(ln.base.transport)
				if err != nil {
					return false, err
				}
			}
			ln.state = 100
		case TagGetResponseWithList:
			if len(ln.data) == 1 {
				return false, fmt.Errorf("expecting normal response")
			}
			l, _, err := decodelength(ln.base.transport, ln.base.tmpbuffer)
			if err != nil {
				return false, err
			}
			if l != uint(len(ln.data)) {
				return false, fmt.Errorf("different amount of data received")
			}
			for i := 0; i < len(ln.data); i++ {
				_, err = io.ReadFull(ln.base.transport, ln.base.tmpbuffer[:1])
				if err != nil {
					return false, err
				}
				if ln.base.tmpbuffer[0] != 0 {
					_, err = io.ReadFull(ln.base.transport, ln.base.tmpbuffer[:1])
					if err != nil {
						return false, err
					}
					ln.data[i] = DlmsData{Tag: TagError, Value: DlmsError{Result: AccessResultTag(ln.base.tmpbuffer[0])}}
				} else {
					ln.data[i], _, err = ln.base.decodeDataTag(ln.base.transport)
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
				ln.data[i], _, err = ln.base.decodeDataTag(ln)
			} else { // with list, so read first byte to decide if there is an error and result byte or decode data
				err = ln.decodedata(i)
			}
			if err != nil {
				return false, err
			}
		default:
			return false, fmt.Errorf("unexpected response tag: %x", ln.base.tmpbuffer[0])
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
	_, err = io.ReadFull(ln, ln.base.tmpbuffer[:1])
	if err != nil {
		return
	}
	if ln.base.tmpbuffer[0] != 0 {
		_, err = io.ReadFull(ln, ln.base.tmpbuffer[:1])
		if err != nil {
			return
		}
		ln.data[i] = DlmsData{Tag: TagError, Value: DlmsError{Result: AccessResultTag(ln.base.tmpbuffer[0])}}
	} else {
		ln.data[i], _, err = ln.base.decodeDataTag(ln)
	}
	return
}

func (ln *dlmsalget) Read(p []byte) (n int, err error) { // this will go to data decoder
	if len(p) == 0 { // that shouldnt happen
		return 0, fmt.Errorf("no data to read")
	}
	switch ln.state {
	case 1: // read block header
		_, err = io.ReadFull(ln.base.transport, ln.base.tmpbuffer[:6])
		if err != nil {
			return
		}
		ln.lastblock = ln.base.tmpbuffer[0] != 0
		if ln.base.tmpbuffer[5] != 0 {
			return 0, fmt.Errorf("returned failed request, not handled, error: %v", ln.base.tmpbuffer[5])
		}
		blockno := (uint32(ln.base.tmpbuffer[1]) << 24) | (uint32(ln.base.tmpbuffer[2]) << 16) | (uint32(ln.base.tmpbuffer[3]) << 8) | uint32(ln.base.tmpbuffer[4])
		ln.blockexp = blockno
		ln.remaining, _, err = decodelength(ln.base.transport, ln.base.tmpbuffer) // refactor usage of these tmp buffers...
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
		n, err = ln.base.transport.Read(p)
		ln.remaining -= uint(n) // hiopefully this never returns negative value ;)
		return n, err
	case 2: // read block content
		if ln.remaining == 0 { // next block please
			if ln.lastblock {
				return 0, io.EOF // or some common error?
			}
			// ask for the next block
			ln.base.tmpbuffer[0] = byte(TagGetRequest)
			ln.base.tmpbuffer[1] = byte(TagGetRequestNext)
			ln.base.tmpbuffer[2] = ln.base.invokeid | ln.base.settings.HighPriority | ln.base.settings.ConfirmedRequests
			ln.base.tmpbuffer[3] = byte(ln.blockexp >> 24)
			ln.base.tmpbuffer[4] = byte(ln.blockexp >> 16)
			ln.base.tmpbuffer[5] = byte(ln.blockexp >> 8)
			ln.base.tmpbuffer[6] = byte(ln.blockexp)
			err = ln.base.transport.Write(ln.base.tmpbuffer[:7])
			if err != nil {
				return 0, err
			}
			_, err = io.ReadFull(ln.base.transport, ln.base.tmpbuffer[:9]) // read block answer header
			if err != nil {
				return 0, err
			}
			if ln.base.tmpbuffer[0] != byte(TagGetResponse) || ln.base.tmpbuffer[1] != byte(TagGetResponseWithDataBlock) || ln.base.tmpbuffer[2]&7 != ln.base.invokeid {
				return 0, fmt.Errorf("unexpected response tag: %x", ln.base.tmpbuffer[1])
			}
			// set last, check block number and set remaining
			ln.lastblock = ln.base.tmpbuffer[3] != 0
			if ln.base.tmpbuffer[8] != 0 {
				return 0, fmt.Errorf("returned failed request, not handled, error: %v", ln.base.tmpbuffer[8])
			}
			ln.blockexp++
			blockno := (uint32(ln.base.tmpbuffer[4]) << 24) | (uint32(ln.base.tmpbuffer[5]) << 16) | (uint32(ln.base.tmpbuffer[6]) << 8) | uint32(ln.base.tmpbuffer[7])
			if ln.blockexp != blockno {
				return 0, fmt.Errorf("unexpected block number")
			}
			ln.remaining, _, err = decodelength(ln.base.transport, ln.base.tmpbuffer) // refactor usage of these tmp buffers...
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
		n, err = ln.base.transport.Read(p)
		ln.remaining -= uint(n) // hiopefully this never returns negative value ;)
		return n, err
	default:
		return 0, fmt.Errorf("program error, unexpected state: %v", ln.state)
	}
}

func (d *dlmsal) Get(items []DlmsLNRequestItem) ([]DlmsData, error) {
	ln := &dlmsalget{base: d, state: 0, blockexp: 0}
	return ln.get(items)
}
