package dlmsal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/cybroslabs/libdlms-go/base"
)

type dlmsalaction struct { // this will implement io.Reader for LN Action operation, not supporting block data sending, only receiving
	io.Reader
	master *dlmsal
	state  int
	// 0 before first response
	// 1 block header expected
	// 2 block content, remaining/lastblock is set
	// 100 game over all read
	blockexp  uint32
	lastblock bool
	remaining uint
	transport io.Reader
}

func encodelnactionitem(dst *bytes.Buffer, item *DlmsLNRequestItem) error {
	encodelncosemattr(dst, item)
	if item.HasAccess {
		return fmt.Errorf("action item cant have access")
	}
	return nil
}

func (ln *dlmsalaction) action(item DlmsLNRequestItem) (*DlmsData, error) {
	master := ln.master
	local := &master.pdu
	local.Reset()
	local.WriteByte(byte(base.TagActionRequest))
	local.WriteByte(byte(TagActionRequestNormal))
	master.invokeid = (master.invokeid + 1) & 7
	local.WriteByte(master.invokeid | master.settings.invokebyte)
	err := encodelnactionitem(local, &item)
	if err != nil {
		return nil, err
	}

	var sdata bytes.Buffer
	if item.SetData != nil {
		sdata.WriteByte(1)
		err = encodeData(&sdata, item.SetData)
		if err != nil {
			return nil, err
		}
	} else {
		sdata.WriteByte(0)
	}

	if local.Len()+sdata.Len() > master.maxPduSendSize-pduoverhead { // block transfer, count on 6 bytes for tag and worst length and tag, ok, possible byte wasting here
		local.Reset() // yes yes, wasting a bit, but usually this ends in single pdu, just in case...
		local.WriteByte(byte(base.TagActionRequest))
		local.WriteByte(byte(TagActionRequestWithFirstPBlock))
		local.WriteByte(master.invokeid | master.settings.invokebyte)
		_ = encodelnactionitem(local, &item)

		if master.maxPduSendSize < pdublockoverhead+local.Len() {
			return nil, fmt.Errorf("too small max pdu size for block transfer")
		}
		data := sdata.Bytes()
		blno := uint32(1)
		last := false

		for !last {
			var ts int
			if len(data) > master.maxPduSendSize-pdublockoverhead-local.Len() { // 11 bytes for my length and possible gcm length, todo space for signature here
				ts = master.maxPduSendSize - pdublockoverhead - local.Len()
				last = false
			} else {
				ts = len(data)
				last = true
			}

			if last {
				local.WriteByte(1)
			} else {
				local.WriteByte(0)
			}
			local.WriteByte(byte(blno >> 24))
			local.WriteByte(byte(blno >> 16))
			local.WriteByte(byte(blno >> 8))
			local.WriteByte(byte(blno))
			encodelength(local, uint(ts))
			local.Write(data[:ts])
			data = data[ts:]

			tag, str, err := master.sendpdu()
			if err != nil {
				return nil, err
			}
			switch tag {
			case base.TagActionResponse:
			case base.TagExceptionResponse:
				ln.transport = str
				return ln.actiondata(tag)
			default:
				return nil, fmt.Errorf("unexpected tag: %02x", tag)
			}

			_, err = io.ReadFull(str, master.tmpbuffer[:2])
			if err != nil {
				return nil, err
			}
			if master.tmpbuffer[1]&7 != master.invokeid {
				return nil, fmt.Errorf("unexpected invoke id")
			}
			switch ActionResponseTag(master.tmpbuffer[0]) {
			case TagActionResponseNextPBlock:
				if last {
					return nil, fmt.Errorf("expected response with pblock tag, but not got")
				}
				_, err = io.ReadFull(str, master.tmpbuffer[2:6])
				if err != nil {
					return nil, err
				}
				if blno != binary.BigEndian.Uint32(master.tmpbuffer[2:]) {
					return nil, fmt.Errorf("unexpected block number")
				}
				// ask for another block
				local.Reset()
				local.WriteByte(byte(base.TagActionRequest))
				local.WriteByte(master.invokeid | master.settings.invokebyte)
				local.WriteByte(byte(TagActionRequestWithPBlock))
				blno++
			case TagActionResponseWithPBlock:
				if !last {
					return nil, fmt.Errorf("expected response with next pblock tag, but not got")
				}
				ln.transport = str
				return ln.actiondatinnertag(ActionResponseTag(master.tmpbuffer[0])) // there is a question about block numbering
			case TagActionResponseNormal:
				if !last {
					return nil, fmt.Errorf("expected response with next pblock tag, but not got")
				}
				ln.transport = str
				return ln.actiondatinnertag(ActionResponseTag(master.tmpbuffer[0]))
			default:
				return nil, fmt.Errorf("unexpected tag: %02x", master.tmpbuffer[0])
			}
		}
		return nil, fmt.Errorf("program error, unexpected state: %v", ln.state)
	}

	// stuff that into single pdu
	local.Write(sdata.Bytes())

	// send itself, that could be fun, do that in one step for now
	tag, str, err := master.sendpdu()
	if err != nil {
		return nil, err
	}
	ln.transport = str

	// start streaming response
	return ln.actiondata(tag)
}

func (ln *dlmsalaction) actiondatinnertag(tag ActionResponseTag) (data *DlmsData, err error) {
	master := ln.master
	switch tag {
	case TagActionResponseNormal:
		// decode data themselves
		_, err = io.ReadFull(ln.transport, master.tmpbuffer[:1])
		if err != nil {
			return data, err
		}

		ln.state = 100
		if master.tmpbuffer[0] != 0 {
			d := NewDlmsDataError(base.DlmsResultTag(master.tmpbuffer[0]))
			return &d, nil
		}

		_, err = io.ReadFull(ln.transport, master.tmpbuffer[:1])
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil, nil
			}
			return
		}
		if master.tmpbuffer[0] == 0 { // no data as a result
			return
		}
		_, err = io.ReadFull(ln.transport, master.tmpbuffer[:1]) // fuck this reading one by one...
		if err != nil {
			return
		}
		if master.tmpbuffer[0] != 0 {
			_, err = io.ReadFull(ln.transport, master.tmpbuffer[:1])
			if err != nil {
				return
			}
			rd := NewDlmsDataError(base.DlmsResultTag(master.tmpbuffer[0]))
			return &rd, nil
		}

		d, _, err := decodeDataTag(ln.transport, &master.tmpbuffer)
		return &d, err
	case TagActionResponseWithPBlock: // this is a bit of hell, read till eof from lower layer and then ask for next block and so on
		ln.state = 1
		d, _, err := decodeDataTag(ln, &master.tmpbuffer)
		return &d, err
	}
	return data, fmt.Errorf("unexpected response tag: %02x", tag)
}

func (ln *dlmsalaction) actiondata(tag base.CosemTag) (data *DlmsData, err error) {
	master := ln.master
	switch ln.state { // this switch is worthless, just in case
	case 0: // read first things as a response
		switch tag {
		case base.TagActionResponse:
		case base.TagExceptionResponse: // no lower layer readout
			ln.state = 100
			d, err := decodeException(ln.transport, &master.tmpbuffer)
			return &d, err // dont decode exception pdu
		default:
			return data, fmt.Errorf("unexpected tag: %02x", tag)
		}
		_, err = io.ReadFull(ln.transport, master.tmpbuffer[:2])
		if err != nil {
			return data, err
		}

		if master.tmpbuffer[1]&7 != master.invokeid {
			return data, fmt.Errorf("unexpected invoke id")
		}

		return ln.actiondatinnertag(ActionResponseTag(master.tmpbuffer[0]))
	case 100:
		return data, fmt.Errorf("program error, all data are read")
	}
	return data, fmt.Errorf("program error, unexpected state: %v", ln.state)
}

func (ln *dlmsalaction) Read(p []byte) (n int, err error) { // this will go to data decoder, not tested at all
	if len(p) == 0 { // that shouldnt happen
		return 0, base.ErrNothingToRead
	}
	master := ln.master
	switch ln.state {
	case 1: // read block header
		_, err = io.ReadFull(ln.transport, master.tmpbuffer[:5])
		if err != nil {
			return
		}
		ln.lastblock = master.tmpbuffer[0] != 0
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
			local.WriteByte(byte(base.TagActionRequest))
			local.WriteByte(byte(TagActionRequestNextPBlock))
			local.WriteByte(master.invokeid | master.settings.invokebyte)
			local.WriteByte(byte(ln.blockexp >> 24))
			local.WriteByte(byte(ln.blockexp >> 16))
			local.WriteByte(byte(ln.blockexp >> 8))
			local.WriteByte(byte(ln.blockexp))
			tag, str, err := master.sendpdu()
			if err != nil {
				return 0, err
			}
			if tag != base.TagActionResponse {
				return 0, fmt.Errorf("unexpected response tag: %02x", tag)
			}
			ln.transport = str

			_, err = io.ReadFull(ln.transport, master.tmpbuffer[:7]) // read block answer header
			if err != nil {
				return 0, err
			}
			if master.tmpbuffer[0] != byte(TagActionResponseWithPBlock) || master.tmpbuffer[1]&7 != master.invokeid {
				return 0, fmt.Errorf("unexpected response tag: %02x", master.tmpbuffer[0])
			}
			// set last, check block number and set remaining
			ln.lastblock = master.tmpbuffer[2] != 0
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

// action part, only single action is supported, not list of actions, at least not yet, fuck support everything is a bit pointless
func (d *dlmsal) Action(item DlmsLNRequestItem) (data *DlmsData, err error) { // todo blocking support in case of really big action
	if !d.transport.isopen {
		return nil, base.ErrNotOpened
	}

	ln := &dlmsalaction{master: d, state: 0, blockexp: 0}
	return ln.action(item)
}
