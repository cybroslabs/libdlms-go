package dlmsal

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/cybroslabs/libdlms-go/base"
	"github.com/cybroslabs/libdlms-go/gcm"
)

func encodelnsetitem(dst *bytes.Buffer, item *DlmsLNRequestItem) error {
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

func (al *dlmsal) setsingle(item DlmsLNRequestItem) ([]DlmsResultTag, error) {
	local := &al.pdu
	local.Reset()
	local.WriteByte(byte(TagSetRequest))
	al.invokeid = (al.invokeid + 1) & 7
	local.WriteByte(al.invokeid | al.settings.invokebyte)
	local.WriteByte(byte(TagSetRequestNormal))
	err := encodelnsetitem(local, &item)
	if err != nil {
		return nil, err
	}

	var sdata bytes.Buffer
	err = encodeData(&sdata, item.SetData)
	if err != nil {
		return nil, err
	}

	ret := make([]DlmsResultTag, 1)

	if local.Len()+sdata.Len() > al.maxPduSendSize-6-gcm.GCM_TAG_LENGTH { // block transfer, count on 6 bytes for tag and worst length and tag, ok, possible byte wasting here
		local.Reset() // possible large memory allocated here, but only for one job
		local.WriteByte(byte(TagSetRequest))
		local.WriteByte(al.invokeid | al.settings.invokebyte)
		local.WriteByte(byte(TagSetRequestWithFirstDataBlock))
		_ = encodelnsetitem(local, &item)

		if al.maxPduSendSize < 16+gcm.GCM_TAG_LENGTH+local.Len() {
			return nil, fmt.Errorf("too small max pdu size for block transfer")
		}
		data := sdata.Bytes()
		blno := uint32(1)
		last := false
		for !last {
			var ts int
			if len(data) > al.maxPduSendSize-16-gcm.GCM_TAG_LENGTH-local.Len() { // 11 bytes for my length and possible gcm length
				ts = al.maxPduSendSize - 16 - gcm.GCM_TAG_LENGTH - local.Len()
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

			tag, str, err := al.sendpdu()
			if err != nil {
				return nil, err
			}
			switch tag {
			case TagSetResponse:
			case TagExceptionResponse:
				d, err := decodeException(str, &al.tmpbuffer)
				if err != nil {
					return nil, err
				}
				ret[0] = (d.Value.(*DlmsError)).Result
				return ret, nil
			default:
				return nil, fmt.Errorf("unexpected tag: %02x", tag)
			}

			_, err = io.ReadFull(str, al.tmpbuffer[:6])
			if err != nil {
				return nil, err
			}
			if al.tmpbuffer[1]&7 != al.invokeid {
				return nil, fmt.Errorf("unexpected invoke id")
			}
			switch setResponseTag(al.tmpbuffer[0]) {
			case TagSetResponseDataBlock:
				if last {
					return nil, fmt.Errorf("expected last data block tag, but not got")
				}
				if blno != binary.BigEndian.Uint32(al.tmpbuffer[2:]) {
					return nil, fmt.Errorf("unexpected block number")
				}
				// ask for another block
				local.Reset()
				local.WriteByte(byte(TagSetRequest))
				local.WriteByte(al.invokeid | al.settings.invokebyte)
				local.WriteByte(byte(TagSetRequestWithDataBlock))
				blno++
			case TagSetResponseLastDataBlock:
				if !last {
					return nil, fmt.Errorf("expected data block tag, but not got")
				}
				_, err = io.ReadFull(str, al.tmpbuffer[6:7])
				if err != nil {
					return nil, err
				}
				if blno != binary.BigEndian.Uint32(al.tmpbuffer[3:]) {
					return nil, fmt.Errorf("unexpected block number")
				}
				ret[0] = DlmsResultTag(al.tmpbuffer[2])
			default:
				return nil, fmt.Errorf("unexpected tag: %02x", al.tmpbuffer[0])
			}
		}
	} else { // continue with normal set
		local.Write(sdata.Bytes())
		tag, str, err := al.sendpdu()
		if err != nil {
			return nil, err
		}
		switch tag {
		case TagSetResponse:
		case TagExceptionResponse:
			d, err := decodeException(str, &al.tmpbuffer)
			if err != nil {
				return nil, err
			}
			ret[0] = (d.Value.(*DlmsError)).Result
			return ret, nil
		default:
			return nil, fmt.Errorf("unexpected tag: %02x", tag)
		}

		_, err = io.ReadFull(str, al.tmpbuffer[:3])
		if err != nil {
			return nil, err
		}
		if al.tmpbuffer[0] != byte(TagSetResponseNormal) {
			return nil, fmt.Errorf("unexpected tag: %02x, expected TagSetResponseNormal", al.tmpbuffer[0])
		}
		if al.tmpbuffer[1]&7 != al.invokeid {
			return nil, fmt.Errorf("unexpected invoke id")
		}

		ret[0] = DlmsResultTag(al.tmpbuffer[2])
	}
	return ret, nil
}

func (al *dlmsal) Set(items []DlmsLNRequestItem) (ret []DlmsResultTag, err error) {
	if !al.isopen {
		return nil, base.ErrNotOpened
	}

	// buffer request send it optionally using blocks and return result, no streaming here
	switch len(items) {
	case 0:
		return nil, base.ErrNothingToRead
	case 1:
		return al.setsingle(items[0])
	}

	// ok, so fun with list damn it
	local := &al.pdu
	local.Reset()
	local.WriteByte(byte(TagSetRequest))
	al.invokeid = (al.invokeid + 1) & 7
	local.WriteByte(al.invokeid | al.settings.invokebyte)
	local.WriteByte(byte(TagSetRequestWithList))
	encodelength(local, uint(len(items)))
	for _, i := range items {
		err = encodelnsetitem(local, &i)
		if err != nil {
			return
		}
	}

	var sdata bytes.Buffer
	encodelength(&sdata, uint(len(items)))
	for _, i := range items {
		err = encodeData(&sdata, i.SetData)
		if err != nil {
			return
		}
	}

	ret = make([]DlmsResultTag, len(items))

	if local.Len()+sdata.Len() > al.maxPduSendSize-6-gcm.GCM_TAG_LENGTH { // block transfer, count on 6 bytes for tag and worst length and tag, ok, possible byte wasting here
		local.Reset()
		local.WriteByte(byte(TagSetRequest))
		local.WriteByte(al.invokeid | al.settings.invokebyte)
		local.WriteByte(byte(TagSetRequestWithListAndFirstDataBlock)) // yes yes i can force content to this
		encodelength(local, uint(len(items)))
		for _, i := range items {
			_ = encodelnsetitem(local, &i)
		}

		if al.maxPduSendSize < 16+gcm.GCM_TAG_LENGTH+local.Len() {
			return nil, fmt.Errorf("too small max pdu size for block transfer")
		}
		data := sdata.Bytes()
		blno := uint32(1)
		last := false
		for !last {
			var ts int
			if len(data) > al.maxPduSendSize-16-gcm.GCM_TAG_LENGTH-local.Len() { // 11 bytes for my length and possible gcm length
				ts = al.maxPduSendSize - 16 - gcm.GCM_TAG_LENGTH - local.Len()
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

			tag, str, err := al.sendpdu()
			if err != nil {
				return nil, err
			}
			switch tag {
			case TagSetResponse:
			case TagExceptionResponse:
				d, err := decodeException(str, &al.tmpbuffer)
				if err != nil {
					return nil, err
				}
				for i := 0; i < len(items); i++ {
					ret[i] = (d.Value.(*DlmsError)).Result
				}
				return ret, nil
			default:
				return nil, fmt.Errorf("unexpected tag: %02x", tag)
			}

			_, err = io.ReadFull(str, al.tmpbuffer[:2])
			if err != nil {
				return nil, err
			}
			if al.tmpbuffer[1]&7 != al.invokeid {
				return nil, fmt.Errorf("unexpected invoke id")
			}
			switch setResponseTag(al.tmpbuffer[0]) {
			case TagSetResponseDataBlock:
				if last {
					return nil, fmt.Errorf("expected last data block tag, but not got")
				}
				_, err = io.ReadFull(str, al.tmpbuffer[:4])
				if err != nil {
					return nil, err
				}
				if blno != binary.BigEndian.Uint32(al.tmpbuffer[:]) {
					return nil, fmt.Errorf("unexpected block number")
				}
				// ask for another block
				local.Reset()
				local.WriteByte(byte(TagSetRequest))
				local.WriteByte(al.invokeid | al.settings.invokebyte)
				local.WriteByte(byte(TagSetRequestWithDataBlock))
				blno++
			case TagSetResponseLastDataBlockWithList:
				if !last {
					return nil, fmt.Errorf("expected data block tag, but not got")
				}
				l, _, err := decodelength(str, &al.tmpbuffer)
				if err != nil {
					return nil, err
				}
				if l != uint(len(items)) {
					return nil, fmt.Errorf("different amount of data received")
				}
				var res []byte
				if len(items)+4 > len(al.tmpbuffer) {
					res = make([]byte, len(items)+4)
				} else {
					res = al.tmpbuffer[:len(items)+4]
				}
				_, err = io.ReadFull(str, res)
				if err != nil {
					return nil, err
				}
				if blno != binary.BigEndian.Uint32(al.tmpbuffer[len(items):]) {
					return nil, fmt.Errorf("unexpected block number")
				}
				for i := 0; i < len(items); i++ {
					ret[i] = DlmsResultTag(res[i])
				}
			default:
				return nil, fmt.Errorf("unexpected tag: %02x", al.tmpbuffer[0])
			}
		}
	} else { // continue with normal list set
		local.Write(sdata.Bytes())
		tag, str, err := al.sendpdu()
		if err != nil {
			return nil, err
		}
		switch tag {
		case TagSetResponse:
		case TagExceptionResponse:
			d, err := decodeException(str, &al.tmpbuffer)
			if err != nil {
				return nil, err
			}
			for i := 0; i < len(items); i++ {
				ret[i] = (d.Value.(*DlmsError)).Result
			}
			return ret, nil
		default:
			return nil, fmt.Errorf("unexpected tag: %02x", tag)
		}

		_, err = io.ReadFull(str, al.tmpbuffer[:2])
		if err != nil {
			return nil, err
		}
		if al.tmpbuffer[0] != byte(TagSetResponseWithList) {
			return nil, fmt.Errorf("unexpected tag: %02x, expected TagSetResponseWithList", al.tmpbuffer[0])
		}
		if al.tmpbuffer[1]&7 != al.invokeid {
			return nil, fmt.Errorf("unexpected invoke id")
		}
		var l uint
		l, _, err = decodelength(str, &al.tmpbuffer)
		if err != nil {
			return nil, err
		}
		if l != uint(len(items)) {
			return nil, fmt.Errorf("different amount of data received")
		}
		var res []byte
		if len(items) > len(al.tmpbuffer) {
			res = make([]byte, len(items))
		} else {
			res = al.tmpbuffer[:len(items)]
		}
		_, err = io.ReadFull(str, res)
		if err != nil {
			return nil, err
		}
		for i := 0; i < len(items); i++ {
			ret[i] = DlmsResultTag(res[i])
		}
	}
	return ret, nil
}
