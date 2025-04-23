package dlmsal

import (
	"fmt"
	"io"

	"github.com/cybroslabs/libdlms-go/base"
)

// SN func read, for now it should be enough
func (d *dlmsal) Read(items []DlmsSNRequestItem) ([]DlmsData, error) {
	if !d.isopen {
		return nil, base.ErrNotOpened
	}

	if len(items) == 0 {
		return nil, base.ErrNothingToRead
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
		return nil, fmt.Errorf("unexpected tag: %x", tag)
	}
	l, _, err := decodelength(str, &d.tmpbuffer)
	if err != nil {
		return nil, err
	}
	if int(l) != len(items) {
		return nil, fmt.Errorf("different amount of data received")
	}
	ret := make([]DlmsData, len(items))
	for i := 0; i < len(ret); i++ {
		_, err = io.ReadFull(str, d.tmpbuffer[:1])
		if err != nil {
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
		default:
			return nil, fmt.Errorf("unexpected response tag: %x", d.tmpbuffer[0])
		}
	}

	return ret, nil
}

func (d *dlmsal) ReadStream(item DlmsSNRequestItem, inmem bool) (DlmsDataStream, error) {
	if !d.isopen {
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
		return nil, fmt.Errorf("unexpected tag: %x", tag)
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
	}

	return nil, fmt.Errorf("unexpected response tag: %x", d.tmpbuffer[0])
}

// write support here
func (d *dlmsal) Write(items []DlmsSNRequestItem) ([]base.DlmsResultTag, error) {
	if !d.isopen {
		return nil, base.ErrNotOpened
	}

	if len(items) == 0 {
		return nil, base.ErrNothingToRead
	}

	local := &d.pdu
	local.Reset()
	local.WriteByte(byte(base.TagWriteRequest))
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

	encodelength(local, uint(len(items)))
	for _, item := range items {
		err := encodeData(local, item.WriteData)
		if err != nil {
			return nil, err
		}
	}
	tag, str, err := d.sendpdu()
	if err != nil {
		return nil, err
	}
	if tag != base.TagWriteResponse {
		return nil, fmt.Errorf("unexpected tag: %x", tag)
	}

	l, _, err := decodelength(str, &d.tmpbuffer)
	if err != nil {
		return nil, err
	}
	if l != uint(len(items)) {
		return nil, fmt.Errorf("different amount of data received")
	}
	ret := make([]base.DlmsResultTag, len(items))
	for i := 0; i < len(ret); i++ {
		_, err = io.ReadFull(str, d.tmpbuffer[:1])
		if err != nil {
			return nil, err
		}
		switch d.tmpbuffer[0] {
		case 0:
			ret[i] = base.TagResultSuccess
		case 1:
			_, err = io.ReadFull(str, d.tmpbuffer[:1])
			if err != nil {
				return nil, err
			}
			if d.tmpbuffer[0] == 0 {
				ret[i] = base.TagResultOtherReason
			} else {
				ret[i] = base.DlmsResultTag(d.tmpbuffer[0])
			}
		default:
			return nil, fmt.Errorf("unexpected write response item: %x", d.tmpbuffer[0])
		}
	}
	return ret, nil
}
