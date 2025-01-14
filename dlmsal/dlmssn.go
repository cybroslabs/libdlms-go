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
	local.WriteByte(byte(TagReadRequest))
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

	if tag != TagReadResponse {
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
			ret[i] = NewDlmsDataError(AccessResultTag(d.tmpbuffer[0]))
		default:
			return nil, fmt.Errorf("unexpected response tag: %x", d.tmpbuffer[0])
		}
	}

	return ret, nil
}

func (d *dlmsal) ReadStream(item DlmsSNRequestItem, inmem bool) (DlmsDataStream, *DlmsError, error) {
	if !d.isopen {
		return nil, nil, base.ErrNotOpened
	}

	local := &d.pdu
	// format request into byte slice and send that to unit
	local.Reset()
	local.WriteByte(byte(TagReadRequest))
	encodelength(local, 1)
	if item.HasAccess {
		local.WriteByte(4)
		local.WriteByte(byte(item.Address >> 8))
		local.WriteByte(byte(item.Address))
		local.WriteByte(item.AccessDescriptor)
		err := encodeData(local, item.AccessData)
		if err != nil {
			return nil, nil, err
		}
	} else {
		local.WriteByte(2)
		local.WriteByte(byte(item.Address >> 8))
		local.WriteByte(byte(item.Address))
	}

	tag, str, err := d.sendpdu()
	if err != nil {
		return nil, nil, err
	}

	if tag != TagReadResponse {
		return nil, nil, fmt.Errorf("unexpected tag: %x", tag)
	}
	l, _, err := decodelength(str, &d.tmpbuffer)
	if err != nil {
		return nil, nil, err
	}
	if l != 1 {
		return nil, nil, fmt.Errorf("only one item was expected")
	}

	_, err = io.ReadFull(str, d.tmpbuffer[:1])
	if err != nil {
		return nil, nil, err
	}
	switch d.tmpbuffer[0] {
	case 0:
		str, err := newDataStream(str, inmem, d.logger)
		if err != nil {
			return nil, nil, err
		}
		return str, nil, nil
	case 1:
		_, err = io.ReadFull(str, d.tmpbuffer[:1])
		if err != nil {
			return nil, nil, err
		}
		return nil, &DlmsError{Result: AccessResultTag(d.tmpbuffer[0])}, nil
	}

	return nil, nil, fmt.Errorf("unexpected response tag: %x", d.tmpbuffer[0])
}

// write support here
func (d *dlmsal) Write(items []DlmsSNRequestItem) ([]AccessResultTag, error) {
	if !d.isopen {
		return nil, base.ErrNotOpened
	}

	if len(items) == 0 {
		return nil, base.ErrNothingToRead
	}

	local := &d.pdu
	local.Reset()
	local.WriteByte(byte(TagWriteRequest))
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
	if tag != TagWriteResponse {
		return nil, fmt.Errorf("unexpected tag: %x", tag)
	}

	l, _, err := decodelength(str, &d.tmpbuffer)
	if err != nil {
		return nil, err
	}
	if l != uint(len(items)) {
		return nil, fmt.Errorf("different amount of data received")
	}
	ret := make([]AccessResultTag, len(items))
	for i := 0; i < len(ret); i++ {
		_, err = io.ReadFull(str, d.tmpbuffer[:1])
		if err != nil {
			return nil, err
		}
		switch d.tmpbuffer[0] {
		case 0:
			ret[i] = TagAccSuccess
		case 1:
			_, err = io.ReadFull(str, d.tmpbuffer[:1])
			if err != nil {
				return nil, err
			}
			if d.tmpbuffer[0] == 0 {
				ret[i] = TagAccOtherReason
			} else {
				ret[i] = AccessResultTag(d.tmpbuffer[0])
			}
		default:
			return nil, fmt.Errorf("unexpected write response item: %x", d.tmpbuffer[0])
		}
	}
	return ret, nil
}
