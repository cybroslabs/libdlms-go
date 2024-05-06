package dlmsal

import (
	"fmt"
	"io"
)

// SN func read, for now it should be enough
func (d *dlmsal) Read(items []DlmsSNRequestItem) ([]DlmsData, error) {
	if !d.isopen {
		return nil, fmt.Errorf("connection is not open")
	}

	if len(items) == 0 {
		return nil, fmt.Errorf("no items to read")
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

	err := d.transport.Write(local.Bytes())
	if err != nil {
		return nil, err
	}

	_, err = io.ReadFull(d.transport, d.tmpbuffer[:1])
	if err != nil {
		return nil, err
	}
	if d.tmpbuffer[0] != byte(TagReadResponse) {
		return nil, fmt.Errorf("unexpected tag: %x", d.tmpbuffer[0])
	}
	l, _, err := decodelength(d.transport, d.tmpbuffer)
	if err != nil {
		return nil, err
	}
	if int(l) != len(items) {
		return nil, fmt.Errorf("different amount of data received")
	}
	ret := make([]DlmsData, len(items))
	for i := 0; i < len(ret); i++ {
		_, err = io.ReadFull(d.transport, d.tmpbuffer[:1])
		if err != nil {
			return nil, err
		}
		switch d.tmpbuffer[0] {
		case 0:
			ret[i], _, err = decodeDataTag(d.transport, d.tmpbuffer)
			if err != nil {
				return nil, err
			}
		case 1:
			_, err = io.ReadFull(d.transport, d.tmpbuffer[:1])
			if err != nil {
				return nil, err
			}
			ret[i] = NewDlmsDataError(DlmsError{Result: AccessResultTag(d.tmpbuffer[0])})
		default:
			return nil, fmt.Errorf("unexpected response tag: %x", d.tmpbuffer[0])
		}
	}

	return ret, nil
}

func (d *dlmsal) ReadStream(item DlmsSNRequestItem, inmem bool) (DlmsDataStream, *DlmsError, error) {
	if !d.isopen {
		return nil, nil, fmt.Errorf("connection is not open")
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

	err := d.transport.Write(local.Bytes())
	if err != nil {
		return nil, nil, err
	}

	_, err = io.ReadFull(d.transport, d.tmpbuffer[:1])
	if err != nil {
		return nil, nil, err
	}
	if d.tmpbuffer[0] != byte(TagReadResponse) {
		return nil, nil, fmt.Errorf("unexpected tag: %x", d.tmpbuffer[0])
	}
	l, _, err := decodelength(d.transport, d.tmpbuffer)
	if err != nil {
		return nil, nil, err
	}
	if l != 1 {
		return nil, nil, fmt.Errorf("only one item was expected")
	}

	_, err = io.ReadFull(d.transport, d.tmpbuffer[:1])
	if err != nil {
		return nil, nil, err
	}
	switch d.tmpbuffer[0] {
	case 0:
		str, err := newDataStream(d.transport, inmem, d.logger)
		if err != nil {
			return nil, nil, err
		}
		return str, nil, nil
	case 1:
		_, err = io.ReadFull(d.transport, d.tmpbuffer[:1])
		if err != nil {
			return nil, nil, err
		}
		return nil, &DlmsError{Result: AccessResultTag(d.tmpbuffer[0])}, nil
	}

	return nil, nil, fmt.Errorf("unexpected response tag: %x", d.tmpbuffer[0])
}
