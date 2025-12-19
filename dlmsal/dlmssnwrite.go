package dlmsal

import (
	"fmt"
	"io"

	"github.com/cybroslabs/libdlms-go/base"
)

// write support here
func (d *dlmsal) Write(items []DlmsSNRequestItem) ([]base.DlmsResultTag, error) {
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
			ret := make([]base.DlmsResultTag, 0, len(items))
			for _, item := range items {
				tmp[0] = item
				data, err := d.Write(tmp[:])
				if err != nil {
					return nil, err
				}
				ret = append(ret, data[0])
			}
			return ret, nil
		}
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
		return nil, fmt.Errorf("different amount of data received, expected %d got %d", len(items), l)
	}
	ret := make([]base.DlmsResultTag, len(items))
	for i := range ret {
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
