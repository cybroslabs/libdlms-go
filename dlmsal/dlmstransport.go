package dlmsal

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/cybroslabs/libdlms-go/base"
	"github.com/cybroslabs/libdlms-go/gcm"
)

// send and optionally encrypt packet at pdu to transport layer, returns also answer stream object with transparent ciphering and tag reading, hell
func (d *dlmsal) sendpdu() (tag base.CosemTag, str io.Reader, err error) {
	local := &d.pdu
	if local.Len() == 0 {
		return tag, nil, fmt.Errorf("empty pdu")
	}
	b := local.Bytes()
	s := d.settings
	if s.dedgcm != nil {
		switch base.CosemTag(b[0]) {
		case base.TagGetRequest:
			tag = base.TagDedGetRequest
		case base.TagSetRequest:
			tag = base.TagDedSetRequest
		case base.TagActionRequest:
			tag = base.TagDedActionRequest
		case base.TagReadRequest:
			tag = base.TagDedReadRequest
		case base.TagWriteRequest:
			tag = base.TagDedWriteRequest
		default:
			return tag, nil, fmt.Errorf("unsupported tag %v", b[0])
		}
		b, err = d.encryptpacket(byte(tag), b, true)
	} else if s.gcm != nil {
		switch base.CosemTag(b[0]) {
		case base.TagGetRequest:
			tag = base.TagGloGetRequest
		case base.TagSetRequest:
			tag = base.TagGloSetRequest
		case base.TagActionRequest:
			tag = base.TagGloActionRequest
		case base.TagReadRequest:
			tag = base.TagGloReadRequest
		case base.TagWriteRequest:
			tag = base.TagGloWriteRequest
		default:
			return tag, nil, fmt.Errorf("unsupported tag %v", b[0])
		}
		b, err = d.encryptpacket(byte(tag), b, false)
	}
	if err != nil {
		return
	}

	if len(b) > d.maxPduSendSize && d.maxPduSendSize != 0 {
		return tag, nil, fmt.Errorf("PDU size exceeds maximum size: %v > %v", len(b), d.maxPduSendSize)
	}
	err = d.transport.Write(b)
	if err != nil {
		return
	}
	// read first fucking byte, this is sooooo, fuuuuuu
	_, err = io.ReadFull(d.transport, d.tmpbuffer[:1])
	if err != nil {
		return
	}
	tag = base.CosemTag(d.tmpbuffer[0])
	switch tag {
	case base.TagGloGetResponse, base.TagGloSetResponse, base.TagGloActionResponse, base.TagGloReadResponse, base.TagGloWriteResponse:
		return d.recvcipheredpdu(tag, false)
	case base.TagDedGetResponse, base.TagDedSetResponse, base.TagDedActionResponse, base.TagDedReadResponse, base.TagDedWriteResponse:
		return d.recvcipheredpdu(tag, true)
	}
	return tag, d.transport, err
}

func (d *dlmsal) recvcipheredpdu(rtag base.CosemTag, ded bool) (tag base.CosemTag, str io.Reader, err error) {
	tag = rtag
	s := d.settings
	var gcm gcm.Gcm
	if ded {
		if s.dedgcm == nil {
			return tag, nil, fmt.Errorf("no dedicated ciphering set")
		}
		gcm = s.dedgcm
	} else {
		if s.gcm == nil {
			return tag, nil, fmt.Errorf("no global ciphering set")
		}
		gcm = s.gcm
	}
	l, _, err := decodelength(d.transport, &d.tmpbuffer)
	if err != nil {
		return tag, nil, err
	}
	_, err = io.ReadFull(d.transport, d.tmpbuffer[:5])
	if err != nil {
		return tag, nil, fmt.Errorf("unable to read SC byte and frame counter")
	}
	fc := binary.BigEndian.Uint32(d.tmpbuffer[1:])
	str, err = gcm.GetDecryptorStream(d.tmpbuffer[0], fc, io.LimitReader(d.transport, int64(l)))
	if err != nil {
		return
	}
	_, err = io.ReadFull(str, d.tmpbuffer[:1])
	if err != nil {
		return
	}
	tag = base.CosemTag(d.tmpbuffer[0])
	return
}
