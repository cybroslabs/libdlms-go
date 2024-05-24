package dlmsal

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/cybroslabs/libdlms-go/gcm"
)

// send and optionally encrypt packet at pdu to transport layer, returns also answer stream object with transparent ciphering and tag reading, hell
func (d *dlmsal) sendpdu() (tag CosemTag, str io.Reader, err error) {
	local := &d.pdu
	if local.Len() == 0 {
		return tag, nil, fmt.Errorf("empty pdu")
	}
	b := local.Bytes()
	s := d.settings
	if s.dedgcm != nil {
		switch CosemTag(b[0]) {
		case TagGetRequest:
			tag = TagDedGetRequest
		case TagSetRequest:
			tag = TagDedSetRequest
		case TagActionRequest:
			tag = TagDedActionRequest
		case TagReadRequest:
			tag = TagDedReadRequest
		case TagWriteRequest:
			tag = TagDedWriteRequest
		default:
			return tag, nil, fmt.Errorf("unsupported tag %v", b[0])
		}
		b = d.encryptpacket(byte(tag), b, true)
	} else if s.gcm != nil {
		switch CosemTag(b[0]) {
		case TagGetRequest:
			tag = TagGloGetRequest
		case TagSetRequest:
			tag = TagGloSetRequest
		case TagActionRequest:
			tag = TagGloActionRequest
		case TagReadRequest:
			tag = TagGloReadRequest
		case TagWriteRequest:
			tag = TagGloWriteRequest
		default:
			return tag, nil, fmt.Errorf("unsupported tag %v", b[0])
		}
		b = d.encryptpacket(byte(tag), b, false)
	}

	if len(b) > d.maxPduSendSize {
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
	tag = CosemTag(d.tmpbuffer[0])
	switch {
	case tag == TagGloGetResponse || tag == TagGloSetResponse || tag == TagGloActionResponse || tag == TagGloReadResponse || tag == TagGloWriteResponse:
		return d.recvcipheredpdu(tag, false)
	case tag == TagDedGetResponse || tag == TagDedSetResponse || tag == TagDedActionResponse || tag == TagDedReadResponse || tag == TagDedWriteResponse:
		return d.recvcipheredpdu(tag, true)
	}
	return tag, d.transport, err
}

func (d *dlmsal) recvcipheredpdu(rtag CosemTag, ded bool) (tag CosemTag, str io.Reader, err error) {
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
	str, err = gcm.GetDecryptorStream(d.tmpbuffer[0], fc, d.aareres.SystemTitle, io.LimitReader(d.transport, int64(l)))
	if err != nil {
		return
	}
	_, err = io.ReadFull(str, d.tmpbuffer[:1])
	if err != nil {
		return
	}
	tag = CosemTag(d.tmpbuffer[0])
	return
}
