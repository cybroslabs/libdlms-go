package dlmsal

import (
	"encoding/binary"
	"fmt"
)

// tag is common byte in this case, could be also 9 for octetstring and so on, it encodes also length
func (d *dlmsal) encryptpacket(tag byte, apdu []byte, ded bool) ([]byte, error) {
	s := d.settings
	// lets panic in case of nil gcm -> program fault shouldnt happen at all
	wl, _ := s.gcm.GetEncryptLength(byte(s.Security), apdu)
	if cap(d.cryptbuffer) < wl+11 {
		d.cryptbuffer = make([]byte, wl+11)
	} else {
		d.cryptbuffer = d.cryptbuffer[:cap(d.cryptbuffer)]
	}
	d.cryptbuffer[0] = tag
	off := encodelength2(d.cryptbuffer[1:], uint(wl+5))
	off++
	d.cryptbuffer[off] = byte(s.Security)
	off++
	d.cryptbuffer[off] = byte(s.framecounter >> 24) // yeah yeah, binary.BigEndian blabla
	off++
	d.cryptbuffer[off] = byte(s.framecounter >> 16)
	off++
	d.cryptbuffer[off] = byte(s.framecounter >> 8)
	off++
	d.cryptbuffer[off] = byte(s.framecounter)
	off++

	// in this state, encrypt cant remake input reusable buffer
	var err error
	if ded {
		_, err = s.dedgcm.Encrypt(d.cryptbuffer[off:], byte(s.Security), s.framecounter, s.systemtitle, apdu) // this is weird and needs to be tested well
	} else {
		_, err = s.gcm.Encrypt(d.cryptbuffer[off:], byte(s.Security), s.framecounter, s.systemtitle, apdu)
	}
	s.framecounter++
	return d.cryptbuffer[:off+wl], err
}

func (d *dlmsal) decryptpacket(apdu []byte, ded bool) (ret []byte, err error) { // not checking expected fc, just receive everything
	if len(apdu) < 5 {
		return nil, fmt.Errorf("invalid apdu length")
	}
	s := d.settings
	fc := binary.BigEndian.Uint32(apdu[1:])
	if ded {
		if s.dedgcm == nil {
			return nil, fmt.Errorf("no dedicated gcm set for ciphering")
		}
		d.cryptbuffer, err = s.dedgcm.Decrypt(d.cryptbuffer, apdu[0], fc, d.aareres.SystemTitle, apdu[5:])
	} else {
		if s.gcm == nil {
			return nil, fmt.Errorf("no global gcm set for ciphering")
		}
		d.cryptbuffer, err = s.gcm.Decrypt(d.cryptbuffer, apdu[0], fc, d.aareres.SystemTitle, apdu[5:]) // set cryptbuffer just to be reused
	}
	if err != nil {
		return nil, err
	}
	return d.cryptbuffer, nil
}
