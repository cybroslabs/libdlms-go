package dlmsal

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/cybroslabs/libdlms-go/base"
)

// tag is common byte in this case, could be also 9 for octetstring and so on, it encodes also length
func (d *dlmsal) encryptpacket(tag byte, apdu []byte, ded bool) ([]byte, error) {
	usegeneral := tag == byte(base.TagGeneralGloCiphering) || tag == byte(base.TagGeneralDedCiphering)
	s := d.settings
	// lets panic in case of nil gcm -> program fault shouldnt happen at all
	wl, _ := s.cipher.GetEncryptLength(byte(s.Security), apdu)
	if cap(d.cryptbuffer) < wl+20 { // 11 bytes for header and 9 for possible general glo/ded ciphering encoded systemtitle, this is madness, should be set anyway that title
		d.cryptbuffer = make([]byte, wl+20)
	} else {
		d.cryptbuffer = d.cryptbuffer[:cap(d.cryptbuffer)]
	}
	d.cryptbuffer[0] = tag
	off := 1
	if usegeneral {
		if len(s.clientsystemtitle) != 8 { // this seems to be so hardcoded
			return nil, fmt.Errorf("invalid client system title length %d", len(s.clientsystemtitle))
		}
		d.cryptbuffer[1] = 8
		copy(d.cryptbuffer[2:], s.clientsystemtitle)
		off += 9
	}
	off += encodelength2(d.cryptbuffer[off:], uint(wl+5))
	d.cryptbuffer[off] = byte(s.Security)
	off++
	binary.BigEndian.PutUint32(d.cryptbuffer[off:], s.framecounter)
	off += 4

	// in this state, encrypt cant remake input reusable buffer
	var err error
	if ded {
		_, err = s.dedcipher.Encrypt(d.cryptbuffer[off:], byte(s.Security), s.framecounter, apdu) // this is weird and needs to be tested well
	} else {
		_, err = s.cipher.Encrypt(d.cryptbuffer[off:], byte(s.Security), s.framecounter, apdu)
	}
	s.framecounter++
	return d.cryptbuffer[:off+wl], err
}

func (d *dlmsal) decryptpacket(apdu []byte, ded bool) ([]byte, error) { // not checking expected fc, just receive everything, todo handle general ciphering
	if len(apdu) < 5 {
		return nil, fmt.Errorf("invalid apdu length")
	}

	// check tag inside first byte and behave accordingly
	usegeneral := apdu[0] == byte(base.TagGeneralGloCiphering) || apdu[0] == byte(base.TagGeneralDedCiphering)
	s := d.settings
	enc := bytes.NewBuffer(apdu[1:])
	off := 1
	if usegeneral {
		sl, c, err := decodelength(enc, &d.tmpbuffer)
		if err != nil {
			return nil, err
		}
		off += c
		if off+int(sl) > len(apdu) {
			return nil, fmt.Errorf("invalid apdu length, no space for systemtitle")
		}
		var tmptitle []byte
		if len(d.tmpbuffer) >= int(sl) {
			tmptitle = d.tmpbuffer[:sl]
		} else {
			tmptitle = make([]byte, sl)
		}
		_, err = io.ReadFull(enc, tmptitle)
		if err != nil {
			return nil, fmt.Errorf("unable to read system title: %w", err)
		}
		off += int(sl)
	}

	sl, c, err := decodelength(enc, &d.tmpbuffer)
	if err != nil {
		return nil, fmt.Errorf("unable to decode length: %w", err)
	}
	off += c
	apdu = apdu[off:]
	if len(apdu) < int(sl) || len(apdu) < 5 {
		return nil, fmt.Errorf("invalid apdu length, no space for ciphered data")
	}

	fc := binary.BigEndian.Uint32(apdu[1:])
	if ded {
		if s.dedcipher == nil {
			return nil, fmt.Errorf("no dedicated gcm set for ciphering")
		}
		d.cryptbuffer, err = s.dedcipher.Decrypt(d.cryptbuffer, apdu[0], fc, apdu[5:])
	} else {
		if s.cipher == nil {
			return nil, fmt.Errorf("no global gcm set for ciphering")
		}
		d.cryptbuffer, err = s.cipher.Decrypt(d.cryptbuffer, apdu[0], fc, apdu[5:]) // set cryptbuffer just to be reused
	}
	if err != nil {
		return nil, err
	}
	return d.cryptbuffer, nil
}
