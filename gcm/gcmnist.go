package gcm

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"slices"
)

type gcmnist struct {
	nist         cipher.AEAD
	aad          []byte
	systemtitleC []byte
	systemtitleS []byte
	stoc         []byte
	ctos         []byte
	iv           [12]byte
}

// Decrypt implements Gcm.
func (g *gcmnist) Decrypt(ret []byte, sc byte, fc uint32, apdu []byte) ([]byte, error) {
	return g.Decrypt2(ret, sc, sc, fc, apdu)
}

// Encrypt implements Gcm.
func (g *gcmnist) Encrypt(ret []byte, sc byte, fc uint32, apdu []byte) ([]byte, error) {
	return g.encryptinternal(ret, sc, sc, fc, g.systemtitleC, apdu)
}

func (g *gcmnist) Setup(systemtitleS []byte, stoc []byte) (err error) {
	if len(systemtitleS) != 8 {
		return fmt.Errorf("systitle has to be 8 bytes long")
	}
	g.systemtitleS = slices.Clone(systemtitleS)
	g.stoc = slices.Clone(stoc)
	return nil
}

func (g *gcmnist) Hash(sc byte, fc uint32) ([]byte, error) {
	e, err := g.encryptinternal(nil, sc, sc, fc, g.systemtitleC, g.stoc)
	if err != nil {
		return nil, err
	}
	if len(e) < GCM_TAG_LENGTH { // definitely shouldnt happen
		return nil, fmt.Errorf("encrypted data too short")
	}
	return e[len(e)-GCM_TAG_LENGTH:], nil
}

func (g *gcmnist) Verify(sc byte, fc uint32, hash []byte) (bool, error) {
	e, err := g.encryptinternal(nil, sc, sc, fc, g.systemtitleS, g.ctos)
	if err != nil {
		return false, err
	}
	if len(e) < GCM_TAG_LENGTH { // definitely shouldnt happen
		return false, fmt.Errorf("encrypted data too short")
	}
	return bytes.Equal(e[len(e)-GCM_TAG_LENGTH:], hash), nil
}

// Decrypt2 implements Gcm.
func (g *gcmnist) Decrypt2(ret []byte, scControl byte, scContent byte, fc uint32, apdu []byte) ([]byte, error) {
	if scControl&0x80 != 0 {
		return nil, fmt.Errorf("compression not yet supported")
	}
	if scControl&0x40 != 0 {
		return nil, fmt.Errorf("only unicast keys are supported")
	}

	copy(g.iv[:], g.systemtitleS)
	binary.BigEndian.PutUint32(g.iv[8:], fc)
	switch scControl & 0x30 {
	case 0x10:
		if len(apdu) < GCM_TAG_LENGTH {
			return nil, fmt.Errorf("too short ciphered data, no space for tag")
		}
		aad := make([]byte, len(g.aad)+len(apdu)-GCM_TAG_LENGTH)
		aad[0] = scContent
		copy(aad[1:], g.aad[1:])
		copy(aad[len(g.aad):], apdu[:len(apdu)-GCM_TAG_LENGTH])
		_, err := g.nist.Open(nil, g.iv[:], apdu[:len(apdu)-GCM_TAG_LENGTH], aad)
		if err != nil {
			return nil, err
		}
		if cap(ret) >= len(apdu)-GCM_TAG_LENGTH {
			return append(ret[:0], apdu[:len(apdu)-GCM_TAG_LENGTH]...), nil
		}
		return slices.Clone(apdu[:len(apdu)-GCM_TAG_LENGTH]), nil // make a copy?
	case 0x30:
		if len(apdu) < GCM_TAG_LENGTH {
			return nil, fmt.Errorf("too short ciphered data, no space for tag")
		}
		g.aad[0] = scContent
		return g.nist.Open(ret[:0], g.iv[:], apdu, g.aad)
	default:
		return nil, fmt.Errorf("scControl %02X not supported", scControl)
	}
}

// Encrypt2 implements Gcm.
func (g *gcmnist) Encrypt2(ret []byte, scControl byte, scContent byte, fc uint32, apdu []byte) ([]byte, error) { // check systitle equality, but it really hurts sending it every packet
	return g.encryptinternal(ret, scControl, scContent, fc, g.systemtitleC, apdu)
}

func (g *gcmnist) encryptinternal(ret []byte, scControl byte, scContent byte, fc uint32, title []byte, apdu []byte) ([]byte, error) { // check systitle equality, but it really hurts sending it every packet
	if scControl&0x80 != 0 {
		return nil, fmt.Errorf("compression not yet supported")
	}
	if scControl&0x40 != 0 {
		return nil, fmt.Errorf("only unicast keys are supported")
	}

	copy(g.iv[:], title)
	binary.BigEndian.PutUint32(g.iv[8:], fc)
	switch scControl & 0x30 {
	case 0x10:
		aad := make([]byte, len(g.aad)+len(apdu))
		aad[0] = scContent
		copy(aad[1:], g.aad[1:])
		copy(aad[len(g.aad):], apdu)

		tag := g.nist.Seal(nil, g.iv[:], nil, aad)
		ret = append(ret[:0], apdu...)
		ret = append(ret, tag...)
		return ret, nil
	case 0x30:
		g.aad[0] = scContent
		ret = g.nist.Seal(ret[:0], g.iv[:], apdu, g.aad)
		return ret, nil
	default:
		return nil, fmt.Errorf("unsupported security control byte: %v", scControl)
	}
}

// GetDecryptorStream implements Gcm.
func (g *gcmnist) GetDecryptorStream(sc byte, fc uint32, apdu io.Reader) (io.Reader, error) {
	return g.GetDecryptorStream2(sc, sc, fc, apdu)
}

// GetDecryptorStream2 implements Gcm.
func (g *gcmnist) GetDecryptorStream2(scControl byte, scContent byte, fc uint32, apdu io.Reader) (io.Reader, error) {
	data, err := io.ReadAll(apdu) // not streamed at all in this case
	if err != nil {
		return nil, err
	}

	dec, err := g.Decrypt2(nil, scControl, scContent, fc, data)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(dec), nil
}

// GetEncryptLength implements Gcm.
func (g *gcmnist) GetEncryptLength(scControl byte, apdu []byte) (int, error) {
	switch scControl & 0x30 {
	case 0x10, 0x30:
		return len(apdu) + GCM_TAG_LENGTH, nil
	}
	return 0, fmt.Errorf("GetEncryptLength not implemented for scControl %02X", scControl)
}

// this is not thread safe at all
func NewGCMNist(ek []byte, ak []byte, systemtitlec []byte, ctos []byte) (Gcm, error) { // so only suite 0 right now, just proof of concept
	if len(ek) != 16 && len(ek) != 24 && len(ek) != 32 {
		return nil, fmt.Errorf("EK has to be 16, 24 or 32 bytes long")
	}
	if ak != nil && len(ak) != 16 && len(ak) != 24 && len(ak) != 32 {
		return nil, fmt.Errorf("AK has to be 16, 24 or 32 bytes long")
	}

	cr, err := aes.NewCipher(ek)
	if err != nil {
		return nil, err
	}
	enc, err := cipher.NewGCMWithTagSize(cr, GCM_TAG_LENGTH)
	if err != nil {
		return nil, err
	}

	ret := &gcmnist{
		nist: enc,
		aad:  make([]byte, 1+len(ak)),
	}
	ret.systemtitleC = slices.Clone(systemtitlec)
	ret.ctos = slices.Clone(ctos)
	copy(ret.aad[1:], ak)
	return ret, nil
}
