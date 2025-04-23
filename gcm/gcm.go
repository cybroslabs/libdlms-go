package gcm

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	AES_BLOCK_SIZE     = 16
	AES_BLOCK_SIZE_ROT = 4
	GCM_TAG_LENGTH     = 12
)

type GcmDirection byte

const (
	DirectionClientToServer = 0
	DirectionServerToClient = 1
)

type Gcm interface { // add length to the streamer interface? add systitle to constructor? not to copy it every damn time
	Setup(systemtitleS []byte, stoc []byte) error
	Hash(dir GcmDirection, sc byte, fc uint32) ([]byte, error)
	GetEncryptLength(scControl byte, apdu []byte) (int, error)
	// ret can be nil in case of not reused, ret and apdu can overlap, but exactly
	Encrypt(ret []byte, sc byte, fc uint32, apdu []byte) ([]byte, error)
	// ret can be nil in case of not reused
	Encrypt2(ret []byte, scControl byte, scContent byte, fc uint32, apdu []byte) ([]byte, error)
	// ret can be nil in case of not reused
	Decrypt(ret []byte, sc byte, fc uint32, apdu []byte) ([]byte, error)
	// ret can be nil in case of not reused
	Decrypt2(ret []byte, scControl byte, scContent byte, fc uint32, apdu []byte) ([]byte, error)
	GetDecryptorStream(sc byte, fc uint32, apdu io.Reader) (io.Reader, error)
	GetDecryptorStream2(scControl byte, scContent byte, fc uint32, apdu io.Reader) (io.Reader, error)
}

type gcm struct {
	ak     []byte
	tmp    [AES_BLOCK_SIZE * 4]byte
	hl     [16]uint64
	hh     [16]uint64
	aes    cipher.Block
	aad    []byte
	aadbuf [1 + 32]byte

	systemtitleC []byte
	systemtitleS []byte
	stoc         []byte
	ctos         []byte
}

// no constant arrays in go, but these numbers are black magic
var last4 = [...]uint64{0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0, 0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0}

func NewGCM(ek []byte, ak []byte, systemtitlec []byte, ctos []byte) (Gcm, error) {
	if len(ek) != 16 && len(ek) != 24 && len(ek) != 32 {
		return nil, fmt.Errorf("EK has to be 16, 24 or 32 bytes long")
	}
	if ak != nil && len(ak) != 16 && len(ak) != 24 && len(ak) != 32 {
		return nil, fmt.Errorf("AK has to be 16, 24 or 32 bytes long")
	}
	aa, err := aes.NewCipher(ek)
	if err != nil {
		return nil, err
	}
	if len(systemtitlec) != 8 {
		return nil, fmt.Errorf("systitle has to be 8 bytes long")
	}
	g := gcm{
		aes: aa,
	}
	g.systemtitleC = append([]byte{}, systemtitlec...)
	g.ctos = append([]byte{}, ctos...)
	copy(g.aadbuf[1:], ak)
	g.aad = g.aadbuf[:1+len(ak)]
	g.ak = g.aadbuf[1 : 1+len(ak)]
	g.make_tables()
	return &g, nil
}

// using first tmp slot, depends on zero initialized arrays
func (g *gcm) make_tables() {
	h := g.tmp[:AES_BLOCK_SIZE]
	g.aes.Encrypt(h, h) // rely on the fact that all bytes in gcm are zero

	vh := binary.BigEndian.Uint64(h)
	vl := binary.BigEndian.Uint64(h[8:])

	g.hl[8] = vl // 8 = 1000 corresponds to 1 in GF(2^128)
	g.hh[8] = vh

	for i := 4; i > 0; i >>= 1 {
		T := uint32(vl&1) * 0xe1000000
		vl = (vh << 63) | (vl >> 1)
		vh = (vh >> 1) ^ (uint64(T) << 32)
		g.hl[i] = vl
		g.hh[i] = vh
	}

	for i := 2; i < 16; i <<= 1 {
		vh = g.hh[i]
		vl = g.hl[i]
		for j := 1; j < i; j++ {
			g.hh[i+j] = vh ^ g.hh[j]
			g.hl[i+j] = vl ^ g.hl[j]
		}
	}
}

func (g *gcm) Setup(systemtitleS []byte, stoc []byte) error {
	if len(systemtitleS) != 8 {
		return fmt.Errorf("systitle has to be 8 bytes long")
	}
	g.systemtitleS = append([]byte{}, systemtitleS...)
	g.stoc = append([]byte{}, stoc...)
	return nil
}

func (g *gcm) Hash(dir GcmDirection, sc byte, fc uint32) ([]byte, error) {
	switch dir {
	case DirectionClientToServer:
		e, err := g.encryptinternal(nil, sc, sc, fc, g.systemtitleC, g.stoc)
		if err != nil {
			return nil, err
		}
		if len(e) < GCM_TAG_LENGTH { // definitely shouldnt happen
			return nil, fmt.Errorf("encrypted data too short")
		}
		return e[len(e)-GCM_TAG_LENGTH:], nil
	case DirectionServerToClient:
		e, err := g.encryptinternal(nil, sc, sc, fc, g.systemtitleS, g.ctos)
		if err != nil {
			return nil, err
		}
		if len(e) < GCM_TAG_LENGTH { // definitely shouldnt happen
			return nil, fmt.Errorf("encrypted data too short")
		}
		return e[len(e)-GCM_TAG_LENGTH:], nil
	default:
		return nil, fmt.Errorf("invalid direction")
	}
}

func (g *gcm) Decrypt(ret []byte, sc byte, fc uint32, apdu []byte) ([]byte, error) {
	return g.Decrypt2(ret, sc, sc, fc, apdu)
}

func (g *gcm) Decrypt2(ret []byte, scControl byte, scContent byte, fc uint32, apdu []byte) ([]byte, error) {
	if apdu == nil {
		return nil, fmt.Errorf("apdu is nil")
	}
	iv := g.tmp[:AES_BLOCK_SIZE] // a bit hardcore
	copy(iv, g.systemtitleS)
	iv[8] = byte(fc >> 24)
	iv[9] = byte(fc >> 16)
	iv[10] = byte(fc >> 8)
	iv[11] = byte(fc)
	iv[12] = 0 // last four bytes are still the same
	iv[13] = 0
	iv[14] = 0
	iv[15] = 1

	switch scControl & 0xf0 {
	case 0x10:
		{
			if len(apdu) < GCM_TAG_LENGTH {
				return nil, fmt.Errorf("too short ciphered data, no space for tag")
			}
			aad := make([]byte, 1+len(g.ak)+len(apdu)-GCM_TAG_LENGTH)
			aad[0] = scContent
			copy(aad[1:], g.ak)
			copy(aad[1+len(g.ak):], apdu[:len(apdu)-GCM_TAG_LENGTH])

			err := g.aes_gcm_ad(nil, aad, nil, apdu[len(apdu)-GCM_TAG_LENGTH:])
			if err != nil {
				return nil, err
			}
			wl := len(apdu) - GCM_TAG_LENGTH
			if ret != nil && cap(ret) >= wl {
				ret = ret[:wl]
			} else {
				ret = make([]byte, wl)
			}
			copy(ret, apdu[:wl])
			return ret, nil
		}
	case 0x20:
		{
			wl := len(apdu)
			if ret != nil && cap(ret) >= wl {
				ret = ret[:wl]
			} else {
				ret = make([]byte, wl)
			}
			err := g.aes_gcm_ad(apdu, nil, ret, nil)
			return ret, err
		}
	case 0x30:
		{
			if len(apdu) < GCM_TAG_LENGTH {
				return nil, fmt.Errorf("too short ciphered data, no space for tag")
			}
			g.aad[0] = scContent
			wl := len(apdu) - GCM_TAG_LENGTH
			if ret != nil && cap(ret) >= wl {
				ret = ret[:wl]
			} else {
				ret = make([]byte, wl)
			}
			err := g.aes_gcm_ad(apdu[:len(apdu)-GCM_TAG_LENGTH], g.aad, ret, apdu[len(apdu)-GCM_TAG_LENGTH:])
			return ret, err
		}
	}
	return nil, fmt.Errorf("unsupported security control byte: %v", scControl)
}

func (g *gcm) GetDecryptorStream(sc byte, fc uint32, apdu io.Reader) (io.Reader, error) {
	return g.GetDecryptorStream2(sc, sc, fc, apdu)
}

func (g *gcm) GetDecryptorStream2(scControl byte, scContent byte, fc uint32, apdu io.Reader) (io.Reader, error) {
	if apdu == nil {
		return nil, fmt.Errorf("apdu is nil")
	}
	iv := g.tmp[:AES_BLOCK_SIZE] // a bit hardcore
	copy(iv, g.systemtitleS)
	iv[8] = byte(fc >> 24)
	iv[9] = byte(fc >> 16)
	iv[10] = byte(fc >> 8)
	iv[11] = byte(fc)
	iv[12] = 0 // last four bytes are still the same
	iv[13] = 0
	iv[14] = 0
	iv[15] = 1

	switch scControl & 0xf0 {
	case 0x10:
		return newgcmdecstream10(g, scContent, apdu), nil
	case 0x20:
		return newgcmdecstream20(g, apdu), nil
	case 0x30:
		return newgcmdecstream30(g, scContent, apdu), nil
	}
	return nil, fmt.Errorf("unsupported security control byte: %v", scControl)
}

func (g *gcm) Encrypt(ret []byte, sc byte, fc uint32, apdu []byte) ([]byte, error) {
	return g.encryptinternal(ret, sc, sc, fc, g.systemtitleC, apdu)
}

func (g *gcm) Encrypt2(ret []byte, scControl byte, scContent byte, fc uint32, apdu []byte) ([]byte, error) {
	return g.encryptinternal(ret, scControl, scContent, fc, g.systemtitleC, apdu)
}

func (g *gcm) encryptinternal(ret []byte, scControl byte, scContent byte, fc uint32, systemtitle []byte, apdu []byte) ([]byte, error) {
	if apdu == nil {
		return nil, fmt.Errorf("apdu is nil")
	}
	iv := g.tmp[:AES_BLOCK_SIZE] // a bit hardcore
	copy(iv, systemtitle)
	iv[8] = byte(fc >> 24)
	iv[9] = byte(fc >> 16)
	iv[10] = byte(fc >> 8)
	iv[11] = byte(fc)
	iv[12] = 0 // last four bytes are still the same
	iv[13] = 0
	iv[14] = 0
	iv[15] = 1

	wl, err := g.GetEncryptLength(scControl, apdu)
	if err != nil {
		return nil, err
	}
	switch scControl & 0xf0 {
	case 0x10:
		{
			aad := make([]byte, 1+len(g.ak)+len(apdu))
			aad[0] = scContent
			copy(aad[1:], g.ak)
			copy(aad[1+len(g.ak):], apdu)

			if cap(ret) >= wl {
				ret = ret[:wl]
			} else {
				ret = make([]byte, wl)
			}
			g.aes_gcm_ae(nil, aad, nil, ret[len(apdu):])
			copy(ret, apdu)
			return ret, nil
		}
	case 0x20:
		{
			if ret != nil && cap(ret) >= wl {
				ret = ret[:wl]
			} else {
				ret = make([]byte, wl)
			}
			g.aes_gcm_ae(apdu, nil, ret, nil)
			return ret, nil
		}
	case 0x30:
		{
			g.aad[0] = scContent
			if cap(ret) >= wl {
				ret = ret[:wl]
			} else {
				ret = make([]byte, wl)
			}
			g.aes_gcm_ae(apdu, g.aad, ret[:len(apdu)], ret[len(apdu):])
			return ret, nil
		}
	}
	return nil, fmt.Errorf("unsupported security control byte: %v", scControl)
}

func (g *gcm) GetEncryptLength(scControl byte, apdu []byte) (int, error) {
	switch scControl & 0xf0 {
	case 0x10:
		return len(apdu) + GCM_TAG_LENGTH, nil
	case 0x20:
		return len(apdu), nil
	case 0x30:
		return len(apdu) + GCM_TAG_LENGTH, nil
	}
	return 0, fmt.Errorf("unsupported security control byte: %v", scControl)
}

// x is not changed, dst is changed, needs 2nd tmp slot
func (g *gcm) ghash(x []byte, dst []byte) {
	tmp := g.tmp[AES_BLOCK_SIZE<<1 : AES_BLOCK_SIZE*3]
	m := len(x) >> AES_BLOCK_SIZE_ROT
	for i := 0; i < m; i++ {
		xor_block2(tmp, dst, x)
		x = x[AES_BLOCK_SIZE:]
		g.gf_mult(tmp, dst)
	}

	if len(x) != 0 {
		copy(tmp, x)
		os_memzero(tmp[len(x):])
		xor_block(dst, tmp)
		g.gf_mult(dst, tmp)
		copy(dst, tmp)
	}
}

// x is not changed, dst is changed, this is really black magic...
func (g *gcm) gf_mult(x []byte, dst []byte) {
	lo := x[15] & 0x0f
	hi := x[15] >> 4

	zh := g.hh[lo]
	zl := g.hl[lo]

	rem := zl & 0x0f
	zl = ((zh << 60) | (zl >> 4)) ^ g.hl[hi]
	zh = (zh >> 4) ^ (last4[rem] << 48) ^ g.hh[hi]

	for i := 14; i >= 0; i-- {
		lo = x[i] & 0x0f
		hi = x[i] >> 4

		rem = zl & 0x0f
		zl = ((zh << 60) | (zl >> 4)) ^ g.hl[lo]
		zh = (zh >> 4) ^ (last4[rem] << 48) ^ g.hh[lo]
		rem = zl & 0x0f
		zl = ((zh << 60) | (zl >> 4)) ^ g.hl[hi]
		zh = (zh >> 4) ^ (last4[rem] << 48) ^ g.hh[hi]
	}
	binary.BigEndian.PutUint64(dst, zh)
	binary.BigEndian.PutUint64(dst[8:], zl)
}

func inc32(block []byte) {
	ctr := block[AES_BLOCK_SIZE-4:]
	binary.BigEndian.PutUint32(ctr, binary.BigEndian.Uint32(ctr)+1)
}

func set32(block []byte, val uint32) {
	binary.BigEndian.PutUint32(block[AES_BLOCK_SIZE-4:], val)
}

// dst is changed, src is not
func xor_block(dst []byte, src []byte) {
	// for i := 0; i < AES_BLOCK_SIZE; i++ {
	// 	dst[i] ^= src[i]
	// }
	// subtle.XORBytes(dst, dst, src) // this must not overlap and doesnt help much
	binary.NativeEndian.PutUint64(dst, binary.NativeEndian.Uint64(dst)^binary.NativeEndian.Uint64(src))
	binary.NativeEndian.PutUint64(dst[8:], binary.NativeEndian.Uint64(dst[8:])^binary.NativeEndian.Uint64(src[8:]))
}

func xor_block2(dst []byte, src1 []byte, src2 []byte) {
	// for i := 0; i < AES_BLOCK_SIZE; i++ {
	// 	dst[i] ^= src[i]
	// }
	// subtle.XORBytes(dst, dst, src) // this must not overlap and doesnt help much
	binary.NativeEndian.PutUint64(dst, binary.NativeEndian.Uint64(src1)^binary.NativeEndian.Uint64(src2))
	binary.NativeEndian.PutUint64(dst[8:], binary.NativeEndian.Uint64(src1[8:])^binary.NativeEndian.Uint64(src2[8:]))
}

func os_memzero(dst []byte) {
	for i := 0; i < len(dst); i++ {
		dst[i] = 0
	}
}

// icb is not changed, x is not changed, dst is changed
func (g *gcm) aes_gctr(icb []byte, x []byte, dst []byte) {
	g.aes.Encrypt(dst, icb)
	xor_block(dst, x)
}

// J0 is changed, S is changed, plain and crypt are changed according to encrypt, aad is not changed, needs 2,3 tmp slot
func (g *gcm) aes_gcm_gctr_ghash(J0 []byte, S []byte, plain []byte, crypt []byte, aad []byte, encrypt bool) {
	os_memzero(S)
	g.ghash(aad, S)
	if len(plain) != 0 { // fortunately in case of reading whole aad from plain for hash, then this condition is always false as plain is already read
		inc32(J0)
		if encrypt {
			g.aes_gctr_ghash(J0, plain, crypt, S)
		} else {
			g.aes_gctr_ghash_de(J0, crypt, plain, S)
		}
	}

	len_buf := g.tmp[AES_BLOCK_SIZE*3 : AES_BLOCK_SIZE<<2]
	binary.BigEndian.PutUint64(len_buf, uint64(len(aad))<<3)
	binary.BigEndian.PutUint64(len_buf[8:], uint64(len(crypt))<<3)
	g.ghash(len_buf, S)
}

// J0 content is incremented, x is not changed, dst is changed, dsts is changed, needs 2nd tmp slot
func (g *gcm) aes_gctr_ghash(J0 []byte, x []byte, dst []byte, dsthash []byte) {
	tmp := g.tmp[AES_BLOCK_SIZE<<1 : AES_BLOCK_SIZE*3]
	n := len(x) >> AES_BLOCK_SIZE_ROT
	for i := 0; i < n; i++ { // this part should be streamed
		g.aes.Encrypt(tmp, J0)
		xor_block2(dst, tmp, x)
		xor_block2(tmp, dsthash, dst)
		g.gf_mult(tmp, dsthash)

		x = x[AES_BLOCK_SIZE:]
		dst = dst[AES_BLOCK_SIZE:]
		inc32(J0)
	}

	if len(x) != 0 {
		g.aes.Encrypt(tmp, J0)
		for i := 0; i < len(x); i++ {
			dst[i] = x[i] ^ tmp[i]
			dsthash[i] ^= dst[i]
		}

		g.gf_mult(dsthash, tmp)
		copy(dsthash, tmp)
	}
}

// J0 content is incremented, x is not changed, dst is changed, dsts is changed, needs 2nd tmp slot
func (g *gcm) aes_gctr_ghash_de(J0 []byte, x []byte, dst []byte, dsthash []byte) {
	tmp := g.tmp[AES_BLOCK_SIZE<<1 : AES_BLOCK_SIZE*3]
	n := len(x) >> AES_BLOCK_SIZE_ROT
	for i := 0; i < n; i++ { // this part should be streamed
		g.aes.Encrypt(tmp, J0)
		xor_block2(dst, tmp, x)
		xor_block2(tmp, dsthash, x)
		g.gf_mult(tmp, dsthash)

		x = x[AES_BLOCK_SIZE:]
		dst = dst[AES_BLOCK_SIZE:]
		inc32(J0)
	}

	if len(x) != 0 {
		g.aes.Encrypt(tmp, J0)
		for i := 0; i < len(x); i++ {
			dst[i] = x[i] ^ tmp[i]
			dsthash[i] ^= x[i]
		}

		g.gf_mult(dsthash, tmp)
		copy(dsthash, tmp)
	}
}

// crypt is output, needs 0,1,2,3 tmp slots
func (g *gcm) aes_gcm_ae(plain []byte, aad []byte, crypt []byte, tag []byte) {
	J0 := g.tmp[:AES_BLOCK_SIZE] // hardcore, initialized at the start
	S := g.tmp[AES_BLOCK_SIZE : AES_BLOCK_SIZE<<1]

	g.aes_gcm_gctr_ghash(J0, S, plain, crypt, aad, true)

	if tag != nil {
		set32(J0, 1)
		T := g.tmp[AES_BLOCK_SIZE<<1 : AES_BLOCK_SIZE*3]
		g.aes_gctr(J0, S, T)
		copy(tag, T)
	}
}

// plain is output, needs 0,1,2,3 tmp slots
func (g *gcm) aes_gcm_ad(crypt []byte, aad []byte, plain []byte, tag []byte) error {
	J0 := g.tmp[:AES_BLOCK_SIZE] // hardcore, initialized at the start
	S := g.tmp[AES_BLOCK_SIZE : AES_BLOCK_SIZE<<1]

	g.aes_gcm_gctr_ghash(J0, S, plain, crypt, aad, false)

	set32(J0, 1)
	T := g.tmp[AES_BLOCK_SIZE<<1 : AES_BLOCK_SIZE*3]
	g.aes_gctr(J0, S, T)

	if tag != nil && !bytes.Equal(tag, T[:len(tag)]) {
		return fmt.Errorf("tag mismatch")
	}
	return nil
}
