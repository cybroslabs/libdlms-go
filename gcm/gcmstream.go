package gcm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/cybroslabs/libdlms-go/base"
)

type gcmdecstream10 struct { // no tag/hash, no aad, decrypt only
	master      *gcm
	apdu        io.Reader
	block       [AES_BLOCK_SIZE << 2]byte // space for largest possible ak + one byte for sc, so this, but still at least four block to limit returned data
	blockoffer  int
	blockread   int
	blockwrite  int
	blockoffset int
	aadsize     int
	J0          []byte
	S           []byte
	ineof       bool
}

func newgcmdecstream10(master *gcm, sc byte, src io.Reader) io.Reader {
	ret := gcmdecstream10{master: master, apdu: src, blockoffset: 0, blockread: 0, blockoffer: 0, ineof: false}
	ret.J0 = master.tmp[:AES_BLOCK_SIZE] // yes, this is reusable hardcore
	ret.S = master.tmp[AES_BLOCK_SIZE : AES_BLOCK_SIZE<<1]
	ret.block[0] = sc
	ret.blockwrite = 1 + copy(ret.block[1:], master.ak)
	ret.aadsize = ret.blockwrite
	os_memzero(ret.S)
	return &ret
}

func (g *gcmdecstream10) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, base.ErrNothingToRead
	}

	if g.blockoffset < g.blockoffer { // decrypted block, return what is available
		n = g.blockoffer - g.blockoffset
		n = copy(p, g.block[g.blockoffset:g.blockoffset+n])
		g.blockoffset += n
		return n, nil
	}
	// whole block read, descrypt another one
	if g.ineof {
		return 0, io.EOF
	}

	if g.blockwrite == 0 { // normal operation here
		copy(g.block[:], g.block[g.blockoffer:g.blockread])
		n, err = io.ReadFull(g.apdu, g.block[g.blockread-g.blockoffer:])
		if err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
				g.ineof = true
			} else { // dont process anything more
				return 0, err
			}
		}
		g.aadsize += n
		n += g.blockread - g.blockoffer
	} else { // first round, but handle whole sc+ak + maybe something
		n, err = io.ReadFull(g.apdu, g.block[g.blockwrite:])
		if err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
				if n < GCM_TAG_LENGTH {
					return 0, fmt.Errorf("gcm: too short data, no space for tag")
				}
				g.ineof = true
			} else {
				return 0, err
			}
		}
		g.aadsize += n
		n += g.blockwrite
	}

	// blockread is always avail bytes to return and after that is always tag bytes, here is either aes block size, on something less in case of eof
	m := g.master
	tmp := m.tmp[AES_BLOCK_SIZE<<1 : AES_BLOCK_SIZE*3]
	// n contains bytes valid in block, so i have to hash everything

	if g.ineof { // check tag here
		bl := (n - GCM_TAG_LENGTH) >> AES_BLOCK_SIZE_ROT // having there tag for sure already
		bb := g.block[:n-GCM_TAG_LENGTH]
		for range bl {
			xor_block2(tmp, g.S, bb)
			m.gf_mult(tmp, g.S)
			bb = bb[AES_BLOCK_SIZE:]
		}
		if len(bb) != 0 {
			copy(tmp, bb) // could avoid this copy and memzero, but whatever now
			os_memzero(tmp[len(bb):])
			xor_block(g.S, tmp)
			m.gf_mult(g.S, tmp)
			copy(g.S, tmp) // fuck copy
		}
		binary.BigEndian.PutUint64(tmp, uint64(g.aadsize-GCM_TAG_LENGTH)<<3)
		binary.BigEndian.PutUint64(tmp[8:], 0)
		xor_block(g.S, tmp)
		m.gf_mult(g.S, tmp)

		m.aes.Encrypt(g.S, g.J0)
		xor_block(g.S, tmp) // compare resulted S with received tag
		if !bytes.Equal(g.S[:GCM_TAG_LENGTH], g.block[n-GCM_TAG_LENGTH:n]) {
			return 0, fmt.Errorf("tag mismatch")
		}
		g.blockoffer = n - GCM_TAG_LENGTH
	} else {
		bl := (len(g.block) >> AES_BLOCK_SIZE_ROT) - 1 // keep last block in the buffer till some eof here, always full block read
		bb := g.block[:]
		for range bl {
			xor_block2(tmp, g.S, bb)
			m.gf_mult(tmp, g.S)
			bb = bb[AES_BLOCK_SIZE:]
		}
		g.blockoffer = bl << AES_BLOCK_SIZE_ROT
		g.blockread = len(g.block)
	}
	g.blockoffset = g.blockwrite
	g.blockwrite = 0
	return g.Read(p)
}

type gcmdecstream20 struct { // no tag/hash, no aad, decrypt only
	master      *gcm
	apdu        io.Reader
	block       [AES_BLOCK_SIZE]byte // can be more than one block here, maybe
	blockread   int
	blockoffset int
	J0          []byte
	ineof       bool
}

func newgcmdecstream20(master *gcm, src io.Reader) io.Reader {
	ret := gcmdecstream20{master: master, apdu: src, blockoffset: 0, blockread: 0, ineof: false}
	ret.J0 = master.tmp[:AES_BLOCK_SIZE] // yes, this is reusable hardcore
	inc32(ret.J0)
	return &ret
}

func (g *gcmdecstream20) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, base.ErrNothingToRead
	}

	if g.blockoffset < g.blockread { // decrypted block, return what is available
		n = g.blockread - g.blockoffset
		n = copy(p, g.block[g.blockoffset:g.blockoffset+n])
		g.blockoffset += n
		return n, nil
	}
	// whole block read, descrypt another one
	if g.ineof {
		return 0, io.EOF
	}

	g.blockread, err = io.ReadFull(g.apdu, g.block[:])
	g.blockoffset = 0
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			g.ineof = true
			if g.blockread == 0 {
				return 0, io.EOF
			}
		} else { // dont process anything more
			return 0, err
		}
	}

	m := g.master
	tmp := m.tmp[AES_BLOCK_SIZE<<1 : AES_BLOCK_SIZE*3]
	m.aes.Encrypt(tmp, g.J0)
	xor_block(g.block[:], tmp) // wasting xor and inc in case of the latest block, but who cares
	inc32(g.J0)

	return g.Read(p)
}

type gcmdecstream30 struct { // no tag/hash, no aad, decrypt only
	master      *gcm
	apdu        io.Reader
	block       [AES_BLOCK_SIZE << 2]byte // at least 4 blocks for most large ak, so aad
	blockread   int
	blockoffset int
	blockoffer  int
	cryptsize   int
	J0          []byte
	S           []byte
	ineof       bool
}

func newgcmdecstream30(master *gcm, sc byte, src io.Reader) io.Reader {
	ret := gcmdecstream30{master: master, apdu: src, blockoffset: 0, blockread: 0, cryptsize: 0, ineof: false}
	ret.J0 = master.tmp[:AES_BLOCK_SIZE] // yes, this is reusable hardcore
	inc32(ret.J0)
	ret.S = master.tmp[AES_BLOCK_SIZE : AES_BLOCK_SIZE<<1]
	master.aad[0] = sc
	os_memzero(ret.S)
	master.ghash(master.aad, ret.S)
	return &ret
}

func (g *gcmdecstream30) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, base.ErrNothingToRead
	}

	if g.blockoffset < g.blockoffer { // decrypted block, return what is available
		n = g.blockoffer - g.blockoffset
		n = copy(p, g.block[g.blockoffset:g.blockoffset+n])
		g.blockoffset += n
		return n, nil
	}
	// whole block read, descrypt another one
	if g.ineof {
		return 0, io.EOF
	}

	copy(g.block[:], g.block[g.blockoffer:g.blockread])
	n, err = io.ReadFull(g.apdu, g.block[g.blockread-g.blockoffer:])
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			g.ineof = true
		} else { // dont process anything more
			return 0, err
		}
	}
	g.cryptsize += n
	n += g.blockread - g.blockoffer

	// blockread is always avail bytes to return and after that is always tag bytes, here is either aes block size, on something less in case of eof
	m := g.master
	tmp := m.tmp[AES_BLOCK_SIZE<<1 : AES_BLOCK_SIZE*3]
	// n contains bytes valid in block, so i have to hash everything

	if g.ineof { // check tag here
		bl := (n - GCM_TAG_LENGTH) >> AES_BLOCK_SIZE_ROT // having there tag for sure already
		bb := g.block[:n-GCM_TAG_LENGTH]
		for i := 0; i < bl; i++ {
			xor_block2(tmp, bb, g.S)
			m.gf_mult(tmp, g.S)
			m.aes.Encrypt(tmp, g.J0)
			xor_block(bb, tmp)
			inc32(g.J0)
			bb = bb[AES_BLOCK_SIZE:]
		}
		if len(bb) != 0 {
			m.aes.Encrypt(tmp, g.J0)
			for i := 0; i < len(bb); i++ {
				g.S[i] ^= bb[i]
				bb[i] ^= tmp[i]
			}
			m.gf_mult(g.S, tmp)
			copy(g.S, tmp)
		}
		binary.BigEndian.PutUint64(tmp, uint64(len(m.aad))<<3)
		binary.BigEndian.PutUint64(tmp[8:], uint64(g.cryptsize-GCM_TAG_LENGTH)<<3)
		xor_block(tmp, g.S)
		m.gf_mult(tmp, g.S)

		set32(g.J0, 1)
		m.aes.Encrypt(tmp, g.J0)
		xor_block(g.S, tmp) // compare resulted S with received tag
		if !bytes.Equal(g.S[:GCM_TAG_LENGTH], g.block[n-GCM_TAG_LENGTH:n]) {
			return 0, fmt.Errorf("tag mismatch")
		}
		g.blockoffer = n - GCM_TAG_LENGTH
	} else {
		bl := (len(g.block) >> AES_BLOCK_SIZE_ROT) - 1 // keep last block in the buffer till some eof here, always full block read
		bb := g.block[:]
		for i := 0; i < bl; i++ {
			xor_block2(tmp, bb, g.S)
			m.gf_mult(tmp, g.S)
			m.aes.Encrypt(tmp, g.J0)
			xor_block(bb, tmp)
			inc32(g.J0)
			bb = bb[AES_BLOCK_SIZE:]
		}
		g.blockoffer = bl << AES_BLOCK_SIZE_ROT
		g.blockread = len(g.block)
	}
	g.blockoffset = 0
	return g.Read(p)
}
