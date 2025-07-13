package v44

import (
	"bytes"
)

type v44compress struct { // dictionary, root, etc
	history   []byte
	output    []byte
	bitoffset byte
	tmp       byte
	c2        int
	c2n       int16
	c5        int
	lastcode  int16
	sentcode  bool

	root  [256]int16 // root node of the dictionary tree
	nodes []v44node
}

func (v *v44compress) emitbit(b byte) {
	if v.bitoffset == 8 {
		v.output = append(v.output, v.tmp)
		v.bitoffset = 0
		v.tmp = 0
	}
	v.tmp |= b << v.bitoffset
	v.bitoffset++
}

func (v *v44compress) emitcontrolcode(c int16) {
	v.sentcode = false
	v.emitbit(1)
	for range v.c2 {
		v.emitbit(byte(c & 1))
		c >>= 1
	}
}

func (v *v44compress) emitcodeword(codeword int16) {
	for codeword >= v.c2n { // stepup for codewords, no limit here as max codeword is already limited, so this ends with 11 at maximum
		v.emitcontrolcode(2)
		v.c2++
		v.c2n <<= 1
	}
	v.emitcontrolcode(codeword)
	v.sentcode = true
}

func (v *v44compress) emitstringext(l int16) {
	v.sentcode = false
	v.emitbit(0)
	v.emitbit(1)
	if l == 1 {
		v.emitbit(1)
		return
	}
	if l > 12 {
		v.emitbit(0)
		v.emitbit(0)
		v.emitbit(0)
		v.emitbit(1)
		for range 8 {
			v.emitbit(byte(l & 1))
			l >>= 1
		}
		return
	}
	v.emitbit(0)
	switch l {
	case 2:
		v.emitbit(1)
		v.emitbit(0)
	case 3:
		v.emitbit(0)
		v.emitbit(1)
	case 4:
		v.emitbit(1)
		v.emitbit(1)
	default:
		v.emitbit(0)
		v.emitbit(0)
		v.emitbit(0)
		l -= 5
		for range 3 {
			v.emitbit(byte(l & 1))
			l >>= 1
		}
	}
}

func (v *v44compress) emitordinal(b byte) {
	if v.c5 == 8 { // just emit that thing
		v.emitbit(0)
		if v.sentcode {
			v.emitbit(0)
			v.sentcode = false
		}
		for range 8 {
			v.emitbit(b & 1)
			b >>= 1
		}
		return
	}
	if b&0x80 != 0 { // stepup for c5
		v.emitcontrolcode(2)
		v.c5 = 8
		v.emitordinal(b)
		return
	}
	// emit only 7-bit value of that thing
	v.emitbit(0)
	if v.sentcode {
		v.emitbit(0)
		v.sentcode = false
	}
	for range 7 {
		v.emitbit(b & 1)
		b >>= 1
	}
}

func (v *v44compress) compress() {
	slen := int16(0)
	off := int16(0)
	stringext := int16(0)
M:
	for ii := int32(0); ii < int32(len(v.history)); ii++ {
		b := v.history[ii]
		// check if we are not solving string extension
		if stringext != 0 {
			se := v.nodes[stringext]
			if slen < maxstring && b == v.history[se.pos+int32(se.length)+int32(off)] { // keep extensing
				off++
				slen++
				continue M
			}
			// create node and emit string extenstion
			if off > 0 { // having something to extend, so do it
				v.emitstringext(off)
				if v.lastcode < maxcodeword {
					v.nodes = append(v.nodes, v44node{
						pos:    ii - int32(off),
						length: off,
						side:   se.down,
					})
					v.nodes[stringext].down = v.lastcode
					v.lastcode++
				}
			} else if slen < maxstring && v.lastcode < maxcodeword { // single character substring
				v.nodes = append(v.nodes, v44node{
					pos:    ii,
					length: 1,
					side:   se.down,
				})
				v.nodes[stringext].down = v.lastcode
				v.lastcode++
			}
			stringext = 0
			off = 0
		}

		// try to find the longest match
		sid := v.root[b]
		// find the longest match, just linear search, try first level, if it is not found, then double ordinal should be trasnferred
		rem := int32(len(v.history)) - ii - 1
		lastmatch := int16(0)
		slen = 1
		for sid != 0 {
			max := int16(0)
			maxl := int16(0)
			for sid != 0 {
				cn := v.nodes[sid]
				// try to match whole thing, so cn.length bytes, no sorting, just linear search, very suboptimal, but in this small scale it could work
				if rem >= int32(cn.length) && cn.length > maxl && bytes.Equal(v.history[cn.pos:cn.pos+int32(cn.length)], v.history[ii+int32(slen):ii+int32(slen)+int32(cn.length)]) {
					max = sid
					maxl = cn.length
				}
				sid = cn.side
			}
			if max != 0 { // found something
				cn := v.nodes[max]
				slen += cn.length
				rem -= int32(cn.length)
				lastmatch = max
				sid = cn.down
			}
		}
		if lastmatch != 0 { // found something
			v.emitcodeword(lastmatch)
			ii += int32(slen) - 1
			stringext = lastmatch
			continue M
		}

		// no match start from scratch
		v.emitordinal(b)
		if v.lastcode < maxcodeword {
			v.nodes = append(v.nodes, v44node{
				pos:    ii + 1,
				length: 1,
				side:   v.root[b],
			})
			v.root[b] = v.lastcode
			v.lastcode++
		}
	}

	// handle possible string extension state
	if off > 0 {
		v.emitstringext(off)
	}
}

func (v *v44compress) flush() {
	v.emitcontrolcode(1)
	v.output = append(v.output, v.tmp)
}

func Compress(dst []byte, input []byte) []byte {
	ctx := v44compress{
		c2:        6,
		c2n:       64,
		c5:        7,
		bitoffset: 0,
		lastcode:  4,
		history:   input,
		sentcode:  false,
		nodes:     make([]v44node, 4),
		output:    dst,
	}
	ctx.compress()
	ctx.flush()
	return ctx.output
}
