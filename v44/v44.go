package v44

import (
	"bytes"
	"fmt"
)

const (
	maxcodeword = 1525 // it should be constant according to itu
	maxstring   = 255
)

type v44ctx struct { // dictionary, root, etc
	history   []byte
	input     []byte
	inputbits int
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

	// decompress things
	stepup   bool
	prevcode int16
}

type v44node struct {
	pos    int32
	side   int16 // this side should be common array of sorted things, but in this scale, it will be maybe ok, but later refactor that, move array to upper level
	down   int16
	length int16
}

func (v *v44ctx) emitbit(b byte) {
	if v.bitoffset == 8 {
		v.output = append(v.output, v.tmp)
		v.bitoffset = 0
		v.tmp = 0
	}
	v.tmp |= b << v.bitoffset
	v.bitoffset++
}

func (v *v44ctx) emitcontrolcode(c int16) {
	v.sentcode = false
	v.emitbit(1)
	for range v.c2 {
		v.emitbit(byte(c & 1))
		c >>= 1
	}
}

func (v *v44ctx) emitcodeword(codeword int16) {
	for codeword >= v.c2n { // stepup for codewords, no limit here as max codeword is already limited, so this ends with 11 at maximum
		v.emitcontrolcode(2)
		v.c2++
		v.c2n <<= 1
	}
	v.emitcontrolcode(codeword)
	v.sentcode = true
}

func (v *v44ctx) emitstringext(l int16) {
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

func (v *v44ctx) emitordinal(b byte) {
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

func (v *v44ctx) compress() {
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
		}
		stringext = 0
		off = 0

		// try to find the longest match
		r := v.root[b]
		if r == 0 { // not even in the dictionary, emit ordinal
			v.emitordinal(b)
			if v.lastcode < maxcodeword {
				v.nodes = append(v.nodes, v44node{
					pos:    ii + 1, // next possible extension
					length: 1,
				})
				v.root[b] = v.lastcode
				v.lastcode++
			}
			continue M
		}
		// find the longest match, just linear search, try first level, if it is not found, then double ordinal should be trasnferred
		rem := int32(len(v.history)) - ii - 1
		if rem == 0 {
			v.emitordinal(b)
			break M // game over anyway
		}
		sid := r
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

func (v *v44ctx) flush() {
	v.emitcontrolcode(1)
	v.output = append(v.output, v.tmp)
}

func Compress(input []byte) []byte {
	ctx := v44ctx{
		c2:        6,
		c2n:       64,
		c5:        7,
		bitoffset: 0,
		lastcode:  4,
		history:   input,
		sentcode:  false,
		nodes:     make([]v44node, 4),
	}
	ctx.compress()
	ctx.flush()
	return ctx.output
}

func (v *v44ctx) readbit() (b byte) {
	b |= v.input[0] & 1
	v.input[0] >>= 1
	v.bitoffset++
	v.inputbits--
	if v.bitoffset == 8 {
		v.input = v.input[1:]
		v.bitoffset = 0
	}
	return
}

func (v *v44ctx) readcontrolcode() (int16, error) {
	if v.inputbits < v.c2 {
		return 0, fmt.Errorf("not enough bits for control code")
	}
	r := int16(0)
	for ii := range v.c2 {
		r |= int16(v.readbit()) << ii
	}
	return r, nil
}

func (v *v44ctx) readordinal() (byte, error) {
	if v.inputbits < v.c5 {
		return 0, fmt.Errorf("not enough bits for ordinal")
	}
	r := byte(0)
	for ii := range v.c5 {
		r |= v.readbit() << ii
	}
	return r, nil
}

func (v *v44ctx) readstringext() (int16, error) {
	if v.inputbits == 0 {
		return 0, fmt.Errorf("no more bits for string extension")
	}
	if v.readbit() != 0 {
		return 1, nil
	}
	if v.inputbits < 2 {
		return 0, fmt.Errorf("not enough bits for string extension")
	}
	r := int16(0)
	for ii := range 2 {
		r |= int16(v.readbit()) << ii
	}
	switch r {
	case 1, 2, 3:
		return r + 1, nil
	}
	if v.inputbits < 4 {
		return 0, fmt.Errorf("not enough bits for string extension")
	}
	r = 0
	for ii := range 4 {
		r |= int16(v.readbit()) << ii
	}
	if r&1 == 0 {
		return (r >> 1) + 5, nil
	}
	if v.inputbits < 5 {
		return 0, fmt.Errorf("not enough bits for string extension")
	}
	r >>= 1
	for ii := range 5 {
		r |= int16(v.readbit()) << (ii + 3)
	}
	return r, nil
}

const (
	state_empty = iota
	state_codeword
	state_stringext
	state_ordinal
)

func (v *v44ctx) decompress() ([]byte, error) {
	prevstate := state_empty
	for v.inputbits > 0 {
		if v.readbit() != 0 { // control code or codeword
			if v.stepup {
				v.c2++
				v.c2n <<= 1
				if v.c2 > 11 {
					return nil, fmt.Errorf("c2 cant be more than 11")
				}
				v.stepup = false
			}
			ctr, err := v.readcontrolcode()
			if err != nil {
				return nil, err
			}
			if ctr < 4 { // control code
				v.sentcode = false
				switch ctr {
				case 1: // flush
					if v.inputbits >= 8 {
						return nil, fmt.Errorf("premature flush observed")
					}
					return v.history, nil
				case 2: // stepup
					v.stepup = true
				default:
					return nil, fmt.Errorf("unknown control code %d", ctr) // etm and reinit are not supported in packed mode
				}
			} else { // codeword
				err = v.processcodeword(prevstate, ctr)
				if err != nil {
					return nil, err
				}
				v.sentcode = true // expecting extended prefix, this is madness
				v.prevcode = ctr
				prevstate = state_codeword
			}
		} else {
			if v.sentcode {
				v.sentcode = false
				if v.inputbits == 0 {
					return nil, fmt.Errorf("no more bits")
				}
				if v.readbit() != 0 { // string extension
					err := v.processstringext(prevstate)
					if err != nil {
						return nil, err
					}
					prevstate = state_stringext
				} else { // ordinal
					err := v.processordinal(prevstate)
					if err != nil {
						return nil, err
					}
					prevstate = state_ordinal
				}
			} else { // ordinal
				err := v.processordinal(prevstate)
				if err != nil {
					return nil, err
				}
				prevstate = state_ordinal
			}
		}
	}
	return nil, fmt.Errorf("no terminal flush found")
}

func (v *v44ctx) adddecnode(pos int32, length int16) {
	if v.lastcode >= maxcodeword {
		return
	}
	v.nodes = append(v.nodes, v44node{
		pos:    pos,
		length: length,
	})
	v.lastcode++
}

func (v *v44ctx) processordinal(prev int) error {
	if v.stepup {
		if v.c5 == 8 {
			return fmt.Errorf("c5 cant be more than 8")
		}
		v.c5 = 8
		v.stepup = false
	}
	o, err := v.readordinal()
	if err != nil {
		return err
	}

	v.history = append(v.history, o)
	switch prev {
	case state_empty:
	case state_codeword:
		if v.nodes[v.prevcode].length < maxstring {
			v.adddecnode(int32(len(v.history))-1, v.nodes[v.prevcode].length+1)
		}
	case state_stringext:
	case state_ordinal:
		v.adddecnode(int32(len(v.history))-1, 2)
	default:
		return fmt.Errorf("invalid state %d, program error", prev)
	}
	return nil
}

func (v *v44ctx) processcodeword(prev int, ctr int16) error {
	if ctr > v.lastcode {
		return fmt.Errorf("codeword %d is not in the dictionary", ctr)
	}

	var cn v44node
	switch prev {
	case state_codeword:
		if ctr == v.lastcode {
			cn = v.nodes[v.prevcode]
			v.history = append(v.history, v.history[cn.pos+1-int32(cn.length):cn.pos+1]...)
			v.history = append(v.history, v.history[cn.pos+1-int32(cn.length)]) // this is real black magic
			cn.length++                                                         // hacky hack, this is copy, so it is ok
		} else {
			cn = v.nodes[ctr]
			v.history = append(v.history, v.history[cn.pos+1-int32(cn.length):cn.pos+1]...)
		}

		if v.nodes[v.prevcode].length < maxstring {
			v.adddecnode(int32(len(v.history))-int32(cn.length), v.nodes[v.prevcode].length+1)
		}
	case state_stringext:
		if ctr < v.lastcode {
			cn = v.nodes[ctr]
			v.history = append(v.history, v.history[cn.pos+1-int32(cn.length):cn.pos+1]...)
		}
	case state_ordinal:
		if ctr == v.lastcode { // damn that extra rule
			cn.length = 2 // hacky hack
			v.history = append(v.history, v.history[len(v.history)-1], v.history[len(v.history)-1])
		} else {
			cn = v.nodes[ctr]
			v.history = append(v.history, v.history[cn.pos+1-int32(cn.length):cn.pos+1]...)
		}

		v.adddecnode(int32(len(v.history))-int32(cn.length), 2)
	default:
		return fmt.Errorf("invalid state %d", prev)
	}

	return nil
}

func (v *v44ctx) processstringext(prev int) error {
	if v.stepup {
		return fmt.Errorf("stepup not expected")
	}
	s, err := v.readstringext()
	if err != nil {
		return err
	}

	switch prev {
	case state_codeword:
		cn := v.nodes[v.prevcode]
		for ii := range int32(s) { // one by one, this thing can overlap into non existing history
			v.history = append(v.history, v.history[cn.pos+1+ii])
		}
		if cn.length+s <= maxstring {
			v.adddecnode(int32(len(v.history))-1, cn.length+s)
		}
	default:
		return fmt.Errorf("invalid state %d", prev)
	}

	return nil
}

func Decompress(input []byte) ([]byte, error) {
	ctx := v44ctx{
		c2:        6,
		c2n:       64,
		c5:        7,
		bitoffset: 0,
		lastcode:  4,
		sentcode:  false,
		input:     input,
		inputbits: len(input) * 8,
		nodes:     make([]v44node, 4),
	}
	// empty array is not possible as at least flush control code has to be here
	return ctx.decompress()
}
