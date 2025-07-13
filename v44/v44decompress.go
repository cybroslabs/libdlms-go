package v44

import (
	"fmt"
	"io"
)

type v44decompress struct { // dictionary, root, etc
	history   []byte
	input     io.ByteReader
	bitoffset byte
	tmp       byte
	c2        int
	c2n       int16
	c5        int
	lastcode  int16
	sentcode  bool

	nodes []v44node

	stepup   bool
	prevcode int16
	err      error
}

func (v *v44decompress) readbit() (b byte) {
	if v.bitoffset == 8 {
		if v.err == nil { // dont repeat if with error
			v.tmp, v.err = v.input.ReadByte()
		}
		v.bitoffset = 0
	}
	b = v.tmp & 1
	v.tmp >>= 1
	v.bitoffset++
	return
}

func (v *v44decompress) readcontrolcode() (int16, error) {
	r := int16(0)
	for ii := range v.c2 {
		r |= int16(v.readbit()) << ii
	}
	return r, v.err
}

func (v *v44decompress) readordinal() (byte, error) {
	r := byte(0)
	for ii := range v.c5 {
		r |= v.readbit() << ii
	}
	return r, v.err
}

func (v *v44decompress) readstringext() (int16, error) {
	if v.readbit() != 0 {
		return 1, v.err
	}
	r := int16(0)
	for ii := range 2 {
		r |= int16(v.readbit()) << ii
	}
	switch r {
	case 1, 2, 3:
		return r + 1, v.err
	}
	r = 0
	for ii := range 4 {
		r |= int16(v.readbit()) << ii
	}
	if r&1 == 0 {
		return (r >> 1) + 5, v.err
	}
	r >>= 1
	for ii := range 5 {
		r |= int16(v.readbit()) << (ii + 3)
	}
	return r, v.err
}

func (v *v44decompress) decompress() ([]byte, error) {
	prevstate := state_empty
	for {
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
}

func (v *v44decompress) adddecnode(pos int32, length int16) {
	if v.lastcode >= maxcodeword {
		return
	}
	v.nodes = append(v.nodes, v44node{
		pos:    pos,
		length: length,
	})
	v.lastcode++
}

func (v *v44decompress) processordinal(prev int) error {
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

func (v *v44decompress) processcodeword(prev int, ctr int16) error {
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

func (v *v44decompress) processstringext(prev int) error {
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

func Decompress(dst []byte, input io.ByteReader) ([]byte, error) {
	ctx := v44decompress{
		c2:        6,
		c2n:       64,
		c5:        7,
		bitoffset: 8,
		lastcode:  4,
		sentcode:  false,
		input:     input,
		nodes:     make([]v44node, 4),
		history:   dst,
	}
	return ctx.decompress()
}
