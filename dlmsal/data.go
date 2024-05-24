package dlmsal

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"strings"
	"time"
	"unicode/utf8"
)

type dataTag uint16

const (
	TagNull               dataTag = 0
	TagArray              dataTag = 1
	TagStructure          dataTag = 2
	TagBoolean            dataTag = 3
	TagBitString          dataTag = 4
	TagDoubleLong         dataTag = 5
	TagDoubleLongUnsigned dataTag = 6
	TagFloatingPoint      dataTag = 7
	TagOctetString        dataTag = 9
	TagVisibleString      dataTag = 10
	TagUTF8String         dataTag = 12
	TagBCD                dataTag = 13
	TagInteger            dataTag = 15
	TagLong               dataTag = 16
	TagUnsigned           dataTag = 17
	TagLongUnsigned       dataTag = 18
	TagCompactArray       dataTag = 19
	TagLong64             dataTag = 20
	TagLong64Unsigned     dataTag = 21
	TagEnum               dataTag = 22
	TagFloat32            dataTag = 23
	TagFloat64            dataTag = 24
	TagDateTime           dataTag = 25
	TagDate               dataTag = 26
	TagTime               dataTag = 27
	TagDontCare           dataTag = 255
	TagError              dataTag = 0x1000 // artifical tag outside of dlms standard but not interfering with it
)

type DlmsData struct {
	Value interface{}
	Tag   dataTag
}

func NewDlmsDataError(err DlmsError) DlmsData {
	return DlmsData{Tag: TagError, Value: err}
}

type DlmsError struct {
	Result AccessResultTag
}

type DlmsCompactArray struct {
	tag   dataTag
	tags  []dataTag
	value []DlmsData
}

func decodeDataTag(src io.Reader, tmpbuffer *tmpbuffer) (data DlmsData, c int, err error) {
	_, err = io.ReadFull(src, tmpbuffer[:1])
	if err != nil {
		return
	}
	t := dataTag(tmpbuffer[0])
	data, c, err = decodeData(src, t, tmpbuffer)
	return data, c + 1, err
}

func decodeDataArray(src io.Reader, tag dataTag, tmpbuffer *tmpbuffer) (data DlmsData, c int, err error) {
	var ii int
	l, c, err := decodelength(src, tmpbuffer)
	if err != nil {
		return data, 0, err
	}
	d := make([]DlmsData, l)
	for i := 0; i < int(l); i++ {
		d[i], ii, err = decodeDataTag(src, tmpbuffer)
		if err != nil {
			return data, 0, err
		}
		c += ii
	}
	return DlmsData{Tag: tag, Value: d}, c, nil
}

func decodeData(src io.Reader, tag dataTag, tmpbuffer *tmpbuffer) (data DlmsData, c int, err error) {
	switch tag {
	case TagNull:
		return DlmsData{Tag: tag}, 0, nil
	case TagArray:
		return decodeDataArray(src, tag, tmpbuffer)
	case TagStructure:
		return decodeDataArray(src, tag, tmpbuffer)
	case TagBoolean:
		{
			_, err = io.ReadFull(src, tmpbuffer[:1])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for boolean, %v", err)
			}
			return DlmsData{Tag: tag, Value: tmpbuffer[0] != 0}, 1, nil
		}
	case TagBitString:
		{
			l, c, err := decodelength(src, tmpbuffer)
			if err != nil {
				return data, 0, err
			}
			blen := (l + 7) >> 3
			var tmp []byte
			if blen > uint(len(tmpbuffer)) {
				tmp = make([]byte, blen)
			} else {
				tmp = tmpbuffer[:blen]
			}
			_, err = io.ReadFull(src, tmp)
			if err != nil {
				return data, 0, fmt.Errorf("too short data for bitstring %v", err)
			}
			val := make([]bool, l)
			off := uint(0)
			for i := uint(0); i < blen; i++ {
				for j := uint(0); j < 8; j++ {
					val[off] = (tmp[i] & (1 << (7 - j))) != 0
					off++
					if off >= l {
						i = blen
						break
					}
				}
			}
			return DlmsData{Tag: tag, Value: val}, c + int(blen), nil // this type is a bit questionable, better is maybe []bool ?, todo how to interpret that
		}
	case TagDoubleLong:
		{
			_, err = io.ReadFull(src, tmpbuffer[:4])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for double long %v", err)
			}
			v := int32(tmpbuffer[0])<<24 | int32(tmpbuffer[1])<<16 | int32(tmpbuffer[2])<<8 | int32(tmpbuffer[3])
			return DlmsData{Tag: tag, Value: v}, 4, nil
		}
	case TagDoubleLongUnsigned:
		{
			_, err = io.ReadFull(src, tmpbuffer[:4])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for double long unsigned %v", err)
			}
			v := uint32(tmpbuffer[0])<<24 | uint32(tmpbuffer[1])<<16 | uint32(tmpbuffer[2])<<8 | uint32(tmpbuffer[3])
			return DlmsData{Tag: tag, Value: v}, 4, nil
		}
	case TagFloatingPoint:
		{
			_, err = io.ReadFull(src, tmpbuffer[:4])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for floating point %v", err)
			}
			return DlmsData{Tag: tag, Value: math.Float32frombits(binary.BigEndian.Uint32(tmpbuffer[:4]))}, 4, nil
		}
	case TagOctetString:
		{
			l, c, err := decodelength(src, tmpbuffer)
			if err != nil {
				return data, 0, err
			}
			v := make([]byte, l)
			_, err = io.ReadFull(src, v)
			if err != nil {
				return data, 0, fmt.Errorf("too short data for octet string %v", err)
			}
			return DlmsData{Tag: tag, Value: v}, c + int(l), nil
		}
	case TagVisibleString:
		{
			l, c, err := decodelength(src, tmpbuffer)
			if err != nil {
				return data, 0, err
			}
			v := make([]byte, l)
			_, err = io.ReadFull(src, v)
			if err != nil {
				return data, 0, fmt.Errorf("too short data for visible string %v", err)
			}
			return DlmsData{Tag: tag, Value: string(v)}, c + int(l), nil // double copy
		}
	case TagUTF8String:
		{
			l, c, err := decodelength(src, tmpbuffer)
			if err != nil {
				return data, 0, err
			}
			inner := io.LimitReader(src, int64(l))
			reader := bufio.NewReader(inner)
			var sb strings.Builder
			for uint(sb.Len()) < l {
				r, _, err := reader.ReadRune()
				if r == utf8.RuneError || err != nil {
					return data, 0, fmt.Errorf("byte slice contain invalid UTF-8 runes")
				}
				sb.WriteRune(r)
			}
			return DlmsData{Tag: tag, Value: sb.String()}, c + int(l), nil
		}
	case TagBCD:
		{
			_, err = io.ReadFull(src, tmpbuffer[:1])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for bcd %v", err)
			}
			v := int(tmpbuffer[0]&0xf) + 10*(int(tmpbuffer[0]>>4)&7)
			if (tmpbuffer[0] & 0x80) != 0 {
				v = -v
			}
			return DlmsData{Tag: tag, Value: int8(v)}, 1, nil
		}
	case TagInteger:
		{
			_, err = io.ReadFull(src, tmpbuffer[:1])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for integer %v", err)
			}
			v := int8(tmpbuffer[0])
			return DlmsData{Tag: tag, Value: v}, 1, nil
		}
	case TagLong:
		{
			_, err = io.ReadFull(src, tmpbuffer[:2])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for long %v", err)
			}
			v := int16(tmpbuffer[0])<<8 | int16(tmpbuffer[1])
			return DlmsData{Tag: tag, Value: v}, 2, nil
		}
	case TagUnsigned:
		{
			_, err = io.ReadFull(src, tmpbuffer[:1])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for unsigned %v", err)
			}
			v := uint8(tmpbuffer[0])
			return DlmsData{Tag: tag, Value: v}, 1, nil
		}
	case TagLongUnsigned:
		{
			_, err = io.ReadFull(src, tmpbuffer[:2])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for long unsigned %v", err)
			}
			v := uint16(tmpbuffer[0])<<8 | uint16(tmpbuffer[1])
			return DlmsData{Tag: tag, Value: v}, 2, nil
		}
	case TagCompactArray:
		{
			n, err := io.ReadFull(src, tmpbuffer[:1])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for compact array %v", err)
			}
			ctag := dataTag(tmpbuffer[0])
			var types []dataTag
			if ctag == TagStructure { // determine structure items types
				l, c, err := decodelength(src, tmpbuffer)
				if err != nil {
					return data, 0, err
				}
				n += c
				var tmp []byte
				if uint(len(tmpbuffer)) < l {
					tmp = make([]byte, l)
				} else {
					tmp = tmpbuffer[:l]
				}
				_, err = io.ReadFull(src, tmp)
				if err != nil {
					return data, 0, fmt.Errorf("too short data for compact array (number of structure items), %v", err)
				}
				types = make([]dataTag, l)
				for i := 0; i < int(l); i++ {
					types[i] = dataTag(tmp[i])
				}
				n += int(l)
			} else { // just bunch of items
				if ctag == TagNull {
					return data, 0, fmt.Errorf("unable to decode compact array with null tag")
				}
				types = make([]dataTag, 1)
				types[0] = ctag
			}

			// length in bytes, then slice it and traverse through slice till there is something left
			l, c, err := decodelength(src, tmpbuffer)
			if err != nil {
				return data, 0, fmt.Errorf("too short data for compact array (length) %v", err)
			}
			n += c

			if l != 0 {
				if len(types) == 0 {
					return data, 0, fmt.Errorf("no types for compact array")
				}
				on := true
				for _, ty := range types {
					if ty != TagNull {
						on = false
					}
				}
				if on {
					return data, 0, fmt.Errorf("unable to decode compact array with all null types")
				}
			}

			// ok, this type is a bit shit, do that in memory fucked up way, otherwise i have to return consumbed bytes, so maybe next refactor, this type is not widely used anyway...
			cntstr := io.LimitReader(src, int64(l))
			rem := int(l)
			n += rem
			items := make([]DlmsData, 0, 100) // maybe too much
			for rem > 0 {
				if ctag == TagStructure { // artifical structure with len(types) items
					str := make([]DlmsData, len(types))
					for i := 0; i < len(types); i++ {
						if rem <= 0 {
							return data, 0, fmt.Errorf("there are no bytes left for another structure item")
						}
						str[i], c, err = decodeData(cntstr, types[i], tmpbuffer)
						if err != nil {
							return data, 0, err
						}
						rem -= c
					}
					items = append(items, DlmsData{Tag: TagStructure, Value: str})
				} else {
					data, c, err := decodeData(cntstr, ctag, tmpbuffer)
					if err != nil {
						return data, 0, err
					}
					rem -= c
					items = append(items, data)
				}
			}
			toret := DlmsCompactArray{tag: ctag, value: items}
			if ctag == TagStructure {
				toret.tags = types
			}
			return DlmsData{Tag: tag, Value: toret}, n, nil
		}
	case TagLong64:
		{
			_, err = io.ReadFull(src, tmpbuffer[:8])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for long64 %v", err)
			}
			v := int64(tmpbuffer[0])<<56 | int64(tmpbuffer[1])<<48 | int64(tmpbuffer[2])<<40 | int64(tmpbuffer[3])<<32 | int64(tmpbuffer[4])<<24 | int64(tmpbuffer[5])<<16 | int64(tmpbuffer[6])<<8 | int64(tmpbuffer[7])
			return DlmsData{Tag: tag, Value: v}, 8, nil
		}
	case TagLong64Unsigned:
		{
			_, err = io.ReadFull(src, tmpbuffer[:8])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for long64 unsigned %v", err)
			}
			v := uint64(tmpbuffer[0])<<56 | uint64(tmpbuffer[1])<<48 | uint64(tmpbuffer[2])<<40 | uint64(tmpbuffer[3])<<32 | uint64(tmpbuffer[4])<<24 | uint64(tmpbuffer[5])<<16 | uint64(tmpbuffer[6])<<8 | uint64(tmpbuffer[7])
			return DlmsData{Tag: tag, Value: v}, 8, nil
		}
	case TagEnum:
		{
			_, err = io.ReadFull(src, tmpbuffer[:1])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for enum %v", err)
			}
			v := uint8(tmpbuffer[0])
			return DlmsData{Tag: tag, Value: v}, 1, nil
		}
	case TagFloat32:
		{
			_, err = io.ReadFull(src, tmpbuffer[:4])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for float32 %v", err)
			}
			return DlmsData{Tag: tag, Value: math.Float32frombits(binary.BigEndian.Uint32(tmpbuffer[:4]))}, 4, nil
		}
	case TagFloat64:
		{
			_, err = io.ReadFull(src, tmpbuffer[:8])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for float64 %v", err)
			}
			return DlmsData{Tag: tag, Value: math.Float64frombits(binary.BigEndian.Uint64(tmpbuffer[:8]))}, 8, nil
		}
	case TagDateTime:
		{
			_, err = io.ReadFull(src, tmpbuffer[:12])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for datetime %v", err)
			}
			v := DlmsDateTime{
				Date: DlmsDate{
					Year:      uint16(tmpbuffer[0])<<8 | uint16(tmpbuffer[1]),
					Month:     tmpbuffer[2],
					Day:       tmpbuffer[3],
					DayOfWeek: tmpbuffer[4],
				},
				Time: DlmsTime{
					Hour:       tmpbuffer[5],
					Minute:     tmpbuffer[6],
					Second:     tmpbuffer[7],
					Hundredths: tmpbuffer[8],
				},
				Deviation: int16(tmpbuffer[9])<<8 | int16(tmpbuffer[10]), // signed
				Status:    tmpbuffer[11],
			}
			return DlmsData{Tag: tag, Value: v}, 12, nil
		}
	case TagDate:
		{
			_, err = io.ReadFull(src, tmpbuffer[:5])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for date %v", err)
			}
			v := DlmsDate{
				Year:      uint16(tmpbuffer[0])<<8 | uint16(tmpbuffer[1]),
				Month:     tmpbuffer[2],
				Day:       tmpbuffer[3],
				DayOfWeek: tmpbuffer[4],
			}
			return DlmsData{Tag: tag, Value: v}, 5, nil
		}
	case TagTime:
		{
			_, err = io.ReadFull(src, tmpbuffer[:4])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for time %v", err)
			}
			v := DlmsTime{
				Hour:       tmpbuffer[0],
				Minute:     tmpbuffer[1],
				Second:     tmpbuffer[2],
				Hundredths: tmpbuffer[3],
			}
			return DlmsData{Tag: tag, Value: v}, 4, nil
		}
	}
	return data, 0, fmt.Errorf("unknown tag %d", tag)
}

func EncodeData(d DlmsData) ([]byte, error) {
	var out bytes.Buffer
	err := encodeData(&out, &d)
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func encodeData(out *bytes.Buffer, d *DlmsData) error {
	if d == nil {
		return fmt.Errorf("nil data") // no panic here
	}
	out.WriteByte(byte(d.Tag))
	return encodeDatanoTag(out, d)
}

func encodeDatanoTag(out *bytes.Buffer, d *DlmsData) error {
	switch d.Tag {
	case TagNull:
	case TagArray: // fuck how many casting we will be supporting
		return encodeArrayStructure(out, d)
	case TagStructure:
		return encodeArrayStructure(out, d)
	case TagBoolean:
		return encodeInteger(out, d, 1)
	case TagBitString:
		return encodeBitstring(out, d)
	case TagDoubleLong:
		return encodeInteger(out, d, 4)
	case TagDoubleLongUnsigned:
		return encodeInteger(out, d, 4)
	case TagFloatingPoint:
		return encodeFloat(out, d, 4)
	case TagOctetString:
		return encodeOctetString(out, d)
	case TagVisibleString:
		return encodeVisibleString(out, d)
	case TagUTF8String:
		return encodeVisibleString(out, d)
	case TagBCD:
		return encodeBCD(out, d)
	case TagInteger:
		return encodeInteger(out, d, 1)
	case TagLong:
		return encodeInteger(out, d, 2)
	case TagUnsigned:
		return encodeInteger(out, d, 1)
	case TagLongUnsigned:
		return encodeInteger(out, d, 2)
	case TagCompactArray:
		return encodeCompactArray(out, d)
	case TagLong64:
		return encodeInteger(out, d, 8)
	case TagLong64Unsigned:
		return encodeInteger(out, d, 8)
	case TagEnum:
		return encodeInteger(out, d, 1)
	case TagFloat32:
		return encodeFloat(out, d, 4)
	case TagFloat64:
		return encodeFloat(out, d, 8)
	case TagDateTime:
		return encodeDateTime(out, d)
	case TagDate:
		return encodeDate(out, d)
	case TagTime:
		return encodeTime(out, d)
	default:
		return fmt.Errorf("unsupported data tag: %v", d.Tag)
	}
	return nil
}

func encodeDateTime(out *bytes.Buffer, d *DlmsData) error { // refactor this a bit
	switch t := d.Value.(type) {
	case time.Time:
		dt := NewDlmsDateTimeFromTime(&t)
		encodedatetime(out, dt)
	case DlmsDateTime:
		encodedatetime(out, &t)
	case *DlmsDateTime:
		encodedatetime(out, t)
	default:
		return fmt.Errorf("unsupported data type for date time: %T", d.Value)
	}
	return nil
}

func encodeDate(out *bytes.Buffer, d *DlmsData) error {
	switch t := d.Value.(type) {
	case DlmsDate:
		encodedate(out, &t)
	case *DlmsDate:
		encodedate(out, t)
	default:
		return fmt.Errorf("unsupported data type for date: %T", d.Value)
	}
	return nil
}

func encodeTime(out *bytes.Buffer, d *DlmsData) error {
	switch t := d.Value.(type) {
	case DlmsTime:
		encodetime(out, &t)
	case *DlmsTime:
		encodetime(out, t)
	default:
		return fmt.Errorf("unsupported data type for time: %T", d.Value)
	}
	return nil
}

func encodeCompactArray(out *bytes.Buffer, d *DlmsData) (err error) {
	var input *DlmsCompactArray
	switch t := d.Value.(type) { // this is shit, better to go with callback
	case DlmsCompactArray:
		input = &t
	case *DlmsCompactArray:
		input = t
	default:
		return fmt.Errorf("unsupported data type for compact array: %T", d.Value)
	}
	if input.tag == TagStructure && input.tags == nil {
		return fmt.Errorf("no structure tags provided")
	}

	// well... shit, all things has to have the same type and in case of structure, this could be fun, in case of zero items, well... fuck, special structure for this?
	if len(input.value) == 0 { // nothing, so not interesting in anything, encopde it as a zero empty structures
		out.WriteByte(byte(input.tag))
		if input.tag == TagStructure {
			encodelength(out, uint(len(input.tags)))
			for _, tt := range input.tags {
				out.WriteByte(byte(tt))
			}
		}
		out.WriteByte(0) // zero bytes, this is very questionable, at least not so used data type, things for some future
	}
	for _, t := range input.value {
		if t.Tag != input.tag {
			return fmt.Errorf("data tag differs, unable to perform encoding compact array")
		}
		if input.tag == TagStructure {
			tmp, err := getstructuretypes(&t)
			if err != nil {
				return err
			}
			if len(tmp) != len(input.tags) {
				return fmt.Errorf("inner structure differs")
			}
			for ii, jj := range tmp {
				if jj != input.tags[ii] {
					return fmt.Errorf("inner structure differs")
				}
			}
		}
	}

	if input.tag == TagNull || len(input.tags) == 0 {
		return fmt.Errorf("unable to encode compact array with null tag")
	}
	on := true
	for _, ty := range input.tags {
		if ty != TagNull {
			on = false
		}
	}
	if on {
		return fmt.Errorf("unable to decode compact array with all null types")
	}

	// ok, having everything, encode that shit, really clusterfuck thing
	out.WriteByte(byte(input.tag))
	if input.tag == TagStructure {
		encodelength(out, uint(len(input.tags)))
		for _, tt := range input.tags {
			out.WriteByte(byte(tt))
		}
	}
	// ok, create internal buffer, encode shits, determine size and put that together
	var internal bytes.Buffer
	if input.tag == TagStructure { // shit shit shit
		for _, dd := range input.value {
			err = encodeStructureWithoutTags(&internal, &dd)
			if err != nil {
				return err
			}
		}
	} else {
		for _, dd := range input.value {
			err = encodeDatanoTag(&internal, &dd)
			if err != nil {
				return err
			}
		}
	}
	encodelength(out, uint(internal.Len()))
	out.Write(internal.Bytes())
	return nil
}

func encodeStructureWithoutTags(out *bytes.Buffer, d *DlmsData) error {
	switch t := d.Value.(type) {
	case []*DlmsData:
		for _, dd := range t {
			err := encodeDatanoTag(out, dd)
			if err != nil {
				return err
			}
		}
	case []DlmsData:
		for _, dd := range t {
			err := encodeDatanoTag(out, &dd)
			if err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("programm error")
	}
	return nil
}

func getstructuretypes(d *DlmsData) ([]dataTag, error) {
	if d.Tag != TagStructure {
		return nil, fmt.Errorf("data are not a structure")
	}
	switch t := d.Value.(type) {
	case []*DlmsData:
		r := make([]dataTag, len(t))
		for i, dt := range t {
			r[i] = dt.Tag
		}
		return r, nil
	case []DlmsData:
		r := make([]dataTag, len(t))
		for i, dt := range t {
			r[i] = dt.Tag
		}
		return r, nil
	default:
		return nil, fmt.Errorf("invalid inner structure data")
	}
}

func encodeBCD(out *bytes.Buffer, d *DlmsData) error {
	var lr int64
	switch t := d.Value.(type) {
	case int:
		lr = int64(t)
	case int8:
		lr = int64(t)
	case int16:
		lr = int64(t)
	case int32:
		lr = int64(t)
	case int64:
		lr = int64(t)
	default:
		return fmt.Errorf("unsupported data type for BCD: %T", d.Value)
	}
	b := byte(((lr/10)%10)<<4) | byte(lr%10)
	if lr < 0 {
		b |= 0x80
	}
	out.WriteByte(b)
	return nil
}

func encodeVisibleString(out *bytes.Buffer, d *DlmsData) error {
	switch t := d.Value.(type) {
	case string:
		encodelength(out, uint(len(t)))
		out.WriteString(t)
	default:
		return fmt.Errorf("unsupported data type for visible string: %T", d.Value)
	}
	return nil
}

func encodeOctetString(out *bytes.Buffer, d *DlmsData) error {
	switch t := d.Value.(type) {
	case []byte:
		encodelength(out, uint(len(t)))
		out.Write(t)
	case DlmsDateTime:
		encodelength(out, 12)
		encodedatetime(out, &t)
	case *DlmsDateTime:
		encodelength(out, 12)
		encodedatetime(out, t)
	case DlmsObis:
		encodeobis(out, &t)
	case *DlmsObis:
		encodeobis(out, t)
	case time.Time:
		dt := NewDlmsDateTimeFromTime(&t)
		encodedatetime(out, dt)
	default:
		return fmt.Errorf("unsupported data type for octet string: %T", d.Value)
	}
	return nil
}

func encodeobis(out *bytes.Buffer, t *DlmsObis) {
	encodelength(out, 6)
	out.WriteByte(t.A)
	out.WriteByte(t.B)
	out.WriteByte(t.C)
	out.WriteByte(t.D)
	out.WriteByte(t.E)
	out.WriteByte(t.F)
}

func encodetime(out *bytes.Buffer, t *DlmsTime) {
	out.WriteByte(t.Hour)
	out.WriteByte(t.Minute)
	out.WriteByte(t.Second)
	out.WriteByte(t.Hundredths)
}

func encodedate(out *bytes.Buffer, t *DlmsDate) {
	out.WriteByte(byte(t.Year >> 8))
	out.WriteByte(byte(t.Year))
	out.WriteByte(t.Month)
	out.WriteByte(t.Day)
	out.WriteByte(t.DayOfWeek)
}

func encodedatetime(out *bytes.Buffer, t *DlmsDateTime) {
	encodedate(out, &t.Date)
	encodetime(out, &t.Time)
	out.WriteByte(byte(t.Deviation >> 8))
	out.WriteByte(byte(t.Deviation))
	out.WriteByte(t.Status)
}

func encodeFloat(out *bytes.Buffer, d *DlmsData, len int) error {
	switch len {
	case 4:
	case 8:
	default:
		return fmt.Errorf("strange target float length: %v", len)
	}
	switch t := d.Value.(type) { // support also interger tyoes?
	case float32:
		if len == 8 {
			_ = binary.Write(out, binary.BigEndian, float64(t))
		} else {
			_ = binary.Write(out, binary.BigEndian, t)
		}
	case float64:
		if len == 4 {
			_ = binary.Write(out, binary.BigEndian, float32(t))
		} else {
			_ = binary.Write(out, binary.BigEndian, t)
		}
	default:
		return fmt.Errorf("unsupported data type for float: %T", d.Value)
	}
	return nil
}

func encodeBitstring(out *bytes.Buffer, d *DlmsData) error {
	var res []byte
	var bitlen int
	switch t := d.Value.(type) {
	case string:
		bitlen = len(t)
		res = make([]byte, (bitlen+7)>>3)
		o := 7
		b := byte(0)
		for i, c := range t {
			switch c {
			case '0':
			case '1':
				b |= 1 << o
			default:
				return fmt.Errorf("invalid character in bitstring: %c", c)
			}
			if o == 0 {
				res[i>>3] = b
				b = 0
				o = 7
			} else {
				o--
			}
		}
		if o != 7 {
			res[len(res)-1] = b
		}
	case []bool:
		bitlen = len(t)
		res = make([]byte, (bitlen+7)>>3)
		o := 7
		b := byte(0)
		for i, c := range t {
			if c {
				b |= 1 << o
			}
			if o == 0 {
				res[i>>3] = b
				b = 0
				o = 7
			} else {
				o--
			}
		}
		if o != 7 {
			res[len(res)-1] = b
		}
	default:
		return fmt.Errorf("unsupported data type for bitstring: %T", d.Value)
	}
	encodelength(out, uint(bitlen))
	out.Write(res)
	return nil
}

func encodeInteger(out *bytes.Buffer, d *DlmsData, len int) error {
	var lr uint64
	switch t := d.Value.(type) {
	case bool:
		lr = 0
		if t {
			lr = 1
		}
	case uint:
		lr = uint64(t)
	case uint8:
		lr = uint64(t)
	case uint16:
		lr = uint64(t)
	case uint32:
		lr = uint64(t)
	case uint64:
		lr = uint64(t)
	case int:
		lr = uint64(int64(t)) // i know it exapnds signed bits, but i like it that way
	case int8:
		lr = uint64(int64(t))
	case int16:
		lr = uint64(int64(t))
	case int32:
		lr = uint64(int64(t))
	case int64:
		lr = uint64(int64(t))
	default:
		return fmt.Errorf("unsupported data type for unsigned number: %T", d.Value)
	}
	switch len {
	case 1:
		out.WriteByte(byte(lr))
	case 2:
		out.WriteByte(byte(lr >> 8))
		out.WriteByte(byte(lr))
	case 4:
		out.WriteByte(byte(lr >> 24))
		out.WriteByte(byte(lr >> 16))
		out.WriteByte(byte(lr >> 8))
		out.WriteByte(byte(lr))
	case 8:
		out.WriteByte(byte(lr >> 56))
		out.WriteByte(byte(lr >> 48))
		out.WriteByte(byte(lr >> 40))
		out.WriteByte(byte(lr >> 32))
		out.WriteByte(byte(lr >> 24))
		out.WriteByte(byte(lr >> 16))
		out.WriteByte(byte(lr >> 8))
		out.WriteByte(byte(lr))
	default:
		return fmt.Errorf("strange target number length: %v", len)
	}
	return nil
}

func encodeArrayStructure(out *bytes.Buffer, d *DlmsData) error {
	if d.Value == nil {
		encodelength(out, 0)
		return nil
	}

	switch t := d.Value.(type) {
	case []*DlmsData:
		encodelength(out, uint(len(t)))
		for _, v := range t {
			err := encodeData(out, v)
			if err != nil {
				return err
			}
		}
	case []DlmsData:
		encodelength(out, uint(len(t)))
		for _, v := range t {
			err := encodeData(out, &v)
			if err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported data type for array/structure: %T", d.Value)
	}
	return nil
}
