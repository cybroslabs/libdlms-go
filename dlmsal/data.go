package dlmsal

import (
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
	Tag   dataTag
	Value interface{}
}

type DlmsError struct {
	Result AccessResultTag
}

type DlmsCompactArray struct {
	Tag   dataTag
	Tags  []dataTag
	Value []DlmsData
}

func (d *dlmsal) decodeDataTag(src io.Reader) (data DlmsData, c int, err error) {
	_, err = io.ReadFull(src, d.tmpbuffer[:1])
	if err != nil {
		return
	}
	t := d.tmpbuffer[0]
	data, c, err = d.decodeData(src, dataTag(t))
	return data, c + 1, err
}

func (al *dlmsal) decodeData(src io.Reader, tag dataTag) (data DlmsData, c int, err error) {
	switch tag {
	case TagNull:
		return DlmsData{Tag: tag, Value: nil}, 0, nil
	case TagArray:
		var ii int
		l, c, err := decodelength(src, al.tmpbuffer)
		if err != nil {
			return data, 0, err
		}
		d := make([]DlmsData, l)
		for i := 0; i < int(l); i++ {
			d[i], ii, err = al.decodeDataTag(src)
			if err != nil {
				return data, 0, err
			}
			c += ii
		}
		return DlmsData{Tag: tag, Value: d}, c, nil
	case TagStructure:
		var ii int
		l, c, err := decodelength(src, al.tmpbuffer)
		if err != nil {
			return data, 0, err
		}
		d := make([]DlmsData, l)
		for i := 0; i < int(l); i++ {
			d[i], ii, err = al.decodeDataTag(src)
			if err != nil {
				return data, 0, err
			}
			c += ii
		}
		return DlmsData{Tag: tag, Value: d}, c, nil
	case TagBoolean:
		{
			_, err = io.ReadFull(src, al.tmpbuffer[:1])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for boolean, %v", err)
			}
			return DlmsData{Tag: tag, Value: al.tmpbuffer[0] != 0}, 1, nil
		}
	case TagBitString:
		{
			l, c, err := decodelength(src, al.tmpbuffer)
			if err != nil {
				return data, 0, err
			}
			blen := (l + 7) >> 3
			var tmp []byte
			if blen > uint(len(al.tmpbuffer)) {
				tmp = make([]byte, blen)
			} else {
				tmp = al.tmpbuffer[:blen]
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
			_, err = io.ReadFull(src, al.tmpbuffer[:4])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for double long %v", err)
			}
			v := int32(al.tmpbuffer[0])<<24 | int32(al.tmpbuffer[1])<<16 | int32(al.tmpbuffer[2])<<8 | int32(al.tmpbuffer[3])
			return DlmsData{Tag: tag, Value: v}, 4, nil
		}
	case TagDoubleLongUnsigned:
		{
			_, err = io.ReadFull(src, al.tmpbuffer[:4])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for double long unsigned %v", err)
			}
			v := uint32(al.tmpbuffer[0])<<24 | uint32(al.tmpbuffer[1])<<16 | uint32(al.tmpbuffer[2])<<8 | uint32(al.tmpbuffer[3])
			return DlmsData{Tag: tag, Value: v}, 4, nil
		}
	case TagFloatingPoint:
		{
			_, err = io.ReadFull(src, al.tmpbuffer[:4])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for floating point %v", err)
			}
			v := math.Float32frombits(binary.BigEndian.Uint32(al.tmpbuffer[:4]))
			return DlmsData{Tag: tag, Value: v}, 4, nil
		}
	case TagOctetString:
		{
			l, c, err := decodelength(src, al.tmpbuffer)
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
			l, c, err := decodelength(src, al.tmpbuffer)
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
			l, c, err := decodelength(src, al.tmpbuffer)
			if err != nil {
				return data, 0, err
			}
			outByte := make([]byte, l)
			_, err = io.ReadFull(src, outByte)
			if err != nil {
				return data, 0, fmt.Errorf("too short data for utf8 string %v", err)
			}

			var sb strings.Builder
			for uint(sb.Len()) < l {
				r, _ := utf8.DecodeRune(outByte[sb.Len():])
				if r == utf8.RuneError {
					return data, 0, fmt.Errorf("byte slice contain invalid UTF-8 runes")
				}
				sb.WriteRune(r)
			}
			return DlmsData{Tag: tag, Value: sb.String()}, c + int(l), nil
		}
	case TagBCD:
		{
			_, err = io.ReadFull(src, al.tmpbuffer[:1])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for bcd %v", err)
			}
			v := int(al.tmpbuffer[0]&0xf) + 10*(int(al.tmpbuffer[0]>>4)&7)
			if (al.tmpbuffer[0] & 0x80) != 0 {
				v = -v
			}
			return DlmsData{Tag: tag, Value: int8(v)}, 1, nil
		}
	case TagInteger:
		{
			_, err = io.ReadFull(src, al.tmpbuffer[:1])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for integer %v", err)
			}
			v := int8(al.tmpbuffer[0])
			return DlmsData{Tag: tag, Value: v}, 1, nil
		}
	case TagLong:
		{
			_, err = io.ReadFull(src, al.tmpbuffer[:2])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for long %v", err)
			}
			v := int16(al.tmpbuffer[0])<<8 | int16(al.tmpbuffer[1])
			return DlmsData{Tag: tag, Value: v}, 2, nil
		}
	case TagUnsigned:
		{
			_, err = io.ReadFull(src, al.tmpbuffer[:1])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for unsigned %v", err)
			}
			v := uint8(al.tmpbuffer[0])
			return DlmsData{Tag: tag, Value: v}, 1, nil
		}
	case TagLongUnsigned:
		{
			_, err = io.ReadFull(src, al.tmpbuffer[:2])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for long unsigned %v", err)
			}
			v := uint16(al.tmpbuffer[0])<<8 | uint16(al.tmpbuffer[1])
			return DlmsData{Tag: tag, Value: v}, 2, nil
		}
	case TagCompactArray:
		{
			n, err := io.ReadFull(src, al.tmpbuffer[:1])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for compact array %v", err)
			}
			ctag := dataTag(al.tmpbuffer[0])
			var types []dataTag
			if ctag == TagStructure { // determine structure items types
				l, c, err := decodelength(src, al.tmpbuffer)
				if err != nil {
					return data, 0, err
				}
				n += c
				var tmp []byte
				if uint(len(al.tmpbuffer)) < l {
					tmp = make([]byte, l)
				} else {
					tmp = al.tmpbuffer[:l]
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
			l, c, err := decodelength(src, al.tmpbuffer)
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
			cont := make([]byte, l)
			_, err = io.ReadFull(src, cont)
			if err != nil {
				return data, 0, fmt.Errorf("too short data for compact array %v", err)
			}
			n += int(l)
			cntstr := bytes.NewBuffer(cont)

			rem := len(cont)
			items := make([]DlmsData, 0, 100) // maybe too much
			for rem > 0 {
				if ctag == TagStructure { // artifical structure with len(types) items
					str := make([]DlmsData, len(types))
					for i := 0; i < len(types); i++ {
						if rem <= 0 {
							return data, 0, fmt.Errorf("there are no bytes left for another structure item")
						}
						str[i], c, err = al.decodeData(cntstr, types[i])
						if err != nil {
							return data, 0, err
						}
						rem -= c
					}
					items = append(items, DlmsData{Tag: TagStructure, Value: str})
				} else {
					data, c, err := al.decodeData(cntstr, ctag)
					if err != nil {
						return data, 0, err
					}
					rem -= c
					items = append(items, data)
				}
			}
			toret := DlmsCompactArray{Tag: ctag, Value: items}
			if ctag == TagStructure {
				toret.Tags = types
			}
			return DlmsData{Tag: tag, Value: toret}, n, nil
		}
	case TagLong64:
		{
			_, err = io.ReadFull(src, al.tmpbuffer[:8])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for long64 %v", err)
			}
			v := int64(al.tmpbuffer[0])<<56 | int64(al.tmpbuffer[1])<<48 | int64(al.tmpbuffer[2])<<40 | int64(al.tmpbuffer[3])<<32 | int64(al.tmpbuffer[4])<<24 | int64(al.tmpbuffer[5])<<16 | int64(al.tmpbuffer[6])<<8 | int64(al.tmpbuffer[7])
			return DlmsData{Tag: tag, Value: v}, 8, nil
		}
	case TagLong64Unsigned:
		{
			_, err = io.ReadFull(src, al.tmpbuffer[:8])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for long64 unsigned %v", err)
			}
			v := uint64(al.tmpbuffer[0])<<56 | uint64(al.tmpbuffer[1])<<48 | uint64(al.tmpbuffer[2])<<40 | uint64(al.tmpbuffer[3])<<32 | uint64(al.tmpbuffer[4])<<24 | uint64(al.tmpbuffer[5])<<16 | uint64(al.tmpbuffer[6])<<8 | uint64(al.tmpbuffer[7])
			return DlmsData{Tag: tag, Value: v}, 8, nil
		}
	case TagEnum:
		{
			_, err = io.ReadFull(src, al.tmpbuffer[:1])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for enum %v", err)
			}
			v := uint8(al.tmpbuffer[0])
			return DlmsData{Tag: tag, Value: v}, 1, nil
		}
	case TagFloat32:
		{
			_, err = io.ReadFull(src, al.tmpbuffer[:4])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for float32 %v", err)
			}
			v := math.Float32frombits(binary.BigEndian.Uint32(al.tmpbuffer[:4]))
			return DlmsData{Tag: tag, Value: v}, 4, nil
		}
	case TagFloat64:
		{
			_, err = io.ReadFull(src, al.tmpbuffer[:8])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for float64 %v", err)
			}
			v := math.Float64frombits(binary.BigEndian.Uint64(al.tmpbuffer[:8]))
			return DlmsData{Tag: tag, Value: v}, 8, nil
		}
	case TagDateTime:
		{
			_, err = io.ReadFull(src, al.tmpbuffer[:12])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for datetime %v", err)
			}
			v := DlmsDateTime{
				Date: DlmsDate{
					Year:      uint16(al.tmpbuffer[0])<<8 | uint16(al.tmpbuffer[1]),
					Month:     al.tmpbuffer[2],
					Day:       al.tmpbuffer[3],
					DayOfWeek: al.tmpbuffer[4],
				},
				Time: DlmsTime{
					Hour:       al.tmpbuffer[5],
					Minute:     al.tmpbuffer[6],
					Second:     al.tmpbuffer[7],
					Hundredths: al.tmpbuffer[8],
				},
				Deviation: int16(al.tmpbuffer[9])<<8 | int16(al.tmpbuffer[10]), // signed
				Status:    al.tmpbuffer[11],
			}
			return DlmsData{Tag: tag, Value: v}, 12, nil
		}
	case TagDate:
		{
			_, err = io.ReadFull(src, al.tmpbuffer[:5])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for date %v", err)
			}
			v := DlmsDate{
				Year:      uint16(al.tmpbuffer[0])<<8 | uint16(al.tmpbuffer[1]),
				Month:     al.tmpbuffer[2],
				Day:       al.tmpbuffer[3],
				DayOfWeek: al.tmpbuffer[4],
			}
			return DlmsData{Tag: tag, Value: v}, 5, nil
		}
	case TagTime:
		{
			_, err = io.ReadFull(src, al.tmpbuffer[:4])
			if err != nil {
				return data, 0, fmt.Errorf("too short data for time %v", err)
			}
			v := DlmsTime{
				Hour:       al.tmpbuffer[0],
				Minute:     al.tmpbuffer[1],
				Second:     al.tmpbuffer[2],
				Hundredths: al.tmpbuffer[3],
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
	if input.Tag == TagStructure && input.Tags == nil {
		return fmt.Errorf("no structure tags provided")
	}

	// well... shit, all things has to have the same type and in case of structure, this could be fun, in case of zero items, well... fuck, special structure for this?
	if len(input.Value) == 0 { // nothing, so not interesting in anything, encopde it as a zero empty structures
		out.WriteByte(byte(input.Tag))
		if input.Tag == TagStructure {
			encodelength(out, uint(len(input.Tags)))
			for _, tt := range input.Tags {
				out.WriteByte(byte(tt))
			}
		}
		out.WriteByte(0) // zero bytes, this is very questionable, at least not so used data type, things for some future
	}
	for _, t := range input.Value {
		if t.Tag != input.Tag {
			return fmt.Errorf("data tag differs, unable to perform encoding compact array")
		}
		if input.Tag == TagStructure {
			tmp, err := getstructuretypes(&t)
			if err != nil {
				return err
			}
			if len(tmp) != len(input.Tags) {
				return fmt.Errorf("inner structure differs")
			}
			for ii, jj := range tmp {
				if jj != input.Tags[ii] {
					return fmt.Errorf("inner structure differs")
				}
			}
		}
	}

	if input.Tag == TagNull || len(input.Tags) == 0 {
		return fmt.Errorf("unable to encode compact array with null tag")
	}
	on := true
	for _, ty := range input.Tags {
		if ty != TagNull {
			on = false
		}
	}
	if on {
		return fmt.Errorf("unable to decode compact array with all null types")
	}

	// ok, having everything, encode that shit, really clusterfuck thing
	out.WriteByte(byte(input.Tag))
	if input.Tag == TagStructure {
		encodelength(out, uint(len(input.Tags)))
		for _, tt := range input.Tags {
			out.WriteByte(byte(tt))
		}
	}
	// ok, create internal buffer, encode shits, determine size and put that together
	var internal bytes.Buffer
	if input.Tag == TagStructure { // shit shit shit
		for _, dd := range input.Value {
			err = encodeStructureWithoutTags(&internal, &dd)
			if err != nil {
				return err
			}
		}
	} else {
		for _, dd := range input.Value {
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
