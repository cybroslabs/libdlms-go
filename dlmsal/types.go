package dlmsal

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

type GetRequestTag byte

const (
	TagGetRequestNormal   GetRequestTag = 0x1
	TagGetRequestNext     GetRequestTag = 0x2
	TagGetRequestWithList GetRequestTag = 0x3
)

type GetResponseTag byte

const (
	TagGetResponseNormal        GetResponseTag = 0x1
	TagGetResponseWithDataBlock GetResponseTag = 0x2
	TagGetResponseWithList      GetResponseTag = 0x3
)

type SetRequestTag byte

const (
	TagSetRequestNormal                    SetRequestTag = 0x1
	TagSetRequestWithFirstDataBlock        SetRequestTag = 0x2
	TagSetRequestWithDataBlock             SetRequestTag = 0x3
	TagSetRequestWithList                  SetRequestTag = 0x4
	TagSetRequestWithListAndFirstDataBlock SetRequestTag = 0x5
)

type SetResponseTag byte

const (
	TagSetResponseNormal                SetResponseTag = 0x1
	TagSetResponseDataBlock             SetResponseTag = 0x2
	TagSetResponseLastDataBlock         SetResponseTag = 0x3
	TagSetResponseLastDataBlockWithList SetResponseTag = 0x4
	TagSetResponseWithList              SetResponseTag = 0x5
)

type ActionRequestTag byte

const (
	TagActionRequestNormal                 ActionRequestTag = 0x1
	TagActionRequestNextPBlock             ActionRequestTag = 0x2
	TagActionRequestWithList               ActionRequestTag = 0x3
	TagActionRequestWithFirstPBlock        ActionRequestTag = 0x4
	TagActionRequestWithListAndFirstPBlock ActionRequestTag = 0x5
	TagActionRequestWithPBlock             ActionRequestTag = 0x6
)

type ActionResponseTag byte

const (
	TagActionResponseNormal     ActionResponseTag = 0x1
	TagActionResponseWithPBlock ActionResponseTag = 0x2
	TagActionResponseWithList   ActionResponseTag = 0x3
	TagActionResponseNextPBlock ActionResponseTag = 0x4
)

type ValueType byte

const (
	SignedInt   ValueType = 0   // int64
	UnsignedInt ValueType = 1   // uint64
	Real        ValueType = 2   // float64
	String      ValueType = 3   // string
	DateTime    ValueType = 4   // DlmsDateTime
	Boolean     ValueType = 5   // bool
	Unknown     ValueType = 255 // nil

	ObisHasA = 0x20
	ObisHasB = 0x10
	ObisHasC = 0x08
	ObisHasD = 0x04
	ObisHasE = 0x02
	ObisHasF = 0x01
)

type Value struct {
	Type  ValueType
	Value any
}

func (n *Value) ToString() string {
	switch n.Type {
	case SignedInt:
		return fmt.Sprintf("%d", n.Value.(int64))
	case UnsignedInt:
		return fmt.Sprintf("%d", n.Value.(uint64))
	case Real:
		return fmt.Sprintf("%f", n.Value.(float64))
	case String:
		return n.Value.(string)
	case DateTime:
		v := n.Value.(DlmsDateTime)
		r, err := v.AsTime()
		if err != nil {
			break
		}
		return r.String()
	case Boolean:
		return fmt.Sprintf("%t", n.Value.(bool))
	}
	return "invalid"
}

type DlmsDateTime struct {
	Date      DlmsDate
	Time      DlmsTime
	Deviation int16
	Status    byte
}

const (
	DateTimeInvalidDeviation int16 = -32768
)

func (t *DlmsDateTime) String() string {
	return fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d.%02d UTC%+03d Status: %02x",
		t.Date.Year, t.Date.Month, t.Date.Day,
		t.Time.Hour, t.Time.Minute, t.Time.Second, t.Time.Hundredths, t.Deviation, t.Status)
}

func (t *DlmsDateTime) AsTime() (tt time.Time, err error) {
	if t.Date.Year == 0xffff || t.Date.Month == 0xff || t.Date.Day == 0xff || t.Time.Hour == 0xff || t.Time.Minute == 0xff {
		return tt, fmt.Errorf("invalid date or time")
	}
	ns := 0
	if t.Time.Hundredths != 0xff {
		ns = int(t.Time.Hundredths) * 10000000
	}
	dev := 0
	if t.Deviation != DateTimeInvalidDeviation {
		dev = int(t.Deviation)
	}
	tt = time.Date(int(t.Date.Year), time.Month(t.Date.Month), int(t.Date.Day), int(t.Time.Hour), int(t.Time.Minute), int(t.Time.Second), ns, time.FixedZone("UTC", dev*60))
	return
}

func (t *DlmsDateTime) AsUTCTime() (tt time.Time, err error) {
	tmp := t.Deviation
	t.Deviation = 0
	tt, err = t.AsTime()
	t.Deviation = tmp
	return
}

func (t *DlmsDateTime) EncodeToDlms(dst *bytes.Buffer) {
	encodelength(dst, 12)
	dst.WriteByte(byte(t.Date.Year >> 8))
	dst.WriteByte(byte(t.Date.Year))
	dst.WriteByte(t.Date.Month)
	dst.WriteByte(t.Date.Day)
	dst.WriteByte(t.Date.DayOfWeek)
	dst.WriteByte(t.Time.Hour)
	dst.WriteByte(t.Time.Minute)
	dst.WriteByte(t.Time.Second)
	dst.WriteByte(t.Time.Hundredths)
	dst.WriteByte(byte(t.Deviation >> 8))
	dst.WriteByte(byte(t.Deviation))
	dst.WriteByte(t.Status)
}

// NewDlmsDateTimeFromTime converts a Go time.Time to a DLMS DateTime structure.
// The timezone offset is extracted from the source time.
func NewDlmsDateTimeFromTime(src time.Time) DlmsDateTime {
	wd := byte(src.Weekday())
	if wd == 0 {
		wd = 7
	}
	_, off := src.Zone()
	return DlmsDateTime{
		Date:      DlmsDate{Year: uint16(src.Year()), Month: byte(src.Month()), Day: byte(src.Day()), DayOfWeek: wd},
		Time:      DlmsTime{Hour: byte(src.Hour()), Minute: byte(src.Minute()), Second: byte(src.Second()), Hundredths: byte(src.Nanosecond() / 10000000)},
		Deviation: int16(off / 60),
		Status:    0,
	}
}

type DlmsDateTimeOptions byte

const (
	DlmsDateTimeNoOption          DlmsDateTimeOptions = 0x00
	DlmsDateTimeClearMilliseconds DlmsDateTimeOptions = 0x01
	DlmsDateTimeSetDstBit         DlmsDateTimeOptions = 0x02
	DlmsDateTimeSetInvalidStatus  DlmsDateTimeOptions = 0x04
)

// NewDlmsDateTimeFromTime2 converts a Go time.Time to a DLMS DateTime with custom options and deviation.
// Options can control milliseconds, DST bit, and status field settings.
func NewDlmsDateTimeFromTime2(src time.Time, options DlmsDateTimeOptions, deviation int16) DlmsDateTime {
	wd := byte(src.Weekday())
	if wd == 0 {
		wd = 7
	}
	ret := DlmsDateTime{
		Date:      DlmsDate{Year: uint16(src.Year()), Month: byte(src.Month()), Day: byte(src.Day()), DayOfWeek: wd},
		Time:      DlmsTime{Hour: byte(src.Hour()), Minute: byte(src.Minute()), Second: byte(src.Second()), Hundredths: byte(src.Nanosecond() / 10000000)},
		Deviation: deviation,
		Status:    0,
	}
	if options&DlmsDateTimeClearMilliseconds != 0 {
		ret.Time.Hundredths = 0
	}
	if options&DlmsDateTimeSetDstBit != 0 {
		ret.Status |= 0x80
	}
	if options&DlmsDateTimeSetInvalidStatus != 0 {
		ret.Status = 0xff
	}
	return ret
}

// NewDlmsDateTimeFromSlice creates a DLMS DateTime from a 12-byte slice.
func NewDlmsDateTimeFromSlice(src []byte) (val DlmsDateTime, err error) {
	if len(src) < 12 {
		err = fmt.Errorf("invalid length")
		return
	}
	return DlmsDateTime{
		Date:      DlmsDate{Year: uint16(src[0])<<8 | uint16(src[1]), Month: src[2], Day: src[3], DayOfWeek: src[4]},
		Time:      DlmsTime{Hour: src[5], Minute: src[6], Second: src[7], Hundredths: src[8]},
		Deviation: int16(src[9])<<8 | int16(src[10]),
		Status:    src[11],
	}, nil
}

type DlmsDate struct {
	Year      uint16
	Month     byte
	Day       byte
	DayOfWeek byte
}

type DlmsTime struct {
	Hour       byte
	Minute     byte
	Second     byte
	Hundredths byte
}

type DlmsObis struct {
	A byte
	B byte
	C byte
	D byte
	E byte
	F byte
}

type DlmsObisLayoutType byte

const (
	ObisLayoutStandart DlmsObisLayoutType = 0x00
	ObisLayoutAsterisk DlmsObisLayoutType = 0x01
	ObisLayoutDots     DlmsObisLayoutType = 0x02
)

func (o DlmsObis) String() string {
	return fmt.Sprintf("%d-%d:%d.%d.%d.%d", o.A, o.B, o.C, o.D, o.E, o.F)
}

func (o DlmsObis) Format(layout DlmsObisLayoutType) string {
	switch layout {
	case ObisLayoutAsterisk:
		return fmt.Sprintf("%d-%d:%d.%d.%d*%d", o.A, o.B, o.C, o.D, o.E, o.F)
	case ObisLayoutDots:
		return fmt.Sprintf("%d.%d.%d.%d.%d.%d", o.A, o.B, o.C, o.D, o.E, o.F)
	default:
		return o.String()
	}
}

func (o DlmsObis) Bytes() []byte {
	return []byte{o.A, o.B, o.C, o.D, o.E, o.F}
}

func (o DlmsObis) EqualTo(o2 DlmsObis) bool {
	return o.A == o2.A && o.B == o2.B && o.C == o2.C && o.D == o2.D && o.E == o2.E && o.F == o2.F
}

// NewDlmsObisFromSlice creates a DLMS OBIS code from a 6-byte slice.
func NewDlmsObisFromSlice(src []byte) (ob DlmsObis, err error) {
	if len(src) < 6 {
		err = fmt.Errorf("invalid length")
		return
	}
	return DlmsObis{A: src[0], B: src[1], C: src[2], D: src[3], E: src[4], F: src[5]}, nil
}

func mustatoi(s string) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		// This should not happen as the regex already validated the format
		panic(err)
	}
	return i
}

// NewDlmsObisFromString parses a DLMS OBIS code from a string (e.g., "1-0:1.8.0.255").
func NewDlmsObisFromString(src string) (ob DlmsObis, err error) {
	ob, _, err = NewDlmsObisFromStringComp(src)
	return
}

var stdobisregex = regexp.MustCompile(`^((\d+)-(\d+):)?(\d+)\.(\d+)(\.(\d+)([\.*](\d+))?)?$`)
var dotobisregex = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)\.(\d+)\.(\d+)(\.(\d+))?$`)

// NewDlmsObisFromStringComp parses a DLMS OBIS code from a string and returns which components are present.
// The cmp return value is a bitmask indicating which OBIS fields (A-F) were specified.
func NewDlmsObisFromStringComp(src string) (ob DlmsObis, cmp int, err error) {
	var a, b, c, d, e, f int
	cmp = ObisHasC | ObisHasD
	m := stdobisregex.FindStringSubmatch(src)
	if m == nil {
		m = dotobisregex.FindStringSubmatch(src)
		if m == nil {
			err = fmt.Errorf("invalid format")
			return
		}
		a = mustatoi(m[1])
		b = mustatoi(m[2])
		cmp |= ObisHasA | ObisHasB | ObisHasE
		c = mustatoi(m[3])
		d = mustatoi(m[4])
		e = mustatoi(m[5])
		f = 255
		if len(m[6]) > 0 {
			f = mustatoi(m[7])
			cmp |= ObisHasF
		}
	} else {
		if len(m[1]) > 0 {
			a = mustatoi(m[2])
			b = mustatoi(m[3])
			cmp |= ObisHasA | ObisHasB
		}
		c = mustatoi(m[4])
		d = mustatoi(m[5])
		e, f = 255, 255
		if len(m[6]) > 0 {
			e = mustatoi(m[7])
			cmp |= ObisHasE
			if len(m[8]) > 0 {
				f = mustatoi(m[9])
				cmp |= ObisHasF
			}
		}
	}

	if a > 255 || b > 255 || c > 255 || d > 255 || e > 255 || f > 255 {
		err = fmt.Errorf("invalid value, all parts must be 0-255")
		return
	}
	ob.A = byte(a)
	ob.B = byte(b)
	ob.C = byte(c)
	ob.D = byte(d)
	ob.E = byte(e)
	ob.F = byte(f)
	return
}
