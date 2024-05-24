package dlmsal

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

type NumberType byte

const (
	SignedInt   NumberType = 0
	UnsignedInt NumberType = 1
	Real        NumberType = 2
)

type Number struct {
	Type        NumberType
	SignedInt   int64
	UnsignedInt uint64
	Real        float64
}

func (n *Number) String() string {
	switch n.Type {
	case SignedInt:
		return fmt.Sprintf("%d", n.SignedInt)
	case UnsignedInt:
		return fmt.Sprintf("%d", n.UnsignedInt)
	case Real:
		return fmt.Sprintf("%f", n.Real)
	}
	return "invalid"
}

type DlmsDateTime struct {
	Date      DlmsDate
	Time      DlmsTime
	Deviation int16
	Status    byte
}

func (t *DlmsDateTime) ToTime() (tt time.Time, err error) {
	if t.Date.Year == 0xffff || t.Date.Month == 0xff || t.Date.Day == 0xff || t.Time.Hour == 0xff || t.Time.Minute == 0xff {
		return tt, fmt.Errorf("invalid date or time")
	}
	ns := 0
	if t.Time.Hundredths != 0xff {
		ns = int(t.Time.Hundredths) * 10000000
	}
	dev := 0
	if t.Deviation != -32768 {
		dev = int(t.Deviation)
	}
	tt = time.Date(int(t.Date.Year), time.Month(t.Date.Month), int(t.Date.Day), int(t.Time.Hour), int(t.Time.Minute), int(t.Time.Second), ns, time.FixedZone("UTC", dev*60))
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

func NewDlmsDateTimeFromTime(src *time.Time) *DlmsDateTime {
	wd := byte(src.Weekday())
	if wd == 0 {
		wd = 7
	}
	_, off := src.Zone()
	return &DlmsDateTime{
		Date:      DlmsDate{Year: uint16(src.Year()), Month: byte(src.Month()), Day: byte(src.Day()), DayOfWeek: wd},
		Time:      DlmsTime{Hour: byte(src.Hour()), Minute: byte(src.Minute()), Second: byte(src.Second()), Hundredths: byte(src.Nanosecond() / 10000000)},
		Deviation: int16(off / 60),
		Status:    0,
	}
}

func NewDlmsDateTimeFromSlice(src []byte) (*DlmsDateTime, error) {
	if len(src) < 12 {
		return nil, fmt.Errorf("invalid length")
	}
	return &DlmsDateTime{
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

func (o *DlmsObis) String() string {
	return fmt.Sprintf("%d-%d:%d.%d.%d.%d", o.A, o.B, o.C, o.D, o.E, o.F)
}

func (o *DlmsObis) Bytes() []byte {
	return []byte{o.A, o.B, o.C, o.D, o.E, o.F}
}

func (o *DlmsObis) EqualTo(o2 *DlmsObis) bool {
	return o.A == o2.A && o.B == o2.B && o.C == o2.C && o.D == o2.D && o.E == o2.E && o.F == o2.F
}

func NewDlmsObisFromSlice(src []byte) (*DlmsObis, error) {
	if len(src) < 6 {
		return nil, fmt.Errorf("invalid length")
	}
	return &DlmsObis{A: src[0], B: src[1], C: src[2], D: src[3], E: src[4], F: src[5]}, nil
}

func mustatoi(s string) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		panic(err)
	}
	return i
}

func NewDlmsObisFromString(src string) (*DlmsObis, error) {
	rg := regexp.MustCompile(`^(\d+)-(\d+):(\d+)\.(\d+)\.(\d+)\.(\d+)$`)
	if !rg.MatchString(src) {
		return nil, fmt.Errorf("invalid format")
	}
	m := rg.FindStringSubmatch(src)
	a := mustatoi(m[1])
	b := mustatoi(m[2])
	c := mustatoi(m[3])
	d := mustatoi(m[4])
	e := mustatoi(m[5])
	f := mustatoi(m[6])
	if a < 0 || b < 0 || c < 0 || d < 0 || e < 0 || f < 0 || a > 255 || b > 255 || c > 255 || d > 255 || e > 255 || f > 255 {
		return nil, fmt.Errorf("invalid value")
	}
	return &DlmsObis{A: byte(a), B: byte(b), C: byte(c), D: byte(d), E: byte(e), F: byte(f)}, nil
}
