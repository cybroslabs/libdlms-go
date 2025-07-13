package base

import (
	"fmt"
	"io"
	"strings"
	"time"

	"go.uber.org/zap"
)

type Stream interface { // todo add ByteReader here
	io.ReadCloser
	Open() error
	Disconnect() error // hard end of connection without solving any unassociation or so
	SetLogger(logger *zap.SugaredLogger)
	SetDeadline(t time.Time)     // zero time means no deadline
	SetTimeout(t time.Duration)  // zero duration means no timeout
	SetMaxReceivedBytes(m int64) // every call resets current counter, exceeding bytes count means comm error, only incomming bytes are counted
	Write(src []byte) error      // always write everything
	GetRxTxBytes() (int64, int64)
}

func LogHex(s string, b []byte) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s (%d):", s, len(b)))
	cnt := 0
	var sbl2 strings.Builder
	lastline := 0

	for _, v := range b {
		if (cnt & 0xf) == 0 {
			if sbl2.Len() != 0 {
				sb.WriteString(" ")
				sb.WriteString(sbl2.String())
				sb.WriteString("\n")
			} else {
				sb.WriteString("\n")
			}
			sbl2.Reset()
			sb.WriteString(fmt.Sprintf("%08X", cnt))
			lastline = 9
		}
		sb.WriteString(fmt.Sprintf(" %02X", v))
		sbl2.WriteString(byteToChar(v))
		lastline += 3
		cnt++
	}
	if sbl2.Len() != 0 {
		for lastline < 58 {
			sb.WriteString(" ")
			lastline++
		}
		sb.WriteString(sbl2.String())
	}

	return sb.String()
}

func byteToChar(d byte) string {
	if d >= 32 && d < 127 {
		return string(d)
	}
	return "."
}
