package dlmsal

import (
	"errors"
	"io"
)

func decodeException(src io.Reader, tmp *tmpbuffer) (e DlmsData, err error) {
	var n int
	n, err = io.ReadFull(src, tmp[:2])
	switch n {
	case 0:
		e = NewDlmsDataError(TagResultOtherReason)
	case 1, 2:
		e = NewDlmsDataError(TagResultOtherReason) // not decoding state-error or service-error
	default:
		panic("programatic error, unexpected read bytes count")
	}
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			err = nil
		}
	}
	return
}
