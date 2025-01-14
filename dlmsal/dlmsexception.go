package dlmsal

import (
	"fmt"
	"io"
)

func decodeException(src io.Reader, tmp *tmpbuffer) (e DlmsData, err error) {
	var n int
	n, err = io.ReadFull(src, tmp[:2])
	switch n {
	case 0:
		e = NewDlmsDataError(TagAccOtherReason)
	case 1:
		e = NewDlmsDataError(TagAccOtherReason) // not decoding state-error
	case 2:
		e = NewDlmsDataError(TagAccOtherReason) // not decoding service error
	default:
		err = fmt.Errorf("programatic error, unexpected read bytes count")
	}
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		err = nil
	}
	return
}
