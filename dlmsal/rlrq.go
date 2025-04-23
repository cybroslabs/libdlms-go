package dlmsal

import "github.com/cybroslabs/libdlms-go/base"

func encodeRLRQ(s *DlmsSettings) (out []byte, err error) {
	out = make([]byte, 5)
	out[0] = byte(base.TagRLRQ)
	if s.EmptyRLRQ {
		out[1] = 0
		return out[:2], nil
	}

	out[1] = 3
	out[2] = base.BERTypeContext
	out[3] = 1
	out[4] = byte(base.ReleaseRequestReasonNormal)
	return
}
