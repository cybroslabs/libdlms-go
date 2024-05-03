package dlmsal

type ReleaseRequestReason byte

const (
	ReleaseRequestReasonNormal      ReleaseRequestReason = 0
	ReleaseRequestReasonUrgent      ReleaseRequestReason = 1
	ReleaseRequestReasonUserDefined ReleaseRequestReason = 30
)

func encodeRLRQ(_ *DlmsSettings) (out []byte, err error) {
	out = make([]byte, 5)
	out[0] = byte(TagRLRQ)
	out[1] = 3
	out[2] = BERTypeContext
	out[3] = 1
	out[4] = byte(ReleaseRequestReasonNormal)

	return
}
