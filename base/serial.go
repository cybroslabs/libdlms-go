package base

const (
	Serial5DataBits          = 5
	Serial6DataBits          = 6
	Serial7DataBits          = 7
	Serial8DataBits          = 8
	SerialNoParity           = 1
	SerialOddParity          = 2
	SerialEvenParity         = 3
	SerialMarkParity         = 4
	SerialSpaceParity        = 5
	SerialOneStopBit         = 1
	SerialTwoStopBits        = 2
	SerialOneAndHalfStopBits = 3
	SerialNoFlowControl      = 1
	SerialSWFlowControl      = 2
	SerialHWFlowControl      = 3
	SerialDCDFlowControl     = 17
	SerialDSRFlowControl     = 19
)

type SerialStream interface {
	Stream

	SetSpeed(baudRate int, dataBits int, parity int, stopBits int) error
	SetFlowControl(flowControl int) error
	SetDTR(dtr bool) error
}
