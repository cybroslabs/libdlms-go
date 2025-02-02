package base

type SerialDataBits int
type SerialParity int
type SerialStopBits int
type SerialFlowControl int

const (
	Serial5DataBits          SerialDataBits    = 5
	Serial6DataBits          SerialDataBits    = 6
	Serial7DataBits          SerialDataBits    = 7
	Serial8DataBits          SerialDataBits    = 8
	SerialNoParity           SerialParity      = 1
	SerialOddParity          SerialParity      = 2
	SerialEvenParity         SerialParity      = 3
	SerialMarkParity         SerialParity      = 4
	SerialSpaceParity        SerialParity      = 5
	SerialOneStopBit         SerialStopBits    = 1
	SerialTwoStopBits        SerialStopBits    = 2
	SerialOneAndHalfStopBits SerialStopBits    = 3
	SerialNoFlowControl      SerialFlowControl = 1
	SerialSWFlowControl      SerialFlowControl = 2
	SerialHWFlowControl      SerialFlowControl = 3
	SerialDCDFlowControl     SerialFlowControl = 17
	SerialDSRFlowControl     SerialFlowControl = 19
)

type SerialStreamSettings struct {
	BaudRate    int
	DataBits    SerialDataBits
	Parity      SerialParity
	StopBits    SerialStopBits
	FlowControl SerialFlowControl
}

type SerialStream interface {
	Stream

	SetSpeed(baudRate int, dataBits SerialDataBits, parity SerialParity, stopBits SerialStopBits) error
	SetFlowControl(flowControl SerialFlowControl) error
	SetDTR(dtr bool) error
}
