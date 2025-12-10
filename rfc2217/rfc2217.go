package rfc2217

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/cybroslabs/libdlms-go/base"
	"go.uber.org/zap"
)

const (
	COM_PORT_OPTION = 44 // 0x2c
	BINARY_OPTION   = 0
	SGA_OPTION      = 3

	IAC = 255
	SB  = 250 // 0xfa
	SE  = 240 // 0xf0

	WILL = 251 // 0xfb
	WONT = 252 // 0xfc
	DO   = 253 // 0xfd
	DONT = 254 // 0xfe

	Signature = "DLMS-Serial-Client"

	writeChunk = 2048
)

type rfc2217Serial struct {
	transport   base.Stream // usually tcp
	isopen      bool
	writebuffer []byte

	settings     base.SerialStreamSettings
	havesettings bool

	// status variables
	linestate  byte
	modemstate byte

	logger *zap.SugaredLogger
}

func (r *rfc2217Serial) logf(format string, v ...any) {
	if r.logger != nil {
		r.logger.Infof(format, v...)
	}
}

// Close implements SerialStream.
func (r *rfc2217Serial) Close() error {
	return nil // just do nothing, yes, bad semantic, should be renamed
}

// Disconnect implements SerialStream.
func (r *rfc2217Serial) Disconnect() error {
	r.isopen = false
	return r.transport.Disconnect()
}

// GetRxTxBytes implements SerialStream.
func (r *rfc2217Serial) GetRxTxBytes() (int64, int64) {
	return r.transport.GetRxTxBytes()
}

// Open implements SerialStream.
func (r *rfc2217Serial) Open() error {
	if r.isopen {
		return nil
	}

	if err := sanityControl(r.settings.FlowControl); err != nil {
		return err
	}
	if err := sanitySpeed(r.settings.BaudRate, r.settings.DataBits, r.settings.Parity, r.settings.StopBits); err != nil {
		return err
	}

	if err := r.transport.Open(); err != nil {
		return err
	}

	// set basic telnet options like binary, echo and go ahead ability (seen from other source)
	r.logf("negotiating telnet options")
	r.writebuffer = r.writeOption(r.writebuffer[:0], BINARY_OPTION, WILL)
	r.writebuffer = r.writeOption(r.writebuffer, SGA_OPTION, WILL)
	r.writebuffer = r.writeOption(r.writebuffer, COM_PORT_OPTION, WILL)
	// do purge here?
	r.writebuffer = r.writeSubnegotiation(r.writebuffer, 12, []byte{0x03}) // purge data
	// According to RFC855, binary mode and SGA are false by default
	// Send an artificial signature for identification
	r.writebuffer = r.writeSignature(r.writebuffer)

	// set desired settings
	if r.havesettings {
		var cmd [4]byte
		binary.BigEndian.PutUint32(cmd[:], uint32(r.settings.BaudRate))
		r.writebuffer = r.writeSubnegotiation(r.writebuffer, 1, cmd[:])
		cmd[0] = byte(r.settings.DataBits)
		r.writebuffer = r.writeSubnegotiation(r.writebuffer, 2, cmd[:1])
		cmd[0] = byte(r.settings.Parity)
		r.writebuffer = r.writeSubnegotiation(r.writebuffer, 3, cmd[:1])
		cmd[0] = byte(r.settings.StopBits)
		r.writebuffer = r.writeSubnegotiation(r.writebuffer, 4, cmd[:1])

		cmd[0] = byte(r.settings.FlowControl)
		r.writebuffer = r.writeSubnegotiation(r.writebuffer[:0], 5, cmd[:1])
		if r.settings.FlowControl == base.SerialNoFlowControl { // set RTS to true by force
			cmd[0] = 11
			r.writebuffer = r.writeSubnegotiation(r.writebuffer, 5, cmd[:1])
		}
	}
	r.isopen = true
	return r.transport.Write(r.writebuffer)
}

func (r *rfc2217Serial) writeOption(src []byte, option byte, intent byte) []byte {
	return append(src, IAC, intent, option)
}

func (r *rfc2217Serial) writeSignature(src []byte) []byte {
	src = append(src, IAC, SB, COM_PORT_OPTION, 0)
	src = append(src, Signature...)
	return append(src, IAC, SE)
}

func (r *rfc2217Serial) writeSubnegotiation(src []byte, cmd byte, value []byte) []byte {
	src = append(src, IAC, SB, COM_PORT_OPTION, cmd)
	for _, b := range value { // maybe a bit too much
		if b == IAC {
			src = append(src, IAC)
		}
		src = append(src, b)
	}
	return append(src, IAC, SE)
}

func (r *rfc2217Serial) getCode() (byte, error) {
	var code [1]byte
	_, err := io.ReadFull(r.transport, code[:])
	if err != nil {
		return 0, err
	}
	return code[0], nil
}

func (r *rfc2217Serial) processCommand(cmd byte) (err error) {
	var code byte
	switch cmd {
	case WILL: // confirm that something is happening, just check that
		code, err = r.getCode()
		if err != nil {
			return err
		}
		switch code {
		case BINARY_OPTION, SGA_OPTION, COM_PORT_OPTION:
		default:
			r.logf("other party has intent to do %v", code)
			return fmt.Errorf("unsupported com state")
		}
	case WONT:
		code, err = r.getCode()
		if err != nil {
			return err
		}
		switch code {
		case BINARY_OPTION, SGA_OPTION, COM_PORT_OPTION:
			r.logf("other party doesnt support mandatory option %v")
			return fmt.Errorf("unsupported mandatory option")
		default:
			r.logf("other party has intent not to do %v", code)
		}
	case DO:
		code, err = r.getCode()
		if err != nil {
			return err
		}
		switch code {
		case BINARY_OPTION, SGA_OPTION, COM_PORT_OPTION:
		default:
			r.logf("other party has intent to do %v", code)
			return r.transport.Write([]byte{IAC, WONT, code}) // immediate response
		}
	case DONT:
		code, err = r.getCode()
		if err != nil {
			return err
		}
		switch code {
		case BINARY_OPTION, SGA_OPTION, COM_PORT_OPTION:
			r.logf("other party doesnt want mandatory option %v")
			return fmt.Errorf("unsupported mandatory option")
		default:
			r.logf("other party has intent not to do %v", code)
			return r.transport.Write([]byte{IAC, WONT, code})
		}
	case SB:
		return r.handleSubnegotiation()
	default:
		r.logf("unknown/unsupported command: %02x", cmd)
	}
	return nil
}

func (r *rfc2217Serial) handleSubnegotiation() error {
	var buffer [1024]byte // maximum size of subnegotiation command
	var s [1]byte
	offset := 0
	riac := false
	for {
		if offset >= len(buffer) {
			return fmt.Errorf("subnegotiation buffer overflow")
		}

		_, err := io.ReadFull(r.transport, s[:])
		if err != nil {
			return err
		}
		if riac {
			switch s[0] {
			case IAC:
				buffer[offset] = IAC
				offset++
				riac = false
			case SE:
				return r.processSubnegotiation(buffer[:offset])
			default:
				return fmt.Errorf("invalid subnegotiation command")
			}
		} else {
			if s[0] == IAC {
				riac = true
			} else {
				buffer[offset] = s[0]
				offset++
			}
		}
	}
}

func (r *rfc2217Serial) processSubnegotiation(sub []byte) error {
	if len(sub) < 2 {
		return fmt.Errorf("subnegotiation too short")
	}
	if sub[0] != COM_PORT_OPTION {
		return fmt.Errorf("unsupported subnegotiation option %02x", sub[0])
	}
	sub = sub[1:]
	switch sub[0] {
	case 0: // signature
		if len(sub) == 1 { // wanted signature?
			r.writebuffer = r.writeSignature(r.writebuffer[:0])
			return r.transport.Write(r.writebuffer)
		}
		r.logf("signature: \"%s\"", strings.Trim(string(sub[1:]), "\x00 \n\r\t"))
	case 101: // set baud rate
		if len(sub) != 5 {
			return fmt.Errorf("invalid subnegotiation length")
		}
		baudrate := int(binary.BigEndian.Uint32(sub[1:]))
		r.logf("reported baudrate: %d", baudrate)
	case 102: // set data bits
		if len(sub) != 2 {
			return fmt.Errorf("invalid subnegotiation length")
		}
		switch base.SerialDataBits(sub[1]) {
		case base.Serial5DataBits, base.Serial6DataBits, base.Serial7DataBits, base.Serial8DataBits:
		default:
			return fmt.Errorf("unsupported data bits %02x", sub[1])
		}
		databits := base.SerialDataBits(sub[1])
		r.logf("reported data bits: %v", databits)
	case 103: // set parity
		if len(sub) != 2 {
			return fmt.Errorf("invalid subnegotiation length")
		}
		switch base.SerialParity(sub[1]) {
		case base.SerialNoParity, base.SerialOddParity, base.SerialEvenParity, base.SerialMarkParity, base.SerialSpaceParity:
		default:
			return fmt.Errorf("unsupported parity %02x", sub[1])
		}
		parity := base.SerialParity(sub[1])
		r.logf("reported parity: %v", parity)
	case 104: // set stop bits
		if len(sub) != 2 {
			return fmt.Errorf("invalid subnegotiation length")
		}
		switch base.SerialStopBits(sub[1]) {
		case base.SerialOneStopBit, base.SerialTwoStopBits, base.SerialOneAndHalfStopBits:
		default:
			return fmt.Errorf("unsupported stop bits %02x", sub[1])
		}
		stopbits := base.SerialStopBits(sub[1])
		r.logf("reported stop bits: %v", stopbits)
	case 105: // set control
		if len(sub) != 2 {
			return fmt.Errorf("invalid subnegotiation length")
		}
		switch base.SerialFlowControl(sub[1]) {
		case base.SerialNoFlowControl, base.SerialSWFlowControl, base.SerialHWFlowControl, base.SerialDCDFlowControl, base.SerialDSRFlowControl:
			control := base.SerialFlowControl(sub[1])
			r.logf("reported control: %v", control)
		default:
			r.logf("unsupported control %02x", sub[1])
		}
	case 106: // notify line state
		if len(sub) != 2 {
			return fmt.Errorf("invalid subnegotiation length")
		}
		r.linestate = sub[1]
		r.logf("reported line state: %02x", r.linestate)
	case 107: // notify modem state
		if len(sub) != 2 {
			return fmt.Errorf("invalid subnegotiation length")
		}
		r.modemstate = sub[1]
		r.logf("reported modem state: %02x", r.modemstate)
	case 108, 109: // flow control suspend, flow control resume
		if len(sub) != 1 {
			return fmt.Errorf("invalid subnegotiation length")
		}
		r.logf("flow control notification: %d", sub[0])
	case 110, 111, 112: // set line state mask, set modem state mask, purge data
		if len(sub) != 2 {
			return fmt.Errorf("invalid subnegotiation length")
		}
		r.logf("access server notification: %d with data %02x", sub[0], sub[1])
	default:
		return fmt.Errorf("unsupported subnegotiation command %02x", sub[0])
	}
	return nil
}

// Read implements SerialStream.
func (r *rfc2217Serial) Read(p []byte) (n int, err error) {
	if !r.isopen {
		return 0, base.ErrNotOpened
	}
	if len(p) == 0 {
		return 0, base.ErrNothingToRead
	}

	// read byte by byte, as lower layew SHOULD be buffered, that approach should be fine
	var nn int
	for len(p) > 0 {
		nn, err = r.transport.Read(p[:1])
		if err != nil {
			return // Return both n and error (may be EOF with partial data)
		}
		if nn == 0 {
			return n, io.EOF
		}
		if p[0] == IAC { // le problem, at least another byte should be read
			_, err = io.ReadFull(r.transport, p[:1])
			if err != nil {
				return
			}
			if p[0] != IAC {
				err = r.processCommand(p[0])
				if err != nil {
					return
				}
			} else {
				p = p[1:]
				n++
			}
		} else {
			p = p[1:]
			n++
		}
	}
	return
}

func (r *rfc2217Serial) SetTimeout(t time.Duration) {
	r.transport.SetTimeout(t)
}

// SetDeadline implements SerialStream.
func (r *rfc2217Serial) SetDeadline(t time.Time) {
	r.transport.SetDeadline(t)
}

// SetLogger implements SerialStream.
func (r *rfc2217Serial) SetLogger(logger *zap.SugaredLogger) {
	r.logger = logger
	r.transport.SetLogger(logger)
}

// SetMaxReceivedBytes implements SerialStream.
func (r *rfc2217Serial) SetMaxReceivedBytes(m int64) {
	r.transport.SetMaxReceivedBytes(m)
}

func (r *rfc2217Serial) SetDTR(dtr bool) error {
	if !r.isopen {
		return base.ErrNotOpened
	}

	setdtr := byte(8)
	if !dtr {
		setdtr = 9
	}
	r.writebuffer = r.writeSubnegotiation(r.writebuffer[:0], 5, []byte{setdtr})
	return r.transport.Write(r.writebuffer)
}

// SetFlowControl implements SerialStream.
func (r *rfc2217Serial) SetFlowControl(flowControl base.SerialFlowControl) error {
	if !r.isopen {
		return base.ErrNotOpened
	}

	if err := sanityControl(flowControl); err != nil {
		return err
	}

	r.settings.FlowControl = flowControl

	r.writebuffer = r.writeSubnegotiation(r.writebuffer[:0], 5, []byte{byte(flowControl)})
	if flowControl == base.SerialNoFlowControl { // set RTS to true by force
		r.writebuffer = r.writeSubnegotiation(r.writebuffer, 5, []byte{11})
	}
	return r.transport.Write(r.writebuffer)
}

func sanityControl(flowControl base.SerialFlowControl) error {
	switch flowControl {
	case base.SerialNoFlowControl, base.SerialSWFlowControl, base.SerialHWFlowControl, base.SerialDCDFlowControl, base.SerialDSRFlowControl:
	default:
		return fmt.Errorf("unsupported flow control %d", flowControl)
	}
	return nil
}

func sanitySpeed(baudRate int, dataBits base.SerialDataBits, parity base.SerialParity, stopBits base.SerialStopBits) error {
	switch baudRate {
	case 300, 600, 1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 128000, 256000:
	default:
		return fmt.Errorf("unsupported baud rate %d", baudRate)
	}
	switch dataBits {
	case base.Serial5DataBits, base.Serial6DataBits, base.Serial7DataBits, base.Serial8DataBits:
	default:
		return fmt.Errorf("unsupported data bits %d", dataBits)
	}
	switch parity {
	case base.SerialNoParity, base.SerialOddParity, base.SerialEvenParity, base.SerialMarkParity, base.SerialSpaceParity:
	default:
		return fmt.Errorf("unsupported parity %d", parity)
	}
	switch stopBits {
	case base.SerialOneStopBit, base.SerialTwoStopBits, base.SerialOneAndHalfStopBits:
	default:
		return fmt.Errorf("unsupported stop bits %d", stopBits)
	}

	return nil
}

// SetSpeed implements SerialStream.
func (r *rfc2217Serial) SetSpeed(baudRate int, dataBits base.SerialDataBits, parity base.SerialParity, stopBits base.SerialStopBits) error {
	var cmd [4]byte
	if !r.isopen {
		return base.ErrNotOpened
	}

	if err := sanitySpeed(baudRate, dataBits, parity, stopBits); err != nil {
		return err
	}

	r.settings.BaudRate = baudRate
	r.settings.DataBits = dataBits
	r.settings.Parity = parity
	r.settings.StopBits = stopBits

	binary.BigEndian.PutUint32(cmd[:], uint32(baudRate))
	r.writebuffer = r.writeSubnegotiation(r.writebuffer[:0], 1, cmd[:])
	cmd[0] = byte(dataBits)
	r.writebuffer = r.writeSubnegotiation(r.writebuffer, 2, cmd[:1])
	cmd[0] = byte(parity)
	r.writebuffer = r.writeSubnegotiation(r.writebuffer, 3, cmd[:1])
	cmd[0] = byte(stopBits)
	r.writebuffer = r.writeSubnegotiation(r.writebuffer, 4, cmd[:1])
	return r.transport.Write(r.writebuffer)
}

// Write implements SerialStream.
func (r *rfc2217Serial) Write(src []byte) error {
	if !r.isopen {
		return base.ErrNotOpened
	}
	if len(src) == 0 {
		return nil
	}
	// escape IAC bytes, limit size and chunk that thing, even not optimally due to lower MTU?
	r.writebuffer = r.writebuffer[:0]
	for _, b := range src {
		if len(r.writebuffer) >= writeChunk {
			if err := r.transport.Write(r.writebuffer); err != nil {
				return err
			}
			r.writebuffer = r.writebuffer[:0]
		}
		if b == IAC {
			r.writebuffer = append(r.writebuffer, IAC)
		}
		r.writebuffer = append(r.writebuffer, b)
	}
	return r.transport.Write(r.writebuffer)
}

func New(t base.Stream, settings *base.SerialStreamSettings) base.SerialStream {
	ret := &rfc2217Serial{
		transport:   t,
		isopen:      false,
		writebuffer: make([]byte, 0, 1024),
	}
	if settings != nil {
		ret.havesettings = true
		ret.settings = *settings // at least copy
	}
	return ret
}
