package moxarealcom

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/cybroslabs/libdlms-go/base"
	"go.uber.org/zap"
)

// ASPP (Async Server Protocol) Command Codes
const (
	ASPP_CMD_IOCTL         = 16
	ASPP_CMD_FLOWCTRL      = 17
	ASPP_CMD_LINECTRL      = 18
	ASPP_CMD_LSTATUS       = 19
	ASPP_CMD_FLUSH         = 20
	ASPP_CMD_IQUEUE        = 21
	ASPP_CMD_OQUEUE        = 22
	ASPP_CMD_SETBAUD       = 23
	ASPP_CMD_XONXOFF       = 24
	ASPP_CMD_SETXON        = 25
	ASPP_CMD_NOTIFY        = 38
	ASPP_CMD_POLLING       = 39
	ASPP_CMD_ALIVE         = 40
	ASPP_CMD_START_BREAK   = 33
	ASPP_CMD_STOP_BREAK    = 34
	ASPP_CMD_START_NOTIFY  = 36
	ASPP_CMD_STOP_NOTIFY   = 37
	ASPP_CMD_HOST          = 43
	ASPP_CMD_PORT_INIT     = 44
	ASPP_CMD_WAIT_OQUEUE   = 47
	ASPP_CMD_TX_FIFO       = 48

	// Command Set Types
	NPREAL_ASPP_COMMAND_SET  = 1
	NPREAL_LOCAL_COMMAND_SET = 2

	// Local Commands
	LOCAL_CMD_TTY_USED   = 1
	LOCAL_CMD_TTY_UNUSED = 2

	// Modem Control Lines (for LINECTRL)
	ASPP_MODEM_DTR = 1
	ASPP_MODEM_RTS = 2

	// Flow Control Types
	ASPP_FLOW_NONE = 0
	ASPP_FLOW_HW   = 1
	ASPP_FLOW_SW   = 2

	// Buffer sizes
	writeChunk = 2048
)

type moxaRealCOMSerial struct {
	transport   base.Stream // usually tcp
	isopen      bool
	writebuffer []byte
	readbuffer  []byte

	settings     base.SerialStreamSettings
	havesettings bool

	// status variables
	linestate  byte
	modemstate byte

	logger *zap.SugaredLogger
}

func (m *moxaRealCOMSerial) logf(format string, v ...any) {
	if m.logger != nil {
		m.logger.Infof(format, v...)
	}
}

// Close implements SerialStream.
func (m *moxaRealCOMSerial) Close() error {
	return nil // just do nothing, yes, bad semantic, should be renamed
}

// Disconnect implements SerialStream.
func (m *moxaRealCOMSerial) Disconnect() error {
	if m.isopen {
		// Send TTY_UNUSED notification
		m.writebuffer = m.writeCommand(m.writebuffer[:0], NPREAL_LOCAL_COMMAND_SET, LOCAL_CMD_TTY_UNUSED, nil)
		_ = m.transport.Write(m.writebuffer) // ignore error on disconnect
		m.isopen = false
	}
	return m.transport.Disconnect()
}

// GetRxTxBytes implements SerialStream.
func (m *moxaRealCOMSerial) GetRxTxBytes() (int64, int64) {
	return m.transport.GetRxTxBytes()
}

// Open implements SerialStream.
func (m *moxaRealCOMSerial) Open() error {
	if m.isopen {
		return nil
	}

	if m.havesettings {
		if err := sanityControl(m.settings.FlowControl); err != nil {
			return err
		}
		if err := sanitySpeed(m.settings.BaudRate, m.settings.DataBits, m.settings.Parity, m.settings.StopBits); err != nil {
			return err
		}
	}

	if err := m.transport.Open(); err != nil {
		return err
	}

	m.logf("initializing moxa real com connection")

	// Send TTY_USED notification
	m.writebuffer = m.writeCommand(m.writebuffer[:0], NPREAL_LOCAL_COMMAND_SET, LOCAL_CMD_TTY_USED, nil)

	// Send PORT_INIT if we have settings
	if m.havesettings {
		// PORT_INIT command payload: baud(4) + databits(1) + stopbits(1) + parity(1)
		initData := make([]byte, 7)
		binary.BigEndian.PutUint32(initData[0:4], uint32(m.settings.BaudRate))
		initData[4] = byte(m.settings.DataBits)
		initData[5] = byte(m.settings.StopBits)
		initData[6] = byte(m.settings.Parity)
		m.writebuffer = m.writeCommand(m.writebuffer, NPREAL_ASPP_COMMAND_SET, ASPP_CMD_PORT_INIT, initData)

		// Set flow control
		flowData := []byte{byte(moxaFlowControl(m.settings.FlowControl))}
		m.writebuffer = m.writeCommand(m.writebuffer, NPREAL_ASPP_COMMAND_SET, ASPP_CMD_FLOWCTRL, flowData)

		// Set DTR and RTS high for no flow control
		if m.settings.FlowControl == base.SerialNoFlowControl {
			lineData := []byte{ASPP_MODEM_DTR | ASPP_MODEM_RTS}
			m.writebuffer = m.writeCommand(m.writebuffer, NPREAL_ASPP_COMMAND_SET, ASPP_CMD_LINECTRL, lineData)
		}
	}

	// Send START_NOTIFY to receive status updates
	m.writebuffer = m.writeCommand(m.writebuffer, NPREAL_ASPP_COMMAND_SET, ASPP_CMD_START_NOTIFY, nil)

	if err := m.transport.Write(m.writebuffer); err != nil {
		m.transport.Disconnect()
		return err
	}

	m.isopen = true
	return nil
}

// writeCommand creates a Moxa Real COM command packet
// Format: [command_set(1)][command(1)][length(2,BE)][data...]
func (m *moxaRealCOMSerial) writeCommand(dst []byte, cmdSet byte, cmd byte, data []byte) []byte {
	dst = append(dst, cmdSet, cmd)
	dataLen := len(data)
	dst = append(dst, byte(dataLen>>8), byte(dataLen))
	if dataLen > 0 {
		dst = append(dst, data...)
	}
	return dst
}

// processCommand handles incoming command packets from the server
func (m *moxaRealCOMSerial) processCommand() error {
	var header [4]byte
	_, err := io.ReadFull(m.transport, header[:])
	if err != nil {
		return err
	}

	cmdSet := header[0]
	cmd := header[1]
	length := int(binary.BigEndian.Uint16(header[2:4]))

	// Read command data if present
	var data []byte
	if length > 0 {
		if length > 1024 {
			return fmt.Errorf("command data too large: %d", length)
		}
		data = make([]byte, length)
		_, err = io.ReadFull(m.transport, data)
		if err != nil {
			return err
		}
	}

	// Process based on command set
	switch cmdSet {
	case NPREAL_ASPP_COMMAND_SET:
		return m.handleASPPCommand(cmd, data)
	case NPREAL_LOCAL_COMMAND_SET:
		m.logf("received local command: %d", cmd)
		return nil
	default:
		return fmt.Errorf("unknown command set: %d", cmdSet)
	}
}

// handleASPPCommand processes ASPP protocol commands
func (m *moxaRealCOMSerial) handleASPPCommand(cmd byte, data []byte) error {
	switch cmd {
	case ASPP_CMD_NOTIFY:
		if len(data) >= 1 {
			m.modemstate = data[0]
			m.logf("modem state notify: %02x", m.modemstate)
		}
	case ASPP_CMD_LSTATUS:
		if len(data) >= 1 {
			m.linestate = data[0]
			m.logf("line state: %02x", m.linestate)
		}
	case ASPP_CMD_POLLING:
		// Respond with ALIVE
		m.writebuffer = m.writeCommand(m.writebuffer[:0], NPREAL_ASPP_COMMAND_SET, ASPP_CMD_ALIVE, nil)
		return m.transport.Write(m.writebuffer)
	case ASPP_CMD_ALIVE:
		m.logf("received alive response")
	default:
		m.logf("unhandled ASPP command: %d (length: %d)", cmd, len(data))
	}
	return nil
}

// Read implements SerialStream.
func (m *moxaRealCOMSerial) Read(p []byte) (n int, err error) {
	if !m.isopen {
		return 0, base.ErrNotOpened
	}
	if len(p) == 0 {
		return 0, base.ErrNothingToRead
	}

	// Try to read data from transport
	// In Moxa Real COM, control commands are interspersed with data
	// We need to filter out commands and only return actual serial data
	for n < len(p) {
		// Peek at first byte to see if it's a command
		var peek [1]byte
		nn, err := m.transport.Read(peek[:])
		if err != nil {
			return n, err
		}
		if nn == 0 {
			return n, io.EOF
		}

		// Check if this looks like a command header (command sets are 1 or 2)
		if peek[0] == NPREAL_ASPP_COMMAND_SET || peek[0] == NPREAL_LOCAL_COMMAND_SET {
			// Put it back and try to process as command
			// We need to read the full command header to determine
			var header [4]byte
			header[0] = peek[0]
			_, err = io.ReadFull(m.transport, header[1:])
			if err != nil {
				return n, err
			}

			cmdSet := header[0]
			cmd := header[1]
			length := int(binary.BigEndian.Uint16(header[2:4]))

			// Read command data if present
			var data []byte
			if length > 0 {
				if length > 1024 {
					return n, fmt.Errorf("command data too large: %d", length)
				}
				data = make([]byte, length)
				_, err = io.ReadFull(m.transport, data)
				if err != nil {
					return n, err
				}
			}

			// Process the command
			if cmdSet == NPREAL_ASPP_COMMAND_SET {
				err = m.handleASPPCommand(cmd, data)
				if err != nil {
					return n, err
				}
			} else {
				m.logf("received local command: %d during read", cmd)
			}
			continue
		}

		// It's data, copy it to output
		p[n] = peek[0]
		n++
	}

	return n, nil
}

func (m *moxaRealCOMSerial) SetTimeout(t time.Duration) {
	m.transport.SetTimeout(t)
}

// SetDeadline implements SerialStream.
func (m *moxaRealCOMSerial) SetDeadline(t time.Time) {
	m.transport.SetDeadline(t)
}

// SetLogger implements SerialStream.
func (m *moxaRealCOMSerial) SetLogger(logger *zap.SugaredLogger) {
	m.logger = logger
	m.transport.SetLogger(logger)
}

// SetMaxReceivedBytes implements SerialStream.
func (m *moxaRealCOMSerial) SetMaxReceivedBytes(max int64) {
	m.transport.SetMaxReceivedBytes(max)
}

func (m *moxaRealCOMSerial) SetDTR(dtr bool) error {
	if !m.isopen {
		return base.ErrNotOpened
	}

	lineCtrl := byte(0)
	if dtr {
		lineCtrl |= ASPP_MODEM_DTR
	}
	// Keep RTS state (read current state or default to on)
	lineCtrl |= ASPP_MODEM_RTS

	m.writebuffer = m.writeCommand(m.writebuffer[:0], NPREAL_ASPP_COMMAND_SET, ASPP_CMD_LINECTRL, []byte{lineCtrl})
	return m.transport.Write(m.writebuffer)
}

// SetFlowControl implements SerialStream.
func (m *moxaRealCOMSerial) SetFlowControl(flowControl base.SerialFlowControl) error {
	if !m.isopen {
		return base.ErrNotOpened
	}

	if err := sanityControl(flowControl); err != nil {
		return err
	}

	m.settings.FlowControl = flowControl

	flowData := []byte{byte(moxaFlowControl(flowControl))}
	m.writebuffer = m.writeCommand(m.writebuffer[:0], NPREAL_ASPP_COMMAND_SET, ASPP_CMD_FLOWCTRL, flowData)

	// Set RTS/DTR for no flow control
	if flowControl == base.SerialNoFlowControl {
		lineData := []byte{ASPP_MODEM_DTR | ASPP_MODEM_RTS}
		m.writebuffer = m.writeCommand(m.writebuffer, NPREAL_ASPP_COMMAND_SET, ASPP_CMD_LINECTRL, lineData)
	}

	return m.transport.Write(m.writebuffer)
}

// moxaFlowControl converts base flow control to Moxa ASPP flow control
func moxaFlowControl(fc base.SerialFlowControl) byte {
	switch fc {
	case base.SerialNoFlowControl:
		return ASPP_FLOW_NONE
	case base.SerialSWFlowControl:
		return ASPP_FLOW_SW
	case base.SerialHWFlowControl:
		return ASPP_FLOW_HW
	default:
		return ASPP_FLOW_NONE
	}
}

func sanityControl(flowControl base.SerialFlowControl) error {
	switch flowControl {
	case base.SerialNoFlowControl, base.SerialSWFlowControl, base.SerialHWFlowControl:
		return nil
	case base.SerialDCDFlowControl, base.SerialDSRFlowControl:
		return fmt.Errorf("unsupported flow control %d (DCD/DSR not supported by Moxa Real COM)", flowControl)
	default:
		return fmt.Errorf("unsupported flow control %d", flowControl)
	}
}

func sanitySpeed(baudRate int, dataBits base.SerialDataBits, parity base.SerialParity, stopBits base.SerialStopBits) error {
	switch baudRate {
	case 300, 600, 1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600:
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
func (m *moxaRealCOMSerial) SetSpeed(baudRate int, dataBits base.SerialDataBits, parity base.SerialParity, stopBits base.SerialStopBits) error {
	if !m.isopen {
		return base.ErrNotOpened
	}

	if err := sanitySpeed(baudRate, dataBits, parity, stopBits); err != nil {
		return err
	}

	m.settings.BaudRate = baudRate
	m.settings.DataBits = dataBits
	m.settings.Parity = parity
	m.settings.StopBits = stopBits

	// Send SETBAUD command
	baudData := make([]byte, 4)
	binary.BigEndian.PutUint32(baudData, uint32(baudRate))
	m.writebuffer = m.writeCommand(m.writebuffer[:0], NPREAL_ASPP_COMMAND_SET, ASPP_CMD_SETBAUD, baudData)

	// Send LINECTRL for data bits, parity, stop bits
	// Note: The actual encoding may vary by device - this is a simplified version
	// In practice, these might be combined into PORT_INIT or separate commands
	lineCtrlData := []byte{byte(dataBits), byte(parity), byte(stopBits)}
	m.writebuffer = m.writeCommand(m.writebuffer, NPREAL_ASPP_COMMAND_SET, ASPP_CMD_LINECTRL, lineCtrlData)

	return m.transport.Write(m.writebuffer)
}

// Write implements SerialStream.
func (m *moxaRealCOMSerial) Write(src []byte) error {
	if !m.isopen {
		return base.ErrNotOpened
	}
	if len(src) == 0 {
		return nil
	}

	// Moxa Real COM sends raw data without escaping
	// However, we should chunk large writes to avoid buffer issues
	for len(src) > 0 {
		chunk := src
		if len(chunk) > writeChunk {
			chunk = src[:writeChunk]
		}

		if err := m.transport.Write(chunk); err != nil {
			return err
		}

		src = src[len(chunk):]
	}

	return nil
}

// New creates a new Moxa Real COM serial stream
func New(t base.Stream, settings *base.SerialStreamSettings) base.SerialStream {
	ret := &moxaRealCOMSerial{
		transport:   t,
		isopen:      false,
		writebuffer: make([]byte, 0, 1024),
		readbuffer:  make([]byte, 0, 1024),
	}
	if settings != nil {
		ret.havesettings = true
		ret.settings = *settings // copy settings
	}
	return ret
}
